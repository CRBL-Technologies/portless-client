use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    io::{self, Cursor},
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use futures_util::StreamExt;
use portless_contracts::portless::v1::QuicApplicationErrorCode;
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use rand::{rngs::OsRng, RngCore};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};
use reqwest::{
    header::{self, HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
    Client, Method, Url,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    RootCertStore,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::{
    fs,
    io::{self as tokio_io, AsyncWriteExt},
    net::lookup_host,
    time,
};
use tracing::{info, warn};
use x509_parser::prelude::*;

use crate::{
    config::{Config, KeepaliveProfile},
    control::{CertificateResponse, ControlClient, DeviceConfig, TrustBundle},
    state::DaemonState,
    ui::{DaemonStatus, UiState},
};

const ALPN: &[u8] = b"portless-quic-v1";
const MAX_FRAME_HEAD: usize = 128 * 1024;
const MAX_REQUEST_BODY: u64 = 64 * 1024 * 1024;
const STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const CONNECTION_RECEIVE_WINDOW: u32 = 64 * 1024 * 1024;
const SEND_WINDOW: u64 = 32 * 1024 * 1024;
const INITIAL_RTT: Duration = Duration::from_millis(100);
const STREAM_CANCELLED: VarInt = VarInt::from_u32(QuicApplicationErrorCode::Cancelled as u32);
const STREAM_RELAY_DRAINING: VarInt =
    VarInt::from_u32(QuicApplicationErrorCode::RelayDraining as u32);
const STREAM_QUOTA_EXCEEDED: VarInt =
    VarInt::from_u32(QuicApplicationErrorCode::QuotaExceeded as u32);
const STREAM_REVOKED: VarInt = VarInt::from_u32(QuicApplicationErrorCode::Revoked as u32);
const THROUGHPUT_METHOD: &str = "PORTLESS_BENCH";
const THROUGHPUT_PATH: &str = "/_portless/throughput";
const THROUGHPUT_BYTES_HEADER: &str = "x-portless-synthetic-bytes";
const THROUGHPUT_CHUNK_HEADER: &str = "x-portless-synthetic-chunk";
const MAX_THROUGHPUT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_THROUGHPUT_CHUNK_BYTES: usize = 1024 * 1024;
const DEVICE_KEY_SECRET_FILE: &str = "device.key.secret";
const DEVICE_KEY_ENCRYPTED_FILE: &str = "device.key.pem.enc";
const DEVICE_KEY_PLAINTEXT_FILE: &str = "device.key.pem";
const DEVICE_KEY_SECRET_ENV: &str = "PORTLESS_DEVICE_KEY_SECRET";
const DEVICE_KEY_AAD: &[u8] = b"portless-device-key-v1";

pub struct TunnelIdentity {
    ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

pub struct TunnelContext {
    device: DeviceConfig,
    identity: TunnelIdentity,
}

pub async fn load_tunnel_context(
    cfg: &Config,
    control: &ControlClient,
    ui: &UiState,
) -> Result<TunnelContext> {
    let trust = control.fetch_trust().await?;
    info!(trust_bytes = trust.pem.len(), "fetched trust bundle");

    let device = control.fetch_device_config().await?;
    info!(
        tunnel_id = %device.tunnel_id,
        subdomain = %device.subdomain,
        relay = %device.relay_address,
        config_generation = device.config_generation,
        "fetched device config"
    );
    persist_device_state(cfg, &device, ui).await?;
    ui.set_status(DaemonStatus::Reconnecting).await;

    let identity = ensure_identity(cfg, control, &device, &trust).await?;
    Ok(TunnelContext { device, identity })
}

async fn persist_device_state(cfg: &Config, device: &DeviceConfig, ui: &UiState) -> Result<()> {
    let mut state = DaemonState::load(&cfg.data_dir).await?;
    state.tunnel_id = Some(device.tunnel_id.clone());
    state.subdomain = Some(device.subdomain.clone());
    state.config_generation = Some(device.config_generation);
    state.relay_address = Some(device.relay_address.clone());
    state.save(&cfg.data_dir).await?;
    ui.set_device(device).await;
    Ok(())
}

async fn ensure_identity(
    cfg: &Config,
    control: &ControlClient,
    device: &DeviceConfig,
    trust: &TrustBundle,
) -> Result<TunnelIdentity> {
    fs::create_dir_all(&cfg.data_dir)
        .await
        .context("create daemon data dir")?;
    let cert_path = cfg.data_dir.join("device.cert.pem");
    let trust_path = cfg.data_dir.join("trust.pem");

    let existing_key = read_device_key(&cfg.data_dir).await?;
    let existing_cert = match fs::read_to_string(&cert_path).await {
        Ok(raw) => Some(raw),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err).context("read daemon certificate"),
    };
    if let (Some(key_pem), Some(cert_pem)) = (&existing_key, &existing_cert) {
        if !certificate_needs_renewal(cert_pem, device) {
            write_encrypted_device_key(&cfg.data_dir, key_pem).await?;
            fs::write(&trust_path, &trust.pem)
                .await
                .context("write trust bundle")?;
            return Ok(TunnelIdentity {
                ca_pem: trust.pem.clone(),
                cert_pem: cert_pem.clone(),
                key_pem: key_pem.clone(),
            });
        }
    }

    let key_pair = match existing_key {
        Some(raw) => KeyPair::from_pem(&raw).context("parse existing daemon key")?,
        None => KeyPair::generate().context("generate daemon key")?,
    };
    let key_pem = key_pair.serialize_pem();
    let csr_pem = device_csr_pem(device, &key_pair)?;
    let request_id = certificate_request_id(device);
    let issued = control
        .request_certificate(&csr_pem, &request_id)
        .await
        .context("request daemon certificate")?;
    write_identity_files(&cfg.data_dir, &key_pem, &issued, &trust.pem).await?;

    Ok(TunnelIdentity {
        ca_pem: trust.pem.clone(),
        cert_pem: issued.certificate_pem,
        key_pem,
    })
}

pub async fn run(
    cfg: Config,
    control: ControlClient,
    mut context: TunnelContext,
    ui: UiState,
) -> Result<()> {
    let http = Client::builder()
        .redirect(Policy::none())
        .build()
        .context("build PMS HTTP client")?;
    let mut attempt = 0_u32;

    loop {
        if certificate_needs_renewal(&context.identity.cert_pem, &context.device) {
            match load_tunnel_context(&cfg, &control, &ui).await {
                Ok(updated) => {
                    context = updated;
                    attempt = 0;
                }
                Err(err) => {
                    ui.set_status(DaemonStatus::RelayUnreachable).await;
                    warn!(
                        error = %format!("{err:#}"),
                        attempt,
                        "refresh daemon certificate failed"
                    );
                    let delay = reconnect_delay(attempt);
                    attempt = attempt.saturating_add(1);
                    time::sleep(delay).await;
                    continue;
                }
            }
        }

        let remote = relay_target(&context.device.relay_address).await?;
        let client_config = quic_client_config(&context.identity, &cfg.keepalive_profile)?;
        ui.set_status(DaemonStatus::Reconnecting).await;
        let (endpoint, connection) = match connect_once(
            &context.device,
            &client_config,
            &remote,
            &cfg.keepalive_profile,
        )
        .await
        {
            Ok(active) => active,
            Err(err) => {
                ui.set_status(DaemonStatus::RelayUnreachable).await;
                warn!(
                    error = %format!("{err:#}"),
                    relay = %remote.addr,
                    attempt,
                    "relay QUIC tunnel disconnected"
                );
                let delay = reconnect_delay(attempt);
                attempt = attempt.saturating_add(1);
                time::sleep(delay).await;
                continue;
            }
        };

        attempt = 0;
        ui.set_status(DaemonStatus::Connected).await;
        let renewal_delay = certificate_renewal_delay(&context.identity.cert_pem, &context.device);
        let renewal_timer = time::sleep(renewal_delay);
        tokio::pin!(renewal_timer);
        let connection_for_renewal = connection.clone();
        let delay = tokio::select! {
            result = serve_connection(&cfg, &http, endpoint, connection, ui.clone()) => {
                match result {
                    Ok(status) => {
                        ui.set_status(status).await;
                        warn!(relay = %remote.addr, status = ?status, "relay QUIC tunnel closed");
                        if terminal_close_status(status) {
                            Duration::from_secs(60)
                        } else {
                            reconnect_delay(0)
                        }
                    }
                    Err(err) => {
                        ui.set_status(DaemonStatus::Reconnecting).await;
                        warn!(error = %format!("{err:#}"), relay = %remote.addr, "relay QUIC tunnel disconnected");
                        reconnect_delay(0)
                    }
                }
            }
            _ = &mut renewal_timer => {
                ui.set_status(DaemonStatus::Reconnecting).await;
                connection_for_renewal.close(STREAM_CANCELLED, b"daemon certificate renewal");
                info!(
                    relay = %remote.addr,
                    "daemon certificate renewal threshold reached; reconnecting"
                );
                Duration::ZERO
            }
        };
        time::sleep(delay).await;
    }
}

async fn connect_once(
    device: &DeviceConfig,
    client_config: &quinn::ClientConfig,
    remote: &RelayTarget,
    keepalive_profile: &KeepaliveProfile,
) -> Result<(Endpoint, Connection)> {
    let bind: SocketAddr = "[::]:0".parse().expect("valid client bind address");
    let mut endpoint = Endpoint::client(bind).context("create QUIC client endpoint")?;
    endpoint.set_default_client_config(client_config.clone());
    let connecting = endpoint
        .connect(remote.addr, &remote.server_name)
        .context("start QUIC relay connection")?;
    let connection = time::timeout(keepalive_profile.quic_connect_timeout(), connecting)
        .await
        .context("connect QUIC relay timed out")?
        .context("connect QUIC relay")?;
    time::timeout(
        keepalive_profile.relay_hello_timeout(),
        send_hello(&connection, device),
    )
    .await
    .context("send relay hello timed out")??;
    info!(relay = %remote.addr, server_name = %remote.server_name, "relay QUIC tunnel connected");
    Ok((endpoint, connection))
}

async fn serve_connection(
    cfg: &Config,
    http: &Client,
    _endpoint: Endpoint,
    connection: Connection,
    ui: UiState,
) -> Result<DaemonStatus> {
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let http = http.clone();
                let pms_url = cfg.pms_url.clone();
                let ui = ui.clone();
                tokio::spawn(async move {
                    if let Err(err) = forward_request(http, pms_url, send, recv, ui).await {
                        warn!(error = %format!("{err:#}"), "forward QUIC request failed");
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed(close)) => {
                return Ok(status_for_application_close(close.error_code));
            }
            Err(err) => return Err(err).context("accept QUIC request stream"),
        }
    }
}

fn status_for_application_close(error_code: VarInt) -> DaemonStatus {
    if error_code == STREAM_QUOTA_EXCEEDED {
        DaemonStatus::CapReached
    } else if error_code == STREAM_REVOKED {
        DaemonStatus::DeviceRevoked
    } else if error_code == STREAM_RELAY_DRAINING || error_code == STREAM_CANCELLED {
        DaemonStatus::Reconnecting
    } else {
        DaemonStatus::RelayUnreachable
    }
}

fn terminal_close_status(status: DaemonStatus) -> bool {
    matches!(
        status,
        DaemonStatus::CapReached | DaemonStatus::DeviceRevoked
    )
}

async fn send_hello(connection: &Connection, device: &DeviceConfig) -> Result<()> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("open daemon hello stream")?;
    write_json_frame(
        &mut send,
        &DaemonHello {
            tunnel_id: device.tunnel_id.clone(),
            subdomain: device.subdomain.clone(),
        },
    )
    .await
    .context("write daemon hello")?;
    send.finish().context("finish daemon hello stream")?;
    let ack: RelayHello = read_json_frame(&mut recv)
        .await
        .context("read relay hello ack")?;
    if !ack.accepted {
        bail!("relay rejected daemon hello");
    }
    Ok(())
}

async fn forward_request(
    http: Client,
    pms_url: Url,
    send: SendStream,
    mut recv: RecvStream,
    ui: UiState,
) -> Result<()> {
    let request: TunnelRequest = read_json_frame(&mut recv)
        .await
        .context("read relay request head")?;
    let started = time::Instant::now();
    if let Some(config) = synthetic_benchmark_config(&request)? {
        return stream_synthetic_response(request, send, started, config).await;
    }
    if request.upgrade.is_some() {
        return forward_upgrade_request(http, pms_url, request, send, recv, started, ui).await;
    }

    let body = quic_request_body(recv);
    let mut send = send;
    match send_local_request(&http, &pms_url, &request, body).await {
        Ok(response) => {
            ui.set_status(DaemonStatus::Connected).await;
            let rewrite = RedirectRewrite::from_request(&pms_url, &request.headers);
            stream_local_response(
                request.id,
                request.method,
                request.path_query,
                response,
                &mut send,
                false,
                started,
                rewrite.as_ref(),
            )
            .await
        }
        Err(err) => {
            ui.set_status(DaemonStatus::PlexUnreachable).await;
            warn!(
                request_id = %request.id,
                method = %request.method,
                error = %format!("{err:#}"),
                "local PMS request failed"
            );
            log_daemon_transfer(DaemonTransferLog {
                request_id: &request.id,
                method: &request.method,
                kind: "http",
                status: 502,
                request_bytes: 0,
                response_bytes: 0,
                io: DaemonIoMetrics::default(),
                started,
                outcome: "pms_request_failed",
            });
            send_error_response(request.id, err, &mut send).await
        }
    }
}

async fn forward_upgrade_request(
    http: Client,
    pms_url: Url,
    request: TunnelRequest,
    mut send: SendStream,
    recv: RecvStream,
    started: time::Instant,
    ui: UiState,
) -> Result<()> {
    match send_local_upgrade_request(&http, &pms_url, &request).await {
        Ok(response) if response.status() == reqwest::StatusCode::SWITCHING_PROTOCOLS => {
            ui.set_status(DaemonStatus::Connected).await;
            stream_local_upgrade_response(request.id, request.method, response, send, recv, started)
                .await
        }
        Ok(response) => {
            ui.set_status(DaemonStatus::Connected).await;
            let rewrite = RedirectRewrite::from_request(&pms_url, &request.headers);
            stream_local_response(
                request.id,
                request.method,
                request.path_query,
                response,
                &mut send,
                false,
                started,
                rewrite.as_ref(),
            )
            .await
        }
        Err(err) => {
            ui.set_status(DaemonStatus::PlexUnreachable).await;
            warn!(
                request_id = %request.id,
                method = %request.method,
                error = %format!("{err:#}"),
                "local PMS upgrade request failed"
            );
            log_daemon_transfer(DaemonTransferLog {
                request_id: &request.id,
                method: &request.method,
                kind: "upgrade",
                status: 502,
                request_bytes: 0,
                response_bytes: 0,
                io: DaemonIoMetrics::default(),
                started,
                outcome: "pms_upgrade_request_failed",
            });
            send_error_response(request.id, err, &mut send).await
        }
    }
}

fn synthetic_benchmark_config(request: &TunnelRequest) -> Result<Option<SyntheticBenchmarkConfig>> {
    if request.method != THROUGHPUT_METHOD || request.path_query != THROUGHPUT_PATH {
        return Ok(None);
    }
    if request.upgrade.is_some() {
        bail!("synthetic throughput benchmark cannot be an upgrade request");
    }
    let bytes = synthetic_header(request, THROUGHPUT_BYTES_HEADER)
        .ok_or_else(|| anyhow!("missing synthetic throughput byte count"))?
        .parse::<u64>()
        .context("parse synthetic throughput byte count")?;
    if bytes == 0 || bytes > MAX_THROUGHPUT_BYTES {
        bail!("synthetic throughput byte count out of range");
    }
    let chunk_bytes = synthetic_header(request, THROUGHPUT_CHUNK_HEADER)
        .ok_or_else(|| anyhow!("missing synthetic throughput chunk size"))?
        .parse::<usize>()
        .context("parse synthetic throughput chunk size")?;
    if chunk_bytes == 0 || chunk_bytes > MAX_THROUGHPUT_CHUNK_BYTES {
        bail!("synthetic throughput chunk size out of range");
    }
    Ok(Some(SyntheticBenchmarkConfig { bytes, chunk_bytes }))
}

fn synthetic_header<'a>(request: &'a TunnelRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

async fn stream_synthetic_response(
    request: TunnelRequest,
    mut send: SendStream,
    started: time::Instant,
    config: SyntheticBenchmarkConfig,
) -> Result<()> {
    let request_id = request.id;
    let method = request.method;
    let status = 200;
    let head = TunnelResponseHead {
        id: request_id.clone(),
        status,
        headers: vec![
            HeaderPair {
                name: header::CONTENT_TYPE.as_str().to_owned(),
                value: "application/octet-stream".to_owned(),
            },
            HeaderPair {
                name: header::CONTENT_LENGTH.as_str().to_owned(),
                value: config.bytes.to_string(),
            },
            HeaderPair {
                name: header::CACHE_CONTROL.as_str().to_owned(),
                value: "no-store".to_owned(),
            },
        ],
    };
    if let Err(err) = write_json_frame(&mut send, &head).await {
        log_daemon_transfer(DaemonTransferLog {
            request_id: &request_id,
            method: &method,
            kind: "synthetic",
            status,
            request_bytes: 0,
            response_bytes: 0,
            io: DaemonIoMetrics::default(),
            started,
            outcome: "write_head_failed",
        });
        return Err(err).context("write synthetic response head");
    }

    let chunk = vec![0_u8; config.chunk_bytes];
    let mut remaining = config.bytes;
    let mut response_bytes = 0_u64;
    let mut io_metrics = DaemonIoMetrics::default();
    while remaining > 0 {
        let write_len = remaining.min(chunk.len() as u64) as usize;
        let quic_write_started = time::Instant::now();
        let write_result = send.write_all(&chunk[..write_len]).await;
        io_metrics.quic_write_wait_micros = io_metrics
            .quic_write_wait_micros
            .saturating_add(elapsed_micros(quic_write_started));
        if let Err(err) = write_result {
            log_daemon_transfer(DaemonTransferLog {
                request_id: &request_id,
                method: &method,
                kind: "synthetic",
                status,
                request_bytes: 0,
                response_bytes,
                io: io_metrics,
                started,
                outcome: "quic_write_failed",
            });
            return Err(err).context("write synthetic response body");
        }
        remaining -= write_len as u64;
        response_bytes = response_bytes.saturating_add(write_len as u64);
    }
    if let Err(err) = send.finish() {
        log_daemon_transfer(DaemonTransferLog {
            request_id: &request_id,
            method: &method,
            kind: "synthetic",
            status,
            request_bytes: 0,
            response_bytes,
            io: io_metrics,
            started,
            outcome: "finish_failed",
        });
        return Err(err).context("finish synthetic response stream");
    }
    log_daemon_transfer(DaemonTransferLog {
        request_id: &request_id,
        method: &method,
        kind: "synthetic",
        status,
        request_bytes: 0,
        response_bytes,
        io: io_metrics,
        started,
        outcome: "ok",
    });
    Ok(())
}

async fn send_local_request(
    http: &Client,
    pms_url: &Url,
    request: &TunnelRequest,
    body: reqwest::Body,
) -> Result<reqwest::Response> {
    let method = Method::from_bytes(request.method.as_bytes()).context("parse request method")?;
    let target = pms_target_url(pms_url, &request.path_query)?;
    let mut builder = http.request(method, target);
    for header in &request.headers {
        let name = HeaderName::from_bytes(header.name.as_bytes()).context("parse header name")?;
        if is_hop_by_hop(&name) {
            continue;
        }
        let value = HeaderValue::from_str(&header.value).context("parse header value")?;
        builder = builder.header(name, value);
    }
    builder
        .body(body)
        .send()
        .await
        .context("send local PMS request")
}

async fn send_local_upgrade_request(
    http: &Client,
    pms_url: &Url,
    request: &TunnelRequest,
) -> Result<reqwest::Response> {
    let method = Method::from_bytes(request.method.as_bytes()).context("parse request method")?;
    let target = pms_target_url(pms_url, &request.path_query)?;
    let upgrade = request
        .upgrade
        .as_deref()
        .ok_or_else(|| anyhow!("missing upgrade token"))?;
    let mut builder = http
        .request(method, target)
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, upgrade);
    for header in &request.headers {
        let name = HeaderName::from_bytes(header.name.as_bytes()).context("parse header name")?;
        if is_hop_by_hop(&name) {
            continue;
        }
        let value = HeaderValue::from_str(&header.value).context("parse header value")?;
        builder = builder.header(name, value);
    }
    builder
        .send()
        .await
        .context("send local PMS upgrade request")
}

fn quic_request_body(mut recv: RecvStream) -> reqwest::Body {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, io::Error>>(64);
    tokio::spawn(async move {
        let mut total = 0_u64;
        let mut buf = vec![0_u8; 64 * 1024];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(read)) => {
                    total = total.saturating_add(read as u64);
                    if total > MAX_REQUEST_BODY {
                        let err = io::Error::new(
                            io::ErrorKind::InvalidData,
                            "request body exceeds daemon limit",
                        );
                        let _ = tx.send(Err(err)).await;
                        break;
                    }
                    if tx.send(Ok(buf[..read].to_vec())).await.is_err() {
                        let _ = recv.stop(STREAM_CANCELLED);
                        break;
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    let err = io::Error::new(io::ErrorKind::ConnectionAborted, err.to_string());
                    let _ = tx.send(Err(err)).await;
                    break;
                }
            }
        }
    });
    reqwest::Body::wrap_stream(tokio_stream::wrappers::ReceiverStream::new(rx))
}

#[allow(clippy::too_many_arguments)]
async fn stream_local_response(
    request_id: String,
    method: String,
    path_query: String,
    response: reqwest::Response,
    send: &mut SendStream,
    allow_upgrade_headers: bool,
    started: time::Instant,
    rewrite: Option<&RedirectRewrite>,
) -> Result<()> {
    let status = response.status().as_u16();
    let preserve_content_length = should_preserve_response_content_length(&method, &path_query);
    let head = TunnelResponseHead {
        id: request_id.clone(),
        status,
        headers: serializable_response_headers(
            response.headers(),
            allow_upgrade_headers,
            rewrite,
            preserve_content_length,
        ),
    };
    if let Err(err) = write_json_frame(send, &head).await {
        log_daemon_transfer(DaemonTransferLog {
            request_id: &request_id,
            method: &method,
            kind: "http",
            status,
            request_bytes: 0,
            response_bytes: 0,
            io: DaemonIoMetrics::default(),
            started,
            outcome: "write_head_failed",
        });
        return Err(err).context("write response head");
    }

    let mut body = response.bytes_stream();
    let mut response_bytes = 0_u64;
    let mut io_metrics = DaemonIoMetrics::default();
    loop {
        let pms_read_started = time::Instant::now();
        let chunk = body.next().await;
        io_metrics.pms_read_wait_micros = io_metrics
            .pms_read_wait_micros
            .saturating_add(elapsed_micros(pms_read_started));
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(err) => {
                log_daemon_transfer(DaemonTransferLog {
                    request_id: &request_id,
                    method: &method,
                    kind: "http",
                    status,
                    request_bytes: 0,
                    response_bytes,
                    io: io_metrics,
                    started,
                    outcome: "pms_read_failed",
                });
                return Err(err).context("read local PMS response chunk");
            }
        };
        response_bytes = response_bytes.saturating_add(chunk.len() as u64);
        let quic_write_started = time::Instant::now();
        let write_result = send.write_all(&chunk).await;
        io_metrics.quic_write_wait_micros = io_metrics
            .quic_write_wait_micros
            .saturating_add(elapsed_micros(quic_write_started));
        if let Err(err) = write_result {
            log_daemon_transfer(DaemonTransferLog {
                request_id: &request_id,
                method: &method,
                kind: "http",
                status,
                request_bytes: 0,
                response_bytes,
                io: io_metrics,
                started,
                outcome: "quic_write_failed",
            });
            return Err(err).context("write response body chunk");
        }
    }
    if let Err(err) = send.finish() {
        log_daemon_transfer(DaemonTransferLog {
            request_id: &request_id,
            method: &method,
            kind: "http",
            status,
            request_bytes: 0,
            response_bytes,
            io: io_metrics,
            started,
            outcome: "finish_failed",
        });
        return Err(err).context("finish response stream");
    }
    log_daemon_transfer(DaemonTransferLog {
        request_id: &request_id,
        method: &method,
        kind: "http",
        status,
        request_bytes: 0,
        response_bytes,
        io: io_metrics,
        started,
        outcome: "ok",
    });
    Ok(())
}

async fn stream_local_upgrade_response(
    request_id: String,
    method: String,
    response: reqwest::Response,
    mut send: SendStream,
    recv: RecvStream,
    started: time::Instant,
) -> Result<()> {
    let status = response.status().as_u16();
    let head = TunnelResponseHead {
        id: request_id.clone(),
        status,
        headers: serializable_response_headers(response.headers(), true, None, false),
    };
    if let Err(err) = write_json_frame(&mut send, &head).await {
        log_daemon_transfer(DaemonTransferLog {
            request_id: &request_id,
            method: &method,
            kind: "upgrade",
            status,
            request_bytes: 0,
            response_bytes: 0,
            io: DaemonIoMetrics::default(),
            started,
            outcome: "write_head_failed",
        });
        return Err(err).context("write upgrade response head");
    }

    let upgraded = match response.upgrade().await {
        Ok(upgraded) => upgraded,
        Err(err) => {
            log_daemon_transfer(DaemonTransferLog {
                request_id: &request_id,
                method: &method,
                kind: "upgrade",
                status,
                request_bytes: 0,
                response_bytes: 0,
                io: DaemonIoMetrics::default(),
                started,
                outcome: "pms_upgrade_failed",
            });
            return Err(err).context("upgrade local PMS response");
        }
    };
    let (mut pms_read, mut pms_write) = tokio_io::split(upgraded);
    let mut relay_send = send;
    let mut relay_recv = recv;

    let relay_to_pms = async {
        let copied = tokio_io::copy(&mut relay_recv, &mut pms_write)
            .await
            .context("copy upgraded QUIC bytes to PMS")?;
        pms_write
            .shutdown()
            .await
            .context("shutdown upgraded PMS write")?;
        Ok::<u64, anyhow::Error>(copied)
    };

    let pms_to_relay = async {
        let copied = tokio_io::copy(&mut pms_read, &mut relay_send)
            .await
            .context("copy upgraded PMS bytes to QUIC")?;
        relay_send
            .finish()
            .context("finish upgraded QUIC response stream")?;
        Ok::<u64, anyhow::Error>(copied)
    };

    match tokio::try_join!(relay_to_pms, pms_to_relay) {
        Ok((request_bytes, response_bytes)) => {
            log_daemon_transfer(DaemonTransferLog {
                request_id: &request_id,
                method: &method,
                kind: "upgrade",
                status,
                request_bytes,
                response_bytes,
                io: DaemonIoMetrics::default(),
                started,
                outcome: "ok",
            });
        }
        Err(err) => {
            log_daemon_transfer(DaemonTransferLog {
                request_id: &request_id,
                method: &method,
                kind: "upgrade",
                status,
                request_bytes: 0,
                response_bytes: 0,
                io: DaemonIoMetrics::default(),
                started,
                outcome: "copy_failed",
            });
            return Err(err);
        }
    }
    Ok(())
}

async fn send_error_response(
    request_id: String,
    err: anyhow::Error,
    send: &mut SendStream,
) -> Result<()> {
    let body = err.to_string();
    write_json_frame(
        send,
        &TunnelResponseHead {
            id: request_id,
            status: 502,
            headers: vec![HeaderPair {
                name: header::CONTENT_TYPE.as_str().to_owned(),
                value: "text/plain; charset=utf-8".to_owned(),
            }],
        },
    )
    .await
    .context("write error response head")?;
    send.write_all(body.as_bytes())
        .await
        .context("write error response body")?;
    send.finish().context("finish error response stream")?;
    Ok(())
}

async fn write_json_frame<T: Serialize>(send: &mut SendStream, value: &T) -> Result<()> {
    let raw = serde_json::to_vec(value).context("encode JSON frame")?;
    if raw.len() > MAX_FRAME_HEAD {
        bail!("JSON frame exceeds {MAX_FRAME_HEAD} bytes");
    }
    send.write_all(&(raw.len() as u32).to_be_bytes())
        .await
        .context("write JSON frame length")?;
    send.write_all(&raw).await.context("write JSON frame")
}

async fn read_json_frame<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T> {
    let mut len = [0_u8; 4];
    recv.read_exact(&mut len)
        .await
        .context("read JSON frame length")?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_HEAD {
        bail!("JSON frame exceeds {MAX_FRAME_HEAD} bytes");
    }
    let mut raw = vec![0_u8; len];
    recv.read_exact(&mut raw).await.context("read JSON frame")?;
    serde_json::from_slice(&raw).context("decode JSON frame")
}

fn pms_target_url(pms_url: &Url, path_query: &str) -> Result<Url> {
    let mut base = pms_url.clone();
    base.set_path("");
    base.set_query(None);
    base.set_fragment(None);
    let prefix = base.as_str().trim_end_matches('/');
    let suffix = if path_query.starts_with('/') {
        path_query.to_owned()
    } else {
        format!("/{path_query}")
    };
    Url::parse(&format!("{prefix}{suffix}")).context("build local PMS request URL")
}

struct RedirectRewrite {
    pms_origin: Url,
    public_origin: Url,
}

impl RedirectRewrite {
    fn from_request(pms_url: &Url, headers: &[HeaderPair]) -> Option<Self> {
        let public_host = first_header(headers, "x-forwarded-host")
            .or_else(|| first_header(headers, "host"))?
            .split(',')
            .next()?
            .trim();
        if public_host.is_empty() {
            return None;
        }
        let public_scheme = first_header(headers, "x-forwarded-proto")
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| {
                value.eq_ignore_ascii_case("http") || value.eq_ignore_ascii_case("https")
            })
            .unwrap_or("https")
            .to_ascii_lowercase();
        let public_origin = Url::parse(&format!("{public_scheme}://{public_host}/")).ok()?;
        let mut pms_origin = pms_url.clone();
        pms_origin.set_path("");
        pms_origin.set_query(None);
        pms_origin.set_fragment(None);
        Some(Self {
            pms_origin,
            public_origin,
        })
    }

    fn location(&self, raw: &str) -> Option<String> {
        let mut location = Url::parse(raw).ok()?;
        if !same_url_origin(&location, &self.pms_origin)
            && !same_url_hostname(&location, &self.public_origin)
        {
            return None;
        }
        location.set_scheme(self.public_origin.scheme()).ok()?;
        location.set_host(self.public_origin.host_str()).ok()?;
        location.set_port(self.public_origin.port()).ok()?;
        Some(location.to_string())
    }
}

fn first_header<'a>(headers: &'a [HeaderPair], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn same_url_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme() && same_url_host_port(left, right)
}

fn same_url_hostname(left: &Url, right: &Url) -> bool {
    left.host_str()
        .zip(right.host_str())
        .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn same_url_host_port(left: &Url, right: &Url) -> bool {
    same_url_hostname(left, right) && left.port_or_known_default() == right.port_or_known_default()
}

async fn relay_target(relay_address: &str) -> Result<RelayTarget> {
    let raw = relay_address.trim();
    if raw.is_empty() {
        return Err(anyhow!("relay address is empty"));
    }
    let url = if raw.contains("://") {
        Url::parse(raw).context("parse relay URL")?
    } else {
        Url::parse(&format!("https://{raw}")).context("parse relay host")?
    };
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("relay address is missing a host"))?
        .trim_matches(['[', ']'])
        .to_owned();
    let port = url.port_or_known_default().unwrap_or(443);
    let addr = lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("resolve relay {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("relay host resolved to no addresses"))?;
    Ok(RelayTarget {
        server_name: host,
        addr,
    })
}

fn bytes_per_second(bytes: u64, duration_ms: u64) -> u64 {
    if duration_ms == 0 {
        return 0;
    }
    bytes.saturating_mul(1000) / duration_ms
}

struct DaemonTransferLog<'a> {
    request_id: &'a str,
    method: &'a str,
    kind: &'static str,
    status: u16,
    request_bytes: u64,
    response_bytes: u64,
    io: DaemonIoMetrics,
    started: time::Instant,
    outcome: &'static str,
}

#[derive(Clone, Copy, Default)]
struct DaemonIoMetrics {
    pms_read_wait_micros: u64,
    quic_write_wait_micros: u64,
}

fn log_daemon_transfer(event: DaemonTransferLog<'_>) {
    let duration_ms = elapsed_millis(event.started);
    info!(
        request_id = event.request_id,
        method = event.method,
        kind = event.kind,
        status = event.status,
        request_bytes = event.request_bytes,
        response_bytes = event.response_bytes,
        duration_ms,
        response_bytes_per_sec = bytes_per_second(event.response_bytes, duration_ms),
        pms_read_wait_ms = micros_to_millis(event.io.pms_read_wait_micros),
        quic_write_wait_ms = micros_to_millis(event.io.quic_write_wait_micros),
        outcome = event.outcome,
        "daemon transfer finished"
    );
}

fn elapsed_millis(started: time::Instant) -> u64 {
    let elapsed = started.elapsed();
    let millis = elapsed.as_millis() as u64;
    if millis == 0 && elapsed > Duration::ZERO {
        1
    } else {
        millis
    }
}

fn elapsed_micros(started: time::Instant) -> u64 {
    started.elapsed().as_micros() as u64
}

fn micros_to_millis(value: u64) -> u64 {
    value / 1000
}

fn reconnect_delay(attempt: u32) -> Duration {
    let base = Duration::from_secs(1);
    let multiplier = 1_u32 << attempt.min(5);
    let capped = base.saturating_mul(multiplier).min(Duration::from_secs(15));
    capped + reconnect_jitter(attempt)
}

fn reconnect_jitter(attempt: u32) -> Duration {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut hasher = DefaultHasher::new();
    now.hash(&mut hasher);
    attempt.hash(&mut hasher);
    let jitter_ms = hasher.finish() % 1000;
    Duration::from_millis(jitter_ms)
}

#[cfg(test)]
fn serializable_headers(headers: &HeaderMap) -> Vec<HeaderPair> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            if is_hop_by_hop(name) {
                return None;
            }
            Some(HeaderPair {
                name: name.as_str().to_owned(),
                value: value.to_str().ok()?.to_owned(),
            })
        })
        .collect()
}

fn serializable_response_headers(
    headers: &HeaderMap,
    allow_upgrade_headers: bool,
    rewrite: Option<&RedirectRewrite>,
    preserve_content_length: bool,
) -> Vec<HeaderPair> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            if !allow_upgrade_headers && is_hop_by_hop_response(name, preserve_content_length) {
                return None;
            }
            let raw_value = value.to_str().ok()?;
            let value = if name == header::LOCATION {
                rewrite
                    .and_then(|rewrite| rewrite.location(raw_value))
                    .unwrap_or_else(|| raw_value.to_owned())
            } else {
                raw_value.to_owned()
            };
            Some(HeaderPair {
                name: name.as_str().to_owned(),
                value,
            })
        })
        .collect()
}

fn should_preserve_response_content_length(method: &str, path_query: &str) -> bool {
    method.eq_ignore_ascii_case("HEAD")
        || (method.eq_ignore_ascii_case("GET") && is_plex_download_media_path(path_query))
}

fn is_plex_download_media_path(path_query: &str) -> bool {
    let path = path_query
        .split_once('?')
        .map_or(path_query, |(path, _)| path);
    let segments: Vec<_> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    matches!(
        segments.as_slice(),
        ["downloadQueue", _, "item", _, "media"]
    )
}

fn is_hop_by_hop_response(name: &HeaderName, preserve_content_length: bool) -> bool {
    if preserve_content_length && name == header::CONTENT_LENGTH {
        return false;
    }
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}

fn quic_client_config(
    identity: &TunnelIdentity,
    keepalive_profile: &KeepaliveProfile,
) -> Result<quinn::ClientConfig> {
    let mut roots = RootCertStore::empty();
    for cert in parse_certs_pem(&identity.ca_pem)? {
        roots.add(cert).context("add relay CA certificate")?;
    }
    let certs = parse_certs_pem(&identity.cert_pem)?;
    let key = parse_private_key_pem(&identity.key_pem)?;
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .context("build daemon TLS client config")?;
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .context("build QUIC rustls client config")?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(0_u8.into());
    transport.max_concurrent_bidi_streams(128_u32.into());
    transport.stream_receive_window(STREAM_RECEIVE_WINDOW.into());
    transport.receive_window(CONNECTION_RECEIVE_WINDOW.into());
    transport.send_window(SEND_WINDOW);
    transport.initial_rtt(INITIAL_RTT);
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    transport.keep_alive_interval(Some(keepalive_profile.quic_keep_alive_interval()));
    transport.max_idle_timeout(Some(keepalive_profile.quic_max_idle_timeout().try_into()?));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

fn parse_certs_pem(raw: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = Cursor::new(raw.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse certificate PEM")?;
    if certs.is_empty() {
        bail!("certificate PEM did not contain any certificates");
    }
    Ok(certs)
}

fn parse_private_key_pem(raw: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = Cursor::new(raw.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .context("parse private key PEM")?
        .ok_or_else(|| anyhow!("private key PEM did not contain a private key"))
}

async fn read_device_key(data_dir: &Path) -> Result<Option<String>> {
    let encrypted_path = data_dir.join(DEVICE_KEY_ENCRYPTED_FILE);
    match fs::read_to_string(&encrypted_path).await {
        Ok(raw) => return decrypt_device_key(data_dir, &raw).await.map(Some),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("read encrypted daemon key"),
    }

    let plaintext_path = data_dir.join(DEVICE_KEY_PLAINTEXT_FILE);
    match fs::read_to_string(&plaintext_path).await {
        Ok(raw) => Ok(Some(raw)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).context("read plaintext daemon key"),
    }
}

async fn write_encrypted_device_key(data_dir: &Path, key_pem: &str) -> Result<()> {
    let secret = read_or_create_device_key_secret(data_dir).await?;
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = derive_device_key(&secret, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| anyhow!("build daemon key cipher: invalid key length"))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: key_pem.as_bytes(),
                aad: DEVICE_KEY_AAD,
            },
        )
        .map_err(|_| anyhow!("encrypt daemon private key"))?;
    let envelope = EncryptedDeviceKey {
        version: 1,
        kdf: "argon2id".to_owned(),
        cipher: "aes-256-gcm".to_owned(),
        salt: BASE64_STANDARD.encode(salt),
        nonce: BASE64_STANDARD.encode(nonce),
        ciphertext: BASE64_STANDARD.encode(ciphertext),
    };
    let encoded = serde_json::to_string_pretty(&envelope).context("encode encrypted daemon key")?;
    fs::write(data_dir.join(DEVICE_KEY_ENCRYPTED_FILE), encoded)
        .await
        .context("write encrypted daemon key")?;
    match fs::remove_file(data_dir.join(DEVICE_KEY_PLAINTEXT_FILE)).await {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("remove plaintext daemon key"),
    }
    Ok(())
}

async fn decrypt_device_key(data_dir: &Path, raw: &str) -> Result<String> {
    let secret = read_device_key_secret(data_dir).await?;
    let envelope: EncryptedDeviceKey =
        serde_json::from_str(raw).context("decode encrypted daemon key")?;
    if envelope.version != 1 || envelope.kdf != "argon2id" || envelope.cipher != "aes-256-gcm" {
        bail!("unsupported encrypted daemon key envelope");
    }
    let salt = BASE64_STANDARD
        .decode(envelope.salt)
        .context("decode daemon key salt")?;
    let nonce = BASE64_STANDARD
        .decode(envelope.nonce)
        .context("decode daemon key nonce")?;
    let ciphertext = BASE64_STANDARD
        .decode(envelope.ciphertext)
        .context("decode daemon key ciphertext")?;
    let key = derive_device_key(&secret, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| anyhow!("build daemon key cipher: invalid key length"))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext.as_ref(),
                aad: DEVICE_KEY_AAD,
            },
        )
        .map_err(|_| anyhow!("decrypt daemon private key"))?;
    String::from_utf8(plaintext).context("daemon private key is not UTF-8")
}

async fn read_or_create_device_key_secret(data_dir: &Path) -> Result<Vec<u8>> {
    if let Ok(raw) = std::env::var(DEVICE_KEY_SECRET_ENV) {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            bail!("{DEVICE_KEY_SECRET_ENV} is empty");
        }
        return Ok(trimmed.as_bytes().to_vec());
    }

    match read_device_key_secret(data_dir).await {
        Ok(secret) => Ok(secret),
        Err(err) if is_not_found(&err) => {
            let mut secret = [0_u8; 32];
            OsRng.fill_bytes(&mut secret);
            let path = data_dir.join(DEVICE_KEY_SECRET_FILE);
            write_secret_file(&path, &secret).await?;
            Ok(secret.to_vec())
        }
        Err(err) => Err(err),
    }
}

async fn read_device_key_secret(data_dir: &Path) -> Result<Vec<u8>> {
    if let Ok(raw) = std::env::var(DEVICE_KEY_SECRET_ENV) {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            bail!("{DEVICE_KEY_SECRET_ENV} is empty");
        }
        return Ok(trimmed.as_bytes().to_vec());
    }

    let path = data_dir.join(DEVICE_KEY_SECRET_FILE);
    let raw = fs::read(&path).await.context("read daemon key secret")?;
    let trimmed = String::from_utf8_lossy(&raw).trim().to_owned();
    if trimmed.is_empty() {
        bail!("daemon key secret is empty");
    }
    BASE64_STANDARD
        .decode(trimmed)
        .context("decode daemon key secret")
}

async fn write_secret_file(path: &Path, secret: &[u8]) -> Result<()> {
    fs::write(path, BASE64_STANDARD.encode(secret))
        .await
        .context("write daemon key secret")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions)
            .await
            .context("restrict daemon key secret permissions")?;
    }
    Ok(())
}

fn derive_device_key(secret: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|err| anyhow!("build Argon2id params: {err}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; 32];
    argon2
        .hash_password_into(secret, salt, &mut key)
        .map_err(|err| anyhow!("derive daemon key encryption key: {err}"))?;
    Ok(key)
}

fn is_not_found(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
    })
}

fn device_csr_pem(device: &DeviceConfig, key_pair: &KeyPair) -> Result<String> {
    let mut params = CertificateParams::new(vec![device.subdomain.clone()])
        .context("build daemon certificate parameters")?;
    params
        .distinguished_name
        .push(DnType::CommonName, device.tunnel_id.clone());
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    params
        .serialize_request(key_pair)
        .context("serialize daemon CSR")?
        .pem()
        .context("encode daemon CSR PEM")
}

fn certificate_needs_renewal(cert_pem: &str, device: &DeviceConfig) -> bool {
    let Ok(certs) = parse_certs_pem(cert_pem) else {
        return true;
    };
    let Some(leaf) = certs.first() else {
        return true;
    };
    let Ok((_, cert)) = X509Certificate::from_der(leaf.as_ref()) else {
        return true;
    };
    if !certificate_matches_device(&cert, device) {
        info!(
            tunnel_id = %device.tunnel_id,
            subdomain = %device.subdomain,
            "cached daemon certificate identity does not match device config; requesting replacement"
        );
        return true;
    }
    seconds_until_certificate_renewal(&cert, device) <= 0
}

fn certificate_renewal_delay(cert_pem: &str, device: &DeviceConfig) -> Duration {
    let Ok(certs) = parse_certs_pem(cert_pem) else {
        return Duration::ZERO;
    };
    let Some(leaf) = certs.first() else {
        return Duration::ZERO;
    };
    let Ok((_, cert)) = X509Certificate::from_der(leaf.as_ref()) else {
        return Duration::ZERO;
    };
    if !certificate_matches_device(&cert, device) {
        return Duration::ZERO;
    }
    let seconds = seconds_until_certificate_renewal(&cert, device);
    if seconds <= 0 {
        Duration::ZERO
    } else {
        Duration::from_secs(seconds as u64)
    }
}

fn seconds_until_certificate_renewal(cert: &X509Certificate<'_>, device: &DeviceConfig) -> i64 {
    let seconds_left = cert
        .validity()
        .not_after
        .timestamp()
        .saturating_sub(now_unix_seconds());
    seconds_left - renewal_threshold_seconds(&device.tunnel_id)
}

fn certificate_request_id(device: &DeviceConfig) -> String {
    certificate_request_id_at(device, now_unix_seconds())
}

fn certificate_request_id_at(device: &DeviceConfig, unix_seconds: i64) -> String {
    format!(
        "{}-{}-h{}",
        device.tunnel_id,
        device.config_generation,
        unix_seconds.div_euclid(60 * 60)
    )
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn certificate_matches_device(cert: &X509Certificate<'_>, device: &DeviceConfig) -> bool {
    let common_name_matches = cert.subject().iter_common_name().any(|name| {
        name.as_str()
            .map(|value| value == device.tunnel_id)
            .unwrap_or(false)
    });
    if !common_name_matches {
        return false;
    }

    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return false;
    };
    let expected_spiffe = format!("spiffe://portless.io/tunnel/{}", device.tunnel_id);
    let dns_matches = san.value.general_names.iter().any(|name| match name {
        GeneralName::DNSName(value) => *value == device.subdomain,
        _ => false,
    });
    let spiffe_matches = san.value.general_names.iter().any(|name| match name {
        GeneralName::URI(value) => *value == expected_spiffe,
        _ => false,
    });
    dns_matches && spiffe_matches
}

fn renewal_threshold_seconds(tunnel_id: &str) -> i64 {
    let mut hasher = DefaultHasher::new();
    tunnel_id.hash(&mut hasher);
    let jitter = (hasher.finish() % (2 * 60 * 60)) as i64;
    (16 * 60 * 60) + jitter
}

async fn write_identity_files(
    data_dir: &Path,
    key_pem: &str,
    issued: &CertificateResponse,
    trust_pem: &str,
) -> Result<()> {
    write_encrypted_device_key(data_dir, key_pem).await?;
    fs::write(data_dir.join("device.cert.pem"), &issued.certificate_pem)
        .await
        .context("write daemon certificate")?;
    fs::write(data_dir.join("trust.pem"), trust_pem)
        .await
        .context("write trust bundle")?;
    Ok(())
}

struct RelayTarget {
    server_name: String,
    addr: SocketAddr,
}

struct SyntheticBenchmarkConfig {
    bytes: u64,
    chunk_bytes: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct EncryptedDeviceKey {
    version: u8,
    kdf: String,
    cipher: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct DaemonHello {
    tunnel_id: String,
    subdomain: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RelayHello {
    accepted: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct TunnelRequest {
    id: String,
    method: String,
    path_query: String,
    headers: Vec<HeaderPair>,
    upgrade: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TunnelResponseHead {
    id: String,
    status: u16,
    headers: Vec<HeaderPair>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct HeaderPair {
    name: String,
    value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_pms_url_with_path_and_query() {
        let pms_url = Url::parse("http://127.0.0.1:32400").unwrap();
        let got = pms_target_url(
            &pms_url,
            "/video/:/transcode/universal/start.m3u8?X-Plex-Token=abc",
        )
        .unwrap();

        assert_eq!(
            got.as_str(),
            "http://127.0.0.1:32400/video/:/transcode/universal/start.m3u8?X-Plex-Token=abc"
        );
    }

    #[test]
    fn builds_pms_url_with_colon_prefixed_path() {
        let pms_url = Url::parse("http://127.0.0.1:32400").unwrap();
        let got = pms_target_url(&pms_url, ":/websockets/notifications?X-Plex-Token=abc").unwrap();

        assert_eq!(
            got.as_str(),
            "http://127.0.0.1:32400/:/websockets/notifications?X-Plex-Token=abc"
        );
    }

    #[test]
    fn omits_hop_by_hop_headers_but_keeps_host() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "plex.example.com".parse().unwrap());
        headers.insert(header::CONNECTION, "keep-alive".parse().unwrap());
        headers.insert(header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(header::ACCEPT, "text/html".parse().unwrap());

        let got = serializable_headers(&headers);

        assert_eq!(got.len(), 2);
        assert!(got
            .iter()
            .any(|header| header.name == "host" && header.value == "plex.example.com"));
        assert!(got
            .iter()
            .any(|header| header.name == "accept" && header.value == "text/html"));
    }

    #[test]
    fn application_close_codes_match_contract_statuses() {
        assert_eq!(
            u64::from(STREAM_CANCELLED),
            QuicApplicationErrorCode::Cancelled as u64
        );
        assert_eq!(
            status_for_application_close(STREAM_QUOTA_EXCEEDED),
            DaemonStatus::CapReached
        );
        assert_eq!(
            status_for_application_close(STREAM_REVOKED),
            DaemonStatus::DeviceRevoked
        );
        assert_eq!(
            status_for_application_close(STREAM_RELAY_DRAINING),
            DaemonStatus::Reconnecting
        );
        assert!(terminal_close_status(DaemonStatus::CapReached));
        assert!(terminal_close_status(DaemonStatus::DeviceRevoked));
        assert!(!terminal_close_status(DaemonStatus::Reconnecting));
    }

    #[test]
    fn rewrites_local_pms_redirects_to_public_origin() {
        let pms_url = Url::parse("http://127.0.0.1:32400").unwrap();
        let rewrite = RedirectRewrite::from_request(
            &pms_url,
            &[
                HeaderPair {
                    name: "host".to_owned(),
                    value: "antoine.staging.portless.io".to_owned(),
                },
                HeaderPair {
                    name: "x-forwarded-proto".to_owned(),
                    value: "https".to_owned(),
                },
            ],
        )
        .unwrap();

        let got = rewrite
            .location("http://127.0.0.1:32400/web/index.html")
            .unwrap();

        assert_eq!(got, "https://antoine.staging.portless.io/web/index.html");
    }

    #[test]
    fn rewrites_public_host_redirects_to_public_scheme() {
        let pms_url = Url::parse("http://127.0.0.1:32400").unwrap();
        let rewrite = RedirectRewrite::from_request(
            &pms_url,
            &[
                HeaderPair {
                    name: "host".to_owned(),
                    value: "antoine.staging.portless.io".to_owned(),
                },
                HeaderPair {
                    name: "x-forwarded-proto".to_owned(),
                    value: "https".to_owned(),
                },
            ],
        )
        .unwrap();

        let got = rewrite
            .location("http://antoine.staging.portless.io/web/index.html")
            .unwrap();

        assert_eq!(got, "https://antoine.staging.portless.io/web/index.html");
    }

    #[test]
    fn preserves_upgrade_response_headers_when_requested() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, "Upgrade".parse().unwrap());
        headers.insert(header::UPGRADE, "websocket".parse().unwrap());
        headers.insert("sec-websocket-accept", "abc".parse().unwrap());

        let got = serializable_response_headers(&headers, true, None, false);

        assert_eq!(got.len(), 3);
        assert!(got.iter().any(|header| header.name == "connection"));
        assert!(got.iter().any(|header| header.name == "upgrade"));
        assert!(got
            .iter()
            .any(|header| header.name == "sec-websocket-accept"));
    }

    #[test]
    fn strips_streaming_response_length_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, "1234".parse().unwrap());
        headers.insert(header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.insert(header::CONTENT_TYPE, "video/mp4".parse().unwrap());

        let got = serializable_response_headers(&headers, false, None, false);

        assert_eq!(got.len(), 1);
        assert!(got.iter().any(|header| header.name == "content-type"));
        assert!(!got.iter().any(|header| header.name == "content-length"));
        assert!(!got.iter().any(|header| header.name == "transfer-encoding"));
    }

    #[test]
    fn preserves_head_response_content_length() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, "1234".parse().unwrap());
        headers.insert(header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.insert(header::CONTENT_TYPE, "video/mp4".parse().unwrap());

        let got = serializable_response_headers(&headers, false, None, true);

        assert_eq!(got.len(), 2);
        assert!(got.iter().any(|header| header.name == "content-type"));
        assert!(got
            .iter()
            .any(|header| header.name == "content-length" && header.value == "1234"));
        assert!(!got.iter().any(|header| header.name == "transfer-encoding"));
    }

    #[test]
    fn preserves_download_media_get_response_content_length() {
        assert!(should_preserve_response_content_length(
            "GET",
            "/downloadQueue/2/item/75/media?token=redacted"
        ));
    }

    #[test]
    fn strips_generic_get_response_content_length() {
        assert!(!should_preserve_response_content_length(
            "GET",
            "/library/parts/7490/file.mp4"
        ));
    }

    #[test]
    fn renewal_threshold_fits_24_hour_certificates() {
        let threshold = renewal_threshold_seconds("tunnel-123");

        assert!(threshold >= 16 * 60 * 60);
        assert!(threshold < 18 * 60 * 60);
    }

    #[test]
    fn certificate_request_id_rotates_by_hour() {
        let device = test_device_config("tun_abc", "antoine");

        assert_eq!(certificate_request_id_at(&device, 3_600), "tun_abc-1-h1");
        assert_eq!(certificate_request_id_at(&device, 7_199), "tun_abc-1-h1");
        assert_eq!(certificate_request_id_at(&device, 7_200), "tun_abc-1-h2");
    }

    #[test]
    fn cached_certificate_matching_device_is_reused() {
        let device = test_device_config("tun_abc", "antoine");
        let cert_pem = test_device_certificate("tun_abc", "antoine");

        assert!(!certificate_needs_renewal(&cert_pem, &device));
        assert!(certificate_renewal_delay(&cert_pem, &device) > Duration::ZERO);
    }

    #[test]
    fn cached_certificate_for_previous_tunnel_is_renewed() {
        let device = test_device_config("tun_new", "antoine");
        let cert_pem = test_device_certificate("tun_old", "antoine");

        assert!(certificate_needs_renewal(&cert_pem, &device));
    }

    #[test]
    fn cached_certificate_for_previous_subdomain_is_renewed() {
        let device = test_device_config("tun_abc", "antoine");
        let cert_pem = test_device_certificate("tun_abc", "old-antoine");

        assert!(certificate_needs_renewal(&cert_pem, &device));
    }

    #[tokio::test]
    async fn encrypted_key_storage_migrates_plaintext_key() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("portless-key-test-{nonce}"));
        fs::create_dir_all(&dir).await.unwrap();
        fs::write(dir.join(DEVICE_KEY_PLAINTEXT_FILE), "test-private-key")
            .await
            .unwrap();

        assert_eq!(
            read_device_key(&dir).await.unwrap().unwrap(),
            "test-private-key"
        );
        write_encrypted_device_key(&dir, "test-private-key")
            .await
            .unwrap();

        assert!(fs::metadata(dir.join(DEVICE_KEY_PLAINTEXT_FILE))
            .await
            .is_err());
        assert!(fs::metadata(dir.join(DEVICE_KEY_ENCRYPTED_FILE))
            .await
            .is_ok());
        assert_eq!(
            read_device_key(&dir).await.unwrap().unwrap(),
            "test-private-key"
        );

        fs::remove_dir_all(&dir).await.unwrap();
    }

    #[test]
    fn converts_accumulated_micros_to_whole_millis() {
        assert_eq!(micros_to_millis(999), 0);
        assert_eq!(micros_to_millis(1000), 1);
        assert_eq!(micros_to_millis(1500), 1);
    }

    #[test]
    fn reconnect_delay_stays_short_and_bounded() {
        let first = reconnect_delay(0);
        assert!(first >= Duration::from_secs(1));
        assert!(first < Duration::from_secs(2));

        let capped = reconnect_delay(12);
        assert!(capped >= Duration::from_secs(15));
        assert!(capped < Duration::from_secs(16));
    }

    #[test]
    fn residential_keepalive_profile_detects_dead_relay_quickly() {
        let profile = KeepaliveProfile::Residential;

        assert_eq!(profile.quic_keep_alive_interval(), Duration::from_secs(3));
        assert_eq!(profile.quic_max_idle_timeout(), Duration::from_secs(12));
        assert_eq!(profile.quic_connect_timeout(), Duration::from_secs(4));
        assert_eq!(profile.relay_hello_timeout(), Duration::from_secs(5));
    }

    fn test_device_config(tunnel_id: &str, subdomain: &str) -> DeviceConfig {
        DeviceConfig {
            tunnel_id: tunnel_id.to_owned(),
            subdomain: subdomain.to_owned(),
            relay_address: "staging.portless.io:8443".to_owned(),
            public_url: None,
            control_url: "https://staging.portless.io:8443".to_owned(),
            config_generation: 1,
            keepalive_profile: "residential".to_owned(),
            monthly_bytes_used: 0,
            monthly_byte_limit: 1_000_000_000_000,
        }
    }

    fn test_device_certificate(tunnel_id: &str, subdomain: &str) -> String {
        let mut params = CertificateParams::new(vec![subdomain.to_owned()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2026, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        params
            .distinguished_name
            .push(DnType::CommonName, tunnel_id.to_owned());
        params.subject_alt_names.push(rcgen::SanType::URI(
            format!("spiffe://portless.io/tunnel/{tunnel_id}")
                .try_into()
                .unwrap(),
        ));
        let key_pair = KeyPair::generate().unwrap();
        params.self_signed(&key_pair).unwrap().pem()
    }
}
