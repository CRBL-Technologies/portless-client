use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    io::{self, Cursor},
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use futures_util::StreamExt;
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
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
    config::Config,
    control::{CertificateResponse, ControlClient, DeviceConfig, TrustBundle},
};

const ALPN: &[u8] = b"portless-quic-v1";
const MAX_FRAME_HEAD: usize = 128 * 1024;
const MAX_REQUEST_BODY: u64 = 64 * 1024 * 1024;
const STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const CONNECTION_RECEIVE_WINDOW: u32 = 64 * 1024 * 1024;
const SEND_WINDOW: u64 = 32 * 1024 * 1024;
const STREAM_CANCELLED: VarInt = VarInt::from_u32(0x100);

pub struct TunnelIdentity {
    ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

pub async fn ensure_identity(
    cfg: &Config,
    control: &ControlClient,
    device: &DeviceConfig,
    trust: &TrustBundle,
) -> Result<TunnelIdentity> {
    fs::create_dir_all(&cfg.data_dir)
        .await
        .context("create daemon data dir")?;
    let key_path = cfg.data_dir.join("device.key.pem");
    let cert_path = cfg.data_dir.join("device.cert.pem");
    let trust_path = cfg.data_dir.join("trust.pem");

    let existing_key = match fs::read_to_string(&key_path).await {
        Ok(raw) => Some(raw),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err).context("read daemon key"),
    };
    let existing_cert = match fs::read_to_string(&cert_path).await {
        Ok(raw) => Some(raw),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err).context("read daemon certificate"),
    };
    if let (Some(key_pem), Some(cert_pem)) = (&existing_key, &existing_cert) {
        if !certificate_needs_renewal(cert_pem, &device.tunnel_id) {
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
    let request_id = format!("{}-{}", device.tunnel_id, device.config_generation);
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

pub async fn run(cfg: Config, device: DeviceConfig, identity: TunnelIdentity) -> Result<()> {
    let remote = relay_target(&device.relay_address).await?;
    let http = Client::builder()
        .redirect(Policy::none())
        .build()
        .context("build PMS HTTP client")?;
    let client_config = quic_client_config(&identity)?;
    let mut attempt = 0_u32;

    loop {
        match run_once(&cfg, &device, &http, &client_config, &remote).await {
            Ok(()) => {
                attempt = 0;
                warn!(relay = %remote.addr, "relay QUIC tunnel closed");
            }
            Err(err) => {
                warn!(error = %format!("{err:#}"), relay = %remote.addr, "relay QUIC tunnel disconnected");
            }
        }
        let delay = reconnect_delay(&cfg, attempt);
        attempt = attempt.saturating_add(1);
        time::sleep(delay).await;
    }
}

async fn run_once(
    cfg: &Config,
    device: &DeviceConfig,
    http: &Client,
    client_config: &quinn::ClientConfig,
    remote: &RelayTarget,
) -> Result<()> {
    let bind: SocketAddr = "[::]:0".parse().expect("valid client bind address");
    let mut endpoint = Endpoint::client(bind).context("create QUIC client endpoint")?;
    endpoint.set_default_client_config(client_config.clone());
    let connection = endpoint
        .connect(remote.addr, &remote.server_name)
        .context("start QUIC relay connection")?
        .await
        .context("connect QUIC relay")?;
    send_hello(&connection, device).await?;
    info!(relay = %remote.addr, server_name = %remote.server_name, "relay QUIC tunnel connected");

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let http = http.clone();
                let pms_url = cfg.pms_url.clone();
                tokio::spawn(async move {
                    if let Err(err) = forward_request(http, pms_url, send, recv).await {
                        warn!(error = %format!("{err:#}"), "forward QUIC request failed");
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => return Ok(()),
            Err(err) => return Err(err).context("accept QUIC request stream"),
        }
    }
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
) -> Result<()> {
    let request: TunnelRequest = read_json_frame(&mut recv)
        .await
        .context("read relay request head")?;
    let started = time::Instant::now();
    if request.upgrade.is_some() {
        return forward_upgrade_request(http, pms_url, request, send, recv, started).await;
    }

    let body = quic_request_body(recv);
    let mut send = send;
    match send_local_request(&http, &pms_url, &request, body).await {
        Ok(response) => {
            stream_local_response(
                request.id,
                request.method,
                response,
                &mut send,
                false,
                started,
            )
            .await
        }
        Err(err) => {
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
) -> Result<()> {
    match send_local_upgrade_request(&http, &pms_url, &request).await {
        Ok(response) if response.status() == reqwest::StatusCode::SWITCHING_PROTOCOLS => {
            stream_local_upgrade_response(request.id, request.method, response, send, recv, started)
                .await
        }
        Ok(response) => {
            stream_local_response(
                request.id,
                request.method,
                response,
                &mut send,
                false,
                started,
            )
            .await
        }
        Err(err) => {
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
                started,
                outcome: "pms_upgrade_request_failed",
            });
            send_error_response(request.id, err, &mut send).await
        }
    }
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

async fn stream_local_response(
    request_id: String,
    method: String,
    response: reqwest::Response,
    send: &mut SendStream,
    allow_upgrade_headers: bool,
    started: time::Instant,
) -> Result<()> {
    let status = response.status().as_u16();
    let head = TunnelResponseHead {
        id: request_id.clone(),
        status,
        headers: serializable_response_headers(response.headers(), allow_upgrade_headers),
    };
    if let Err(err) = write_json_frame(send, &head).await {
        log_daemon_transfer(DaemonTransferLog {
            request_id: &request_id,
            method: &method,
            kind: "http",
            status,
            request_bytes: 0,
            response_bytes: 0,
            started,
            outcome: "write_head_failed",
        });
        return Err(err).context("write response head");
    }

    let mut body = response.bytes_stream();
    let mut response_bytes = 0_u64;
    while let Some(chunk) = body.next().await {
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
                    started,
                    outcome: "pms_read_failed",
                });
                return Err(err).context("read local PMS response chunk");
            }
        };
        response_bytes = response_bytes.saturating_add(chunk.len() as u64);
        if let Err(err) = send.write_all(&chunk).await {
            log_daemon_transfer(DaemonTransferLog {
                request_id: &request_id,
                method: &method,
                kind: "http",
                status,
                request_bytes: 0,
                response_bytes,
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
        headers: serializable_response_headers(response.headers(), true),
    };
    if let Err(err) = write_json_frame(&mut send, &head).await {
        log_daemon_transfer(DaemonTransferLog {
            request_id: &request_id,
            method: &method,
            kind: "upgrade",
            status,
            request_bytes: 0,
            response_bytes: 0,
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
    started: time::Instant,
    outcome: &'static str,
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

fn reconnect_delay(cfg: &Config, attempt: u32) -> Duration {
    let base = cfg
        .keepalive_profile
        .interval()
        .min(Duration::from_secs(30));
    let multiplier = 1_u32 << attempt.min(5);
    let capped = base
        .saturating_mul(multiplier)
        .min(Duration::from_secs(120));
    capped + reconnect_jitter(attempt, base)
}

fn reconnect_jitter(attempt: u32, base: Duration) -> Duration {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut hasher = DefaultHasher::new();
    now.hash(&mut hasher);
    attempt.hash(&mut hasher);
    let jitter_ms = hasher.finish() % (base.as_millis().max(1) as u64);
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
) -> Vec<HeaderPair> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            if !allow_upgrade_headers && is_hop_by_hop_response(name) {
                return None;
            }
            Some(HeaderPair {
                name: name.as_str().to_owned(),
                value: value.to_str().ok()?.to_owned(),
            })
        })
        .collect()
}

fn is_hop_by_hop_response(name: &HeaderName) -> bool {
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
            | "host"
            | "content-length"
    )
}

fn quic_client_config(identity: &TunnelIdentity) -> Result<quinn::ClientConfig> {
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
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    transport.keep_alive_interval(Some(Duration::from_secs(20)));
    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into()?));
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

fn certificate_needs_renewal(cert_pem: &str, tunnel_id: &str) -> bool {
    let Ok(certs) = parse_certs_pem(cert_pem) else {
        return true;
    };
    let Some(leaf) = certs.first() else {
        return true;
    };
    let Ok((_, cert)) = X509Certificate::from_der(leaf.as_ref()) else {
        return true;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let seconds_left = cert.validity().not_after.timestamp().saturating_sub(now);
    seconds_left <= renewal_threshold_seconds(tunnel_id)
}

fn renewal_threshold_seconds(tunnel_id: &str) -> i64 {
    let mut hasher = DefaultHasher::new();
    tunnel_id.hash(&mut hasher);
    let jitter = (hasher.finish() % (24 * 60 * 60)) as i64;
    (10 * 24 * 60 * 60) + jitter
}

async fn write_identity_files(
    data_dir: &Path,
    key_pem: &str,
    issued: &CertificateResponse,
    trust_pem: &str,
) -> Result<()> {
    fs::write(data_dir.join("device.key.pem"), key_pem)
        .await
        .context("write daemon private key")?;
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
    fn omits_hop_by_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "plex.example.com".parse().unwrap());
        headers.insert(header::CONNECTION, "keep-alive".parse().unwrap());
        headers.insert(header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(header::ACCEPT, "text/html".parse().unwrap());

        let got = serializable_headers(&headers);

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "accept");
    }

    #[test]
    fn preserves_upgrade_response_headers_when_requested() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, "Upgrade".parse().unwrap());
        headers.insert(header::UPGRADE, "websocket".parse().unwrap());
        headers.insert("sec-websocket-accept", "abc".parse().unwrap());

        let got = serializable_response_headers(&headers, true);

        assert_eq!(got.len(), 3);
        assert!(got.iter().any(|header| header.name == "connection"));
        assert!(got.iter().any(|header| header.name == "upgrade"));
        assert!(got
            .iter()
            .any(|header| header.name == "sec-websocket-accept"));
    }
}
