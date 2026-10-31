mod forward;
mod identity;

use forward::*;
pub(crate) use identity::ensure_private_data_dir;
use identity::*;

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    io,
    net::SocketAddr,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
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
use getrandom::fill as fill_random;
use portless_contracts::portless::v1::QuicApplicationErrorCode;
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};
use reqwest::{
    header::{self, HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
    Client, Method, StatusCode, Url,
};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    RootCertStore,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    state::{write_private_file, DaemonState},
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
const RENEWAL_RETRY_DELAY: Duration = Duration::from_secs(60);
const DRAIN_IDLE_GUARD: Duration = Duration::from_secs(5);
const DRAIN_POLL_INTERVAL: Duration = Duration::from_secs(1);
// Match the relay's media leak guard, not a playback/read timeout. This starts
// only after upstream EOF and all writes, and successful completion requires ACKs.
const RESPONSE_DELIVERY_LEAK_GUARD: Duration = Duration::from_secs(4 * 60 * 60);
const THROUGHPUT_METHOD: &str = "PORTLESS_BENCH";
const THROUGHPUT_PATH: &str = "/_portless/throughput";
const THROUGHPUT_BYTES_HEADER: &str = "x-portless-synthetic-bytes";
const THROUGHPUT_CHUNK_HEADER: &str = "x-portless-synthetic-chunk";
const MAX_THROUGHPUT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_THROUGHPUT_CHUNK_BYTES: usize = 1024 * 1024;
const DEVICE_KEY_SECRET_FILE: &str = "device.key.secret";
const DEVICE_KEY_ENCRYPTED_FILE: &str = "device.key.pem.enc";
const DEVICE_KEY_PLAINTEXT_FILE: &str = "device.key.pem";
const DEVICE_CERT_FILE: &str = "device.cert.pem";
const TRUST_BUNDLE_FILE: &str = "trust.pem";
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
    load_tunnel_context_with_identity_refresh(cfg, control, ui, false).await
}

async fn load_tunnel_context_with_identity_refresh(
    cfg: &Config,
    control: &ControlClient,
    ui: &UiState,
    force_identity_refresh: bool,
) -> Result<TunnelContext> {
    ensure_private_data_dir(&cfg.data_dir).await?;

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

    let identity = ensure_identity(cfg, control, &device, &trust, force_identity_refresh).await?;
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

pub async fn run(
    cfg: Config,
    control: ControlClient,
    mut context: TunnelContext,
    ui: UiState,
) -> Result<()> {
    let http = pms_http_client()?;
    let mut attempt = 0_u32;
    let mut force_identity_refresh = false;
    // Consecutive relay revocations without a healthy session in between.
    let mut revocations = 0_u32;

    loop {
        if force_identity_refresh
            || certificate_needs_renewal(&context.identity.cert_pem, &context.device)
        {
            match load_tunnel_context_with_identity_refresh(
                &cfg,
                &control,
                &ui,
                force_identity_refresh,
            )
            .await
            {
                Ok(updated) => {
                    context = updated;
                    attempt = 0;
                    force_identity_refresh = false;
                }
                Err(err) => {
                    ui.set_status(identity_refresh_failure_status(&err)).await;
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

        let remote = match relay_target(&context.device.relay_address, attempt).await {
            Ok(remote) => remote,
            Err(err) => {
                ui.set_status(DaemonStatus::RelayUnreachable).await;
                warn!(
                    error = %format!("{err:#}"),
                    relay_address = %context.device.relay_address,
                    attempt,
                    "resolve relay target failed"
                );
                let delay = reconnect_delay(attempt);
                attempt = attempt.saturating_add(1);
                time::sleep(delay).await;
                continue;
            }
        };
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
                if error_has_application_close(&err, STREAM_REVOKED) {
                    ui.set_status(DaemonStatus::DeviceRevoked).await;
                    let delay = revoked_refresh_delay(revocations);
                    warn!(
                        error = %format!("{err:#}"),
                        relay = %remote.addr,
                        revocations,
                        delay_ms = delay.as_millis() as u64,
                        "relay rejected daemon certificate; refreshing identity"
                    );
                    revocations = revocations.saturating_add(1);
                    force_identity_refresh = true;
                    attempt = 0;
                    time::sleep(delay).await;
                    continue;
                }
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

        let mut remote = remote;
        let mut endpoint = endpoint;
        let mut connection = connection;
        let mut session_started = time::Instant::now();
        ui.set_connection(connection.clone()).await;
        let mut renewal_timer = Box::pin(time::sleep(certificate_renewal_delay(
            &context.identity.cert_pem,
            &context.device,
        )));
        let mut active_streams = Arc::new(AtomicUsize::new(0));
        let mut serve = Box::pin(serve_connection(
            &cfg,
            &http,
            connection.clone(),
            ui.clone(),
            active_streams.clone(),
        ));
        let mut renewal_attempt: Option<
            tokio::task::JoinHandle<std::result::Result<RenewedConnection, RenewalError>>,
        > = None;

        enum ConnectionEvent {
            Serve(Result<DaemonStatus>),
            Renewal(
                Box<
                    std::result::Result<
                        std::result::Result<RenewedConnection, RenewalError>,
                        tokio::task::JoinError,
                    >,
                >,
            ),
            RenewalTimer,
        }

        let delay = loop {
            let event = if let Some(renewal) = renewal_attempt.as_mut() {
                tokio::select! {
                    result = &mut serve => ConnectionEvent::Serve(result),
                    result = renewal => ConnectionEvent::Renewal(Box::new(result)),
                }
            } else {
                tokio::select! {
                    result = &mut serve => ConnectionEvent::Serve(result),
                    _ = &mut renewal_timer => ConnectionEvent::RenewalTimer,
                }
            };

            match event {
                ConnectionEvent::Serve(result) => {
                    if let Some(renewal) = renewal_attempt.take() {
                        renewal.abort();
                    }
                    if session_started.elapsed() >= HEALTHY_SESSION_RESET {
                        revocations = 0;
                    }
                    break match result {
                        Ok(status) => {
                            ui.set_status(status).await;
                            warn!(relay = %remote.addr, status = ?status, "relay QUIC tunnel closed");
                            if status == DaemonStatus::DeviceRevoked {
                                force_identity_refresh = true;
                                attempt = 0;
                                let delay = revoked_refresh_delay(revocations);
                                revocations = revocations.saturating_add(1);
                                delay
                            } else if terminal_close_status(status) {
                                attempt = 0;
                                Duration::from_secs(60)
                            } else {
                                attempt =
                                    next_reconnect_attempt(session_started.elapsed(), attempt);
                                reconnect_delay(attempt)
                            }
                        }
                        Err(err) => {
                            ui.set_status(DaemonStatus::Reconnecting).await;
                            warn!(error = %format!("{err:#}"), relay = %remote.addr, "relay QUIC tunnel disconnected");
                            attempt = next_reconnect_attempt(session_started.elapsed(), attempt);
                            reconnect_delay(attempt)
                        }
                    };
                }
                ConnectionEvent::RenewalTimer => {
                    info!(
                        relay = %remote.addr,
                        "daemon certificate renewal threshold reached; refreshing identity"
                    );
                    renewal_attempt = Some(tokio::spawn(renew_connection(
                        cfg.clone(),
                        control.clone(),
                        ui.clone(),
                    )));
                }
                ConnectionEvent::Renewal(result) => {
                    renewal_attempt = None;
                    match *result {
                        Ok(Ok(renewed)) => {
                            let old_remote = remote.addr;
                            let old_endpoint = std::mem::replace(&mut endpoint, renewed.endpoint);
                            let old_connection =
                                std::mem::replace(&mut connection, renewed.connection);
                            let old_active_streams = std::mem::replace(
                                &mut active_streams,
                                Arc::new(AtomicUsize::new(0)),
                            );
                            drop(serve);
                            spawn_connection_drain(
                                old_endpoint,
                                old_connection,
                                old_active_streams,
                                old_remote,
                            );

                            context = renewed.context;
                            remote = renewed.remote;
                            session_started = time::Instant::now();
                            renewal_timer = Box::pin(time::sleep(certificate_renewal_delay(
                                &context.identity.cert_pem,
                                &context.device,
                            )));
                            serve = Box::pin(serve_connection(
                                &cfg,
                                &http,
                                connection.clone(),
                                ui.clone(),
                                active_streams.clone(),
                            ));
                            ui.set_connection(connection.clone()).await;
                            attempt = 0;
                            info!(
                                old_relay = %old_remote,
                                relay = %remote.addr,
                                "daemon certificate renewed; switched relay connection"
                            );
                        }
                        Ok(Err(RenewalError::Refresh(err))) => {
                            warn!(
                                error = %format!("{err:#}"),
                                retry_secs = RENEWAL_RETRY_DELAY.as_secs(),
                                "refresh daemon certificate failed; retrying"
                            );
                            renewal_timer
                                .as_mut()
                                .reset(time::Instant::now() + RENEWAL_RETRY_DELAY);
                        }
                        Ok(Err(RenewalError::Connect(err))) => {
                            warn!(
                                error = %format!("{err:#}"),
                                retry_secs = RENEWAL_RETRY_DELAY.as_secs(),
                                "daemon certificate renewal connection failed; retrying"
                            );
                            renewal_timer
                                .as_mut()
                                .reset(time::Instant::now() + RENEWAL_RETRY_DELAY);
                        }
                        Err(err) => {
                            warn!(
                                error = %err,
                                retry_secs = RENEWAL_RETRY_DELAY.as_secs(),
                                "daemon certificate renewal task failed; retrying"
                            );
                            renewal_timer
                                .as_mut()
                                .reset(time::Instant::now() + RENEWAL_RETRY_DELAY);
                        }
                    }
                }
            }
        };
        drop(serve);
        drop(connection);
        drop(endpoint);
        if let Some(renewal) = renewal_attempt {
            renewal.abort();
        }
        time::sleep(delay).await;
    }
}

struct RenewedConnection {
    context: TunnelContext,
    remote: RelayTarget,
    endpoint: Endpoint,
    connection: Connection,
}

enum RenewalError {
    Refresh(anyhow::Error),
    Connect(anyhow::Error),
}

async fn renew_connection(
    cfg: Config,
    control: ControlClient,
    ui: UiState,
) -> std::result::Result<RenewedConnection, RenewalError> {
    let context = load_tunnel_context(&cfg, &control, &ui)
        .await
        .map_err(RenewalError::Refresh)?;
    let client_config = quic_client_config(&context.identity, &cfg.keepalive_profile)
        .map_err(RenewalError::Connect)?;
    let remote = relay_target(&context.device.relay_address, 0)
        .await
        .map_err(RenewalError::Connect)?;
    let (endpoint, connection) = connect_once(
        &context.device,
        &client_config,
        &remote,
        &cfg.keepalive_profile,
    )
    .await
    .map_err(RenewalError::Connect)?;

    Ok(RenewedConnection {
        context,
        remote,
        endpoint,
        connection,
    })
}

fn spawn_connection_drain(
    endpoint: Endpoint,
    connection: Connection,
    active_streams: Arc<AtomicUsize>,
    relay: SocketAddr,
) {
    tokio::spawn(async move {
        let started = time::Instant::now();
        let mut idle_since = None;
        loop {
            if connection.close_reason().is_some() {
                break;
            }
            let active_stream_count = active_streams.load(Ordering::Relaxed);
            if active_stream_count == 0 {
                let idle_started = *idle_since.get_or_insert_with(time::Instant::now);
                if !drain_should_close(active_stream_count, idle_started.elapsed()) {
                    time::sleep(DRAIN_POLL_INTERVAL).await;
                    continue;
                }
                connection.close(STREAM_CANCELLED, b"daemon certificate renewal");
                info!(
                    relay = %relay,
                    drained_secs = started.elapsed().as_secs(),
                    idle_guard_secs = DRAIN_IDLE_GUARD.as_secs(),
                    "drained superseded relay connection"
                );
                // The endpoint must live until drain completion or Quinn closes the connection.
                drop(endpoint);
                break;
            }

            idle_since = None;
            time::sleep(DRAIN_POLL_INTERVAL).await;
        }
    });
}

fn drain_should_close(active_streams: usize, idle_elapsed: Duration) -> bool {
    active_streams == 0 && idle_elapsed >= DRAIN_IDLE_GUARD
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
    connection: Connection,
    ui: UiState,
    active_streams: Arc<AtomicUsize>,
) -> Result<DaemonStatus> {
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let http = http.clone();
                let pms_url = cfg.pms_url.clone();
                let ui = ui.clone();
                let active_streams = active_streams.clone();
                let active_stream = ActiveForwardedStream::new(active_streams);
                let connection = connection.clone();
                tokio::spawn(async move {
                    let _active_stream = active_stream;
                    if let Err(err) =
                        forward_request(http, pms_url, connection, send, recv, ui).await
                    {
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

struct ActiveForwardedStream {
    active_streams: Arc<AtomicUsize>,
}

impl ActiveForwardedStream {
    fn new(active_streams: Arc<AtomicUsize>) -> Self {
        active_streams.fetch_add(1, Ordering::Relaxed);
        Self { active_streams }
    }
}

impl Drop for ActiveForwardedStream {
    fn drop(&mut self) {
        let previous = self.active_streams.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(previous > 0);
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

fn error_has_application_close(error: &anyhow::Error, error_code: VarInt) -> bool {
    error.chain().any(|cause| {
        if let Some(error) = cause.downcast_ref::<quinn::ConnectionError>() {
            return connection_error_has_application_close(error, error_code);
        }
        if let Some(error) = cause.downcast_ref::<quinn::ReadError>() {
            return read_error_has_application_close(error, error_code);
        }
        if let Some(error) = cause.downcast_ref::<quinn::ReadExactError>() {
            return read_exact_error_has_application_close(error, error_code);
        }
        false
    })
}

fn connection_error_has_application_close(
    error: &quinn::ConnectionError,
    error_code: VarInt,
) -> bool {
    matches!(error, quinn::ConnectionError::ApplicationClosed(close) if close.error_code == error_code)
}

fn read_error_has_application_close(error: &quinn::ReadError, error_code: VarInt) -> bool {
    matches!(error, quinn::ReadError::ConnectionLost(error) if connection_error_has_application_close(error, error_code))
}

fn read_exact_error_has_application_close(
    error: &quinn::ReadExactError,
    error_code: VarInt,
) -> bool {
    matches!(error, quinn::ReadExactError::ReadError(error) if read_error_has_application_close(error, error_code))
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

async fn relay_target(relay_address: &str, attempt: u32) -> Result<RelayTarget> {
    let (host, port) = parse_relay_endpoint(relay_address)?;
    let addrs: Vec<SocketAddr> = lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("resolve relay {host}:{port}"))?
        .collect();
    let addr = select_relay_addr(&addrs, attempt)
        .ok_or_else(|| anyhow!("relay host resolved to no addresses"))?;
    Ok(RelayTarget {
        server_name: host,
        addr,
    })
}

/// Rotate through every resolved address as reconnect attempts grow, so a
/// dead first DNS answer (e.g. an unreachable address family or relay node)
/// cannot wedge the daemon retrying the same address forever.
fn select_relay_addr(addrs: &[SocketAddr], attempt: u32) -> Option<SocketAddr> {
    if addrs.is_empty() {
        return None;
    }
    Some(addrs[attempt as usize % addrs.len()])
}

fn parse_relay_endpoint(relay_address: &str) -> Result<(String, u16)> {
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
    Ok((host, port))
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

/// Minimum session lifetime before the reconnect backoff resets. Sessions
/// that die sooner keep growing the backoff so a relay that fails right
/// after the handshake is not hammered with full QUIC reconnects.
const HEALTHY_SESSION_RESET: Duration = Duration::from_secs(30);

fn next_reconnect_attempt(session_duration: Duration, attempt: u32) -> u32 {
    if session_duration >= HEALTHY_SESSION_RESET {
        0
    } else {
        attempt.saturating_add(1)
    }
}

/// Control rejecting the device token (401) or the device (403, which also
/// covers a blocked tunnel) is not a connectivity problem; say so in the UI.
fn identity_refresh_failure_status(err: &anyhow::Error) -> DaemonStatus {
    let status = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<reqwest::Error>())
        .and_then(reqwest::Error::status);
    match status {
        Some(StatusCode::UNAUTHORIZED) => DaemonStatus::AuthFailed,
        Some(StatusCode::FORBIDDEN) => DaemonStatus::DeviceRevoked,
        _ => DaemonStatus::RelayUnreachable,
    }
}

/// The first revocation refreshes at once because the certificate may have
/// been rotated. Repeated revocations back off: the relay keeps rejecting a
/// blocked tunnel even after a successful identity refresh.
fn revoked_refresh_delay(consecutive_revocations: u32) -> Duration {
    match consecutive_revocations {
        0 => Duration::ZERO,
        n => reconnect_delay(n - 1),
    }
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

        for path in [
            "http://192.0.2.10:8080/admin",
            "//192.0.2.10:8080/admin",
            r"/\192.0.2.10:8080/admin",
            r"\\192.0.2.10:8080/admin",
            "/%2f%2f192.0.2.10:8080/admin",
            "/%5c%5c192.0.2.10:8080/admin",
            "/../admin?url=http://192.0.2.10:8080/",
            "//user@192.0.2.10:8080/admin",
            "//[2001:db8::10]:8080/admin",
        ] {
            let target = pms_target_url(&pms_url, path).unwrap();
            assert!(same_url_origin(&target, &pms_url), "{path}: {target}");
        }
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
    fn short_lived_sessions_grow_reconnect_backoff() {
        assert_eq!(next_reconnect_attempt(Duration::ZERO, 0), 1);
        assert_eq!(next_reconnect_attempt(Duration::from_secs(2), 3), 4);
        assert_eq!(
            next_reconnect_attempt(Duration::from_secs(1), u32::MAX),
            u32::MAX
        );
    }

    #[test]
    fn healthy_sessions_reset_reconnect_backoff() {
        assert_eq!(next_reconnect_attempt(HEALTHY_SESSION_RESET, 5), 0);
        assert_eq!(next_reconnect_attempt(Duration::from_secs(3600), 2), 0);
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
    fn detects_revoked_application_close_in_read_errors() {
        let close = quinn::ApplicationClose {
            error_code: STREAM_REVOKED,
            reason: Default::default(),
        };
        let error = anyhow::Error::new(quinn::ReadExactError::ReadError(
            quinn::ReadError::ConnectionLost(quinn::ConnectionError::ApplicationClosed(close)),
        ));

        assert!(error_has_application_close(&error, STREAM_REVOKED));
        assert!(!error_has_application_close(&error, STREAM_QUOTA_EXCEEDED));
    }

    #[test]
    fn rewrites_local_pms_redirects_to_public_origin() {
        let pms_url = Url::parse("http://127.0.0.1:32400").unwrap();
        let rewrite = RedirectRewrite::from_request(
            &pms_url,
            &[
                HeaderPair {
                    name: "host".to_owned(),
                    value: "sample.staging.portless.io".to_owned(),
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

        assert_eq!(got, "https://sample.staging.portless.io/web/index.html");
    }

    #[test]
    fn rewrites_public_host_redirects_to_public_scheme() {
        let pms_url = Url::parse("http://127.0.0.1:32400").unwrap();
        let rewrite = RedirectRewrite::from_request(
            &pms_url,
            &[
                HeaderPair {
                    name: "host".to_owned(),
                    value: "sample.staging.portless.io".to_owned(),
                },
                HeaderPair {
                    name: "x-forwarded-proto".to_owned(),
                    value: "https".to_owned(),
                },
            ],
        )
        .unwrap();

        let got = rewrite
            .location("http://sample.staging.portless.io/web/index.html")
            .unwrap();

        assert_eq!(got, "https://sample.staging.portless.io/web/index.html");
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
        for path in [
            "/library/parts/7490/1725460000/file.mp4",
            "/library/parts/7490/1725460000/file.mkv?download=1",
        ] {
            assert!(should_preserve_response_content_length("GET", path));
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_LENGTH, "1024".parse().unwrap());
            headers.insert(header::CONTENT_RANGE, "bytes 0-1023/4096".parse().unwrap());
            let got = serializable_response_headers(
                &headers,
                false,
                None,
                should_preserve_response_content_length("GET", path),
            );
            assert!(got
                .iter()
                .any(|header| header.name == "content-length" && header.value == "1024"));
            assert!(got.iter().any(
                |header| header.name == "content-range" && header.value == "bytes 0-1023/4096"
            ));
            assert!(!should_preserve_response_content_length("POST", path));
        }
    }

    #[test]
    fn preserves_plex_transcode_media_get_response_content_length() {
        assert!(should_preserve_response_content_length(
            "GET",
            "/video/:/transcode/universal/session/qvb5vmk1jkgru5m8of7yk99b/0/560.m4s"
        ));
        assert!(should_preserve_response_content_length(
            "GET",
            "/video/:/transcode/universal/start.mpd?X-Plex-Token=redacted"
        ));
    }

    #[test]
    fn strips_generic_get_response_content_length() {
        assert!(!should_preserve_response_content_length(
            "GET",
            "/library/parts/7490/file.mp4"
        ));
        assert!(!should_preserve_response_content_length(
            "GET",
            "/video/:/transcode/universal/decision?X-Plex-Token=redacted"
        ));
    }

    #[test]
    fn renewal_threshold_fits_24_hour_certificates() {
        let threshold = renewal_threshold_seconds("tunnel-123");

        assert!(threshold >= 16 * 60 * 60);
        assert!(threshold < 18 * 60 * 60);
    }

    #[test]
    fn drain_closes_only_after_idle_guard() {
        assert!(!drain_should_close(0, Duration::ZERO));
        assert!(!drain_should_close(
            0,
            DRAIN_IDLE_GUARD - Duration::from_secs(1)
        ));
        assert!(drain_should_close(0, DRAIN_IDLE_GUARD));
        assert!(!drain_should_close(1, Duration::from_secs(60 * 60)));
        let active = Arc::new(AtomicUsize::new(0));
        let guard = ActiveForwardedStream::new(active.clone());
        assert!(!drain_should_close(
            active.load(Ordering::Relaxed),
            DRAIN_IDLE_GUARD
        ));
        drop(guard);
        assert!(drain_should_close(
            active.load(Ordering::Relaxed),
            DRAIN_IDLE_GUARD
        ));
    }

    #[test]
    fn certificate_request_id_rotates_by_hour() {
        let device = test_device_config("tun_abc", "sample");
        let key_pair = KeyPair::generate().unwrap();
        let key_suffix = format!("-k{}", certificate_request_key_fingerprint(&key_pair));

        assert_eq!(
            certificate_request_id_at(&device, &key_pair, 3_600),
            format!("tun_abc-1-h1{key_suffix}")
        );
        assert_eq!(
            certificate_request_id_at(&device, &key_pair, 7_199),
            format!("tun_abc-1-h1{key_suffix}")
        );
        assert_eq!(
            certificate_request_id_at(&device, &key_pair, 7_200),
            format!("tun_abc-1-h2{key_suffix}")
        );
    }

    #[test]
    fn certificate_request_id_changes_when_key_changes() {
        let device = test_device_config("tun_abc", "sample");
        let first_key = KeyPair::generate().unwrap();
        let second_key = KeyPair::generate().unwrap();

        assert_ne!(
            certificate_request_id_at(&device, &first_key, 3_600),
            certificate_request_id_at(&device, &second_key, 3_600)
        );
    }

    #[test]
    fn cached_certificate_matching_device_is_reused() {
        let device = test_device_config("tun_abc", "sample");
        let cert_pem = test_device_certificate("tun_abc", "sample");

        assert!(!certificate_needs_renewal(&cert_pem, &device));
        assert!(certificate_renewal_delay(&cert_pem, &device) > Duration::ZERO);
    }

    #[test]
    fn cached_certificate_for_previous_tunnel_is_renewed() {
        let device = test_device_config("tun_new", "sample");
        let cert_pem = test_device_certificate("tun_old", "sample");

        assert!(certificate_needs_renewal(&cert_pem, &device));
    }

    #[test]
    fn cached_certificate_for_previous_subdomain_is_renewed() {
        let device = test_device_config("tun_abc", "sample");
        let cert_pem = test_device_certificate("tun_abc", "old-sample");

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
        assert_private_path_mode(&dir, 0o700).await;
        assert_private_path_mode(&dir.join(DEVICE_KEY_SECRET_FILE), 0o600).await;
        assert_private_path_mode(&dir.join(DEVICE_KEY_ENCRYPTED_FILE), 0o600).await;
        assert_eq!(
            read_device_key(&dir).await.unwrap().unwrap(),
            "test-private-key"
        );

        let encrypted_path = dir.join(DEVICE_KEY_ENCRYPTED_FILE);
        let mut old_file = fs::File::open(&encrypted_path).await.unwrap();
        let original = fs::read(&encrypted_path).await.unwrap();
        write_encrypted_device_key(&dir, "replacement-test-key")
            .await
            .unwrap();
        let mut old_contents = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut old_file, &mut old_contents)
            .await
            .unwrap();
        assert_eq!(
            old_contents, original,
            "replacement must not truncate the old inode"
        );
        assert_eq!(
            read_device_key(&dir).await.unwrap().unwrap(),
            "replacement-test-key"
        );
        assert_private_path_mode(&encrypted_path, 0o600).await;

        let cfg = Config {
            pms_url: Url::parse("http://127.0.0.1:1").unwrap(),
            control_url: Url::parse("http://127.0.0.1:1").unwrap(),
            device_token: "test-token".to_owned(),
            data_dir: dir.clone(),
            keepalive_profile: KeepaliveProfile::Residential,
            ui_addr: None,
        };
        let control = ControlClient::new(cfg.control_url.clone(), cfg.device_token.clone());
        let device = test_device_config("tun_abc", "sample");
        fs::write(
            dir.join(DEVICE_CERT_FILE),
            test_device_certificate("tun_abc", "sample"),
        )
        .await
        .unwrap();
        let trust = TrustBundle {
            pem: "test-trust".to_owned(),
            generated_at: "test".to_owned(),
        };
        let original = fs::read(&encrypted_path).await.unwrap();
        let plaintext_path = dir.join(DEVICE_KEY_PLAINTEXT_FILE);
        fs::write(&plaintext_path, "replacement-test-key")
            .await
            .unwrap();
        let identity = ensure_identity(&cfg, &control, &device, &trust, false)
            .await
            .unwrap();
        assert_eq!(identity.key_pem, "replacement-test-key");
        assert_eq!(
            fs::read(&encrypted_path).await.unwrap(),
            original,
            "valid cached identity must not be rewritten"
        );
        assert!(
            !fs::try_exists(&plaintext_path).await.unwrap(),
            "finish an interrupted plaintext migration"
        );

        fs::write(&plaintext_path, "replacement-test-key")
            .await
            .unwrap();
        fs::write(&encrypted_path, "{invalid").await.unwrap();
        assert!(
            ensure_identity(&cfg, &control, &device, &trust, false)
                .await
                .is_err(),
            "damaged identity must not be silently regenerated"
        );
        assert_eq!(fs::read(&encrypted_path).await.unwrap(), b"{invalid");
        assert_eq!(
            fs::read(&plaintext_path).await.unwrap(),
            b"replacement-test-key",
            "failed encrypted load must preserve the legacy key"
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
    fn repeated_revocations_back_off_after_one_immediate_refresh() {
        assert_eq!(revoked_refresh_delay(0), Duration::ZERO);
        assert!(revoked_refresh_delay(1) >= Duration::from_secs(1));
        assert!(revoked_refresh_delay(3) >= Duration::from_secs(4));
        assert!(revoked_refresh_delay(40) < Duration::from_secs(16));
    }

    #[tokio::test]
    async fn identity_refresh_failures_report_control_rejections() {
        use tokio::io::AsyncReadExt as _;

        for (response, expected) in [
            ("401 Unauthorized", DaemonStatus::AuthFailed),
            ("403 Forbidden", DaemonStatus::DeviceRevoked),
            ("503 Service Unavailable", DaemonStatus::RelayUnreachable),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!(
                "http://{}/v1/device/certificates",
                listener.local_addr().unwrap()
            );
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request).await.unwrap();
                let reply = format!(
                    "HTTP/1.1 {response}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                );
                stream.write_all(reply.as_bytes()).await.unwrap();
            });
            let err = Client::new()
                .post(url)
                .send()
                .await
                .context("request device certificate")
                .and_then(|reply| {
                    reply
                        .error_for_status()
                        .context("certificate response status")
                })
                .unwrap_err();
            server.await.unwrap();
            assert_eq!(
                identity_refresh_failure_status(&err),
                expected,
                "{response}"
            );
        }
        let unreachable = anyhow!("connect relay");
        assert_eq!(
            identity_refresh_failure_status(&unreachable),
            DaemonStatus::RelayUnreachable
        );
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
    fn rotates_relay_addresses_across_attempts() {
        let addrs: Vec<SocketAddr> = vec![
            "10.0.0.1:443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ];

        assert_eq!(select_relay_addr(&addrs, 0), Some(addrs[0]));
        assert_eq!(select_relay_addr(&addrs, 1), Some(addrs[1]));
        assert_eq!(select_relay_addr(&addrs, 2), Some(addrs[0]));
        assert_eq!(select_relay_addr(&[], 7), None);
    }

    async fn local_quic_pair() -> (Connection, Connection, Endpoint, Endpoint) {
        local_quic_pair_with_gate(None).await
    }

    #[derive(Debug, Default)]
    struct TransmitGate {
        closed: std::sync::atomic::AtomicBool,
        dropped: AtomicUsize,
    }

    impl TransmitGate {
        fn open(&self) {
            self.closed.store(false, Ordering::SeqCst);
        }
    }

    #[derive(Debug)]
    struct GatedUdpSocket {
        inner: Arc<dyn quinn::AsyncUdpSocket>,
        gate: Arc<TransmitGate>,
    }

    impl quinn::AsyncUdpSocket for GatedUdpSocket {
        fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
            self.inner.clone().create_io_poller()
        }

        fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
            if self.gate.closed.load(Ordering::SeqCst) {
                // Model wire loss, not socket backpressure: WouldBlock leaves a cached
                // transmit that Quinn can retry even after the connection is closed.
                self.gate.dropped.fetch_add(1, Ordering::SeqCst);
                return Ok(());
            }
            self.inner.try_send(transmit)
        }

        fn poll_recv(
            &self,
            cx: &mut std::task::Context<'_>,
            bufs: &mut [io::IoSliceMut<'_>],
            meta: &mut [quinn::udp::RecvMeta],
        ) -> std::task::Poll<io::Result<usize>> {
            self.inner.poll_recv(cx, bufs, meta)
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }

        fn max_transmit_segments(&self) -> usize {
            self.inner.max_transmit_segments()
        }

        fn max_receive_segments(&self) -> usize {
            self.inner.max_receive_segments()
        }

        fn may_fragment(&self) -> bool {
            self.inner.may_fragment()
        }
    }

    async fn local_quic_pair_with_gate(
        gate: Option<Arc<TransmitGate>>,
    ) -> (Connection, Connection, Endpoint, Endpoint) {
        use quinn::Runtime;
        use rustls::pki_types::PrivatePkcs8KeyDer;

        let key_pair = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
        let server_config =
            quinn::ServerConfig::with_single_cert(vec![cert_der.clone()], key_der.into()).unwrap();
        let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let client_config = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        let mut client = if let Some(gate) = gate {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                Arc::new(GatedUdpSocket {
                    inner: quinn::TokioRuntime.wrap_udp_socket(socket).unwrap(),
                    gate,
                }),
                Arc::new(quinn::TokioRuntime),
            )
            .unwrap()
        } else {
            Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap()
        };
        client.set_default_client_config(client_config);

        let connect = client.connect(server_addr, "localhost").unwrap();
        let (daemon_conn, relay_conn) = tokio::join!(connect, async {
            server.accept().await.unwrap().await.unwrap()
        });
        (daemon_conn.unwrap(), relay_conn, client, server)
    }

    #[tokio::test]
    async fn delayed_response_tail_survives_real_connection_drain() {
        use sha2::{Digest, Sha256};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // The second run is the pre-fix control: finish queues FIN, then the guard drops.
        for finish_only in [false, true] {
            time::timeout(Duration::from_secs(30), async {
                let body: Vec<u8> = (0..8192).map(|n| (n % 251) as u8).collect();
                let prefix_len = 1024;
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let (release_tail, tail_ready) = tokio::sync::oneshot::channel();
                let server_body = body.clone();
                let server = tokio::spawn(async move {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        request.push(socket.read_u8().await.unwrap());
                        assert!(request.len() < 8192);
                    }
                    socket
                        .write_all(
                            format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        server_body.len(),
                    )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                    socket.write_all(&server_body[..prefix_len]).await.unwrap();
                    tail_ready.await.unwrap();
                    socket.write_all(&server_body[prefix_len..]).await.unwrap();
                    socket.shutdown().await.unwrap();
                });
                let cfg = Config {
                    pms_url: Url::parse(&format!("http://{addr}")).unwrap(),
                    control_url: Url::parse("http://127.0.0.1:1").unwrap(),
                    device_token: "test-token".to_owned(),
                    data_dir: std::env::temp_dir(),
                    keepalive_profile: KeepaliveProfile::Residential,
                    ui_addr: None,
                };
                let gate = Arc::new(TransmitGate::default());
                let (daemon, relay, client, _server) = time::timeout(
                    Duration::from_secs(3),
                    local_quic_pair_with_gate(Some(gate.clone())),
                )
                .await
                .expect("gated QUIC handshake");
                let (mut upload, mut download) = relay.open_bi().await.unwrap();
                write_json_frame(
                    &mut upload,
                    &TunnelRequest {
                        id: "delayed-tail".to_owned(),
                        method: "GET".to_owned(),
                        path_query: "/library/parts/7490/1725460000/file.mp4".to_owned(),
                        headers: vec![],
                        upgrade: None,
                    },
                )
                .await
                .unwrap();
                upload.finish().unwrap();
                let (mut send, recv) = daemon.accept_bi().await.unwrap();
                let delivered = send.stopped();
                tokio::pin!(delivered);
                let active = Arc::new(AtomicUsize::new(0));
                let guard = ActiveForwardedStream::new(active.clone());
                let connection = daemon.clone();
                let mut forwarding = tokio::spawn(async move {
                    let _guard = guard;
                    let http = pms_http_client().unwrap();
                    if finish_only {
                        forward_request_inner(
                            http,
                            cfg.pms_url.clone(),
                            &mut send,
                            recv,
                            UiState::new(&cfg),
                        )
                        .await
                    } else {
                        forward_request(
                            http,
                            cfg.pms_url.clone(),
                            connection,
                            send,
                            recv,
                            UiState::new(&cfg),
                        )
                        .await
                    }
                });
                let head: TunnelResponseHead =
                    time::timeout(Duration::from_secs(3), read_json_frame(&mut download))
                        .await
                        .expect("response head")
                        .unwrap();
                assert_eq!(head.status, 200);
                let mut received = vec![0; prefix_len];
                time::timeout(Duration::from_secs(3), download.read_exact(&mut received))
                    .await
                    .expect("response prefix")
                    .unwrap();
                assert_eq!(received, body[..prefix_len]);

                // No tail exists in QUIC yet. Drop outbound UDP before PMS releases it;
                // delivery after reopening requires QUIC loss recovery, not a cached send.
                gate.closed.store(true, Ordering::SeqCst);
                release_tail.send(()).unwrap();
                time::timeout(Duration::from_secs(3), server)
                    .await
                    .expect("PMS tail sent")
                    .unwrap();
                let mut reader = tokio::spawn(async move { download.read_to_end(8192).await });
                time::timeout(Duration::from_secs(3), async {
                    while gate.dropped.load(Ordering::SeqCst) == 0 {
                        time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("UDP transmit was dropped by the gate");
                assert!(
                    time::timeout(Duration::from_millis(50), &mut delivered)
                        .await
                        .is_err(),
                    "response must be unacknowledged before starting the drain"
                );
                spawn_connection_drain(
                    client,
                    daemon.clone(),
                    active.clone(),
                    _server.local_addr().unwrap(),
                );
                let hold = DRAIN_IDLE_GUARD + DRAIN_POLL_INTERVAL * 2;
                if finish_only {
                    time::timeout(Duration::from_secs(2), &mut forwarding)
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap();
                    assert_eq!(active.load(Ordering::Relaxed), 0);
                    assert!(matches!(
                        time::timeout(hold, daemon.closed())
                            .await
                            .expect("finish-only control must close while the tail is lost"),
                        quinn::ConnectionError::LocallyClosed
                    ));
                } else {
                    assert!(
                        time::timeout(hold, &mut delivered).await.is_err(),
                        "tail/FIN cannot be ACKed while UDP transmission is gated"
                    );
                    assert_eq!(
                        active.load(Ordering::Relaxed),
                        1,
                        "forwarded stream must remain active until delivery ACK"
                    );
                    assert!(!forwarding.is_finished());
                    assert!(
                        daemon.close_reason().is_none(),
                        "real drain closed an active response"
                    );
                }
                assert!(
                    !reader.is_finished(),
                    "reader must still be waiting for wire delivery"
                );
                gate.open();
                // Loss recovery backs off during the seven-second outage.
                let recovery_timeout = Duration::from_secs(10);
                if finish_only {
                    // The initial CONNECTION_CLOSE may also have been lost. Peer traffic
                    // elicits another close frame, without permitting stream retransmission.
                    let _ = relay.send_datagram(b"probe".as_slice().into());
                    let result = time::timeout(recovery_timeout, &mut reader)
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(
                        matches!(&result, Err(quinn::ReadToEndError::Read(err))
                            if read_error_has_application_close(err, STREAM_CANCELLED)),
                        "finish-only drain must truncate the response with its close code: {result:?}"
                    );
                } else {
                    received.extend(
                        time::timeout(recovery_timeout, &mut reader)
                            .await
                            .unwrap()
                            .unwrap()
                            .unwrap(),
                    );
                    assert_eq!(received.len(), body.len());
                    assert_eq!(Sha256::digest(&received), Sha256::digest(&body));
                    assert_eq!(
                        time::timeout(Duration::from_secs(3), &mut delivered)
                            .await
                            .unwrap()
                            .unwrap(),
                        None
                    );
                    time::timeout(Duration::from_secs(2), &mut forwarding)
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap();
                    assert_eq!(active.load(Ordering::Relaxed), 0);
                    time::timeout(hold, daemon.closed())
                        .await
                        .expect("real drain must close after the ACK releases the guard");
                }
            })
            .await
            .expect("delayed-tail fixture timed out");
        }
    }

    async fn truncating_pms_stub() -> SocketAddr {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0_u8; 1024];
            let _ = socket.read(&mut buf).await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n")
                .await;
            // Drop the socket without the terminating chunk: a truncated body.
        });
        addr
    }

    #[tokio::test]
    async fn pms_forwarding_stays_on_configured_endpoint() {
        use tokio::io::AsyncReadExt;

        let forbidden = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let forbidden_addr = forbidden.local_addr().unwrap();
        for path in [
            "/library/sections".to_owned(),
            format!("http://{forbidden_addr}/admin"),
            format!("//{forbidden_addr}/admin"),
            format!(r"/\{forbidden_addr}/admin"),
        ] {
            for upgrade in [false, true] {
                let pms = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let pms_url = Url::parse(&format!("http://{}", pms.local_addr().unwrap())).unwrap();
                let server = tokio::spawn(async move {
                    let (mut socket, _) = pms.accept().await.unwrap();
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        head.push(socket.read_u8().await.unwrap());
                        assert!(head.len() < 8192);
                    }
                    assert!(head.starts_with(b"GET /"));
                    let response = if upgrade {
                        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nplex-upgrade".to_owned()
                    } else {
                        format!("HTTP/1.1 302 Found\r\nLocation: http://{forbidden_addr}/admin\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    };
                    socket.write_all(response.as_bytes()).await.unwrap();
                });
                let request = TunnelRequest {
                    id: "pms-boundary".to_owned(),
                    method: "GET".to_owned(),
                    path_query: path.clone(),
                    headers: ["host", "x-forwarded-host", "forwarded"]
                        .into_iter()
                        .map(|name| HeaderPair {
                            name: name.to_owned(),
                            value: forbidden_addr.to_string(),
                        })
                        .collect(),
                    upgrade: upgrade.then(|| "websocket".to_owned()),
                };
                let http = pms_http_client().unwrap();
                let response = time::timeout(Duration::from_secs(2), async {
                    if upgrade {
                        send_local_upgrade_request(&http, &pms_url, &request).await
                    } else {
                        send_local_request(&http, &pms_url, &request, reqwest::Body::from("")).await
                    }
                })
                .await
                .expect("PMS response must not follow another destination")
                .unwrap();
                assert!(same_url_origin(response.url(), &pms_url));
                if upgrade {
                    assert_eq!(response.status(), 101);
                    let mut socket = response.upgrade().await.unwrap();
                    let mut bytes = Vec::new();
                    socket.read_to_end(&mut bytes).await.unwrap();
                    assert_eq!(bytes, b"plex-upgrade");
                } else {
                    assert_eq!(response.status(), 302);
                    assert_eq!(
                        response.headers()[header::LOCATION],
                        format!("http://{forbidden_addr}/admin")
                    );
                }
                server.await.unwrap();
            }
        }
        assert!(time::timeout(Duration::from_millis(50), forbidden.accept())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn connect_never_opens_a_pms_connection() {
        for method in ["CONNECT", "connect"] {
            for upgrade in [None, Some("websocket".to_owned())] {
                let pms = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let cfg = Config {
                    device_token: "test-token".to_owned(),
                    pms_url: Url::parse(&format!("http://{}", pms.local_addr().unwrap())).unwrap(),
                    control_url: Url::parse("http://127.0.0.1:1").unwrap(),
                    data_dir: std::env::temp_dir(),
                    keepalive_profile: KeepaliveProfile::Residential,
                    ui_addr: None,
                };
                let (daemon, relay, _client, _server) = local_quic_pair().await;
                let (mut send, _recv) = relay.open_bi().await.unwrap();
                write_json_frame(
                    &mut send,
                    &TunnelRequest {
                        id: "blocked-connect".to_owned(),
                        method: method.to_owned(),
                        path_query: "192.0.2.10:8080".to_owned(),
                        headers: Vec::new(),
                        upgrade,
                    },
                )
                .await
                .unwrap();
                send.finish().unwrap();
                let (mut send, recv) = daemon.accept_bi().await.unwrap();
                let error = forward_request_inner(
                    pms_http_client().unwrap(),
                    cfg.pms_url.clone(),
                    &mut send,
                    recv,
                    UiState::new(&cfg),
                )
                .await
                .unwrap_err();
                assert_eq!(error.to_string(), "HTTP CONNECT is not supported");
                assert!(time::timeout(Duration::from_millis(50), pms.accept())
                    .await
                    .is_err());
            }
        }
    }

    #[tokio::test]
    async fn pms_read_failure_resets_relay_response_stream() {
        let stub_addr = truncating_pms_stub().await;
        let response = Client::new()
            .get(format!("http://{stub_addr}/library/stream"))
            .send()
            .await
            .unwrap();

        let (daemon_conn, relay_conn, _client_endpoint, _server_endpoint) = local_quic_pair().await;
        let relay_read = tokio::spawn(async move {
            let (_send, mut recv) = relay_conn.accept_bi().await.unwrap();
            recv.read_to_end(1 << 20).await
        });

        let (mut send, _recv) = daemon_conn.open_bi().await.unwrap();
        let result = stream_local_response(
            "req-1".to_owned(),
            "GET".to_owned(),
            "/library/stream".to_owned(),
            response,
            &mut send,
            false,
            time::Instant::now(),
            None,
        )
        .await;
        assert!(result.is_err(), "truncated PMS body should error");
        // Mirrors forward_request returning and dropping the stream.
        drop(send);

        let read = relay_read.await.unwrap();
        assert!(
            matches!(
                read,
                Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code))) if code == STREAM_CANCELLED
            ),
            "relay should see a reset, got {read:?}"
        );
    }

    #[tokio::test]
    async fn downstream_cancel_releases_stalled_pms_and_upload() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for (upgrade, response_head) in [
            (false, ""),
            (false, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
            (true, ""),
            (true, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buf = [0_u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = socket.read(&mut buf).await.unwrap();
                    assert!(read > 0);
                    request.extend_from_slice(&buf[..read]);
                }
                socket.write_all(response_head.as_bytes()).await.unwrap();
                ready_tx.send(()).unwrap();
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(_) => {},
                        Err(err) if err.kind() == io::ErrorKind::ConnectionReset => break,
                        Err(err) => panic!("PMS socket: {err}"),
                    }
                }
            });
            let cfg = Config {
                pms_url: Url::parse(&format!("http://{addr}")).unwrap(),
                control_url: Url::parse("http://127.0.0.1:1").unwrap(),
                device_token: "test-token".to_owned(),
                data_dir: std::env::temp_dir(),
                keepalive_profile: KeepaliveProfile::Residential,
                ui_addr: None,
            };
            let (daemon, relay, _client, _server) = local_quic_pair().await;
            let (mut upload, mut download) = relay.open_bi().await.unwrap();
            write_json_frame(&mut upload, &TunnelRequest {
                id: "cancel-test".to_owned(),
                method: if upgrade { "GET" } else { "POST" }.to_owned(),
                path_query: "/test".to_owned(),
                headers: vec![],
                upgrade: upgrade.then(|| "websocket".to_owned()),
            }).await.unwrap();
            // Keep the upload open so cancellation must also stop its blocked pump.
            upload.write_all(b"x").await.unwrap();
            let (send, recv) = daemon.accept_bi().await.unwrap();
            let active = Arc::new(AtomicUsize::new(0));
            let guard = ActiveForwardedStream::new(active.clone());
            let connection = daemon.clone();
            let mut forwarding = tokio::spawn(async move {
                let _guard = guard;
                forward_request(Client::new(), cfg.pms_url.clone(), connection, send, recv, UiState::new(&cfg)).await
            });
            time::timeout(Duration::from_secs(2), ready_rx).await.unwrap().unwrap();
            if !response_head.is_empty() {
                let _: TunnelResponseHead = time::timeout(Duration::from_secs(2), read_json_frame(&mut download)).await.unwrap().unwrap();
            }
            assert!(time::timeout(Duration::from_millis(100), &mut forwarding).await.is_err(),
                "a stalled but connected consumer must stay active");
            assert_eq!(active.load(Ordering::Relaxed), 1);
            download.stop(STREAM_CANCELLED).unwrap();
            let result = time::timeout(Duration::from_secs(2), forwarding).await.unwrap().unwrap();
            assert!(result.is_err());
            assert_eq!(active.load(Ordering::Relaxed), 0);
            let upload_stop = time::timeout(Duration::from_secs(2), upload.stopped()).await.unwrap().unwrap();
            if upgrade {
                // Dropping an upgraded receive stream uses Quinn's default stop code.
                assert!(upload_stop.is_some());
            } else {
                assert_eq!(upload_stop, Some(STREAM_CANCELLED));
            }
            time::timeout(Duration::from_secs(2), server).await.unwrap().unwrap();
        }
    }

    #[test]
    fn parses_plain_relay_endpoint_with_default_port() {
        let (host, port) = parse_relay_endpoint("relay-ams-1.portless.io").unwrap();

        assert_eq!(host, "relay-ams-1.portless.io");
        assert_eq!(port, 443);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn healthcheck_uses_live_connection_with_ui_disabled() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("portless-health-test-{nonce}"));
        fs::create_dir_all(&dir).await.unwrap();
        let socket = dir.join("health.sock");
        drop(tokio::net::UnixListener::bind(&socket).unwrap());
        let cfg = Config {
            pms_url: Url::parse("http://127.0.0.1:1").unwrap(),
            control_url: Url::parse("http://127.0.0.1:1").unwrap(),
            device_token: "test-token".to_owned(),
            data_dir: dir.clone(),
            keepalive_profile: KeepaliveProfile::Residential,
            ui_addr: None,
        };
        let state = UiState::new(&cfg);
        let server = crate::health::start(&dir, state.clone()).await.unwrap();
        assert_private_path_mode(&dir, 0o700).await;
        assert_private_path_mode(&socket, 0o600).await;
        assert!(
            crate::health::start(&dir, state.clone()).await.is_err(),
            "must not replace a live socket"
        );
        assert!(
            crate::health::check(&dir).await.is_err(),
            "startup is unhealthy"
        );
        state.set_status(DaemonStatus::Connected).await;
        assert!(
            crate::health::check(&dir).await.is_err(),
            "a status without a live connection is insufficient"
        );
        let (daemon, relay, _client, _server) = local_quic_pair().await;
        state.set_connection(daemon.clone()).await;
        crate::health::check(&dir).await.unwrap();
        state.set_status(DaemonStatus::Reconnecting).await;
        assert!(crate::health::check(&dir).await.is_err());
        state.set_connection(daemon.clone()).await;
        relay.close(STREAM_CANCELLED, b"test disconnect");
        time::timeout(Duration::from_secs(2), daemon.closed())
            .await
            .unwrap();
        assert!(
            crate::health::check(&dir).await.is_err(),
            "closed transport must override stale connected status"
        );
        drop(server);
        assert!(!socket.exists());
        assert!(crate::health::check(&dir).await.is_err());
        fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn completed_media_and_half_closed_upgrade_finish_normally() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for (upgrade, method, path, close_connection) in [
            (
                false,
                "GET",
                "/library/parts/7490/1725460000/file.mp4?download=1",
                None,
            ),
            (false, "GET", "/unclassified-range", None),
            (false, "HEAD", "/identity", None),
            (true, "GET", "/test-upgrade", None),
            (true, "GET", "/test-upgrade", Some(true)),
            (true, "GET", "/test-upgrade", Some(false)),
        ] {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.set_recv_buffer_size(1024).unwrap();
            socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let listener = socket.listen(1).unwrap();
            let addr = listener.local_addr().unwrap();
            let (allow_read, wait_for_cancel) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(socket.read_u8().await.unwrap());
                }
                if upgrade {
                    socket.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nhello").await.unwrap();
                    socket.shutdown().await.unwrap();
                    if close_connection.is_some() {
                        wait_for_cancel.await.unwrap();
                    }
                    let mut late_upload = Vec::new();
                    let result = socket.read_to_end(&mut late_upload).await;
                    if close_connection.is_some() {
                        if let Err(err) = result {
                            assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
                        }
                        assert!(!late_upload.is_empty());
                    } else {
                        result.unwrap();
                        assert_eq!(late_upload, b"late upload");
                    }
                } else if method == "HEAD" {
                    socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
                        .await
                        .unwrap();
                } else {
                    socket.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 5\r\nContent-Range: bytes 5-9/20\r\n\r\nhello").await.unwrap();
                }
            });
            let cfg = Config {
                pms_url: Url::parse(&format!("http://{addr}")).unwrap(),
                control_url: Url::parse("http://127.0.0.1:1").unwrap(),
                device_token: "test-token".to_owned(),
                data_dir: std::env::temp_dir(),
                keepalive_profile: KeepaliveProfile::Residential,
                ui_addr: None,
            };
            let (daemon, relay, _client, _server) = local_quic_pair().await;
            let (mut upload, mut download) = relay.open_bi().await.unwrap();
            write_json_frame(
                &mut upload,
                &TunnelRequest {
                    id: "normal-completion-test".to_owned(),
                    method: method.to_owned(),
                    path_query: path.to_owned(),
                    headers: vec![],
                    upgrade: upgrade.then(|| "websocket".to_owned()),
                },
            )
            .await
            .unwrap();
            if !upgrade {
                upload.finish().unwrap();
            }
            let (send, recv) = daemon.accept_bi().await.unwrap();
            let delivered = send.stopped();
            let active = Arc::new(AtomicUsize::new(0));
            let guard = ActiveForwardedStream::new(active.clone());
            let connection = daemon.clone();
            let mut forwarding = tokio::spawn(async move {
                let _guard = guard;
                forward_request(
                    Client::new(),
                    cfg.pms_url.clone(),
                    connection,
                    send,
                    recv,
                    UiState::new(&cfg),
                )
                .await
            });
            let head: TunnelResponseHead =
                time::timeout(Duration::from_secs(2), read_json_frame(&mut download))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(
                head.status,
                if upgrade {
                    101
                } else if method == "HEAD" {
                    200
                } else {
                    206
                }
            );
            if !upgrade {
                assert!(head
                    .headers
                    .iter()
                    .any(|h| h.name == "content-length" && h.value == "5"));
                if method != "HEAD" {
                    assert!(head
                        .headers
                        .iter()
                        .any(|h| h.name == "content-range" && h.value == "bytes 5-9/20"));
                }
            }
            assert_eq!(
                time::timeout(Duration::from_secs(2), download.read_to_end(1024))
                    .await
                    .unwrap()
                    .unwrap(),
                if method == "HEAD" {
                    b"".as_slice()
                } else {
                    b"hello".as_slice()
                }
            );
            if upgrade {
                assert_eq!(
                    time::timeout(Duration::from_secs(2), delivered)
                        .await
                        .unwrap()
                        .unwrap(),
                    None
                );
                assert!(
                    time::timeout(Duration::from_millis(100), &mut forwarding)
                        .await
                        .is_err(),
                    "response ACK must not cancel a half-closed upgrade upload"
                );
                if let Some(close_connection) = close_connection {
                    let bytes = vec![0_u8; 8 * 1024 * 1024];
                    assert!(
                        time::timeout(Duration::from_millis(200), upload.write_all(&bytes))
                            .await
                            .is_err(),
                        "PMS must apply backpressure before cancellation"
                    );
                    assert!(!forwarding.is_finished());
                    assert_eq!(active.load(Ordering::Relaxed), 1);
                    if close_connection {
                        relay.close(STREAM_CANCELLED, b"cancel blocked upload");
                    } else {
                        upload.reset(STREAM_CANCELLED).unwrap();
                    }
                    let result = time::timeout(Duration::from_secs(2), forwarding)
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(result.is_err());
                    assert_eq!(active.load(Ordering::Relaxed), 0);
                    if !close_connection {
                        assert!(relay.close_reason().is_none());
                    }
                    allow_read.send(()).unwrap();
                    time::timeout(Duration::from_secs(2), server)
                        .await
                        .unwrap()
                        .unwrap();
                    continue;
                }
                upload.write_all(b"late upload").await.unwrap();
                upload.finish().unwrap();
            }
            time::timeout(Duration::from_secs(2), forwarding)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn parses_relay_endpoint_with_explicit_scheme_and_port() {
        let (host, port) = parse_relay_endpoint("https://relay-ams-1.portless.io:8443").unwrap();

        assert_eq!(host, "relay-ams-1.portless.io");
        assert_eq!(port, 8443);
    }

    #[test]
    fn rejects_empty_relay_endpoint() {
        let err = parse_relay_endpoint(" ").unwrap_err();

        assert!(format!("{err:#}").contains("relay address is empty"));
    }

    #[test]
    fn residential_keepalive_profile_rides_out_short_network_blips() {
        let profile = KeepaliveProfile::Residential;

        assert_eq!(profile.quic_keep_alive_interval(), Duration::from_secs(3));
        assert_eq!(profile.quic_max_idle_timeout(), Duration::from_secs(30));
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

    #[cfg(unix)]
    async fn assert_private_path_mode(path: &Path, expected: u32) {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path).await.unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, expected, "unexpected mode for {}", path.display());
    }

    #[cfg(not(unix))]
    async fn assert_private_path_mode(_path: &Path, _expected: u32) {}
}
