//! Forwarding tunnel requests to the local Plex Media Server.

use super::*;

pub(super) async fn forward_request(
    http: Client,
    pms_url: Url,
    connection: Connection,
    mut send: SendStream,
    recv: RecvStream,
    ui: UiState,
) -> Result<()> {
    let stopped = send.stopped();
    let cancelled = async {
        match stopped.await {
            // A half-closed upgrade may still be uploading after its response is ACKed.
            Ok(None) => std::future::pending().await,
            result => result,
        }
    };
    let result = tokio::select! {
        biased;
        error = connection.closed() => Err(anyhow!("relay connection closed: {error}")),
        result = cancelled => Err(anyhow!("relay stopped response stream: {result:?}")),
        result = forward_request_inner(http, pms_url, &mut send, recv, ui) => result,
    };
    if let Err(err) = result {
        let _ = send.reset(STREAM_CANCELLED);
        return Err(err);
    }

    // finish() only queues FIN. Keep the active-stream guard until delivery,
    // downstream cancellation, connection loss, or the existing leak-guard bound.
    match time::timeout(RESPONSE_DELIVERY_LEAK_GUARD, send.stopped()).await {
        Ok(Ok(None)) => Ok(()),
        result => {
            let _ = send.reset(STREAM_CANCELLED);
            bail!("response delivery did not complete: {result:?}")
        }
    }
}

pub(super) async fn forward_request_inner(
    http: Client,
    pms_url: Url,
    send: &mut SendStream,
    mut recv: RecvStream,
    ui: UiState,
) -> Result<()> {
    let request: TunnelRequest = read_json_frame(&mut recv)
        .await
        .context("read relay request head")?;
    if request.method.eq_ignore_ascii_case("CONNECT") {
        bail!("HTTP CONNECT is not supported");
    }
    let started = time::Instant::now();
    if let Some(config) = synthetic_benchmark_config(&request)? {
        return stream_synthetic_response(request, send, started, config).await;
    }
    if request.upgrade.is_some() {
        return forward_upgrade_request(http, pms_url, request, send, recv, started, ui).await;
    }

    let (body, _cancel_upload) = quic_request_body(recv);
    match send_local_request(&http, &pms_url, &request, body).await {
        Ok(response) => {
            ui.set_status(DaemonStatus::Connected).await;
            let rewrite = RedirectRewrite::from_request(&pms_url, &request.headers);
            stream_local_response(
                request.id,
                request.method,
                request.path_query,
                response,
                send,
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
            send_error_response(request.id, err, send).await
        }
    }
}

pub(super) async fn forward_upgrade_request(
    http: Client,
    pms_url: Url,
    request: TunnelRequest,
    send: &mut SendStream,
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
                send,
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
            send_error_response(request.id, err, send).await
        }
    }
}

pub(super) fn synthetic_benchmark_config(
    request: &TunnelRequest,
) -> Result<Option<SyntheticBenchmarkConfig>> {
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

pub(super) fn synthetic_header<'a>(request: &'a TunnelRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

pub(super) async fn stream_synthetic_response(
    request: TunnelRequest,
    send: &mut SendStream,
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
    if let Err(err) = write_json_frame(send, &head).await {
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

pub(super) fn pms_http_client() -> Result<Client> {
    Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .build()
        .context("build PMS HTTP client")
}

pub(super) async fn send_local_request(
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

pub(super) async fn send_local_upgrade_request(
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

pub(super) fn quic_request_body(
    mut recv: RecvStream,
) -> (reqwest::Body, tokio::sync::oneshot::Sender<()>) {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, io::Error>>(64);
    let (cancel, cancelled) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let pump = async {
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
        };
        tokio::select! {
            _ = cancelled => {},
            _ = tx.closed() => {},
            _ = pump => {},
        }
        let _ = recv.stop(STREAM_CANCELLED);
    });
    (
        reqwest::Body::wrap_stream(tokio_stream::wrappers::ReceiverStream::new(rx)),
        cancel,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn stream_local_response(
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
    let response_is_range = status == 206 && response.headers().contains_key(header::CONTENT_RANGE);
    let preserve_content_length =
        should_preserve_response_content_length(&method, &path_query) || response_is_range;
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
                // Dropping the stream would finish it cleanly, making the
                // truncated body look complete to the relay; reset instead.
                let _ = send.reset(STREAM_CANCELLED);
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

pub(super) async fn stream_local_upgrade_response(
    request_id: String,
    method: String,
    response: reqwest::Response,
    send: &mut SendStream,
    recv: RecvStream,
    started: time::Instant,
) -> Result<()> {
    let status = response.status().as_u16();
    let head = TunnelResponseHead {
        id: request_id.clone(),
        status,
        headers: serializable_response_headers(response.headers(), true, None, false),
    };
    if let Err(err) = write_json_frame(send, &head).await {
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
            let _ = send.reset(STREAM_CANCELLED);
            return Err(err).context("upgrade local PMS response");
        }
    };
    let (mut pms_read, mut pms_write) = tokio_io::split(upgraded);
    let mut relay_send = send;
    let mut relay_recv = recv;

    let relay_to_pms = async {
        let mut copied = 0_u64;
        let mut buf = [0_u8; 8 * 1024];
        while let Some(read) = relay_recv
            .read(&mut buf)
            .await
            .context("read upgraded QUIC bytes")?
        {
            // A blocked PMS write must still observe a request-stream reset.
            let reset = async {
                match relay_recv.received_reset().await {
                    Ok(None) => std::future::pending().await,
                    result => result,
                }
            };
            tokio::select! {
                biased;
                result = reset => bail!("upgraded request stream reset: {result:?}"),
                result = pms_write.write_all(&buf[..read]) => result.context("write upgraded PMS bytes")?,
            }
            copied += read as u64;
        }
        pms_write
            .flush()
            .await
            .context("flush upgraded PMS write")?;
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
            let _ = relay_send.reset(STREAM_CANCELLED);
            return Err(err);
        }
    }
    Ok(())
}

pub(super) async fn send_error_response(
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

pub(super) async fn write_json_frame<T: Serialize>(send: &mut SendStream, value: &T) -> Result<()> {
    let raw = serde_json::to_vec(value).context("encode JSON frame")?;
    if raw.len() > MAX_FRAME_HEAD {
        bail!("JSON frame exceeds {MAX_FRAME_HEAD} bytes");
    }
    send.write_all(&(raw.len() as u32).to_be_bytes())
        .await
        .context("write JSON frame length")?;
    send.write_all(&raw).await.context("write JSON frame")
}

pub(super) async fn read_json_frame<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T> {
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

pub(super) fn pms_target_url(pms_url: &Url, path_query: &str) -> Result<Url> {
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

pub(super) fn first_header<'a>(headers: &'a [HeaderPair], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

pub(super) fn same_url_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme() && same_url_host_port(left, right)
}

pub(super) fn same_url_hostname(left: &Url, right: &Url) -> bool {
    left.host_str()
        .zip(right.host_str())
        .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
}

pub(super) fn same_url_host_port(left: &Url, right: &Url) -> bool {
    same_url_hostname(left, right) && left.port_or_known_default() == right.port_or_known_default()
}

pub(super) fn bytes_per_second(bytes: u64, duration_ms: u64) -> u64 {
    if duration_ms == 0 {
        return 0;
    }
    bytes.saturating_mul(1000) / duration_ms
}

pub(super) fn log_daemon_transfer(event: DaemonTransferLog<'_>) {
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

pub(super) fn elapsed_millis(started: time::Instant) -> u64 {
    let elapsed = started.elapsed();
    let millis = elapsed.as_millis() as u64;
    if millis == 0 && elapsed > Duration::ZERO {
        1
    } else {
        millis
    }
}

pub(super) fn elapsed_micros(started: time::Instant) -> u64 {
    started.elapsed().as_micros() as u64
}

pub(super) fn micros_to_millis(value: u64) -> u64 {
    value / 1000
}

#[cfg(test)]
pub(super) fn serializable_headers(headers: &HeaderMap) -> Vec<HeaderPair> {
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

pub(super) fn serializable_response_headers(
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

pub(super) fn should_preserve_response_content_length(method: &str, path_query: &str) -> bool {
    method.eq_ignore_ascii_case("HEAD")
        || (method.eq_ignore_ascii_case("GET") && is_plex_media_response_path(path_query))
}

pub(super) fn is_plex_media_response_path(path_query: &str) -> bool {
    let path = path_query
        .split_once('?')
        .map_or(path_query, |(path, _)| path);
    let segments: Vec<_> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    match segments.as_slice() {
        ["downloadQueue", _, "item", _, "media"] => true,
        ["library", "parts", _, _, file] => file.starts_with("file."),
        [kind, ":", "transcode", .., file] if is_transcode_kind(kind) => {
            is_plex_transcode_media_file(file)
        }
        _ => false,
    }
}

pub(super) fn is_transcode_kind(kind: &str) -> bool {
    kind == "video" || kind == "music"
}

pub(super) fn is_plex_transcode_media_file(file: &str) -> bool {
    file.ends_with(".aac")
        || file.ends_with(".m3u8")
        || file.ends_with(".m4a")
        || file.ends_with(".m4s")
        || file.ends_with(".mp3")
        || file.ends_with(".mp4")
        || file.ends_with(".mpd")
        || file.ends_with(".ts")
        || file.ends_with(".webm")
}

pub(super) fn is_hop_by_hop_response(name: &HeaderName, preserve_content_length: bool) -> bool {
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

pub(super) fn is_hop_by_hop(name: &HeaderName) -> bool {
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
