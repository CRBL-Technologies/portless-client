use std::{cmp, time::Duration};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use reqwest::{
    header::{self, HeaderMap, HeaderName, HeaderValue},
    Client, Method, Url,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
    time,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
};
use tracing::{info, warn};

use crate::{config::Config, control::DeviceConfig};

const CONNECT_PATH: &str = "/_portless/connect";

pub async fn run(cfg: Config, device: DeviceConfig) -> Result<()> {
    let relay_url = relay_websocket_url(&device.relay_address)?;
    let http = Client::new();
    loop {
        if let Err(err) = run_once(&cfg, &http, relay_url.clone()).await {
            warn!(error = %err, relay = %relay_url, "relay tunnel disconnected");
        }
        time::sleep(reconnect_delay(&cfg)).await;
    }
}

async fn run_once(cfg: &Config, http: &Client, relay_url: Url) -> Result<()> {
    let mut request = relay_url
        .as_str()
        .into_client_request()
        .context("build relay websocket request")?;
    request.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", cfg.device_token))
            .context("build relay authorization header")?,
    );

    let (socket, _) = connect_async(request)
        .await
        .with_context(|| format!("connect relay websocket {relay_url}"))?;
    info!(relay = %relay_url, "relay tunnel connected");

    let (mut ws_tx, mut ws_rx) = socket.split();
    let (out_tx, mut out_rx) = mpsc::channel::<OutboundFrame>(64);
    let writer = async move {
        while let Some(frame) = out_rx.recv().await {
            let message = match frame {
                OutboundFrame::Daemon(frame) => {
                    let raw = serde_json::to_string(&frame).context("encode relay response")?;
                    Message::Text(raw)
                }
                OutboundFrame::Pong(payload) => Message::Pong(payload),
            };
            ws_tx
                .send(message)
                .await
                .context("send relay websocket frame")?;
        }
        Ok::<(), anyhow::Error>(())
    };

    let pms_url = cfg.pms_url.clone();
    let http = http.clone();
    let reader = async move {
        while let Some(message) = ws_rx.next().await {
            match message.context("read relay websocket frame")? {
                Message::Text(raw) => {
                    let RelayFrame::Request { request } =
                        serde_json::from_str(&raw).context("decode relay request")?;
                    let http = http.clone();
                    let pms_url = pms_url.clone();
                    let out_tx = out_tx.clone();
                    tokio::spawn(async move {
                        forward_request(http, pms_url, request, out_tx).await;
                    });
                }
                Message::Ping(payload) => {
                    out_tx
                        .send(OutboundFrame::Pong(payload))
                        .await
                        .context("queue websocket pong")?;
                }
                Message::Close(_) => return Ok(()),
                Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        result = writer => result,
        result = reader => result,
    }
}

async fn forward_request(
    http: Client,
    pms_url: Url,
    request: TunnelRequest,
    out_tx: mpsc::Sender<OutboundFrame>,
) {
    let request_id = request.id.clone();
    match send_local_request(&http, &pms_url, &request).await {
        Ok(response) => {
            if let Err(err) = stream_local_response(request_id.clone(), response, out_tx).await {
                warn!(request_id = %request_id, error = %err, "stream relay response failed");
            }
        }
        Err(err) => {
            warn!(request_id = %request_id, error = %err, "local PMS request failed");
            if let Err(send_err) = send_error_response(request_id.clone(), err, out_tx).await {
                warn!(request_id = %request_id, error = %send_err, "send relay error response failed");
            }
        }
    }
}

async fn send_local_request(
    http: &Client,
    pms_url: &Url,
    request: &TunnelRequest,
) -> Result<LocalResponse> {
    if should_use_raw_http(pms_url, request) {
        return send_raw_http_request(pms_url, request)
            .await
            .map(LocalResponse::Raw);
    }

    let method = Method::from_bytes(request.method.as_bytes()).context("parse request method")?;
    let target = pms_target_url(pms_url, &request.path_query)?;
    let body = BASE64
        .decode(&request.body_base64)
        .context("decode request body")?;
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
        .map(LocalResponse::Reqwest)
}

async fn stream_local_response(
    request_id: String,
    response: LocalResponse,
    out_tx: mpsc::Sender<OutboundFrame>,
) -> Result<()> {
    let status = response.status();
    let headers = response.headers();
    out_tx
        .send(OutboundFrame::Daemon(DaemonFrame::ResponseStart {
            response: TunnelResponseHead {
                id: request_id.clone(),
                status,
                headers,
            },
        }))
        .await
        .context("queue response head")?;

    match response {
        LocalResponse::Reqwest(response) => {
            stream_reqwest_body(&request_id, response, &out_tx).await?
        }
        LocalResponse::Raw(response) => stream_raw_body(&request_id, response, &out_tx).await?,
    }

    out_tx
        .send(OutboundFrame::Daemon(DaemonFrame::ResponseBody {
            id: request_id,
            chunk_base64: String::new(),
            end: true,
        }))
        .await
        .context("queue response body end")?;
    Ok(())
}

async fn stream_reqwest_body(
    request_id: &str,
    response: reqwest::Response,
    out_tx: &mpsc::Sender<OutboundFrame>,
) -> Result<()> {
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.context("read local PMS response chunk")?;
        send_body_chunk(request_id, chunk.as_ref(), out_tx).await?;
    }
    Ok(())
}

async fn stream_raw_body(
    request_id: &str,
    mut response: RawHttpResponse,
    out_tx: &mpsc::Sender<OutboundFrame>,
) -> Result<()> {
    if !response.body_prefix.is_empty() {
        let prefix_len = response.body_prefix.len();
        let send_len = response
            .content_length
            .map(|remaining| cmp::min(prefix_len, remaining))
            .unwrap_or(prefix_len);
        send_body_chunk(request_id, &response.body_prefix[..send_len], out_tx).await?;
        if let Some(remaining) = response.content_length.as_mut() {
            *remaining = remaining.saturating_sub(send_len);
            if *remaining == 0 {
                return Ok(());
            }
        }
    }

    let mut buf = vec![0_u8; 64 * 1024];
    loop {
        let max_read = response
            .content_length
            .map(|remaining| cmp::min(buf.len(), remaining))
            .unwrap_or(buf.len());
        if max_read == 0 {
            return Ok(());
        }
        let read = response
            .stream
            .read(&mut buf[..max_read])
            .await
            .context("read raw local PMS response body")?;
        if read == 0 {
            return Ok(());
        }
        send_body_chunk(request_id, &buf[..read], out_tx).await?;
        if let Some(remaining) = response.content_length.as_mut() {
            *remaining = remaining.saturating_sub(read);
        }
    }
}

async fn send_body_chunk(
    request_id: &str,
    chunk: &[u8],
    out_tx: &mpsc::Sender<OutboundFrame>,
) -> Result<()> {
    out_tx
        .send(OutboundFrame::Daemon(DaemonFrame::ResponseBody {
            id: request_id.to_owned(),
            chunk_base64: BASE64.encode(chunk),
            end: false,
        }))
        .await
        .context("queue response body chunk")
}

async fn send_error_response(
    request_id: String,
    err: anyhow::Error,
    out_tx: mpsc::Sender<OutboundFrame>,
) -> Result<()> {
    out_tx
        .send(OutboundFrame::Daemon(DaemonFrame::ResponseStart {
            response: TunnelResponseHead {
                id: request_id.clone(),
                status: 502,
                headers: vec![HeaderPair {
                    name: header::CONTENT_TYPE.as_str().to_owned(),
                    value: "text/plain; charset=utf-8".to_owned(),
                }],
            },
        }))
        .await
        .context("queue error response head")?;
    out_tx
        .send(OutboundFrame::Daemon(DaemonFrame::ResponseBody {
            id: request_id.clone(),
            chunk_base64: BASE64.encode(err.to_string()),
            end: false,
        }))
        .await
        .context("queue error response body")?;
    out_tx
        .send(OutboundFrame::Daemon(DaemonFrame::ResponseBody {
            id: request_id,
            chunk_base64: String::new(),
            end: true,
        }))
        .await
        .context("queue error response end")?;
    Ok(())
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

fn should_use_raw_http(pms_url: &Url, request: &TunnelRequest) -> bool {
    pms_url.scheme() == "http"
        && request
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("range"))
}

async fn send_raw_http_request(pms_url: &Url, request: &TunnelRequest) -> Result<RawHttpResponse> {
    let target = pms_target_url(pms_url, &request.path_query)?;
    if target.scheme() != "http" {
        return Err(anyhow!("raw PMS request only supports http origins"));
    }
    let host = target
        .host_str()
        .ok_or_else(|| anyhow!("PMS URL is missing a host"))?;
    let port = target.port_or_known_default().unwrap_or(80);
    let mut stream = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("connect raw PMS HTTP {host}:{port}"))?;
    let body = BASE64
        .decode(&request.body_base64)
        .context("decode request body")?;
    let path_query = target[url::Position::BeforePath..].to_owned();
    let host_header = target
        .host_str()
        .map(|value| match target.port() {
            Some(port) => format!("{value}:{port}"),
            None => value.to_owned(),
        })
        .unwrap_or_else(|| host.to_owned());

    let mut raw = Vec::new();
    raw.extend_from_slice(format!("{} {path_query} HTTP/1.1\r\n", request.method).as_bytes());
    raw.extend_from_slice(format!("Host: {host_header}\r\n").as_bytes());
    raw.extend_from_slice(b"Connection: close\r\n");
    for header in &request.headers {
        let name = HeaderName::from_bytes(header.name.as_bytes()).context("parse header name")?;
        if is_raw_request_omitted_header(&name) {
            continue;
        }
        raw.extend_from_slice(header.name.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(header.value.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    if !body.is_empty() {
        raw.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(&body);
    stream
        .write_all(&raw)
        .await
        .context("write raw PMS HTTP request")?;

    read_raw_http_response(stream).await
}

async fn read_raw_http_response(mut stream: TcpStream) -> Result<RawHttpResponse> {
    let mut head = Vec::with_capacity(16 * 1024);
    let mut buf = [0_u8; 8192];
    let header_end = loop {
        let read = stream
            .read(&mut buf)
            .await
            .context("read raw PMS response head")?;
        if read == 0 {
            return Err(anyhow!("raw PMS response ended before headers"));
        }
        head.extend_from_slice(&buf[..read]);
        if head.len() > 256 * 1024 {
            return Err(anyhow!("raw PMS response headers exceed 256 KiB"));
        }
        if let Some(index) = find_header_end(&head) {
            break index;
        }
    };

    let body_prefix = head[(header_end + 4)..].to_vec();
    let header_bytes = &head[..header_end];
    let header_text = String::from_utf8_lossy(header_bytes);
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow!("raw PMS response is missing a status line"))?;
    let status = parse_status(status_line)?;
    let mut headers = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.push(HeaderPair {
            name: name.trim().to_owned(),
            value: value.trim().to_owned(),
        });
    }
    let (headers, content_length) = sanitize_raw_response_headers(headers);
    Ok(RawHttpResponse {
        status,
        headers,
        content_length,
        body_prefix,
        stream,
    })
}

fn parse_status(status_line: &str) -> Result<u16> {
    status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("raw PMS response status is missing"))?
        .parse::<u16>()
        .context("parse raw PMS response status")
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn sanitize_raw_response_headers(headers: Vec<HeaderPair>) -> (Vec<HeaderPair>, Option<usize>) {
    let mut sanitized = Vec::new();
    let mut content_length_values = Vec::new();
    let mut content_range = None;

    for header in headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            if let Ok(value) = header.value.trim().parse::<usize>() {
                content_length_values.push(value);
            }
            continue;
        }
        if header.name.eq_ignore_ascii_case("content-range") {
            content_range = Some(header.value.clone());
        }
        let Ok(name) = HeaderName::from_bytes(header.name.as_bytes()) else {
            continue;
        };
        if is_hop_by_hop(&name) {
            continue;
        }
        sanitized.push(header);
    }

    let content_length = content_range
        .as_deref()
        .and_then(content_length_from_range)
        .or_else(|| content_length_values.last().copied());
    if let Some(value) = content_length {
        sanitized.push(HeaderPair {
            name: header::CONTENT_LENGTH.as_str().to_owned(),
            value: value.to_string(),
        });
    }

    (sanitized, content_length)
}

fn content_length_from_range(value: &str) -> Option<usize> {
    let range = value.trim().strip_prefix("bytes ")?;
    let (bounds, _) = range.split_once('/')?;
    let (start, end) = bounds.split_once('-')?;
    let start = start.parse::<usize>().ok()?;
    let end = end.parse::<usize>().ok()?;
    end.checked_sub(start)?.checked_add(1)
}

fn relay_websocket_url(relay_address: &str) -> Result<Url> {
    let raw = relay_address.trim();
    if raw.is_empty() {
        return Err(anyhow!("relay address is empty"));
    }
    let mut url = if raw.starts_with("ws://") || raw.starts_with("wss://") {
        Url::parse(raw).context("parse relay websocket URL")?
    } else if raw.starts_with("http://") || raw.starts_with("https://") {
        let mut url = Url::parse(raw).context("parse relay URL")?;
        match url.scheme() {
            "http" => url.set_scheme("ws").map_err(|_| anyhow!("set ws scheme"))?,
            "https" => url
                .set_scheme("wss")
                .map_err(|_| anyhow!("set wss scheme"))?,
            _ => {}
        }
        url
    } else {
        Url::parse(&format!("wss://{raw}")).context("parse relay host")?
    };
    url.set_path(CONNECT_PATH);
    url.set_query(None);
    Ok(url)
}

fn reconnect_delay(cfg: &Config) -> Duration {
    cfg.keepalive_profile
        .interval()
        .min(Duration::from_secs(30))
}

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

fn is_raw_request_omitted_header(name: &HeaderName) -> bool {
    is_hop_by_hop(name) || name == header::CONTENT_LENGTH || name == header::HOST
}

enum LocalResponse {
    Reqwest(reqwest::Response),
    Raw(RawHttpResponse),
}

impl LocalResponse {
    fn status(&self) -> u16 {
        match self {
            Self::Reqwest(response) => response.status().as_u16(),
            Self::Raw(response) => response.status,
        }
    }

    fn headers(&self) -> Vec<HeaderPair> {
        match self {
            Self::Reqwest(response) => serializable_headers(response.headers()),
            Self::Raw(response) => response.headers.clone(),
        }
    }
}

struct RawHttpResponse {
    status: u16,
    headers: Vec<HeaderPair>,
    content_length: Option<usize>,
    body_prefix: Vec<u8>,
    stream: TcpStream,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RelayFrame {
    Request { request: TunnelRequest },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum DaemonFrame {
    ResponseStart {
        response: TunnelResponseHead,
    },
    ResponseBody {
        id: String,
        chunk_base64: String,
        end: bool,
    },
}

#[derive(Debug, Deserialize, Serialize)]
struct TunnelRequest {
    id: String,
    method: String,
    path_query: String,
    headers: Vec<HeaderPair>,
    body_base64: String,
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

enum OutboundFrame {
    Daemon(DaemonFrame),
    Pong(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_wss_url_from_host() {
        let got = relay_websocket_url("relay.example.com").unwrap();

        assert_eq!(got.as_str(), "wss://relay.example.com/_portless/connect");
    }

    #[test]
    fn preserves_explicit_ws_scheme() {
        let got = relay_websocket_url("ws://localhost:8081").unwrap();

        assert_eq!(got.as_str(), "ws://localhost:8081/_portless/connect");
    }

    #[test]
    fn converts_https_to_wss() {
        let got = relay_websocket_url("https://relay.example.com/foo?bar").unwrap();

        assert_eq!(got.as_str(), "wss://relay.example.com/_portless/connect");
    }

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
        headers.insert(header::ACCEPT, "text/html".parse().unwrap());

        let got = serializable_headers(&headers);

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "accept");
    }

    #[test]
    fn sanitizes_conflicting_range_content_lengths() {
        let (headers, content_length) = sanitize_raw_response_headers(vec![
            HeaderPair {
                name: "X-Plex-Protocol".to_owned(),
                value: "1.0".to_owned(),
            },
            HeaderPair {
                name: "Content-Length".to_owned(),
                value: "208".to_owned(),
            },
            HeaderPair {
                name: "Content-Range".to_owned(),
                value: "bytes 0-31/208".to_owned(),
            },
            HeaderPair {
                name: "Content-Length".to_owned(),
                value: "32".to_owned(),
            },
        ]);

        assert_eq!(content_length, Some(32));
        assert_eq!(
            headers
                .iter()
                .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
                .count(),
            1
        );
        assert!(headers.iter().any(|header| header.name == "Content-Range"));
        assert!(headers.iter().any(
            |header| header.name.eq_ignore_ascii_case("content-length") && header.value == "32"
        ));
    }

    #[test]
    fn detects_range_requests_for_raw_http_path() {
        let pms_url = Url::parse("http://127.0.0.1:32400").unwrap();
        let request = TunnelRequest {
            id: "req_1".to_owned(),
            method: "GET".to_owned(),
            path_query: "/library/parts/1/file.mkv".to_owned(),
            headers: vec![HeaderPair {
                name: "Range".to_owned(),
                value: "bytes=0-".to_owned(),
            }],
            body_base64: String::new(),
        };

        assert!(should_use_raw_http(&pms_url, &request));
    }
}
