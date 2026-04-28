use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use reqwest::{
    header::{self, HeaderMap, HeaderName, HeaderValue},
    Client, Method, Url,
};
use serde::{Deserialize, Serialize};
use tokio::{sync::mpsc, time};
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
) -> Result<reqwest::Response> {
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
}

async fn stream_local_response(
    request_id: String,
    response: reqwest::Response,
    out_tx: mpsc::Sender<OutboundFrame>,
) -> Result<()> {
    let status = response.status().as_u16();
    let headers = serializable_headers(response.headers());
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

    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.context("read local PMS response chunk")?;
        out_tx
            .send(OutboundFrame::Daemon(DaemonFrame::ResponseBody {
                id: request_id.clone(),
                chunk_base64: BASE64.encode(chunk),
                end: false,
            }))
            .await
            .context("queue response body chunk")?;
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

#[derive(Debug, Deserialize, Serialize)]
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
}
