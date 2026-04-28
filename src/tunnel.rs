use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use reqwest::{
    header::{self, HeaderMap, HeaderName, HeaderValue},
    Client, Method, Url,
};
use serde::{Deserialize, Serialize};
use tokio::time;
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

    let (mut socket, _) = connect_async(request)
        .await
        .with_context(|| format!("connect relay websocket {relay_url}"))?;
    info!(relay = %relay_url, "relay tunnel connected");

    while let Some(message) = socket.next().await {
        match message.context("read relay websocket frame")? {
            Message::Text(raw) => {
                let RelayFrame::Request { request } =
                    serde_json::from_str(&raw).context("decode relay request")?;
                let response = forward_request(http, &cfg.pms_url, request).await;
                let raw = serde_json::to_string(&DaemonFrame::Response { response })
                    .context("encode relay response")?;
                socket
                    .send(Message::Text(raw))
                    .await
                    .context("send relay response")?;
            }
            Message::Ping(payload) => {
                socket
                    .send(Message::Pong(payload))
                    .await
                    .context("send websocket pong")?;
            }
            Message::Close(_) => return Ok(()),
            Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
    Ok(())
}

async fn forward_request(http: &Client, pms_url: &Url, request: TunnelRequest) -> TunnelResponse {
    match forward_request_inner(http, pms_url, &request).await {
        Ok(mut response) => {
            response.id = request.id;
            response
        }
        Err(err) => TunnelResponse {
            id: request.id,
            status: 502,
            headers: vec![HeaderPair {
                name: header::CONTENT_TYPE.as_str().to_owned(),
                value: "text/plain; charset=utf-8".to_owned(),
            }],
            body_base64: BASE64.encode(err.to_string()),
        },
    }
}

async fn forward_request_inner(
    http: &Client,
    pms_url: &Url,
    request: &TunnelRequest,
) -> Result<TunnelResponse> {
    let method = Method::from_bytes(request.method.as_bytes()).context("parse request method")?;
    let target = pms_url
        .join(&request.path_query)
        .context("build local PMS request URL")?;
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
    let response = builder
        .body(body)
        .send()
        .await
        .context("send local PMS request")?;
    let status = response.status().as_u16();
    let headers = serializable_headers(response.headers());
    let body = response.bytes().await.context("read local PMS response")?;

    Ok(TunnelResponse {
        id: String::new(),
        status,
        headers,
        body_base64: BASE64.encode(body),
    })
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
    Response { response: TunnelResponse },
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
struct TunnelResponse {
    id: String,
    status: u16,
    headers: Vec<HeaderPair>,
    body_base64: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct HeaderPair {
    name: String,
    value: String,
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
