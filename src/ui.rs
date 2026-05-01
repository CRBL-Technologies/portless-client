use crate::{config::Config, control::DeviceConfig};
use anyhow::{Context, Result};
use serde::Serialize;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
};
use tracing::{debug, info, warn};

#[derive(Clone)]
pub struct UiState {
    inner: Arc<RwLock<UiSnapshot>>,
}

#[derive(Clone, Serialize)]
struct UiSnapshot {
    status: &'static str,
    pms_url: String,
    control_url: String,
    data_dir: String,
    keepalive_profile: String,
    tunnel_id: Option<String>,
    subdomain: Option<String>,
    relay_address: Option<String>,
    config_generation: Option<i64>,
    public_url: Option<String>,
}

impl UiState {
    pub fn new(cfg: &Config) -> Self {
        Self {
            inner: Arc::new(RwLock::new(UiSnapshot {
                status: "starting",
                pms_url: cfg.pms_url.to_string(),
                control_url: cfg.control_url.to_string(),
                data_dir: cfg.data_dir.display().to_string(),
                keepalive_profile: format!("{:?}", cfg.keepalive_profile).to_ascii_lowercase(),
                tunnel_id: None,
                subdomain: None,
                relay_address: None,
                config_generation: None,
                public_url: None,
            })),
        }
    }

    pub async fn set_device(&self, device: &DeviceConfig) {
        let mut snapshot = self.inner.write().await;
        snapshot.status = "connected";
        snapshot.tunnel_id = Some(device.tunnel_id.clone());
        snapshot.subdomain = Some(device.subdomain.clone());
        snapshot.relay_address = Some(device.relay_address.clone());
        snapshot.config_generation = Some(device.config_generation);
        snapshot.public_url = Some(public_url(&device.subdomain, &device.relay_address));
    }

    async fn snapshot(&self) -> UiSnapshot {
        self.inner.read().await.clone()
    }
}

pub async fn serve(addr: SocketAddr, state: UiState) {
    if let Err(err) = serve_inner(addr, state).await {
        warn!(error = %err, "client UI stopped");
    }
}

async fn serve_inner(addr: SocketAddr, state: UiState) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind client UI on {addr}"))?;
    info!(%addr, "client UI listening");

    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .context("accept client UI request")?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle(stream, state).await {
                debug!(%peer, error = %err, "client UI request failed");
            }
        });
    }
}

async fn handle(mut stream: TcpStream, state: UiState) -> Result<()> {
    let mut buf = [0_u8; 2048];
    let n = stream.read(&mut buf).await.context("read request")?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let path = request_path(&request);
    let snapshot = state.snapshot().await;

    match path {
        "/status.json" => {
            let body = serde_json::to_string_pretty(&snapshot).context("encode status json")?;
            write_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &body,
            )
            .await
        }
        "/healthz" => {
            write_response(&mut stream, "200 OK", "text/plain; charset=utf-8", "ok\n").await
        }
        "/" => {
            let body = render_html(&snapshot);
            write_response(&mut stream, "200 OK", "text/html; charset=utf-8", &body).await
        }
        _ => {
            write_response(
                &mut stream,
                "404 Not Found",
                "text/plain; charset=utf-8",
                "not found\n",
            )
            .await
        }
    }
}

fn request_path(request: &str) -> &str {
    request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("write response")
}

fn render_html(snapshot: &UiSnapshot) -> String {
    let public_url = snapshot.public_url.as_deref().unwrap_or("Pending config");
    let tunnel_id = snapshot.tunnel_id.as_deref().unwrap_or("Pending");
    let subdomain = snapshot.subdomain.as_deref().unwrap_or("Pending");
    let relay = snapshot.relay_address.as_deref().unwrap_or("Pending");
    let generation = snapshot
        .config_generation
        .map(|value| value.to_string())
        .unwrap_or_else(|| "Pending".to_owned());
    format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Portless Client</title>
    <style>
      :root {{ color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #17202a; background: #f4f7f5; }}
      * {{ box-sizing: border-box; }}
      body {{ min-width: 320px; margin: 0; background: #f4f7f5; }}
      main {{ width: min(1120px, calc(100vw - 32px)); margin: 0 auto; padding: 28px 0 44px; }}
      header {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 18px; }}
      h1 {{ margin: 0; font-size: 28px; line-height: 1.15; letter-spacing: 0; }}
      .status {{ display: inline-flex; align-items: center; gap: 8px; min-height: 34px; padding: 0 12px; border: 1px solid #a8d5ba; border-radius: 999px; background: #e7f5ed; color: #126339; font-weight: 700; }}
      .dot {{ width: 8px; height: 8px; border-radius: 50%; background: #20a464; }}
      .layout {{ display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(280px, .8fr); gap: 14px; }}
      section {{ border: 1px solid #d7e1db; border-radius: 8px; background: #fff; box-shadow: 0 1px 2px rgb(15 23 42 / 6%); }}
      .primary {{ padding: 22px; }}
      h2 {{ margin: 0 0 10px; font-size: 18px; letter-spacing: 0; }}
      .url {{ display: block; width: 100%; overflow-wrap: anywhere; padding: 14px; border: 1px solid #d7e1db; border-radius: 8px; background: #f8faf9; color: #17202a; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 15px; }}
      .meta {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin-top: 14px; }}
      .item {{ padding: 12px; border: 1px solid #e3e9e5; border-radius: 8px; background: #fbfcfb; }}
      .label {{ margin: 0 0 5px; color: #65736b; font-size: 12px; font-weight: 700; text-transform: uppercase; }}
      .value {{ margin: 0; overflow-wrap: anywhere; font-size: 14px; }}
      .side {{ display: grid; gap: 0; }}
      .row {{ display: grid; grid-template-columns: 122px minmax(0, 1fr); gap: 10px; padding: 14px; border-bottom: 1px solid #e3e9e5; }}
      .row:last-child {{ border-bottom: 0; }}
      .row span:first-child {{ color: #65736b; font-weight: 700; }}
      .row span:last-child {{ overflow-wrap: anywhere; }}
      @media (max-width: 780px) {{
        main {{ width: min(100vw - 20px, 1120px); padding-top: 16px; }}
        header {{ align-items: flex-start; flex-direction: column; }}
        h1 {{ font-size: 24px; }}
        .layout, .meta {{ grid-template-columns: 1fr; }}
        .row {{ grid-template-columns: 1fr; gap: 4px; }}
      }}
    </style>
  </head>
  <body>
    <main>
      <header>
        <h1>Portless Client</h1>
        <div class="status"><span class="dot" aria-hidden="true"></span>{status}</div>
      </header>
      <div class="layout">
        <section class="primary">
          <h2>Public tunnel</h2>
          <code class="url">{public_url}</code>
          <div class="meta">
            <div class="item"><p class="label">Subdomain</p><p class="value">{subdomain}</p></div>
            <div class="item"><p class="label">Config generation</p><p class="value">{generation}</p></div>
            <div class="item"><p class="label">Tunnel ID</p><p class="value">{tunnel_id}</p></div>
            <div class="item"><p class="label">Relay</p><p class="value">{relay}</p></div>
          </div>
        </section>
        <section class="side" aria-label="Daemon settings">
          <div class="row"><span>PMS</span><span>{pms_url}</span></div>
          <div class="row"><span>Control</span><span>{control_url}</span></div>
          <div class="row"><span>Data dir</span><span>{data_dir}</span></div>
          <div class="row"><span>Keepalive</span><span>{keepalive}</span></div>
        </section>
      </div>
    </main>
  </body>
</html>"#,
        status = escape(snapshot.status),
        public_url = escape(public_url),
        subdomain = escape(subdomain),
        generation = escape(&generation),
        tunnel_id = escape(tunnel_id),
        relay = escape(relay),
        pms_url = escape(&snapshot.pms_url),
        control_url = escape(&snapshot.control_url),
        data_dir = escape(&snapshot.data_dir),
        keepalive = escape(&snapshot.keepalive_profile),
    )
}

fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn public_url(subdomain: &str, relay_address: &str) -> String {
    let relay = relay_address
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    format!("https://{subdomain}.{relay}")
}
