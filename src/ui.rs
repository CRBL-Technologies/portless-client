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
    status: DaemonStatus,
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

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum DaemonStatus {
    Starting,
    Connected,
    Reconnecting,
    AuthFailed,
    CapReached,
    DeviceRevoked,
    HomeUnreachable,
    PlexUnreachable,
    RelayUnreachable,
}

impl UiState {
    pub fn new(cfg: &Config) -> Self {
        Self {
            inner: Arc::new(RwLock::new(UiSnapshot {
                status: DaemonStatus::Starting,
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
        snapshot.tunnel_id = Some(device.tunnel_id.clone());
        snapshot.subdomain = Some(device.subdomain.clone());
        snapshot.relay_address = Some(device.relay_address.clone());
        snapshot.config_generation = Some(device.config_generation);
        snapshot.public_url = Some(public_url(&device.subdomain, &device.relay_address));
    }

    pub async fn set_status(&self, status: DaemonStatus) {
        self.inner.write().await.status = status;
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
    let public_url = snapshot
        .public_url
        .as_deref()
        .unwrap_or("Waiting for device config");
    let tunnel_id = snapshot.tunnel_id.as_deref().unwrap_or("Waiting");
    let subdomain = snapshot.subdomain.as_deref().unwrap_or("Waiting");
    let relay = snapshot.relay_address.as_deref().unwrap_or("Waiting");
    let generation = snapshot
        .config_generation
        .map(|value| value.to_string())
        .unwrap_or_else(|| "Waiting".to_owned());
    let status_class = status_class(snapshot.status);
    let status_copy = status_label(snapshot.status);
    format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Portless client</title>
    <style>
      :root {{
        color-scheme: light;
        --canvas: #FFFBF5;
        --surface: #FFF7ED;
        --surface-strong: #FFFFFF;
        --text: #1C1917;
        --muted: #78716C;
        --border: #E7D8C4;
        --border-strong: #D6BFA1;
        --accent: #D97706;
        --accent-hover: #B45309;
        --accent-soft: #FEF3C7;
        --ok: #15803D;
        --ok-soft: #DCFCE7;
        --wait: #92400E;
        --bad: #B91C1C;
        --bad-soft: #FEE2E2;
        --mono: "JetBrains Mono", "SFMono-Regular", Consolas, "Liberation Mono", monospace;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        color: var(--text);
        background: var(--canvas);
      }}
      * {{ box-sizing: border-box; }}
      body {{ min-width: 320px; margin: 0; background: var(--canvas); }}
      main {{ width: min(1120px, calc(100vw - 32px)); margin: 0 auto; padding: 28px 0 48px; }}
      header {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 18px; }}
      h1 {{ margin: 0; font-family: var(--mono); font-size: 28px; line-height: 1.15; letter-spacing: 0; }}
      h1 span {{ color: var(--accent); }}
      h2 {{ margin: 0; font-size: 24px; line-height: 1.18; letter-spacing: 0; }}
      h3 {{ margin: 0; font-size: 17px; line-height: 1.25; letter-spacing: 0; }}
      p {{ margin: 0; color: var(--muted); line-height: 1.55; }}
      button {{ display: inline-flex; align-items: center; justify-content: center; min-height: 38px; padding: 0 12px; border: 1px solid var(--border-strong); border-radius: 6px; background: var(--surface-strong); color: var(--text); font: inherit; font-weight: 800; cursor: pointer; }}
      button:hover {{ border-color: var(--accent); background: var(--accent-soft); }}
      .status {{ display: inline-flex; align-items: center; gap: 8px; min-height: 34px; padding: 0 12px; border: 1px solid var(--border); border-radius: 999px; background: var(--surface); color: var(--muted); font-weight: 700; }}
      .status.ok {{ border-color: #86EFAC; background: var(--ok-soft); color: var(--ok); }}
      .status.wait {{ border-color: #FCD34D; background: var(--accent-soft); color: var(--wait); }}
      .status.bad {{ border-color: #FCA5A5; background: var(--bad-soft); color: var(--bad); }}
      .dot {{ width: 8px; height: 8px; border-radius: 50%; background: currentColor; }}
      .layout {{ display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(280px, .85fr); gap: 16px; }}
      section {{ border: 1px solid var(--border); border-radius: 8px; background: var(--surface); }}
      .panel {{ display: grid; gap: 16px; align-content: start; padding: 22px; }}
      .url-wrap {{ display: grid; gap: 10px; }}
      .url {{ display: block; width: 100%; overflow-wrap: anywhere; padding: 14px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface-strong); color: var(--text); font-family: var(--mono); font-size: 15px; }}
      .meta {{ display: grid; gap: 0; }}
      .row {{ display: grid; grid-template-columns: 132px minmax(0, 1fr); gap: 10px; padding: 12px 0; border-top: 1px solid var(--border); }}
      .row:first-child {{ border-top: 0; }}
      .row span:first-child {{ color: var(--muted); font-weight: 800; }}
      .row span:last-child {{ overflow-wrap: anywhere; }}
      .note {{ border: 1px solid var(--border); border-radius: 8px; background: var(--surface-strong); padding: 12px; }}
      @media (max-width: 780px) {{
        main {{ width: min(100vw - 20px, 1120px); padding-top: 16px; }}
        header {{ align-items: flex-start; flex-direction: column; }}
        h1 {{ font-size: 24px; }}
        .layout {{ grid-template-columns: 1fr; }}
        .row {{ grid-template-columns: 1fr; gap: 4px; }}
      }}
    </style>
  </head>
  <body>
    <main>
      <header>
        <h1><span>P</span>ortless client</h1>
        <div class="status {status_class}"><span class="dot" aria-hidden="true"></span>{status_copy}</div>
      </header>
      <div class="layout">
        <section class="panel">
          <div>
            <h2>Public tunnel</h2>
            <p>This is the customer URL served through Portless when the daemon is connected.</p>
          </div>
          <div class="url-wrap">
            <code id="public-url" class="url">{public_url}</code>
            <button type="button" data-copy="public-url">Copy public URL</button>
          </div>
          <div class="meta">
            <div class="row"><span>Subdomain</span><span>{subdomain}</span></div>
            <div class="row"><span>Config generation</span><span>{generation}</span></div>
            <div class="row"><span>Tunnel ID</span><span>{tunnel_id}</span></div>
            <div class="row"><span>Relay</span><span>{relay}</span></div>
          </div>
        </section>
        <section class="panel" aria-label="Daemon settings">
          <div>
            <h2>Daemon settings</h2>
            <p>The token comes from <code>PORTLESS_DEVICE_TOKEN</code>. Rotate it in the hosted dashboard, then update the container environment and restart this daemon.</p>
          </div>
          <div class="row"><span>PMS</span><span>{pms_url}</span></div>
          <div class="row"><span>Control</span><span>{control_url}</span></div>
          <div class="row"><span>Data dir</span><span>{data_dir}</span></div>
          <div class="row"><span>Keepalive</span><span>{keepalive}</span></div>
          <div class="note"><p>Open <code>/status.json</code> for a machine-readable view of this page.</p></div>
        </section>
      </div>
    </main>
    <script>
      document.querySelectorAll("[data-copy]").forEach((button) => {{
        button.addEventListener("click", async () => {{
          const target = document.getElementById(button.dataset.copy);
          if (!target) return;
          await navigator.clipboard.writeText(target.textContent);
          const original = button.textContent;
          button.textContent = "Copied";
          setTimeout(() => {{ button.textContent = original; }}, 1400);
        }});
      }});
    </script>
  </body>
</html>"#,
        status_class = status_class,
        status_copy = status_copy,
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

fn status_label(status: DaemonStatus) -> &'static str {
    match status {
        DaemonStatus::Starting => "Starting",
        DaemonStatus::Connected => "Connected",
        DaemonStatus::Reconnecting => "Reconnecting",
        DaemonStatus::AuthFailed => "Auth failed",
        DaemonStatus::CapReached => "Capacity reached",
        DaemonStatus::DeviceRevoked => "Device revoked",
        DaemonStatus::HomeUnreachable => "Home unreachable",
        DaemonStatus::PlexUnreachable => "Plex unreachable",
        DaemonStatus::RelayUnreachable => "Relay unreachable",
    }
}

fn status_class(status: DaemonStatus) -> &'static str {
    match status {
        DaemonStatus::Connected => "ok",
        DaemonStatus::RelayUnreachable
        | DaemonStatus::AuthFailed
        | DaemonStatus::CapReached
        | DaemonStatus::DeviceRevoked
        | DaemonStatus::HomeUnreachable
        | DaemonStatus::PlexUnreachable => "bad",
        DaemonStatus::Starting | DaemonStatus::Reconnecting => "wait",
    }
}

fn public_url(subdomain: &str, relay_address: &str) -> String {
    let relay = relay_address
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    format!("https://{subdomain}.{relay}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_status_json_matches_control_contract_names() {
        let cases = [
            (DaemonStatus::Starting, "starting"),
            (DaemonStatus::Connected, "connected"),
            (DaemonStatus::Reconnecting, "reconnecting"),
            (DaemonStatus::AuthFailed, "auth_failed"),
            (DaemonStatus::CapReached, "cap_reached"),
            (DaemonStatus::DeviceRevoked, "device_revoked"),
            (DaemonStatus::HomeUnreachable, "home_unreachable"),
            (DaemonStatus::PlexUnreachable, "plex_unreachable"),
            (DaemonStatus::RelayUnreachable, "relay_unreachable"),
        ];

        for (status, expected) in cases {
            let encoded = serde_json::to_string(&status).expect("serialize daemon status");
            assert_eq!(encoded, format!(r#""{expected}""#));
        }
    }
}
