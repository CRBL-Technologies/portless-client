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

const FAVICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="12" fill="#1f2933"/>
  <path d="M18 19h21a9 9 0 0 1 0 18H28" fill="none" stroke="#f7f5ef" stroke-width="7" stroke-linecap="round"/>
  <path d="M46 45H25a9 9 0 0 1 0-18h11" fill="none" stroke="#b7791f" stroke-width="7" stroke-linecap="round"/>
</svg>
"##;

const BRAND_LOCKUP_HTML: &str = r##"<span class="brand-lockup" aria-hidden="true">
  <svg class="brand-mark" viewBox="0 0 64 64" focusable="false">
    <path d="M18 19h21a9 9 0 0 1 0 18H28" fill="none" stroke="#1f2933" stroke-width="7" stroke-linecap="round"/>
    <path d="M46 45H25a9 9 0 0 1 0-18h11" fill="none" stroke="#b7791f" stroke-width="7" stroke-linecap="round"/>
  </svg>
  <span class="brand-word">Portless</span>
  <span class="brand-scope">local daemon</span>
</span>"##;

#[derive(Clone)]
pub struct UiState {
    inner: Arc<RwLock<UiSnapshot>>,
}

#[derive(Clone, Serialize)]
struct UiSnapshot {
    status: DaemonStatus,
    #[serde(skip)]
    connection: Option<quinn::Connection>,
    pms_url: String,
    control_url: String,
    data_dir: String,
    ui_addr: String,
    keepalive_profile: String,
    tunnel_id: Option<String>,
    subdomain: Option<String>,
    relay_address: Option<String>,
    config_generation: Option<i64>,
    public_url: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
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
                connection: None,
                pms_url: cfg.pms_url.to_string(),
                control_url: cfg.control_url.to_string(),
                data_dir: cfg.data_dir.display().to_string(),
                ui_addr: cfg
                    .ui_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| "disabled".to_owned()),
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
        snapshot.public_url = device
            .public_url
            .clone()
            .or_else(|| Some(public_url(&device.subdomain, &device.relay_address)));
    }

    pub async fn set_status(&self, status: DaemonStatus) {
        self.inner.write().await.status = status;
    }

    pub async fn set_connection(&self, connection: quinn::Connection) {
        let mut snapshot = self.inner.write().await;
        snapshot.connection = Some(connection);
        snapshot.status = DaemonStatus::Connected;
    }

    #[cfg(unix)]
    pub async fn is_connected(&self) -> bool {
        let snapshot = self.inner.read().await;
        snapshot.status == DaemonStatus::Connected
            && snapshot
                .connection
                .as_ref()
                .is_some_and(|connection| connection.close_reason().is_none())
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

    match path {
        "/status.json" => {
            let snapshot = state.snapshot().await;
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
        "/favicon.svg" | "/favicon.ico" => {
            write_response(&mut stream, "200 OK", "image/svg+xml", FAVICON_SVG).await
        }
        "/" => {
            let snapshot = state.snapshot().await;
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
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    path.split_once('?').map_or(path, |(path, _)| path)
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
    let subdomain = snapshot.subdomain.as_deref().unwrap_or("Waiting");
    let relay = snapshot.relay_address.as_deref().unwrap_or("Waiting");
    let generation = snapshot
        .config_generation
        .map(|value| value.to_string())
        .unwrap_or_else(|| "Waiting".to_owned());
    let status_class = status_class(snapshot.status);
    let status_copy = status_label(snapshot.status);
    let status_help = status_help(snapshot.status);
    let dashboard_url = dashboard_url(&snapshot.control_url);
    format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Portless daemon · local UI</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg?v=20260428">
    <style>
      :root {{
        color-scheme: light;
        --canvas: #FFFBF5;
        --surface: #FFF7ED;
        --surface-strong: #FFFFFF;
        --text: #1C1917;
        --muted: #78716C;
        --border: #E7E5E4;
        --border-strong: #D6D3D1;
        --accent: #D97706;
        --accent-link: #B45309;
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
      a {{ color: var(--accent-link); }}
      a:hover {{ color: var(--accent-hover); }}
      a:focus-visible, button:focus-visible {{ outline: 3px solid var(--accent-soft); outline-offset: 3px; }}
      .localhost-bar {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 8px 16px; background: #1C1917; color: #A8A29E; font-family: var(--mono); font-size: 12px; }}
      .localhost-bar .left {{ display: inline-flex; align-items: center; gap: 8px; min-width: 0; }}
      .localhost-bar .dot {{ width: 7px; height: 7px; border-radius: 999px; background: var(--ok); box-shadow: 0 0 6px rgb(21 128 61 / 60%); }}
      .localhost-bar .url {{ color: #FBBF24; overflow-wrap: anywhere; }}
      .topbar {{ position: sticky; top: 0; z-index: 10; border-bottom: 1px solid var(--border); background: rgb(255 251 245 / 92%); backdrop-filter: blur(12px); }}
      .topbar-inner {{ width: min(1100px, calc(100vw - 32px)); margin: 0 auto; padding: 14px 0; display: flex; align-items: center; justify-content: space-between; gap: 16px; }}
      .brand {{ color: var(--text); text-decoration: none; }}
      .brand-lockup {{ display: inline-flex; align-items: center; gap: 8px; }}
      .brand-mark {{ width: 24px; height: 24px; flex: 0 0 auto; }}
      .brand-word {{ font-family: var(--mono); font-size: 17px; line-height: 1.15; font-weight: 800; letter-spacing: 0; }}
      .brand-scope {{ margin-left: 6px; padding: 2px 8px; border: 1px solid var(--border); border-radius: 999px; background: var(--surface); color: var(--muted); font-family: var(--mono); font-size: 12px; }}
      .page {{ width: min(1100px, calc(100vw - 32px)); margin: 0 auto; padding: 28px 0 56px; display: grid; gap: 20px; }}
      h1 {{ margin: 0 0 6px; font-size: 26px; line-height: 1.15; font-weight: 600; letter-spacing: 0; }}
      h2 {{ margin: 0; font-size: 15px; line-height: 1.25; letter-spacing: 0; }}
      h3 {{ margin: 0; font-size: 17px; line-height: 1.25; letter-spacing: 0; }}
      p {{ margin: 0; color: var(--muted); line-height: 1.55; }}
      button, .dashboard-link {{ display: inline-flex; align-items: center; justify-content: center; min-height: 36px; padding: 0 12px; border: 1px solid var(--border-strong); border-radius: 8px; background: var(--surface-strong); color: var(--text); font: inherit; font-weight: 600; cursor: pointer; text-decoration: none; }}
      button:hover {{ border-color: var(--accent); background: var(--accent-soft); }}
      .dashboard-link:hover {{ border-color: var(--accent); background: var(--accent-soft); color: var(--text); }}
      .status-hero {{ display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 24px; align-items: center; padding: 24px 28px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); }}
      .pill-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }}
      .status-pill {{ display: inline-flex; align-items: center; gap: 7px; min-height: 28px; padding: 0 12px; border: 1px solid var(--border); border-radius: 999px; background: var(--surface-strong); color: var(--muted); font-family: var(--mono); font-size: 12px; font-weight: 600; }}
      .status-pill .dot {{ width: 7px; height: 7px; border-radius: 999px; background: currentColor; }}
      .status-pill.ok {{ border-color: #86EFAC; background: var(--ok-soft); color: var(--ok); }}
      .status-pill.wait {{ border-color: #FCD34D; background: var(--accent-soft); color: var(--wait); }}
      .status-pill.bad {{ border-color: #FCA5A5; background: var(--bad-soft); color: var(--bad); }}
      .url-line {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-family: var(--mono); font-size: 14px; }}
      .url-line code {{ color: var(--accent-link); overflow-wrap: anywhere; }}
      .hero-actions {{ display: flex; flex-wrap: wrap; gap: 8px; }}
      .stats {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }}
      .stat, .card {{ border: 1px solid var(--border); border-radius: 8px; background: var(--surface); }}
      .stat {{ display: grid; gap: 5px; padding: 16px; }}
      .stat-label {{ display: flex; align-items: center; gap: 6px; color: var(--muted); font-family: var(--mono); font-size: 11px; font-weight: 600; text-transform: lowercase; }}
      .stat-value {{ color: var(--text); font-size: 22px; line-height: 1.1; font-weight: 600; overflow-wrap: anywhere; }}
      .stat-meta {{ color: var(--muted); font-family: var(--mono); font-size: 12px; }}
      .cols {{ display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(320px, .8fr); gap: 20px; }}
      .card {{ display: grid; gap: 16px; align-content: start; padding: 22px 24px; }}
      .card-head {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; }}
      .card-head .meta {{ color: var(--muted); font-family: var(--mono); font-size: 12px; }}
      .rows {{ display: grid; gap: 0; }}
      .row {{ display: grid; grid-template-columns: 140px minmax(0, 1fr); gap: 14px; padding: 11px 0; border-top: 1px solid var(--border); }}
      .row:first-child {{ border-top: 0; padding-top: 4px; }}
      .row span:first-child {{ color: var(--muted); font-family: var(--mono); font-size: 11px; font-weight: 600; }}
      .row span:last-child {{ overflow-wrap: anywhere; }}
      .note {{ border: 1px solid var(--border); border-radius: 8px; background: var(--surface-strong); padding: 12px; }}
      @media (max-width: 860px) {{
        .status-hero, .cols {{ grid-template-columns: 1fr; }}
        .stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      }}
      @media (max-width: 620px) {{
        .localhost-bar {{ align-items: flex-start; flex-direction: column; gap: 4px; }}
        .topbar-inner, .page {{ width: min(100vw - 20px, 1100px); }}
        .topbar-inner {{ align-items: flex-start; flex-direction: column; }}
        .status-hero {{ padding: 20px; }}
        .hero-actions, .stats {{ grid-template-columns: 1fr; }}
        .row {{ grid-template-columns: 1fr; gap: 4px; }}
      }}
    </style>
  </head>
  <body>
    <div class="localhost-bar">
      <div class="left"><span class="dot" aria-hidden="true"></span><span>local daemon UI</span><span class="url">{ui_addr}</span></div>
      <span>no inbound internet port required</span>
    </div>
    <header class="topbar">
      <div class="topbar-inner">
        <a class="brand" href="/" aria-label="Portless local daemon">{brand}</a>
        <a class="dashboard-link" href="{dashboard_url}" rel="noopener">Open hosted dashboard</a>
      </div>
    </header>
    <main class="page">
      <section class="status-hero">
        <div>
          <div class="pill-row">
            <span class="status-pill {status_class}"><span class="dot" aria-hidden="true"></span>{status_copy}</span>
          </div>
          <h1>{status_copy}</h1>
          <p>{status_help}</p>
          <div class="url-line">
            <span>public URL</span>
            <code id="public-url">{public_url}</code>
          </div>
        </div>
        <div class="hero-actions">
          <button type="button" data-copy="public-url">Copy public URL</button>
          <a class="dashboard-link" href="/status.json">Open status JSON</a>
        </div>
      </section>
      <section class="stats" aria-label="Daemon summary">
        <div class="stat"><span class="stat-label">status</span><strong class="stat-value">{status_copy}</strong><span class="stat-meta">local process</span></div>
        <div class="stat"><span class="stat-label">subdomain</span><strong class="stat-value">{subdomain}</strong><span class="stat-meta">Portless hostname</span></div>
        <div class="stat"><span class="stat-label">Relay</span><strong class="stat-value">{relay}</strong><span class="stat-meta">QUIC outbound</span></div>
        <div class="stat"><span class="stat-label">config</span><strong class="stat-value">{generation}</strong><span class="stat-meta">generation</span></div>
      </section>
      <div class="cols">
        <section class="card">
          <div class="card-head"><h2>Connection path</h2><span class="meta">QUIC tunnel</span></div>
          <div class="rows">
            <div class="row"><span>Browser URL</span><span>{public_url}</span></div>
            <div class="row"><span>Portless relay</span><span>{relay}</span></div>
            <div class="row"><span>Plex server</span><span>{pms_url}</span></div>
            <div class="row"><span>Local UI</span><span>{ui_addr}</span></div>
          </div>
        </section>
        <section class="card" aria-label="Daemon settings">
          <div class="card-head"><h2>Daemon settings</h2><span class="meta">container env</span></div>
          <p>The token comes from <code>PORTLESS_DEVICE_TOKEN</code>. Rotate it in the hosted dashboard, then update the container environment and restart this daemon.</p>
          <div class="rows">
            <div class="row"><span>Portless control URL</span><span>{control_url}</span></div>
            <div class="row"><span>Data directory</span><span>{data_dir}</span></div>
            <div class="row"><span>Keepalive</span><span>{keepalive}</span></div>
          </div>
          <div class="note"><p><code>/status.json</code> exposes the same state for health checks and local automation.</p></div>
        </section>
      </div>
    </main>
    <script>
      document.querySelectorAll("[data-copy]").forEach((button) => {{
        button.addEventListener("click", async () => {{
          const target = document.getElementById(button.dataset.copy);
          if (!target) return;
          await navigator.clipboard.writeText(target.textContent || "");
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
        status_help = escape(status_help),
        brand = BRAND_LOCKUP_HTML,
        dashboard_url = escape(&dashboard_url),
        ui_addr = escape(&snapshot.ui_addr),
        public_url = escape(public_url),
        subdomain = escape(subdomain),
        generation = escape(&generation),
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

fn status_help(status: DaemonStatus) -> &'static str {
    match status {
        DaemonStatus::Starting => "Starting the tunnel and loading device configuration.",
        DaemonStatus::Connected => "The daemon is connected to the Portless relay.",
        DaemonStatus::Reconnecting => "Reconnecting to the relay. If this persists, check the container logs and network path.",
        DaemonStatus::AuthFailed => {
            "Auth failed. Rotate the daemon token in the hosted dashboard, update PORTLESS_DEVICE_TOKEN, and restart the container."
        }
        DaemonStatus::CapReached => {
            "Capacity reached. Wait for quota reset or manage billing in the hosted dashboard."
        }
        DaemonStatus::DeviceRevoked => {
            "Device revoked. Rotate the daemon token in the hosted dashboard and restart this daemon with the new token."
        }
        DaemonStatus::HomeUnreachable => {
            "Home network unreachable. Check that this container can reach your LAN and DNS."
        }
        DaemonStatus::PlexUnreachable => {
            "Plex unreachable. Check that PORTLESS_PMS_URL resolves from this container."
        }
        DaemonStatus::RelayUnreachable => {
            "Relay unreachable. Check outbound firewall rules and the Portless control URL."
        }
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

fn dashboard_url(control_url: &str) -> String {
    let base = control_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return "https://join.portless.io/dashboard".to_owned();
    }
    if let Ok(parsed) = url::Url::parse(base) {
        if let Some(host) = parsed.host_str() {
            let dashboard_target = match host {
                "connect.portless.io" => Some(("join.portless.io".to_owned(), None)),
                "staging-connect.portless.io" => {
                    Some(("staging-join.portless.io".to_owned(), None))
                }
                _ => host
                    .strip_prefix("connect.")
                    .map(|suffix| (format!("join.{suffix}"), parsed.port())),
            };
            if let Some((dashboard_host, dashboard_port)) = dashboard_target {
                let mut dashboard = format!("{}://{}", parsed.scheme(), dashboard_host);
                if let Some(port) = dashboard_port {
                    dashboard.push_str(&format!(":{port}"));
                }
                dashboard.push_str("/dashboard");
                return dashboard;
            }
        }
    }
    if base.ends_with("/dashboard") {
        return base.to_owned();
    }
    format!("{base}/dashboard")
}

fn public_url(subdomain: &str, relay_address: &str) -> String {
    let relay = relay_address
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let mut host = relay;
    let mut port = "";
    if let Some((candidate_host, candidate_port)) = relay.rsplit_once(':') {
        host = candidate_host;
        port = candidate_port;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() > 2 && labels[0].to_ascii_lowercase().starts_with("relay-") {
        host = &host[labels[0].len() + 1..];
    }
    if port.is_empty() || port == "443" {
        format!("https://{subdomain}.{host}")
    } else {
        format!("https://{subdomain}.{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_status_json_uses_expected_names() {
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

    #[test]
    fn dashboard_keeps_relay_without_duplicate_control_status() {
        let snapshot = UiSnapshot {
            status: DaemonStatus::Connected,
            connection: None,
            pms_url: "http://plex:32400/".to_owned(),
            control_url: "https://portless.io/".to_owned(),
            data_dir: "/var/lib/portless".to_owned(),
            ui_addr: "127.0.0.1:43180".to_owned(),
            keepalive_profile: "residential".to_owned(),
            tunnel_id: Some("tun_secret".to_owned()),
            subdomain: Some("sample".to_owned()),
            relay_address: Some("portless.io:8443".to_owned()),
            config_generation: Some(7),
            public_url: Some("https://sample.portless.io".to_owned()),
        };

        let html = render_html(&snapshot);

        assert!(!html.contains("Tunnel ID"));
        assert!(!html.contains("tun_secret"));
        assert!(html.contains("Relay"));
        assert!(html.contains("portless.io:8443"));
        assert!(html.contains("Open hosted dashboard"));
        assert!(html.contains("Plex server"));
        assert!(html.contains("Portless control URL"));
        assert!(!html.contains("Control status"));
    }

    #[test]
    fn dashboard_url_is_derived_from_control_url() {
        assert_eq!(
            dashboard_url("https://connect.portless.io/"),
            "https://join.portless.io/dashboard"
        );
        assert_eq!(
            dashboard_url("https://staging-connect.portless.io:8443/"),
            "https://staging-join.portless.io/dashboard"
        );
        assert_eq!(
            dashboard_url("https://connect.port-less.com/"),
            "https://join.port-less.com/dashboard"
        );
        assert_eq!(
            dashboard_url("https://connect.portless.localhost:8443/"),
            "https://join.portless.localhost:8443/dashboard"
        );
        assert_eq!(
            dashboard_url("https://join.portless.io/"),
            "https://join.portless.io/dashboard"
        );
        assert_eq!(
            dashboard_url("https://join.portless.io/dashboard"),
            "https://join.portless.io/dashboard"
        );
    }

    #[test]
    fn public_url_uses_customer_domain_for_relay_hosts() {
        assert_eq!(
            public_url("sample", "relay-ams-1.portless.io:443"),
            "https://sample.portless.io"
        );
        assert_eq!(
            public_url("sample", "relay-ams-1.staging.portless.io:8443"),
            "https://sample.staging.portless.io:8443"
        );
    }

    #[test]
    fn dashboard_links_svg_favicon() {
        let snapshot = UiSnapshot {
            status: DaemonStatus::Connected,
            connection: None,
            pms_url: "http://plex:32400/".to_owned(),
            control_url: "https://portless.io/".to_owned(),
            data_dir: "/var/lib/portless".to_owned(),
            ui_addr: "127.0.0.1:43180".to_owned(),
            keepalive_profile: "residential".to_owned(),
            tunnel_id: None,
            subdomain: Some("sample".to_owned()),
            relay_address: Some("portless.io:8443".to_owned()),
            config_generation: Some(7),
            public_url: Some("https://sample.portless.io".to_owned()),
        };

        let html = render_html(&snapshot);

        assert!(html
            .contains(r#"<link rel="icon" type="image/svg+xml" href="/favicon.svg?v=20260428">"#));
        assert!(FAVICON_SVG.contains(r##"fill="#1f2933""##));
        assert!(FAVICON_SVG.contains(r##"stroke="#b7791f""##));
    }

    #[test]
    fn request_path_ignores_query_string() {
        assert_eq!(
            request_path("GET /favicon.svg?v=20260428 HTTP/1.1\r\n\r\n"),
            "/favicon.svg"
        );
    }
}
