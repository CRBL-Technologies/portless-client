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
  <span class="brand-word">Portless client</span>
</span>"##;

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
    <title>Portless client</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg?v=20260428">
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
      main {{ width: min(1120px, calc(100vw - 32px)); margin: 0 auto; padding: 28px 0 48px; }}
      header {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 18px; }}
      a {{ color: var(--accent-link); }}
      a:hover {{ color: var(--accent-hover); }}
      a:focus-visible, button:focus-visible {{ outline: 3px solid var(--accent-soft); outline-offset: 3px; }}
      .brand {{ color: var(--text); text-decoration: none; }}
      .brand-lockup {{ display: inline-flex; align-items: center; gap: 10px; }}
      .brand-mark {{ width: 34px; height: 34px; flex: 0 0 auto; }}
      .brand-word {{ font-family: var(--mono); font-size: 26px; line-height: 1.15; font-weight: 800; letter-spacing: 0; }}
      .header-actions {{ display: inline-flex; align-items: flex-start; gap: 12px; flex-wrap: wrap; justify-content: flex-end; }}
      .dashboard-link {{ display: inline-flex; align-items: center; justify-content: center; min-height: 34px; padding: 0 12px; border: 1px solid var(--border-strong); border-radius: 6px; background: var(--surface-strong); color: var(--text); font-weight: 800; text-decoration: none; }}
      .dashboard-link:hover {{ border-color: var(--accent); background: var(--accent-soft); color: var(--text); }}
      h2 {{ margin: 0; font-size: 24px; line-height: 1.18; letter-spacing: 0; }}
      h3 {{ margin: 0; font-size: 17px; line-height: 1.25; letter-spacing: 0; }}
      p {{ margin: 0; color: var(--muted); line-height: 1.55; }}
      button {{ display: inline-flex; align-items: center; justify-content: center; min-height: 38px; padding: 0 12px; border: 1px solid var(--border-strong); border-radius: 6px; background: var(--surface-strong); color: var(--text); font: inherit; font-weight: 800; cursor: pointer; }}
      button:hover {{ border-color: var(--accent); background: var(--accent-soft); }}
      .status-block {{ display: grid; justify-items: end; gap: 6px; max-width: 360px; }}
      .status {{ display: inline-flex; align-items: center; gap: 8px; min-height: 34px; padding: 0 12px; border: 1px solid var(--border); border-radius: 999px; background: var(--surface); color: var(--muted); font-weight: 700; }}
      .status.ok {{ border-color: #86EFAC; background: var(--ok-soft); color: var(--ok); }}
      .status.wait {{ border-color: #FCD34D; background: var(--accent-soft); color: var(--wait); }}
      .status.bad {{ border-color: #FCA5A5; background: var(--bad-soft); color: var(--bad); }}
      .status-help {{ max-width: none; text-align: right; font-size: 13px; line-height: 1.4; }}
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
        .brand-word {{ font-size: 23px; }}
        .header-actions, .status-block {{ justify-content: flex-start; justify-items: start; }}
        .status-help {{ text-align: left; }}
        .layout {{ grid-template-columns: 1fr; }}
        .row {{ grid-template-columns: 1fr; gap: 4px; }}
      }}
    </style>
  </head>
  <body>
    <main>
      <header>
        <a class="brand" href="/" aria-label="Portless client home">{brand}</a>
        <div class="header-actions">
          <a class="dashboard-link" href="{dashboard_url}" rel="noopener">Open hosted dashboard</a>
          <div class="status-block">
            <div class="status {status_class}"><span class="dot" aria-hidden="true"></span>{status_copy}</div>
            <p class="status-help">{status_help}</p>
          </div>
        </div>
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
            <div class="row"><span>Relay</span><span>{relay}</span></div>
          </div>
        </section>
        <section class="panel" aria-label="Daemon settings">
          <div>
            <h2>Daemon settings</h2>
            <p>The token comes from <code>PORTLESS_DEVICE_TOKEN</code>. Rotate it in the hosted dashboard, then update the container environment and restart this daemon.</p>
          </div>
          <div class="row"><span>Plex server</span><span>{pms_url}</span></div>
          <div class="row"><span>Portless control URL</span><span>{control_url}</span></div>
          <div class="row"><span>Data directory</span><span>{data_dir}</span></div>
          <div class="row"><span>Keepalive profile</span><span>{keepalive}</span></div>
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
        status_help = escape(status_help),
        brand = BRAND_LOCKUP_HTML,
        dashboard_url = escape(&dashboard_url),
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
    format!("https://{subdomain}.{relay}")
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
            pms_url: "http://plex:32400/".to_owned(),
            control_url: "https://portless.io/".to_owned(),
            data_dir: "/var/lib/portless".to_owned(),
            keepalive_profile: "residential".to_owned(),
            tunnel_id: Some("tun_secret".to_owned()),
            subdomain: Some("antoine".to_owned()),
            relay_address: Some("portless.io:8443".to_owned()),
            config_generation: Some(7),
            public_url: Some("https://antoine.portless.io".to_owned()),
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
            dashboard_url("https://join.portless.io/"),
            "https://join.portless.io/dashboard"
        );
        assert_eq!(
            dashboard_url("https://join.portless.io/dashboard"),
            "https://join.portless.io/dashboard"
        );
    }

    #[test]
    fn dashboard_links_svg_favicon() {
        let snapshot = UiSnapshot {
            status: DaemonStatus::Connected,
            pms_url: "http://plex:32400/".to_owned(),
            control_url: "https://portless.io/".to_owned(),
            data_dir: "/var/lib/portless".to_owned(),
            keepalive_profile: "residential".to_owned(),
            tunnel_id: None,
            subdomain: Some("antoine".to_owned()),
            relay_address: Some("portless.io:8443".to_owned()),
            config_generation: Some(7),
            public_url: Some("https://antoine.portless.io".to_owned()),
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
