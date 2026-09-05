mod config;
mod control;
#[cfg(unix)]
mod health;
mod state;
mod tunnel;
mod ui;

use anyhow::Result;
use config::Config;
use control::ControlClient;
use tracing::info;
use ui::UiState;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    if let Some(command) = args.next() {
        if command != "healthcheck" || args.next().is_some() {
            anyhow::bail!("usage: portless-daemon [healthcheck]");
        }
        #[cfg(unix)]
        return health::check(&config::data_dir()).await;
        #[cfg(not(unix))]
        anyhow::bail!("healthcheck requires Unix domain sockets");
    }
    install_crypto_provider();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = Config::from_env()?;
    let ui_state = UiState::new(&cfg);
    #[cfg(unix)]
    let _health_server = health::start(&cfg.data_dir, ui_state.clone()).await?;
    if let Some(addr) = cfg.ui_addr {
        tokio::spawn(ui::serve(addr, ui_state.clone()));
    }
    let control = ControlClient::new(cfg.control_url.clone(), cfg.device_token.clone());

    info!(
        pms_url = %cfg.pms_url,
        control_url = %cfg.control_url,
        data_dir = %cfg.data_dir.display(),
        "starting portless daemon"
    );

    let context = tunnel::load_tunnel_context(&cfg, &control, &ui_state).await?;

    tokio::select! {
        result = tunnel::run(cfg, control, context, ui_state.clone()) => result?,
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown signal received");
        }
    }
    Ok(())
}

fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
