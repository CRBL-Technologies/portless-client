mod config;
mod control;
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
    install_crypto_provider();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = Config::from_env()?;
    let ui_state = UiState::new(&cfg);
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
