mod config;
mod control;
mod state;
mod tunnel;

use anyhow::Result;
use config::Config;
use control::ControlClient;
use state::DaemonState;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    install_crypto_provider();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = Config::from_env()?;
    let control = ControlClient::new(cfg.control_url.clone(), cfg.device_token.clone());

    info!(
        pms_url = %cfg.pms_url,
        control_url = %cfg.control_url,
        data_dir = %cfg.data_dir.display(),
        "starting portless daemon"
    );

    let trust = control.fetch_trust().await?;
    info!(trust_bytes = trust.pem.len(), "fetched trust bundle");

    let device = control.fetch_device_config().await?;
    info!(
        tunnel_id = %device.tunnel_id,
        subdomain = %device.subdomain,
        relay = %device.relay_address,
        config_generation = device.config_generation,
        "fetched device config"
    );

    let mut state = DaemonState::load(&cfg.data_dir).await?;
    state.tunnel_id = Some(device.tunnel_id.clone());
    state.subdomain = Some(device.subdomain.clone());
    state.config_generation = Some(device.config_generation);
    state.relay_address = Some(device.relay_address.clone());
    state.save(&cfg.data_dir).await?;
    let identity = tunnel::ensure_identity(&cfg, &control, &device, &trust).await?;

    tokio::select! {
        result = tunnel::run(cfg, device, identity) => result?,
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown signal received");
        }
    }
    Ok(())
}

fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
