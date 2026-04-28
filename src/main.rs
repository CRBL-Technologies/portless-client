mod config;
mod control;
mod state;

use anyhow::Result;
use config::Config;
use control::ControlClient;
use state::DaemonState;
use tokio::time;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
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
    state.tunnel_id = Some(device.tunnel_id);
    state.subdomain = Some(device.subdomain);
    state.config_generation = Some(device.config_generation);
    state.relay_address = Some(device.relay_address);
    state.save(&cfg.data_dir).await?;

    warn!("QUIC/mTLS tunnel is not implemented in this Phase 0 daemon skeleton");
    wait_for_shutdown(cfg.keepalive_profile.interval()).await;
    Ok(())
}

async fn wait_for_shutdown(interval: std::time::Duration) {
    let mut tick = time::interval(interval);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                info!("daemon skeleton heartbeat");
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal received");
                return;
            }
        }
    }
}
