use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct DaemonState {
    pub tunnel_id: Option<String>,
    pub subdomain: Option<String>,
    pub config_generation: Option<i64>,
    pub relay_address: Option<String>,
}

impl DaemonState {
    pub async fn load(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("state.json");
        match fs::read(&path).await {
            Ok(raw) => serde_json::from_slice(&raw).context("decode daemon state"),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err).context("read daemon state"),
        }
    }

    pub async fn save(&self, data_dir: &Path) -> Result<()> {
        fs::create_dir_all(data_dir)
            .await
            .context("create data dir")?;
        let path = data_dir.join("state.json");
        let raw = serde_json::to_vec_pretty(self).context("encode daemon state")?;
        fs::write(path, raw).await.context("write daemon state")
    }
}
