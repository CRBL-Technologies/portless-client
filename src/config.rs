use anyhow::{anyhow, Context, Result};
use std::{env, path::PathBuf, time::Duration};
use url::Url;

#[derive(Clone, Debug)]
pub struct Config {
    pub device_token: String,
    pub pms_url: Url,
    pub control_url: Url,
    pub data_dir: PathBuf,
    pub keepalive_profile: KeepaliveProfile,
}

#[derive(Clone, Debug)]
pub enum KeepaliveProfile {
    Residential,
    Cellular,
    Conservative,
}

impl KeepaliveProfile {
    pub fn interval(&self) -> Duration {
        match self {
            Self::Residential => Duration::from_secs(20),
            Self::Cellular => Duration::from_secs(12),
            Self::Conservative => Duration::from_secs(30),
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let device_token = env::var("PORTLESS_DEVICE_TOKEN")
            .context("PORTLESS_DEVICE_TOKEN is required")?
            .trim()
            .to_owned();
        if device_token.is_empty() {
            return Err(anyhow!("PORTLESS_DEVICE_TOKEN is empty"));
        }

        let pms_url = parse_url("PORTLESS_PMS_URL", "http://plex:32400")?;
        let control_url = parse_url("PORTLESS_CONTROL_URL", "https://join.portless.io")?;
        let data_dir = PathBuf::from(
            env::var("PORTLESS_DATA_DIR").unwrap_or_else(|_| "/var/lib/portless".to_owned()),
        );
        let keepalive_profile = match env::var("PORTLESS_KEEPALIVE_PROFILE")
            .unwrap_or_else(|_| "residential".to_owned())
            .to_ascii_lowercase()
            .as_str()
        {
            "residential" => KeepaliveProfile::Residential,
            "cellular" => KeepaliveProfile::Cellular,
            "conservative" => KeepaliveProfile::Conservative,
            other => return Err(anyhow!("unknown PORTLESS_KEEPALIVE_PROFILE {other:?}")),
        };

        Ok(Self {
            device_token,
            pms_url,
            control_url,
            data_dir,
            keepalive_profile,
        })
    }
}

fn parse_url(key: &str, fallback: &str) -> Result<Url> {
    let raw = env::var(key).unwrap_or_else(|_| fallback.to_owned());
    Url::parse(raw.trim()).with_context(|| format!("parse {key}"))
}
