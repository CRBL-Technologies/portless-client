use anyhow::{anyhow, Context, Result};
use std::{env, net::SocketAddr, path::PathBuf};
use url::Url;

#[derive(Clone, Debug)]
pub struct Config {
    pub device_token: String,
    pub pms_url: Url,
    pub control_url: Url,
    pub data_dir: PathBuf,
    pub keepalive_profile: KeepaliveProfile,
    pub ui_addr: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
pub enum KeepaliveProfile {
    Residential,
    Cellular,
    Conservative,
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
        let ui_addr = parse_ui_addr()?;

        Ok(Self {
            device_token,
            pms_url,
            control_url,
            data_dir,
            keepalive_profile,
            ui_addr,
        })
    }
}

fn parse_url(key: &str, fallback: &str) -> Result<Url> {
    let raw = env::var(key).unwrap_or_else(|_| fallback.to_owned());
    Url::parse(raw.trim()).with_context(|| format!("parse {key}"))
}

fn parse_ui_addr() -> Result<Option<SocketAddr>> {
    let raw = env::var("PORTLESS_UI_ADDR").unwrap_or_else(|_| "127.0.0.1:43180".to_owned());
    let raw = raw.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("off") || raw.eq_ignore_ascii_case("disabled") {
        return Ok(None);
    }
    raw.parse()
        .map(Some)
        .with_context(|| "parse PORTLESS_UI_ADDR")
}
