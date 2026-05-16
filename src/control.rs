use std::{error::Error, fmt};

use anyhow::{Context, Result};
use reqwest::{header, Client, StatusCode, Url};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct ControlClient {
    http: Client,
    base: Url,
    bearer: String,
}

impl ControlClient {
    pub fn new(base: Url, device_token: String) -> Self {
        Self {
            http: Client::new(),
            base,
            bearer: format!("Bearer {device_token}"),
        }
    }

    pub async fn fetch_trust(&self) -> Result<TrustBundle> {
        let url = self.base.join("/v1/trust").context("build trust URL")?;
        self.http
            .get(url)
            .send()
            .await
            .context("fetch trust bundle")?
            .error_for_status()
            .context("trust bundle status")?
            .json()
            .await
            .context("decode trust bundle")
    }

    pub async fn fetch_device_config(&self) -> Result<DeviceConfig> {
        let url = self
            .base
            .join("/v1/device/config")
            .context("build config URL")?;
        self.http
            .get(url)
            .header(header::AUTHORIZATION, &self.bearer)
            .send()
            .await
            .context("fetch device config")?
            .error_for_status()
            .context("device config status")?
            .json()
            .await
            .context("decode device config")
    }

    pub async fn request_certificate(
        &self,
        csr_pem: &str,
        request_id: &str,
    ) -> Result<CertificateResponse> {
        let url = self
            .base
            .join("/v1/device/certificates")
            .context("build certificate URL")?;
        let response = self
            .http
            .post(url)
            .header(header::AUTHORIZATION, &self.bearer)
            .json(&CertificateRequest {
                csr_pem,
                request_id,
            })
            .send()
            .await
            .context("request device certificate")?;
        if response.status() == StatusCode::CONFLICT {
            return Err(CertificateReplayConflict.into());
        }
        response
            .error_for_status()
            .context("certificate response status")?
            .json()
            .await
            .context("decode certificate response")
    }
}

#[derive(Debug)]
pub struct CertificateReplayConflict;

impl fmt::Display for CertificateReplayConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("certificate request was superseded")
    }
}

impl Error for CertificateReplayConflict {}

#[derive(Debug, Deserialize, Serialize)]
pub struct TrustBundle {
    pub pem: String,
    pub generated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceConfig {
    pub tunnel_id: String,
    pub subdomain: String,
    pub relay_address: String,
    #[serde(default)]
    pub public_url: Option<String>,
    pub control_url: String,
    pub config_generation: i64,
    pub keepalive_profile: String,
    pub monthly_bytes_used: i64,
    pub monthly_byte_limit: i64,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
struct CertificateRequest<'a> {
    csr_pem: &'a str,
    request_id: &'a str,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CertificateResponse {
    pub certificate_pem: String,
    pub chain_pem: String,
    pub expires_at: String,
}
