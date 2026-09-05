use anyhow::{Context, Result};
use reqwest::{header, Client, Url};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
            .timeout(CONTROL_REQUEST_TIMEOUT)
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
            .timeout(CONTROL_REQUEST_TIMEOUT)
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
        self.http
            .post(url)
            .timeout(CONTROL_REQUEST_TIMEOUT)
            .header(header::AUTHORIZATION, &self.bearer)
            .json(&CertificateRequest {
                csr_pem,
                request_id,
            })
            .send()
            .await
            .context("request device certificate")?
            .error_for_status()
            .context("certificate response status")?
            .json()
            .await
            .context("decode certificate response")
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinSet,
        time,
    };

    #[tokio::test]
    async fn control_deadlines_cover_headers_and_body_decoding() {
        let mut cases = JoinSet::new();
        for endpoint in ["trust", "config", "certificate"] {
            for body_stall in [false, true] {
                cases.spawn(async move {
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let addr = listener.local_addr().unwrap();
                    let server = tokio::spawn(async move {
                        let (mut socket, _) = listener.accept().await.unwrap();
                        let mut buf = [0_u8; 4096];
                        assert!(socket.read(&mut buf).await.unwrap() > 0);
                        if body_stall {
                            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\n\r\n{")
                                .await.unwrap();
                        }
                        while let Ok(read) = socket.read(&mut buf).await {
                            if read == 0 { break; }
                        }
                    });
                    let control = ControlClient::new(Url::parse(&format!("http://{addr}")).unwrap(), "test-token".to_owned());
                    let request = async {
                        match endpoint {
                            "trust" => control.fetch_trust().await.map(|_| ()),
                            "config" => control.fetch_device_config().await.map(|_| ()),
                            _ => control.request_certificate("test-csr", "test-request").await.map(|_| ()),
                        }
                    };
                    let result = time::timeout(CONTROL_REQUEST_TIMEOUT + Duration::from_secs(5), request).await;
                    server.abort();
                    let _ = server.await;
                    let error = result.expect("control deadline must complete").unwrap_err();
                    assert!(error.chain().any(|cause| cause.downcast_ref::<reqwest::Error>().is_some_and(reqwest::Error::is_timeout)),
                        "{endpoint} body_stall={body_stall}: {error:#}");
                    let context = error.to_string();
                    assert_eq!(context.starts_with("decode"), body_stall, "{context}");
                });
            }
        }
        while let Some(result) = cases.join_next().await {
            result.unwrap();
        }
    }
}
