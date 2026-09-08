use anyhow::{bail, Context, Result};
use std::{
    io,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    task::JoinHandle,
    time,
};

use crate::{tunnel::ensure_private_data_dir, ui::UiState};

const SOCKET_NAME: &str = "health.sock";
const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

pub struct HealthServer {
    task: JoinHandle<()>,
    path: PathBuf,
}

impl Drop for HealthServer {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

pub async fn start(data_dir: &Path, state: UiState) -> Result<HealthServer> {
    ensure_private_data_dir(data_dir).await?;
    let path = data_dir.join(SOCKET_NAME);
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
            if !fs::symlink_metadata(&path).await?.file_type().is_socket() {
                bail!("health socket path is not a socket");
            }
            match time::timeout(HEALTH_TIMEOUT, UnixStream::connect(&path)).await {
                Ok(Err(err)) if err.kind() == io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(&path)
                        .await
                        .context("remove stale health socket")?;
                }
                _ => bail!("health socket is already in use"),
            }
            UnixListener::bind(&path).context("bind replacement health socket")?
        }
        Err(err) => return Err(err).context("bind health socket"),
    };
    if let Err(err) = fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await {
        let _ = fs::remove_file(&path).await;
        return Err(err).context("restrict health socket permissions");
    }
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(err) => {
                    tracing::warn!(error = %err, "health socket stopped");
                    break;
                }
            };
            let _ = time::timeout(HEALTH_TIMEOUT, async {
                let response: &[u8] = if state.is_connected().await {
                    b"connected\n"
                } else {
                    b"unavailable\n"
                };
                stream.write_all(response).await
            })
            .await;
        }
    });
    Ok(HealthServer { task, path })
}

pub async fn check(data_dir: &Path) -> Result<()> {
    time::timeout(HEALTH_TIMEOUT, async {
        let stream = UnixStream::connect(data_dir.join(SOCKET_NAME))
            .await
            .context("connect daemon health socket")?;
        let mut response = Vec::new();
        stream
            .take(32)
            .read_to_end(&mut response)
            .await
            .context("read daemon health status")?;
        if response != b"connected\n" {
            bail!("daemon is not connected");
        }
        Ok(())
    })
    .await
    .context("daemon health check timed out")?
}
