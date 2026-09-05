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
            Ok(raw) => match serde_json::from_slice(&raw) {
                Ok(state) => Ok(state),
                Err(_) => {
                    // These fields are refreshed from control; identity files are not disposable.
                    tracing::warn!("invalid daemon state cache; rebuilding from control");
                    Ok(Self::default())
                }
            },
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
        write_private_file(&path, raw, "daemon state").await
    }
}

pub(crate) async fn write_private_file(
    path: &Path,
    contents: impl AsRef<[u8]>,
    label: &str,
) -> Result<()> {
    let path = path.to_owned();
    let contents = contents.as_ref().to_vec();
    // Complete the replace/cleanup even if the calling async task is cancelled.
    tokio::task::spawn_blocking(move || -> Result<()> {
        use std::{fs, io::Write};

        let parent = path
            .parent()
            .context("private file has no parent directory")?;
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)?;
        let temporary = parent.join(format!(
            ".portless-write-{:032x}.tmp",
            u128::from_ne_bytes(nonce)
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .context("create private temporary file")?;
        let result = (|| -> Result<()> {
            file.write_all(&contents)
                .context("write private temporary file")?;
            file.sync_all().context("sync private temporary file")?;
            drop(file);
            fs::rename(&temporary, &path).context("replace private file")?;
            #[cfg(unix)]
            fs::File::open(parent)?
                .sync_all()
                .context("sync private file directory")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    })
    .await
    .context("join private file write")?
    .with_context(|| format!("write {label}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn state_replacement_is_atomic_and_corrupt_cache_is_rebuilt() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("portless-state-test-{nonce}"));
        let mut state = DaemonState {
            tunnel_id: Some("old".to_owned()),
            ..Default::default()
        };
        state.save(&dir).await.unwrap();
        let path = dir.join("state.json");
        let mut old_file = fs::File::open(&path).await.unwrap();
        state.tunnel_id = Some("new".to_owned());
        state.save(&dir).await.unwrap();
        let mut old = Vec::new();
        old_file.read_to_end(&mut old).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<DaemonState>(&old)
                .unwrap()
                .tunnel_id
                .as_deref(),
            Some("old")
        );
        assert_eq!(
            DaemonState::load(&dir).await.unwrap().tunnel_id.as_deref(),
            Some("new")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).await.unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::write(&path, "{interrupted").await.unwrap();
        assert!(DaemonState::load(&dir).await.unwrap().tunnel_id.is_none());
        state.save(&dir).await.unwrap();
        assert_eq!(
            DaemonState::load(&dir).await.unwrap().tunnel_id.as_deref(),
            Some("new")
        );

        // A failed rename must clean up its temporary file, leaving the target intact.
        let blocked = dir.join("blocked");
        fs::create_dir(&blocked).await.unwrap();
        assert!(write_private_file(&blocked, b"new", "test").await.is_err());
        assert!(fs::metadata(&blocked).await.unwrap().is_dir());
        let mut files = fs::read_dir(&dir).await.unwrap();
        let mut count = 0;
        while let Some(entry) = files.next_entry().await.unwrap() {
            assert!(!entry
                .file_name()
                .to_string_lossy()
                .starts_with(".portless-write-"));
            count += 1;
        }
        assert_eq!(count, 2);
        fs::remove_dir_all(dir).await.unwrap();
    }
}
