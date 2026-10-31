//! Daemon key storage, certificate requests, and renewal timing.

use super::*;

pub(super) async fn ensure_identity(
    cfg: &Config,
    control: &ControlClient,
    device: &DeviceConfig,
    trust: &TrustBundle,
    force_refresh: bool,
) -> Result<TunnelIdentity> {
    ensure_private_data_dir(&cfg.data_dir).await?;
    let cert_path = cfg.data_dir.join(DEVICE_CERT_FILE);
    let trust_path = cfg.data_dir.join(TRUST_BUNDLE_FILE);

    let existing_key = read_device_key(&cfg.data_dir).await?;
    let existing_cert = match fs::read_to_string(&cert_path).await {
        Ok(raw) => Some(raw),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err).context("read daemon certificate"),
    };
    if !force_refresh {
        if let (Some(key_pem), Some(cert_pem)) = (&existing_key, &existing_cert) {
            if !certificate_needs_renewal(cert_pem, device) {
                if !fs::try_exists(cfg.data_dir.join(DEVICE_KEY_ENCRYPTED_FILE)).await? {
                    write_encrypted_device_key(&cfg.data_dir, key_pem).await?;
                }
                write_private_file(&trust_path, trust.pem.as_bytes(), "trust bundle").await?;
                return Ok(TunnelIdentity {
                    ca_pem: trust.pem.clone(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                });
            }
        }
    } else if existing_cert.is_some() {
        info!("cached daemon certificate was rejected; requesting replacement");
    }

    let key_pair = match existing_key {
        Some(raw) => KeyPair::from_pem(&raw).context("parse existing daemon key")?,
        None => KeyPair::generate().context("generate daemon key")?,
    };
    let key_pem = key_pair.serialize_pem();
    let csr_pem = device_csr_pem(device, &key_pair)?;
    let request_id = certificate_request_id(device, &key_pair);
    let issued = control
        .request_certificate(&csr_pem, &request_id)
        .await
        .context("request daemon certificate")?;
    write_identity_files(&cfg.data_dir, &key_pem, &issued, &trust.pem).await?;

    Ok(TunnelIdentity {
        ca_pem: trust.pem.clone(),
        cert_pem: issued.certificate_pem,
        key_pem,
    })
}

pub(super) fn parse_certs_pem(raw: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_slice_iter(raw.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse certificate PEM")?;
    if certs.is_empty() {
        bail!("certificate PEM did not contain any certificates");
    }
    Ok(certs)
}

pub(super) fn parse_private_key_pem(raw: &str) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(raw.as_bytes()).context("parse private key PEM")
}

pub(crate) async fn ensure_private_data_dir(data_dir: &Path) -> Result<()> {
    fs::create_dir_all(data_dir)
        .await
        .context("create daemon data dir")?;
    restrict_data_dir_permissions(data_dir).await?;
    repair_identity_permissions(data_dir).await
}

pub(super) async fn repair_identity_permissions(data_dir: &Path) -> Result<()> {
    for (filename, label) in [
        (DEVICE_KEY_SECRET_FILE, "daemon key secret"),
        (DEVICE_KEY_ENCRYPTED_FILE, "encrypted daemon key"),
        (DEVICE_KEY_PLAINTEXT_FILE, "plaintext daemon key"),
        (DEVICE_CERT_FILE, "daemon certificate"),
        (TRUST_BUNDLE_FILE, "trust bundle"),
    ] {
        let path = data_dir.join(filename);
        match restrict_file_permissions(&path, label).await {
            Ok(()) => {}
            Err(err) if is_not_found(&err) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

pub(super) async fn restrict_data_dir_permissions(data_dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700)).await {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                warn!(
                    path = %data_dir.display(),
                    error = %err,
                    "daemon data dir permissions could not be restricted; continuing because some Docker mounts disallow chmod"
                );
            }
            Err(err) => return Err(err).context("restrict daemon data dir permissions"),
        }
    }
    Ok(())
}

pub(super) async fn restrict_file_permissions(path: &Path, label: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .await
            .with_context(|| format!("restrict {label} permissions"))?;
    }
    Ok(())
}

pub(super) async fn read_device_key(data_dir: &Path) -> Result<Option<String>> {
    repair_identity_permissions(data_dir).await?;

    let encrypted_path = data_dir.join(DEVICE_KEY_ENCRYPTED_FILE);
    match fs::read_to_string(&encrypted_path).await {
        Ok(raw) => {
            let key = decrypt_device_key(data_dir, &raw).await?;
            remove_plaintext_device_key(data_dir).await?;
            return Ok(Some(key));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("read encrypted daemon key"),
    }

    let plaintext_path = data_dir.join(DEVICE_KEY_PLAINTEXT_FILE);
    match fs::read_to_string(&plaintext_path).await {
        Ok(raw) => Ok(Some(raw)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).context("read plaintext daemon key"),
    }
}

pub(super) async fn write_encrypted_device_key(data_dir: &Path, key_pem: &str) -> Result<()> {
    ensure_private_data_dir(data_dir).await?;
    let secret = read_or_create_device_key_secret(data_dir).await?;
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    fill_random(&mut salt)?;
    fill_random(&mut nonce)?;
    let key = derive_device_key(&secret, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| anyhow!("build daemon key cipher: invalid key length"))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: key_pem.as_bytes(),
                aad: DEVICE_KEY_AAD,
            },
        )
        .map_err(|_| anyhow!("encrypt daemon private key"))?;
    let envelope = EncryptedDeviceKey {
        version: 1,
        kdf: "argon2id".to_owned(),
        cipher: "aes-256-gcm".to_owned(),
        salt: BASE64_STANDARD.encode(salt),
        nonce: BASE64_STANDARD.encode(nonce),
        ciphertext: BASE64_STANDARD.encode(ciphertext),
    };
    let encoded = serde_json::to_string_pretty(&envelope).context("encode encrypted daemon key")?;
    write_private_file(
        &data_dir.join(DEVICE_KEY_ENCRYPTED_FILE),
        encoded,
        "encrypted daemon key",
    )
    .await?;
    remove_plaintext_device_key(data_dir).await
}

pub(super) async fn remove_plaintext_device_key(data_dir: &Path) -> Result<()> {
    match fs::remove_file(data_dir.join(DEVICE_KEY_PLAINTEXT_FILE)).await {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("remove plaintext daemon key"),
    }
    Ok(())
}

pub(super) async fn decrypt_device_key(data_dir: &Path, raw: &str) -> Result<String> {
    let secret = read_device_key_secret(data_dir).await?;
    let envelope: EncryptedDeviceKey =
        serde_json::from_str(raw).context("decode encrypted daemon key")?;
    if envelope.version != 1 || envelope.kdf != "argon2id" || envelope.cipher != "aes-256-gcm" {
        bail!("unsupported encrypted daemon key envelope");
    }
    let salt = BASE64_STANDARD
        .decode(envelope.salt)
        .context("decode daemon key salt")?;
    let nonce = BASE64_STANDARD
        .decode(envelope.nonce)
        .context("decode daemon key nonce")?;
    let ciphertext = BASE64_STANDARD
        .decode(envelope.ciphertext)
        .context("decode daemon key ciphertext")?;
    let key = derive_device_key(&secret, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| anyhow!("build daemon key cipher: invalid key length"))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext.as_ref(),
                aad: DEVICE_KEY_AAD,
            },
        )
        .map_err(|_| anyhow!("decrypt daemon private key"))?;
    String::from_utf8(plaintext).context("daemon private key is not UTF-8")
}

pub(super) async fn read_or_create_device_key_secret(data_dir: &Path) -> Result<Vec<u8>> {
    if let Ok(raw) = std::env::var(DEVICE_KEY_SECRET_ENV) {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            bail!("{DEVICE_KEY_SECRET_ENV} is empty");
        }
        return Ok(trimmed.as_bytes().to_vec());
    }

    match read_device_key_secret(data_dir).await {
        Ok(secret) => Ok(secret),
        Err(err) if is_not_found(&err) => {
            let mut secret = [0_u8; 32];
            fill_random(&mut secret)?;
            let path = data_dir.join(DEVICE_KEY_SECRET_FILE);
            write_secret_file(&path, &secret).await?;
            Ok(secret.to_vec())
        }
        Err(err) => Err(err),
    }
}

pub(super) async fn read_device_key_secret(data_dir: &Path) -> Result<Vec<u8>> {
    if let Ok(raw) = std::env::var(DEVICE_KEY_SECRET_ENV) {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            bail!("{DEVICE_KEY_SECRET_ENV} is empty");
        }
        return Ok(trimmed.as_bytes().to_vec());
    }

    let path = data_dir.join(DEVICE_KEY_SECRET_FILE);
    let raw = fs::read(&path).await.context("read daemon key secret")?;
    let trimmed = String::from_utf8_lossy(&raw).trim().to_owned();
    if trimmed.is_empty() {
        bail!("daemon key secret is empty");
    }
    BASE64_STANDARD
        .decode(trimmed)
        .context("decode daemon key secret")
}

pub(super) async fn write_secret_file(path: &Path, secret: &[u8]) -> Result<()> {
    write_private_file(path, BASE64_STANDARD.encode(secret), "daemon key secret").await
}

pub(super) fn derive_device_key(secret: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|err| anyhow!("build Argon2id params: {err}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; 32];
    argon2
        .hash_password_into(secret, salt, &mut key)
        .map_err(|err| anyhow!("derive daemon key encryption key: {err}"))?;
    Ok(key)
}

pub(super) fn is_not_found(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
    })
}

pub(super) fn device_csr_pem(device: &DeviceConfig, key_pair: &KeyPair) -> Result<String> {
    let mut params = CertificateParams::new(vec![device.subdomain.clone()])
        .context("build daemon certificate parameters")?;
    params
        .distinguished_name
        .push(DnType::CommonName, device.tunnel_id.clone());
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    params
        .serialize_request(key_pair)
        .context("serialize daemon CSR")?
        .pem()
        .context("encode daemon CSR PEM")
}

pub(super) fn certificate_needs_renewal(cert_pem: &str, device: &DeviceConfig) -> bool {
    let Ok(certs) = parse_certs_pem(cert_pem) else {
        return true;
    };
    let Some(leaf) = certs.first() else {
        return true;
    };
    let Ok((_, cert)) = X509Certificate::from_der(leaf.as_ref()) else {
        return true;
    };
    if !certificate_matches_device(&cert, device) {
        info!(
            tunnel_id = %device.tunnel_id,
            subdomain = %device.subdomain,
            "cached daemon certificate identity does not match device config; requesting replacement"
        );
        return true;
    }
    seconds_until_certificate_renewal(&cert, device) <= 0
}

pub(super) fn certificate_renewal_delay(cert_pem: &str, device: &DeviceConfig) -> Duration {
    let Ok(certs) = parse_certs_pem(cert_pem) else {
        return Duration::ZERO;
    };
    let Some(leaf) = certs.first() else {
        return Duration::ZERO;
    };
    let Ok((_, cert)) = X509Certificate::from_der(leaf.as_ref()) else {
        return Duration::ZERO;
    };
    if !certificate_matches_device(&cert, device) {
        return Duration::ZERO;
    }
    let seconds = seconds_until_certificate_renewal(&cert, device);
    if seconds <= 0 {
        Duration::ZERO
    } else {
        Duration::from_secs(seconds as u64)
    }
}

pub(super) fn seconds_until_certificate_renewal(
    cert: &X509Certificate<'_>,
    device: &DeviceConfig,
) -> i64 {
    seconds_until_certificate_expiry(cert) - renewal_threshold_seconds(&device.tunnel_id)
}

pub(super) fn seconds_until_certificate_expiry(cert: &X509Certificate<'_>) -> i64 {
    cert.validity()
        .not_after
        .timestamp()
        .saturating_sub(now_unix_seconds())
}

pub(super) fn certificate_request_id(device: &DeviceConfig, key_pair: &KeyPair) -> String {
    certificate_request_id_at(device, key_pair, now_unix_seconds())
}

pub(super) fn certificate_request_id_at(
    device: &DeviceConfig,
    key_pair: &KeyPair,
    unix_seconds: i64,
) -> String {
    let key_fingerprint = certificate_request_key_fingerprint(key_pair);
    format!(
        "{}-{}-h{}-k{}",
        device.tunnel_id,
        device.config_generation,
        unix_seconds.div_euclid(60 * 60),
        key_fingerprint,
    )
}

pub(super) fn certificate_request_key_fingerprint(key_pair: &KeyPair) -> String {
    let digest = Sha256::digest(key_pair.public_key_der());
    hex_prefix(&digest, 8)
}

pub(super) fn hex_prefix(bytes: &[u8], len: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let max = len.min(bytes.len());
    let mut out = String::with_capacity(max * 2);
    for byte in &bytes[..max] {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(super) fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub(super) fn certificate_matches_device(
    cert: &X509Certificate<'_>,
    device: &DeviceConfig,
) -> bool {
    let common_name_matches = cert.subject().iter_common_name().any(|name| {
        name.as_str()
            .map(|value| value == device.tunnel_id)
            .unwrap_or(false)
    });
    if !common_name_matches {
        return false;
    }

    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return false;
    };
    let expected_spiffe = format!("spiffe://portless.io/tunnel/{}", device.tunnel_id);
    let dns_matches = san.value.general_names.iter().any(|name| match name {
        GeneralName::DNSName(value) => *value == device.subdomain,
        _ => false,
    });
    let spiffe_matches = san.value.general_names.iter().any(|name| match name {
        GeneralName::URI(value) => *value == expected_spiffe,
        _ => false,
    });
    dns_matches && spiffe_matches
}

pub(super) fn renewal_threshold_seconds(tunnel_id: &str) -> i64 {
    let mut hasher = DefaultHasher::new();
    tunnel_id.hash(&mut hasher);
    let jitter = (hasher.finish() % (2 * 60 * 60)) as i64;
    (16 * 60 * 60) + jitter
}

pub(super) async fn write_identity_files(
    data_dir: &Path,
    key_pem: &str,
    issued: &CertificateResponse,
    trust_pem: &str,
) -> Result<()> {
    write_encrypted_device_key(data_dir, key_pem).await?;
    write_private_file(
        &data_dir.join(DEVICE_CERT_FILE),
        issued.certificate_pem.as_bytes(),
        "daemon certificate",
    )
    .await?;
    write_private_file(
        &data_dir.join(TRUST_BUNDLE_FILE),
        trust_pem.as_bytes(),
        "trust bundle",
    )
    .await?;
    Ok(())
}
