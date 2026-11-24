//! rustls server config: PEM loading, key-permission and expiry checks, TLS version floor,
//! optional client-certificate verification (mTLS).

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

use crate::config::{TlsMinVersion, TlsSection};

pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut rd =
        BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    let certs = rustls_pemfile::certs(&mut rd)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing {}", path.display()))?;
    if certs.is_empty() {
        bail!("{}: no certificates found", path.display());
    }
    Ok(certs)
}

fn load_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    check_key_permissions(path)?;
    let mut rd =
        BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    rustls_pemfile::private_key(&mut rd)
        .with_context(|| format!("parsing {}", path.display()))?
        .ok_or_else(|| anyhow!("{}: no private key found", path.display()))
}

/// Refuses keys readable by "other" users.
pub fn check_key_permissions(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o004 != 0 {
            bail!(
                "{} is world-readable (mode {:o}); use 0640 root:grep-cp",
                path.display(),
                mode & 0o777
            );
        }
    }
    Ok(())
}

/// `notAfter` of the first (leaf) certificate.
pub fn not_after(cert: &CertificateDer<'_>) -> anyhow::Result<DateTime<Utc>> {
    let (_, c) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| anyhow!("parsing certificate: {e}"))?;
    DateTime::<Utc>::from_timestamp(c.validity().not_after.timestamp(), 0)
        .ok_or_else(|| anyhow!("certificate notAfter out of range"))
}

pub struct Loaded {
    pub config: ServerConfig,
    pub not_after: DateTime<Utc>,
}

pub fn load(t: &TlsSection) -> anyhow::Result<Loaded> {
    let certs = load_certs(&t.cert)?;
    let key = load_key(&t.key)?;
    let not_after = not_after(&certs[0])?;
    if not_after <= Utc::now() {
        bail!("{}: certificate expired at {not_after}", t.cert.display());
    }

    let provider = provider();
    let versions: &[&'static rustls::SupportedProtocolVersion] = match t.min_version {
        TlsMinVersion::V12 => &[&rustls::version::TLS13, &rustls::version::TLS12],
        TlsMinVersion::V13 => &[&rustls::version::TLS13],
    };
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .context("TLS protocol versions")?;
    let builder = match &t.client_ca {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for c in load_certs(ca)? {
                roots.add(c).context("adding client CA")?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .context("building client verifier")?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };
    let mut config = builder
        .with_single_cert(certs, key)
        .context("certificate/key mismatch or unsupported key")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Loaded { config, not_after })
}
