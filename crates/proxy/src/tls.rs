//! TLS interception: CA generation/persistence, on-demand leaf signing, SNI resolution.
//!
//! Built on API shapes verified against the compiler in `docs/TLS-RESEARCH.md` (rcgen 0.14.8 /
//! rustls 0.23.42), including real TLS handshakes through webpki path validation.
//!
//! # Two design points worth knowing
//!
//! **The SNI fallback must be per-connection.** rustls correctly omits SNI for IP-literal
//! connections, so `ClientHello::server_name()` is `None` for `CONNECT 1.2.3.4:443`. A single global
//! resolver with a fixed fallback would mint the wrong certificate for every such connection. So
//! [`TlsEngine::resolver_for`] hands out a cheap per-CONNECT resolver that closes over the right
//! fallback, while all of them share one leaf cache.
//!
//! **Exact per-host leaves, not wildcards.** Measured against webpki: `*.example.test` covers
//! `a.example.test` but neither `a.b.example.test` nor the apex `example.test`. Minting exact leaves
//! avoids three classes of silent handshake failure.

use anyhow::{Context, Result};
use parking_lot::RwLock;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
};
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

/// Leaf validity. Chrome's 398-day cap applies only to publicly-trusted CAs — Chromium's
/// `certificate_lifetimes.md` states it "will not apply to locally-operated CAs that have been
/// manually configured". 397 days is still used: it's free, matches Burp and mitmproxy, and is
/// immune to future tightening.
pub const MAX_LEAF_DAYS: i64 = 397;
const CA_VALID_DAYS: i64 = 3650;

/// A loaded certificate authority.
#[derive(Debug)]
pub struct CertAuthority {
    /// Owns its params, hence `'static`.
    pub issuer: Issuer<'static, KeyPair>,
    /// DER of the CA cert, appended to leaf chains and exported for the trust store.
    pub cert_der: CertificateDer<'static>,
    /// PEM of the CA cert, served at `/ca.crt`.
    pub cert_pem: String,
}

/// Generate a fresh self-signed CA. Returns the CA plus both PEMs to persist.
///
/// Extension set is what Windows/Chrome/Firefox require of a root:
/// `basicConstraints critical CA:TRUE, pathlen:0` and `keyUsage critical keyCertSign, cRLSign`.
/// Deliberately **no EKU on the root** — Windows interprets an EKU there as a constraint.
pub fn generate_ca(common_name: &str) -> Result<(CertAuthority, String, String)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn.push(DnType::OrganizationName, common_name);

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(CA_VALID_DAYS);

    let cert = params.self_signed(&key)?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();
    let cert_der = cert.der().clone();

    Ok((
        CertAuthority {
            issuer: Issuer::new(params, key),
            cert_der,
            cert_pem: cert_pem.clone(),
        },
        cert_pem,
        key_pem,
    ))
}

/// Reload a CA from the two PEMs written by [`generate_ca`].
///
/// `Issuer::from_ca_cert_pem` reconstructs DN, key usages and key-id method by parsing the stored
/// certificate, so the two PEM files are the entire persisted state — no need to serialise params.
/// This requires rcgen's `x509-parser` feature.
pub fn load_ca_pem(cert_pem: &str, key_pem: &str) -> Result<CertAuthority> {
    let key = KeyPair::from_pem(key_pem).context("parsing CA key PEM")?;
    let issuer = Issuer::from_ca_cert_pem(cert_pem, key).context("parsing CA cert PEM")?;
    let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .context("no CERTIFICATE block in CA PEM")??;
    Ok(CertAuthority {
        issuer,
        cert_der,
        cert_pem: cert_pem.to_string(),
    })
}

/// Default CA directory: `~/.burpsy`.
pub fn default_ca_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".burpsy")
}

/// Load the CA from `dir`, generating and persisting it on first run.
///
/// The key is written 0600. A regenerated CA would invalidate a trust-store install, so an existing
/// pair is always preferred over minting a new one.
pub fn load_or_generate_ca(dir: &Path) -> Result<CertAuthority> {
    let cert_path = dir.join("ca.pem");
    let key_path = dir.join("ca.key");

    if cert_path.is_file() && key_path.is_file() {
        let cert_pem = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("read {}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(&key_path)
            .with_context(|| format!("read {}", key_path.display()))?;
        tracing::info!("loaded CA from {}", cert_path.display());
        return load_ca_pem(&cert_pem, &key_pem);
    }

    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let (ca, cert_pem, key_pem) = generate_ca("burpsy CA")?;
    std::fs::write(&cert_path, &cert_pem)?;
    std::fs::write(&key_path, &key_pem)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o644))?;
    }

    tracing::info!("generated new CA at {}", cert_path.display());
    Ok(ca)
}

/// Mint a leaf for `host`, which may be a DNS name or a bare IP literal.
fn mint_leaf(
    ca: &CertAuthority,
    host: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    let san = match IpAddr::from_str(host) {
        Ok(ip) => SanType::IpAddress(ip),
        Err(_) => SanType::DnsName(host.to_string().try_into()?),
    };

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, host);

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.subject_alt_names = vec![san];
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    // rcgen defaults this to false; browsers want an AKI on the leaf.
    params.use_authority_key_identifier_extension = true;
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(MAX_LEAF_DAYS);

    let leaf = params.signed_by(&key, &ca.issuer)?;

    // leaf first, then the CA: Firefox imports only *roots* from the Windows store and expects the
    // server to supply the rest of the path.
    let chain = vec![leaf.der().clone(), ca.cert_der.clone()];
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    Ok((chain, key_der))
}

type LeafCache = Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>;

/// Owns the CA and the shared leaf cache; hands out per-connection resolvers.
#[derive(Debug)]
pub struct TlsEngine {
    ca: Arc<CertAuthority>,
    provider: Arc<CryptoProvider>,
    cache: LeafCache,
}

impl TlsEngine {
    pub fn new(ca: CertAuthority) -> Self {
        // Explicit provider even though the graph is aws-lc-rs-only today: if a future dependency
        // enables rustls/ring, `builder()` would panic at runtime rather than fail to compile.
        let provider = CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        Self {
            ca: Arc::new(ca),
            provider,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca.cert_pem
    }

    pub fn cached_leaves(&self) -> usize {
        self.cache.read().len()
    }

    /// A resolver for one CONNECT, whose fallback is the authority from that CONNECT line.
    pub fn resolver_for(&self, fallback_host: &str) -> Arc<SniResolver> {
        Arc::new(SniResolver {
            ca: self.ca.clone(),
            provider: self.provider.clone(),
            cache: self.cache.clone(),
            fallback: fallback_host.to_string(),
        })
    }

    /// `ServerConfig` offering only `http/1.1` — h2 needs a framing layer to stay byte-honest.
    pub fn server_config(&self, fallback_host: &str) -> rustls::ServerConfig {
        let resolver = self.resolver_for(fallback_host);
        let mut cfg = rustls::ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        cfg
    }
}

/// Mints a leaf per SNI hostname on demand, caching across connections.
#[derive(Debug)]
pub struct SniResolver {
    ca: Arc<CertAuthority>,
    provider: Arc<CryptoProvider>,
    cache: LeafCache,
    /// Used when the ClientHello carries no SNI (raw-IP CONNECT).
    fallback: String,
}

impl SniResolver {
    pub fn certified_key(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        if let Some(hit) = self.cache.read().get(host) {
            return Ok(hit.clone());
        }
        let (chain, key) = mint_leaf(&self.ca, host)?;
        let ck = Arc::new(CertifiedKey::from_der(chain, key, &self.provider)?);
        self.cache.write().insert(host.to_string(), ck.clone());
        Ok(ck)
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = client_hello
            .server_name()
            .map(str::to_owned)
            .unwrap_or_else(|| self.fallback.clone());
        match self.certified_key(&host) {
            Ok(ck) => Some(ck),
            Err(e) => {
                tracing::warn!("leaf mint failed for {host}: {e}");
                None
            }
        }
    }
}

/// Client config for the *upstream* leg of an intercepted connection.
///
/// Certificate verification is deliberately disabled: a testing proxy must reach staging hosts with
/// self-signed, expired or mismatched certs, and refusing them would make the tool useless for most
/// real work. The security boundary here is that burpsy is an explicit local proxy the operator
/// pointed their own browser at — not a transparent MITM on someone else's traffic.
pub fn upstream_client_config() -> Arc<rustls::ClientConfig> {
    use rustls::DigitallySignedStruct;
    use rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use rustls_pki_types::{ServerName, UnixTime};

    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _e: &CertificateDer<'_>,
            _i: &[CertificateDer<'_>],
            _s: &ServerName<'_>,
            _o: &[u8],
            _n: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            use rustls::SignatureScheme::*;
            vec![
                RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384,
                RSA_PKCS1_SHA512,
                ECDSA_NISTP256_SHA256,
                ECDSA_NISTP384_SHA384,
                RSA_PSS_SHA256,
                RSA_PSS_SHA384,
                RSA_PSS_SHA512,
                ED25519,
            ]
        }
    }

    let provider = CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    // Match what we offer the client, so we never bridge h2 downstream to http/1.1 upstream.
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_config_offers_http11_only() {
        let c = upstream_client_config();
        assert_eq!(c.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn generates_and_reloads_ca() {
        let (ca, cert_pem, key_pem) = generate_ca("test CA").unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(!ca.cert_der.is_empty());
        // Reload must produce a working issuer, since the two PEMs are the whole persisted state.
        let reloaded = load_ca_pem(&cert_pem, &key_pem).unwrap();
        assert_eq!(reloaded.cert_der, ca.cert_der);
        let (chain, _k) = mint_leaf(&reloaded, "reload.test").unwrap();
        assert_eq!(chain.len(), 2, "chain must be leaf + CA");
    }

    #[test]
    fn persists_and_reuses_ca_across_runs() {
        let dir = std::env::temp_dir().join(format!("burpsy-ca-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = load_or_generate_ca(&dir).unwrap();
        let b = load_or_generate_ca(&dir).unwrap();
        // Regenerating would invalidate any trust-store install.
        assert_eq!(a.cert_der, b.cert_der, "second run must reuse the CA");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(dir.join("ca.key")).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o600, "key must be 0600");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mints_dns_and_ip_leaves() {
        let (ca, _, _) = generate_ca("t").unwrap();
        let (dns, _) = mint_leaf(&ca, "host.example.test").unwrap();
        assert_eq!(dns.len(), 2);
        // IP literal must work too: CONNECT 1.2.3.4:443 carries no SNI.
        let (ip, _) = mint_leaf(&ca, "10.1.2.3").unwrap();
        assert_eq!(ip.len(), 2);
    }

    #[test]
    fn leaf_cache_is_shared_but_fallback_is_per_connection() {
        let (ca, _, _) = generate_ca("t").unwrap();
        let eng = TlsEngine::new(ca);

        let r1 = eng.resolver_for("1.1.1.1");
        let r2 = eng.resolver_for("2.2.2.2");
        assert_ne!(r1.fallback, r2.fallback, "fallback must differ per CONNECT");

        // Same host through different resolvers is one cache entry and the same Arc.
        let a = r1.certified_key("shared.test").unwrap();
        let b = r2.certified_key("shared.test").unwrap();
        assert!(Arc::ptr_eq(&a, &b), "cache must be shared across resolvers");
        assert_eq!(eng.cached_leaves(), 1);

        // Distinct hosts get distinct leaves.
        r1.certified_key("other.test").unwrap();
        assert_eq!(eng.cached_leaves(), 2);
    }

    #[test]
    fn server_config_offers_only_http11() {
        let (ca, _, _) = generate_ca("t").unwrap();
        let eng = TlsEngine::new(ca);
        let cfg = eng.server_config("fallback.test");
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
