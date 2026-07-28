//! TLS interception: CA generation/persistence, on-demand leaf signing, SNI resolution, and the ALPN
//! decision that decides which protocol an intercepted connection speaks.
//!
//! Built on API shapes verified against the compiler in `docs/TLS-RESEARCH.md` (rcgen 0.14.8 /
//! rustls 0.23.42), including real TLS handshakes through webpki path validation.
//!
//! # Three design points worth knowing
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
//!
//! **ALPN is decided once, from the client's own offer, and never bridged.** See [`alpn_offer`] and
//! [`negotiated_protocol`]. The proxy offers upstream what the client offered it, adopts whatever the
//! target picked, and then offers the client exactly that one protocol — so the two legs always carry
//! the same protocol. What this does *not* do is forward HTTP/2: see [`alpn_offer`]'s note.

use anyhow::{Context, Result};
use burpsy_core::Protocol;
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

/// The two ALPN identifiers this proxy can classify, RFC 9113 §3.1 and RFC 7301.
pub const ALPN_H2: &[u8] = b"h2";
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// An ALPN value the proxy cannot classify, so it will not carry the connection.
///
/// Carries the octets rather than a message: an operator debugging why a connection was refused needs
/// to see what the target actually selected, and a lossy `String` conversion of a protocol identifier
/// is how "the target picked something odd" becomes unanswerable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownAlpn(pub Vec<u8>);

impl std::fmt::Display for UnknownAlpn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "target negotiated ALPN {:?} ({:02X?}), which this proxy cannot carry",
            String::from_utf8_lossy(&self.0),
            self.0
        )
    }
}

impl std::error::Error for UnknownAlpn {}

/// What to offer the target, given the client's own ALPN offer.
///
/// # Why the client's offer and not the target's
///
/// The obvious design — dial the target, learn what it supports, then decide — cannot work. The
/// fallback case ("the target also offered `http/1.1`, so use that") needs to know whether the client
/// would accept `http/1.1`, and that is unknowable until the ClientHello has been read; by then the
/// client-facing `ServerConfig` is already committed and rustls has sent a fatal
/// `NoApplicationProtocol` alert. So the order is: peek the ClientHello, offer the target the
/// client's own list, adopt the answer. That also keeps a client that aborts the handshake — usually
/// because the burpsy CA is not installed yet — costing zero upstream connections, which the
/// dial-first ordering would not.
///
/// # The interception switch
///
/// **With a hold queue attached, only `http/1.1` is offered.** Interception works by reading one
/// request, parking it, and forwarding the bytes an operator approved; that is an HTTP/1 message
/// parser, and it has no HTTP/2 equivalent here. Mirroring an h2-capable target's choice
/// unconditionally would therefore make most of the web silently uninterceptable — a shipped
/// capability turning conditionally false while the checkbox still says it is on. Downgrading instead
/// keeps interception working, and the downgrade is caused by an operator switch rather than by the
/// target, which is the difference H2-04 turns on: it forbids *silently* downgrading.
///
/// # What this does not do
///
/// It does not forward HTTP/2. With no hold queue and an h2-capable target, `h2` is genuinely
/// negotiated on both legs and the connection is then **recorded and closed**, because the frame
/// tap and the two-leg h2 driver are later slices. That is a stated gap, visible in history as an
/// exchange whose `protocol` is `Http2` and whose notes say so — not a silent downgrade, and not a
/// silent success either.
///
/// Unrecognised identifiers are dropped from the offer rather than mirrored: offering the target a
/// protocol this proxy cannot classify invites it to select one, and there is nothing honest to do
/// with the resulting connection. A client offering nothing gets nothing offered on its behalf, so
/// the absence of ALPN is mirrored as an absence.
pub fn alpn_offer(client_offer: &[Vec<u8>], interception_enabled: bool) -> Vec<Vec<u8>> {
    if client_offer.is_empty() {
        return Vec::new();
    }
    if interception_enabled {
        // Only if the client is willing: an h2-only client cannot be served while the queue is on,
        // and returning an empty offer is what lets the caller record that refusal with a reason
        // rather than emitting an opaque handshake alert.
        return client_offer
            .iter()
            .filter(|p| p.as_slice() == ALPN_HTTP11)
            .cloned()
            .collect();
    }
    client_offer
        .iter()
        .filter(|p| matches!(p.as_slice(), ALPN_H2 | ALPN_HTTP11))
        .cloned()
        .collect()
}

/// The protocol a negotiated ALPN value names.
///
/// `None` — no ALPN extension in the server's reply — is [`Protocol::Http1`], and that is a fact
/// rather than an assumption: a server that does not negotiate ALPN is going to speak HTTP/1.1 over
/// the connection. It is the case the project's own `e2e-tls.sh` exercises on every run, since its
/// Python origin sets no ALPN at all. Treating the absence as "assume h2" would break that gate and
/// every plain TLS origin with it.
///
/// Anything else is refused rather than guessed at, in line with the rest of the codebase: an
/// identifier we cannot classify is one we cannot record truthfully, and recording it as HTTP/1
/// because that is the more common answer is exactly the silent-downgrade H2-04 forbids.
pub fn negotiated_protocol(alpn: Option<&[u8]>) -> Result<Protocol, UnknownAlpn> {
    match alpn {
        None | Some(ALPN_HTTP11) => Ok(Protocol::Http1),
        Some(ALPN_H2) => Ok(Protocol::Http2),
        Some(other) => Err(UnknownAlpn(other.to_vec())),
    }
}

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

    /// `ServerConfig` for the client-facing leg, offering exactly `alpn`.
    ///
    /// The caller passes the **one** protocol the target already negotiated, or nothing when the
    /// target negotiated no ALPN at all. Offering a list here would let the client pick a second time
    /// and land on a different answer from the upstream leg, which is precisely the bridge this proxy
    /// must never build: an h2 client leg over an HTTP/1.1 upstream leg means re-encoding every
    /// message between two protocols with different framing, header representation and multiplexing.
    pub fn server_config(&self, fallback_host: &str, alpn: &[Vec<u8>]) -> rustls::ServerConfig {
        let resolver = self.resolver_for(fallback_host);
        let mut cfg = rustls::ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        cfg.alpn_protocols = alpn.to_vec();
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

/// Client config for the *upstream* leg of an intercepted connection, offering `alpn`.
///
/// The offer comes from [`alpn_offer`] — the client's own list, filtered — so the target chooses from
/// exactly what the client was willing to speak. An empty slice offers no ALPN extension at all,
/// which is how a client that sent none is mirrored.
///
/// Certificate verification is deliberately disabled: a testing proxy must reach staging hosts with
/// self-signed, expired or mismatched certs, and refusing them would make the tool useless for most
/// real work. The security boundary here is that burpsy is an explicit local proxy the operator
/// pointed their own browser at — not a transparent MITM on someone else's traffic.
pub fn upstream_client_config(alpn: &[Vec<u8>]) -> Arc<rustls::ClientConfig> {
    use rustls::DigitallySignedStruct;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
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
    cfg.alpn_protocols = alpn.to_vec();
    Arc::new(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ALPN identifiers are `&[u8]` constants and rustls wants owned vectors; this is only that.
    fn owned(v: &[u8]) -> Vec<u8> {
        v.to_vec()
    }

    #[test]
    fn a_config_offers_exactly_the_alpn_it_was_given() {
        let c = upstream_client_config(&[owned(ALPN_H2), owned(ALPN_HTTP11)]);
        assert_eq!(c.alpn_protocols, vec![owned(ALPN_H2), owned(ALPN_HTTP11)]);
        // An empty offer means no ALPN extension, which is how a client that sent none is mirrored.
        assert!(upstream_client_config(&[]).alpn_protocols.is_empty());
    }

    #[test]
    fn the_upstream_offer_mirrors_the_clients_own_list_in_the_clients_order() {
        // Mirroring, not preference: the client decided what it wanted, and reordering here would
        // make the proxy's own taste decide which protocol a target picks.
        assert_eq!(
            alpn_offer(&[owned(ALPN_H2), owned(ALPN_HTTP11)], false),
            vec![owned(ALPN_H2), owned(ALPN_HTTP11)]
        );
        assert_eq!(
            alpn_offer(&[owned(ALPN_HTTP11), owned(ALPN_H2)], false),
            vec![owned(ALPN_HTTP11), owned(ALPN_H2)]
        );
        // A client that sent no ALPN extension gets none sent on its behalf.
        assert!(alpn_offer(&[], false).is_empty());
        // Identifiers this proxy cannot classify are dropped rather than mirrored: offering one
        // invites the target to select it, and there is nothing honest to do with the result.
        assert_eq!(
            alpn_offer(&[owned(b"spdy/3.1"), owned(ALPN_HTTP11)], false),
            vec![owned(ALPN_HTTP11)]
        );
    }

    #[test]
    fn interception_downgrades_the_offer_to_http11_because_holding_h2_is_not_implemented() {
        // C6: mirroring an h2-capable target unconditionally would make most traffic
        // uninterceptable while the operator's switch still says interception is on. The downgrade
        // is the honest trade, and it is caused by that switch rather than by the target.
        assert_eq!(
            alpn_offer(&[owned(ALPN_H2), owned(ALPN_HTTP11)], true),
            vec![owned(ALPN_HTTP11)]
        );
        // An h2-only client cannot be served at all while the queue is on. An empty offer is what
        // lets the caller record that refusal with a reason instead of emitting a bare TLS alert.
        assert!(alpn_offer(&[owned(ALPN_H2)], true).is_empty());
    }

    #[test]
    fn the_negotiated_protocol_is_read_from_the_wire_and_an_absent_alpn_is_http1() {
        assert_eq!(negotiated_protocol(Some(ALPN_H2)), Ok(Protocol::Http2));
        assert_eq!(negotiated_protocol(Some(ALPN_HTTP11)), Ok(Protocol::Http1));
        // No ALPN extension is a fact, not a guess: such a server speaks HTTP/1.1. e2e-tls.sh's
        // Python origin sets no ALPN, so this is the arm the project's own gate exercises.
        assert_eq!(negotiated_protocol(None), Ok(Protocol::Http1));
        // Refuse rather than guess. Recording an unclassifiable protocol as HTTP/1 because that is
        // the likelier answer is the silent downgrade H2-04 exists to forbid.
        assert_eq!(
            negotiated_protocol(Some(b"spdy/3.1")),
            Err(UnknownAlpn(b"spdy/3.1".to_vec()))
        );
        assert!(
            UnknownAlpn(b"spdy/3.1".to_vec())
                .to_string()
                .contains("spdy/3.1"),
            "the refusal must name what the target picked"
        );
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
    fn the_client_facing_config_offers_only_what_the_target_negotiated() {
        let (ca, _, _) = generate_ca("t").unwrap();
        let eng = TlsEngine::new(ca);
        // One protocol, never a list: a second choice here is how the two legs end up disagreeing.
        assert_eq!(
            eng.server_config("fallback.test", &[owned(ALPN_H2)])
                .alpn_protocols,
            vec![owned(ALPN_H2)]
        );
        assert!(
            eng.server_config("fallback.test", &[])
                .alpn_protocols
                .is_empty(),
            "a target that negotiated no ALPN is mirrored as no ALPN"
        );
    }
}
