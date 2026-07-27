# TLS interception: rcgen + rustls, verified against the compiler

Researched 2026-07-26 against a scratch crate at `/tmp/tlsprobe` (Rust 1.92, edition 2024).
**Every code block below was compiled, and the CA→leaf→handshake path was exercised by 7 passing
tests including real TLS handshakes with full webpki path validation.** Nothing here is from a doc
example.

```
test dns_sni_handshake_succeeds ... ok
test ip_literal_handshake_uses_fallback ... ok
test wildcard_san_semantics ... ok
test rsa_ca_also_signs_ecdsa_leaves ... ok
test leaf_cache_returns_same_arc ... ok
test builder_without_explicit_provider ... ok
test crypto_provider_get_default_before_install ... ok
```

---

## 1. Versions — VERIFIED (crates.io API, 2026-07-26)

| crate | latest stable | published |
|---|---|---|
| `rcgen` | **0.14.8** | 2026-05-11 |
| `rustls` | **0.23.42** | 2026-07-13 (`0.24.0-dev.1` exists — pre-release, avoid) |
| `tokio-rustls` | **0.26.4** | 2025-09-26 |
| `rustls-pemfile` | **2.2.0** | 2024-09-30 |
| `rustls-pki-types` | **1.15.1** | 2026-07-23 |

**No duplicate `rustls-pki-types`.** rcgen 0.14.8 depends on `rustls-pki-types ^1.4.1`; your lock
already has 1.15.1, which satisfies it. Verified: the probe's `Cargo.lock` contains exactly one
`rustls-pki-types 1.15.1`, one `rustls 0.23.42`, one `rustls-webpki 0.103.13` — identical to
`/root/burpsy/Cargo.lock`.

### Cargo.toml — VERIFIED-COMPILES

```toml
rcgen           = { version = "0.14.8", default-features = false, features = ["aws_lc_rs", "pem", "x509-parser"] }
rustls          = { version = "0.23.42", default-features = false, features = ["std", "aws-lc-rs", "tls12", "logging"] }
tokio-rustls    = { version = "0.26.4",  default-features = false, features = ["aws-lc-rs", "tls12", "logging"] }
rustls-pemfile  = "2.2.0"
rustls-pki-types = "1.15.1"
time            = "0.3"
parking_lot     = "0.12"
```

**`default-features = false` on rcgen matters.** rcgen's defaults are `crypto, pem, ring` — verified
via `cargo add rcgen --dry-run`. Leaving them on pulls and *compiles* the `ring` crate alongside
`aws-lc-sys` (measured: +10 s cold build). It does **not** cause the provider panic in §5, because it
enables the `ring` *crate*, not the `rustls/ring` *feature* — but there's no reason to pay for it.

`x509-parser` is **required**, not optional: `Issuer::from_ca_cert_pem` is gated on
`#[cfg(all(feature = "pem", feature = "x509-parser"))]`. Without it you cannot reload a persisted CA.

Your existing graph is already aws-lc-rs-only (`cargo tree -i ring` in `/root/burpsy` → *nothing to
print*; `aws-lc-rs 1.17.3` reaches `rustls → tokio-rustls → burpsy-repeater`), so this drops in
cleanly.

> Cosmetic: `ring` still appears as a line in `Cargo.lock` — cargo records optional deps of `rcgen`
> whether or not the feature is on. `cargo tree -i ring` confirms it is not in the build graph.

---

## 2. CA generation + persistence — VERIFIED-COMPILES

rcgen 0.14 API shape, confirmed by reading `rcgen-0.14.8/src/{lib.rs,certificate.rs}`:
- `Certificate::from_params` is **gone** (that was ≤0.12).
- `CertificateParams::self_signed(&signing_key) -> Certificate`.
- `CertificateParams::signed_by(&public_key, &Issuer<'_, impl SigningKey>) -> Certificate`.
- `Issuer<'a, S>` is `pub` but declared in `lib.rs` and **not** re-exported via a `pub use` — import
  it as `rcgen::Issuer` (works).
- `Issuer::new(params, key)` takes params **by value** → `Cow::Owned` → gives you a `'static` issuer.
- `Certificate::der() -> &CertificateDer<'static>`, `Certificate::pem() -> String`,
  `KeyPair::serialize_pem() -> String`, `KeyPair::serialize_der() -> Vec<u8>`.

```rust
// src/tls/ca.rs
use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use time::{Duration, OffsetDateTime};

/// A loaded certificate authority: the signing key + everything needed to issue leaves.
#[derive(Debug)]   // required: ResolvesServerCert: Debug, and this ends up inside the resolver
pub struct CertAuthority {
    /// Owns its params, so it is `'static`.
    pub issuer: Issuer<'static, KeyPair>,
    /// DER of the CA cert, to append to leaf chains and to export for the trust store.
    pub cert_der: rustls_pki_types::CertificateDer<'static>,
}

/// Generate a fresh self-signed CA. Returns (ca, cert_pem, key_pem) — persist both PEMs.
pub fn generate(common_name: &str, valid_days: i64) -> Result<(CertAuthority, String, String)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn.push(DnType::OrganizationName, common_name);

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0)); // CA:TRUE, pathlen:0
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::hours(1);   // clock-skew slack
    params.not_after = now + Duration::days(valid_days);

    let cert = params.self_signed(&key)?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();
    let cert_der = cert.der().clone();

    Ok((CertAuthority { issuer: Issuer::new(params, key), cert_der }, cert_pem, key_pem))
}

/// Reload a CA from the two PEM strings written by `generate`.
pub fn load_pem(cert_pem: &str, key_pem: &str) -> Result<CertAuthority> {
    let key = KeyPair::from_pem(key_pem).context("parsing CA key PEM")?;
    let issuer = Issuer::from_ca_cert_pem(cert_pem, key).context("parsing CA cert PEM")?;
    let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .context("no CERTIFICATE block in CA PEM")??;
    Ok(CertAuthority { issuer, cert_der })
}
```

`Issuer::from_ca_cert_pem` reconstructs the DN, key-usage set and key-identifier method by parsing the
stored cert, so you do **not** need to persist `CertificateParams` — the two PEMs are the whole state.
It performs no validation (it will happily load a non-CA cert).

**RSA-2048 variant** — VERIFIED-COMPILES, and its handshake test passes. Only needed for old
non-browser clients; P-256 is fine for Chrome/Firefox/Edge.

```rust
pub fn generate_rsa(common_name: &str, valid_days: i64) -> Result<(CertAuthority, String, String)> {
    use rcgen::{RsaKeySize, PKCS_RSA_SHA256};
    let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)?;
    /* ...identical params to generate()... */
    # unimplemented!()
}
```
(`generate_rsa_for` / `RsaKeySize` are gated on `feature = "aws_lc_rs"`, which you have.)

### What the generated CA actually looks like — VERIFIED (`openssl x509 -text`)
```
Signature Algorithm: ecdsa-with-SHA256
Issuer/Subject: CN=burpsy CA, O=burpsy CA
Public-Key: (256 bit)  ASN1 OID: prime256v1  NIST CURVE: P-256
X509v3 Key Usage: critical
    Digital Signature, Certificate Sign, CRL Sign
X509v3 Subject Key Identifier:
    F0:D5:E8:B0:...:2C:B0:0F
X509v3 Basic Constraints: critical
    CA:TRUE, pathlen:0
```

---

## 3. Dynamic leaf signing — VERIFIED-COMPILES

Conversion path rcgen → rustls, exactly:
- cert: `Certificate::der() -> &CertificateDer<'static>` → `.clone()`. **No conversion needed** —
  rcgen already returns `rustls_pki_types::CertificateDer`.
- key: `KeyPair::serialize_der() -> Vec<u8>` (PKCS#8) →
  `PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec))`.

```rust
// src/tls/leaf.rs
use anyhow::Result;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{net::IpAddr, str::FromStr};
use time::{Duration, OffsetDateTime};

use crate::tls::ca::CertAuthority;

pub const LEAF_DAYS: i64 = 397;

/// Mint a leaf for `host`, which may be a DNS name or a bare IP literal.
pub fn mint(
    ca: &CertAuthority,
    host: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    // `CONNECT 1.2.3.4:443` has no hostname — emit an iPAddress SAN, not a dNSName.
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
    params.use_authority_key_identifier_extension = true;   // off by default; browsers want it
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(LEAF_DAYS);

    let leaf = params.signed_by(&key, &ca.issuer)?;

    // Leaf first, then the CA — Firefox only imports *roots* from the Windows store and
    // expects the server to supply anything else in the handshake.
    let chain = vec![leaf.der().clone(), ca.cert_der.clone()];
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    Ok((chain, key_der))
}
```

Resulting leaf — VERIFIED (`openssl x509 -text`):
```
Issuer: CN=burpsy CA, O=burpsy CA        Subject: CN=shop.example.test
X509v3 Authority Key Identifier: F0:D5:E8:B0:...     <- matches CA's SKI
X509v3 Subject Alternative Name: DNS:shop.example.test
X509v3 Key Usage: critical  Digital Signature, Key Encipherment
X509v3 Extended Key Usage:  TLS Web Server Authentication
Validity: Jul 26 2026 -> Aug 27 2027     (397 days)
```

`params.signed_by(&key, &ca.issuer)` — note the first argument is the **leaf's** key (used only as
`impl PublicKeyData`); the signature comes from the key inside `Issuer`.

---

## 4. `ResolvesServerCert` + ALPN — VERIFIED-COMPILES

Current trait (rustls 0.23.42, `src/server/server_conn.rs:124`):
```rust
pub trait ResolvesServerCert: Debug + Send + Sync {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<sign::CertifiedKey>>;
    fn only_raw_public_keys(&self) -> bool { false }   // provided
}
```
`ClientHello::server_name(&self) -> Option<&str>`.

Build `CertifiedKey` with **`CertifiedKey::from_der(chain, key, &provider)`** — it calls
`provider.key_provider.load_private_key(..)` for you. You do *not* need
`aws_lc_rs::sign::any_supported_type` directly (that's the manual path behind
`CertifiedKey::new(cert, Arc<dyn SigningKey>)`); `from_der` is provider-agnostic and shorter.

```rust
// src/tls/resolver.rs
use parking_lot::RwLock;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::{collections::HashMap, sync::Arc};

use crate::tls::{ca::CertAuthority, leaf};

#[derive(Debug)]
pub struct SniResolver {
    ca: Arc<CertAuthority>,
    provider: Arc<CryptoProvider>,
    cache: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    /// Used when the ClientHello carries no SNI (raw-IP CONNECT). Set this to the
    /// authority from the CONNECT line.
    fallback: String,
}

impl SniResolver {
    pub fn new(ca: Arc<CertAuthority>, provider: Arc<CryptoProvider>, fallback: String) -> Self {
        Self { ca, provider, cache: RwLock::new(HashMap::new()), fallback }
    }

    pub fn certified_key(&self, host: &str) -> anyhow::Result<Arc<CertifiedKey>> {
        if let Some(hit) = self.cache.read().get(host) {
            return Ok(hit.clone());
        }
        let (chain, key) = leaf::mint(&self.ca, host)?;
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
                None   // None aborts the handshake
            }
        }
    }
}

/// ServerConfig offering only http/1.1 via ALPN.
pub fn server_config(resolver: Arc<SniResolver>) -> rustls::ServerConfig {
    let provider = resolver.provider.clone();
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];   // plain Vec<Vec<u8>> field, no setter
    cfg
}
```

Wire-up (VERIFIED — this exact shape runs in the passing tests):
```rust
let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
let ca = Arc::new(ca::load_pem(&cert_pem, &key_pem)?);
let resolver = Arc::new(SniResolver::new(ca, provider, connect_authority.to_string()));
let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config(resolver)));
let tls_stream = acceptor.accept(tcp_after_connect_200).await?;
```

Cache note: `certified_key` has a benign read-then-write race — two concurrent first hits for the same
host mint twice and the second `insert` wins. Harmless (certs are equivalent); use an entry-level lock
or `dashmap` only if you care about the duplicate keygen.

---

## 5. Gotchas — all VERIFIED empirically

**5.1 CryptoProvider — the panic is at runtime, not compile time.**
With exactly one provider feature enabled, `ServerConfig::builder()` works and lazily installs the
process default (`CryptoProvider::get_default()` is `None` in a fresh process, `Some` after the first
builder call). With **both** `aws-lc-rs` and `ring` enabled on `rustls`, it panics:

```
thread panicked at rustls-0.23.42/src/crypto/mod.rs:249:14:
Could not automatically determine the process-level CryptoProvider from Rustls crate features.
Call CryptoProvider::install_default() before this point to select a provider manually, or make
sure exactly one of the 'aws-lc-rs' and 'ring' features is enabled.
```

Your graph is aws-lc-rs-only today, so `ServerConfig::builder()` is safe. **Use
`builder_with_provider(provider)` anyway** — it is explicit, it never panics, and it survives some
future dependency turning on `rustls/ring`. If you prefer `builder()`, call
`rustls::crypto::aws_lc_rs::default_provider().install_default().ok();` once at startup.

**No conflict with your existing `aws-lc-sys`** — rcgen's `aws_lc_rs` feature resolves to the same
`aws-lc-rs 1.17.3` / `aws-lc-sys 0.43.0` already in your lock. One copy, one build.

**5.2 IP-address SANs.** rustls does **not** send SNI for IP literals (correct per RFC 6066), so
`client_hello.server_name()` returns `None` on `CONNECT 1.2.3.4:443`. That's what the `fallback` field
is for — set it per-connection from the CONNECT authority. Verified: the `ip_literal_handshake_uses_fallback`
test drives exactly this path and the handshake succeeds with an `iPAddress` SAN.
Because the fallback is per-resolver, build **one `SniResolver` per CONNECT** (or key the fallback off
connection state) rather than sharing a single global with a fixed fallback.

**5.3 Wildcard vs exact SAN.** Measured against webpki:

| leaf SAN | client connects as | result |
|---|---|---|
| `*.example.test` | `a.example.test` | ✅ ok |
| `*.example.test` | `a.b.example.test` | ❌ `certificate not valid for name "a.b.example.test"; certificate is only valid for DnsName("*.example.test")` |
| `*.example.test` | `example.test` (apex) | ❌ same error |
| `exact.example.test` | `exact.example.test` | ✅ ok |

Wildcards cover exactly one label and never the apex → **mint exact per-host leaves** (what `mint`
does). A wildcard cache would only pay off for deep single-level fan-out and would break on apex hits.

**5.4 `#[derive(Debug)]` is mandatory.** `ResolvesServerCert: Debug`, so everything reachable from your
resolver needs it. `rcgen::Issuer` has a hand-written `Debug` that elides the key, so
`#[derive(Debug)]` on `CertAuthority` compiles. (This was the only compile error in the whole exercise.)

**5.5 ALPN.** `cfg.alpn_protocols` is a public `Vec<Vec<u8>>` field, not a builder method. Setting it to
`vec![b"http/1.1".to_vec()]` makes the server offer only HTTP/1.1; a client that offers only `h2` will
fail the handshake with a no-application-protocol alert — which is what you want while the proxy is
HTTP/1.1-only, since it forces browsers to downgrade rather than speak h2 you can't parse.

---

## 6. Browser trust on Windows

**Chrome's 398-day cap does not apply to you.** VERIFIED verbatim from
[Chromium `net/docs/certificate_lifetimes.md`](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/certificate_lifetimes.md):

> "TLS server certificates issued on or after 2020-09-01 00:00:00 UTC will be required to have a
> validity period of 398 days or less."
>
> "This will only apply to TLS server certificates from CAs that are trusted in a default installation
> of Google Chrome, commonly known as 'publicly trusted CAs', and will **not apply to locally-operated
> CAs that have been manually configured**."

So a manually-installed root is exempt. I still default leaves to **397 days** — it costs nothing,
keeps you clear of any future tightening, and matches what Burp/mitmproxy do. Don't go to 10 years on
*leaves*; some non-browser clients do enforce caps. 10 years on the *root* is fine.

**What the CA needs** (all present in §2's output, and all exercised by webpki path validation in the
passing tests):
- `basicConstraints = critical, CA:TRUE` — `pathlen:0` is correct since you only issue leaves.
- `keyUsage = critical, keyCertSign, cRLSign` (+ `digitalSignature`, harmless).
- `subjectKeyIdentifier` on the CA, `authorityKeyIdentifier` on the leaf (set
  `use_authority_key_identifier_extension = true` — it is **false** by default in rcgen).
- Leaf needs `extendedKeyUsage = serverAuth` and a **SAN**; CN is ignored by every modern browser.

`CA:TRUE` + `keyCertSign` is sufficient — no `extendedKeyUsage` on the CA. Do **not** put an EKU on the
root: Windows treats an EKU on a root as an EKU constraint, which is an easy way to break things.

**Chrome/Edge on Windows:** install into `Trusted Root Certification Authorities` (`certutil
-addstore -user Root ca.crt`, or Current User store via certmgr). Chrome's own Chrome Root Store does
not displace locally-added roots — user/enterprise roots from the platform store are still honoured.

**Firefox does not use the Windows store by default in the way you'd hope.** It maintains its own NSS
store. Two options:
1. Set `security.enterprise_roots.enabled = true` (about:config or enterprise policy). VERIFIED from
   [MozillaWiki CA/AddRootToFirefox](https://wiki.mozilla.org/CA/AddRootToFirefox): Firefox reads
   `HKLM\SOFTWARE\Microsoft\SystemCertificates`,
   `HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates`, and
   `HKLM\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates`.
   **Limitation, quoted:** "this setting only imports certificates from the Windows Trusted Root
   Certification Authorities store, not corresponding Intermediate Certification Authorities store" —
   and if you hit unknown-issuer errors you should "configure your TLS server to include the necessary
   intermediate certificates in the TLS handshake." This is exactly why §3 ships the CA in the chain.
   Note those are all **HKLM** paths — a CurrentUser-only install will not be picked up by Firefox.
2. Import `ca.crt` directly via Settings → Certificates → View Certificates → Authorities → Import,
   ticking "Trust this CA to identify websites."

Serve the CA for download from the proxy itself (mitmproxy-style `http://burpsy/cert`) — it's the least
painful install path.

---

## 7. Anything that did not build

Nothing. Every snippet above compiles; the only compile error encountered during the exercise was the
missing `#[derive(Debug)]` on `CertAuthority` (§5.4), which is fixed in the code as written.

Two items are **UNVERIFIED** because they cannot be tested from this Linux container:
- Actual Chrome/Firefox-on-Windows acceptance of the generated CA. The cert *structure* is verified by
  openssl and by webpki path validation (which enforces basicConstraints, keyCertSign, EKU serverAuth,
  SAN matching and the validity window), but no real browser was driven.
- `security.enterprise_roots.enabled`'s current default value on Firefox — the Mozilla support page
  failed to render for me and the wiki does not state a default. Set it explicitly rather than
  assuming.

Scratch project retained at `/tmp/tlsprobe` (`cargo test` to re-run all 7).
