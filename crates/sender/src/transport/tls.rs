//! The one outbound TLS client config, shared by both transports.
//!
//! It existed twice before this crate — once in the proxy's `tls` module for the blocking upstream
//! leg, once in the repeater for the async one — with identical `NoVerify` boilerplate. Two copies
//! of a certificate-verification decision is one more than anyone should have to audit, so it lives
//! here once and both transports use it.

use std::sync::Arc;
use tokio_rustls::rustls::ClientConfig;

/// Client config that does not verify server certificates.
///
/// Deliberate, and worth being explicit about: a testing proxy has to reach staging hosts with
/// self-signed, expired, or mismatched certificates, and refusing them would make the tool useless
/// for most real work. The security boundary is not certificate validation — it is that burpsy is an
/// explicit local tool the operator aimed at targets they are authorised to test, and that
/// [`crate::AuthorisedSender`] is what enforces the second half of that.
pub(crate) fn insecure_client_config() -> Arc<ClientConfig> {
    use tokio_rustls::rustls::DigitallySignedStruct;
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
            use tokio_rustls::rustls::SignatureScheme::*;
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

    Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth(),
    )
}
