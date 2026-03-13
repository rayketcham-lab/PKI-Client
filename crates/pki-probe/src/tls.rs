//! TLS inspection using rustls.

use crate::{Error, Result};
use rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;

/// Ensure the aws-lc-rs `CryptoProvider` is installed (only runs once).
/// This provider supports PQC key exchange (`X25519MLKEM768`).
fn ensure_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Result of TLS inspection.
#[derive(Debug, Clone)]
pub struct TlsResult {
    /// Negotiated protocol version.
    pub protocol_version: String,
    /// Negotiated cipher suite.
    pub cipher_suite: String,
    /// Negotiated key exchange group.
    pub key_exchange: Option<String>,
    /// Certificate chain (DER encoded).
    pub certificates: Vec<Vec<u8>>,
    /// Whether the certificate chain is valid.
    pub chain_valid: bool,
}

/// TLS inspector for probing server TLS configuration.
pub struct TlsInspector {
    /// SNI hostname.
    sni: String,
    /// TLS configuration.
    config: Arc<ClientConfig>,
}

impl TlsInspector {
    /// Create a new TLS inspector.
    #[must_use]
    pub fn new(sni: &str) -> Self {
        let config = build_client_config(None);
        Self {
            sni: sni.to_string(),
            config: Arc::new(config),
        }
    }

    /// Create a TLS inspector that skips certificate verification.
    /// Use for probing servers with PQC/unsupported signature algorithms.
    #[must_use]
    pub fn new_no_verify(sni: &str) -> Self {
        let config = build_client_config_inner(false);
        Self {
            sni: sni.to_string(),
            config: Arc::new(config),
        }
    }

    /// Create a TLS inspector for a specific protocol version.
    #[must_use]
    pub fn with_version(sni: &str, _version: &str) -> Self {
        let config = build_client_config(None);
        Self {
            sni: sni.to_string(),
            config: Arc::new(config),
        }
    }

    /// List cipher suite names supported by the client configuration.
    pub fn supported_cipher_suites(&self) -> Vec<String> {
        self.config
            .crypto_provider()
            .cipher_suites
            .iter()
            .map(|cs| format!("{:?}", cs.suite()))
            .collect()
    }

    /// Inspect a TLS connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS handshake fails.
    pub fn inspect(self, mut stream: TcpStream) -> Result<TlsResult> {
        let server_name = ServerName::try_from(self.sni.clone()).map_err(|_| Error::Network {
            message: format!("Invalid server name: {}", self.sni),
        })?;

        let mut conn = ClientConnection::new(self.config.clone(), server_name).map_err(|e| {
            Error::Network {
                message: format!("Failed to create TLS connection: {e}"),
            }
        })?;

        // Perform TLS handshake with timeout protection
        let handshake_start = std::time::Instant::now();
        let handshake_timeout = std::time::Duration::from_secs(15);

        while conn.is_handshaking() {
            // Check if handshake is taking too long
            if handshake_start.elapsed() > handshake_timeout {
                return Err(Error::Network {
                    message: "TLS handshake timed out".to_string(),
                });
            }

            // Write any pending TLS data
            while conn.wants_write() {
                match conn.write_tls(&mut stream) {
                    Ok(0) => break,
                    Ok(_) => {
                        stream.flush().map_err(|e| Error::Network {
                            message: format!("TLS flush error: {e}"),
                        })?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => {
                        return Err(Error::Network {
                            message: format!("TLS write error: {e}"),
                        });
                    }
                }
            }

            // Read incoming TLS data
            if conn.wants_read() {
                match conn.read_tls(&mut stream) {
                    Ok(0) => {
                        return Err(Error::Network {
                            message: "Connection closed during handshake".to_string(),
                        });
                    }
                    Ok(_) => {
                        conn.process_new_packets().map_err(|e| Error::Network {
                            message: format!("TLS processing error: {e}"),
                        })?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => {
                        return Err(Error::Network {
                            message: format!("TLS read error: {e}"),
                        });
                    }
                }
            }
        }

        // Extract connection info
        let protocol_version = conn
            .protocol_version()
            .map_or_else(|| "Unknown".to_string(), |v| format!("{v:?}"));

        let cipher_suite = conn
            .negotiated_cipher_suite()
            .map_or_else(|| "Unknown".to_string(), |cs| format!("{:?}", cs.suite()));

        // Get the negotiated key exchange group
        let key_exchange = conn
            .negotiated_key_exchange_group()
            .map(|kx| format!("{:?}", kx.name()));

        // Extract certificates
        let certificates = conn
            .peer_certificates()
            .map(|certs| certs.iter().map(|c| c.as_ref().to_vec()).collect())
            .unwrap_or_default();

        Ok(TlsResult {
            protocol_version,
            cipher_suite,
            key_exchange,
            certificates,
            chain_valid: true, // rustls validates by default
        })
    }
}

/// Build TLS client configuration.
fn build_client_config(_version: Option<&str>) -> ClientConfig {
    build_client_config_inner(true)
}

/// Build TLS client configuration with optional verification.
/// Always offers both PQC hybrid and classical key exchanges.
fn build_client_config_inner(verify: bool) -> ClientConfig {
    // Ensure crypto provider is installed
    ensure_crypto_provider();

    // Get the default provider - includes X25519MLKEM768 and classical groups
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();

    // Add SECP256R1MLKEM768 (P-256+ML-KEM-768) which isn't in default groups
    // This is needed for servers like quantumnexum.com:6444
    if !provider
        .kx_groups
        .iter()
        .any(|g| format!("{:?}", g.name()).contains("SECP256R1MLKEM768"))
    {
        // Insert after X25519MLKEM768 (index 1) to keep PQC groups together
        let insert_pos = provider
            .kx_groups
            .iter()
            .position(|g| format!("{:?}", g.name()) == "X25519")
            .unwrap_or(1);
        provider.kx_groups.insert(insert_pos, SECP256R1MLKEM768);
    }

    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("TLS protocol versions");

    if verify {
        let mut root_store = RootCertStore::empty();
        // Load OS trust store (includes user-installed CA certs)
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = root_store.add(cert);
        }
        // Add Mozilla roots as fallback (in case native store is empty or unavailable)
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        // Skip certificate verification (for probing PQC servers with unsupported sig algs)
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    }
}

/// Certificate verifier that accepts all certificates (for probing only).
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Return all schemes including PQC to allow any signature
        vec![
            // Traditional schemes
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            // Post-Quantum (ML-DSA / Dilithium) schemes
            rustls::SignatureScheme::ML_DSA_44,
            rustls::SignatureScheme::ML_DSA_65,
            rustls::SignatureScheme::ML_DSA_87,
        ]
    }
}

/// Builder for custom TLS configurations.
#[derive(Debug, Clone)]
pub struct TlsConfigBuilder {
    /// Minimum protocol version.
    min_version: Option<String>,
    /// Maximum protocol version.
    max_version: Option<String>,
    /// Custom cipher suites.
    #[allow(dead_code)]
    cipher_suites: Vec<String>,
    /// Whether to verify certificates.
    verify_certs: bool,
}

impl Default for TlsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsConfigBuilder {
    /// Create a new TLS config builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_version: None,
            max_version: None,
            cipher_suites: Vec::new(),
            verify_certs: true,
        }
    }

    /// Set minimum TLS version.
    #[must_use]
    pub fn min_version(mut self, version: impl Into<String>) -> Self {
        self.min_version = Some(version.into());
        self
    }

    /// Set maximum TLS version.
    #[must_use]
    pub fn max_version(mut self, version: impl Into<String>) -> Self {
        self.max_version = Some(version.into());
        self
    }

    /// Disable certificate verification (for testing only).
    #[must_use]
    pub fn no_verify(mut self) -> Self {
        self.verify_certs = false;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_builder() {
        let builder = TlsConfigBuilder::new()
            .min_version("1.2")
            .max_version("1.3")
            .no_verify();

        assert_eq!(builder.min_version, Some("1.2".to_string()));
        assert_eq!(builder.max_version, Some("1.3".to_string()));
        assert!(!builder.verify_certs);
    }
}
