//! Server probing and TLS inspection.
//!
//! This module provides functionality for probing servers to inspect their
//! TLS configuration, certificates, and security posture.
//!
//! ## Example
//!
//! ```ignore
//! use pki_probe::ServerProbe;
//!
//! let probe = ServerProbe::new();
//! let result = probe.probe("example.com:443")?;
//! println!("Protocol: {}", result.protocol_version);
//! ```

pub mod lint;
pub mod tls;

use thiserror::Error;

/// Error types for pki-probe operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Network-related errors (DNS, connection, TLS).
    #[error("Network error: {message}")]
    Network {
        /// Error description.
        message: String,
    },

    /// Certificate parsing errors.
    #[error("Certificate parse error: {message}")]
    CertParse {
        /// Error description.
        message: String,
    },

    /// I/O errors.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// Create a new certificate parse error.
    pub fn cert_parse(message: impl Into<String>) -> Self {
        Self::CertParse {
            message: message.into(),
        }
    }
}

/// Result type for pki-probe operations.
pub type Result<T> = std::result::Result<T, Error>;
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub use lint::{CertLinter, LintResult, LintSeverity};
pub use tls::TlsInspector;

/// Result of probing a server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Target hostname.
    pub hostname: String,
    /// Target port.
    pub port: u16,
    /// Whether TLS is supported.
    pub tls_supported: bool,
    /// TLS protocol version.
    pub protocol_version: Option<String>,
    /// Cipher suite used.
    pub cipher_suite: Option<String>,
    /// Key exchange group used.
    pub key_exchange: Option<String>,
    /// Certificate chain metadata.
    pub certificate_chain: Vec<CertInfo>,
    /// Raw certificate chain (DER encoded).
    #[serde(skip)]
    pub raw_certificates: Vec<Vec<u8>>,
    /// Supported protocol versions.
    pub supported_protocols: Vec<String>,
    /// Supported cipher suites.
    pub supported_ciphers: Vec<String>,
    /// Connection time in milliseconds.
    pub connection_time_ms: u64,
    /// TLS handshake time in milliseconds.
    pub handshake_time_ms: u64,
    /// Certificate lint results.
    pub lint_results: Vec<LintResult>,
    /// Security warnings.
    pub warnings: Vec<String>,
    /// Probe timestamp.
    pub probed_at: DateTime<Utc>,
}

/// Information about a certificate in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    /// Certificate subject.
    pub subject: String,
    /// Certificate issuer.
    pub issuer: String,
    /// Serial number.
    pub serial: String,
    /// Not before (validity start).
    pub not_before: DateTime<Utc>,
    /// Not after (validity end).
    pub not_after: DateTime<Utc>,
    /// Days until expiration.
    pub days_until_expiry: i64,
    /// Subject Alternative Names.
    pub san: Vec<String>,
    /// Key algorithm.
    pub key_algorithm: String,
    /// Key size in bits.
    pub key_size: Option<u32>,
    /// Signature algorithm.
    pub signature_algorithm: String,
    /// Whether this is a CA certificate.
    pub is_ca: bool,
    /// Position in chain (0 = leaf).
    pub chain_position: usize,
}

/// Server probe configuration.
#[derive(Debug, Clone)]
pub struct ServerProbe {
    /// Connection timeout.
    timeout: Duration,
    /// Whether to check all protocol versions.
    check_protocols: bool,
    /// Whether to enumerate cipher suites.
    check_ciphers: bool,
    /// Whether to run certificate linting.
    lint_certs: bool,
    /// SNI hostname (if different from connection target).
    sni_hostname: Option<String>,
    /// Skip certificate verification (for PQC servers).
    no_verify: bool,
}

impl Default for ServerProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerProbe {
    /// Create a new server probe with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            check_protocols: true,
            check_ciphers: false, // Can be slow
            lint_certs: true,
            sni_hostname: None,
            no_verify: false,
        }
    }

    /// Set connection timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set whether to check all protocol versions.
    #[must_use]
    pub fn with_protocol_check(mut self, check: bool) -> Self {
        self.check_protocols = check;
        self
    }

    /// Set whether to enumerate cipher suites.
    #[must_use]
    pub fn with_cipher_check(mut self, check: bool) -> Self {
        self.check_ciphers = check;
        self
    }

    /// Set whether to run certificate linting.
    #[must_use]
    pub fn with_lint(mut self, lint: bool) -> Self {
        self.lint_certs = lint;
        self
    }

    /// Set SNI hostname.
    #[must_use]
    pub fn with_sni(mut self, hostname: impl Into<String>) -> Self {
        self.sni_hostname = Some(hostname.into());
        self
    }

    /// Skip certificate verification (for PQC servers with unsupported sig algs).
    #[must_use]
    pub fn with_no_verify(mut self, no_verify: bool) -> Self {
        self.no_verify = no_verify;
        self
    }

    /// Probe a server.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails.
    pub fn probe(&self, target: &str) -> Result<ProbeResult> {
        let (hostname, port) = parse_target(target);
        let sni = self.sni_hostname.as_deref().unwrap_or(&hostname);

        let addr = format!("{hostname}:{port}");
        let probed_at = Utc::now();

        // TCP connection with DNS resolution
        let conn_start = std::time::Instant::now();

        // Resolve hostname to socket addresses
        let socket_addr = addr
            .to_socket_addrs()
            .map_err(|e| Error::Network {
                message: format!("DNS resolution failed for {addr}: {e}"),
            })?
            .next()
            .ok_or_else(|| Error::Network {
                message: format!("No addresses found for {addr}"),
            })?;

        let stream =
            TcpStream::connect_timeout(&socket_addr, self.timeout).map_err(|e| Error::Network {
                message: format!("Connection failed to {addr}: {e}"),
            })?;

        // Set read/write timeouts for TLS handshake
        stream.set_read_timeout(Some(self.timeout)).ok();
        stream.set_write_timeout(Some(self.timeout)).ok();

        let connection_time_ms =
            u64::try_from(conn_start.elapsed().as_millis()).unwrap_or(u64::MAX);

        // TLS handshake
        let tls_start = std::time::Instant::now();
        let inspector = if self.no_verify {
            TlsInspector::new_no_verify(sni)
        } else {
            TlsInspector::new(sni)
        };
        let inspector_ciphers = inspector.supported_cipher_suites();
        let tls_result = inspector.inspect(stream)?;
        let handshake_time_ms = u64::try_from(tls_start.elapsed().as_millis()).unwrap_or(u64::MAX);

        // Parse certificates
        let mut certificate_chain = Vec::new();
        for (i, cert_der) in tls_result.certificates.iter().enumerate() {
            if let Ok(cert_info) = parse_cert_info(cert_der, i) {
                certificate_chain.push(cert_info);
            }
        }

        // Run linting if enabled
        let lint_results = if self.lint_certs && !tls_result.certificates.is_empty() {
            let linter = CertLinter::new();
            linter.lint_chain(&tls_result.certificates)
        } else {
            Vec::new()
        };

        // Check for security warnings
        let warnings = check_security_issues(&tls_result, &certificate_chain);

        // Check supported protocols if requested
        let supported_protocols = if self.check_protocols {
            check_supported_protocols(&hostname, port, sni, self.timeout)
        } else {
            vec![tls_result.protocol_version.clone()]
        };

        Ok(ProbeResult {
            hostname,
            port,
            tls_supported: true,
            protocol_version: Some(tls_result.protocol_version),
            cipher_suite: Some(tls_result.cipher_suite),
            key_exchange: tls_result.key_exchange,
            certificate_chain,
            raw_certificates: tls_result.certificates,
            supported_protocols,
            supported_ciphers: inspector_ciphers,
            connection_time_ms,
            handshake_time_ms,
            lint_results,
            warnings,
            probed_at,
        })
    }

    /// Quick check if a server supports TLS.
    ///
    /// # Errors
    ///
    /// Returns an error if the check fails.
    pub fn check_tls(&self, target: &str) -> Result<bool> {
        let (hostname, port) = parse_target(target);
        let sni = self.sni_hostname.as_deref().unwrap_or(&hostname);

        let addr = format!("{hostname}:{port}");

        // Resolve hostname
        let socket_addr = addr
            .to_socket_addrs()
            .map_err(|e| Error::Network {
                message: format!("DNS resolution failed for {addr}: {e}"),
            })?
            .next()
            .ok_or_else(|| Error::Network {
                message: format!("No addresses found for {addr}"),
            })?;

        let stream =
            TcpStream::connect_timeout(&socket_addr, self.timeout).map_err(|e| Error::Network {
                message: format!("Connection failed to {addr}: {e}"),
            })?;

        // Set read/write timeouts
        stream.set_read_timeout(Some(self.timeout)).ok();
        stream.set_write_timeout(Some(self.timeout)).ok();

        let inspector = TlsInspector::new(sni);
        inspector.inspect(stream).map(|_| true)
    }
}

/// Parse target string into hostname and port.
fn parse_target(target: &str) -> (String, u16) {
    // Handle URL format
    let target = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
        .unwrap_or(target);

    // Remove path
    let target = target.split('/').next().unwrap_or(target);

    // Split hostname and port
    if let Some(bracket_end) = target.find(']') {
        // IPv6 address
        let host = &target[..=bracket_end];
        let port =
            if target.len() > bracket_end + 2 && &target[bracket_end + 1..bracket_end + 2] == ":" {
                target[bracket_end + 2..].parse().unwrap_or(443)
            } else {
                443
            };
        (host.to_string(), port)
    } else if let Some(colon) = target.rfind(':') {
        let host = &target[..colon];
        let port = target[colon + 1..].parse().unwrap_or(443);
        (host.to_string(), port)
    } else {
        (target.to_string(), 443)
    }
}

/// Parse certificate info from DER.
fn parse_cert_info(cert_der: &[u8], position: usize) -> Result<CertInfo> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| Error::cert_parse(format!("Invalid certificate: {e}")))?;

    let not_before = Utc
        .timestamp_opt(cert.validity.not_before.timestamp(), 0)
        .single()
        .unwrap_or_else(Utc::now);

    let not_after = Utc
        .timestamp_opt(cert.validity.not_after.timestamp(), 0)
        .single()
        .unwrap_or_else(Utc::now);

    let days_until_expiry = (not_after - Utc::now()).num_days();

    // Extract SANs
    let mut san = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                x509_parser::prelude::GeneralName::DNSName(dns) => {
                    san.push((*dns).to_string());
                }
                x509_parser::prelude::GeneralName::IPAddress(ip) => {
                    san.push(format!(
                        "IP:{}",
                        ip.iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(".")
                    ));
                }
                _ => {}
            }
        }
    }

    // Get key info
    let (key_algorithm, key_size) = get_key_info(&cert);

    // Check if CA
    let is_ca = cert
        .basic_constraints()
        .ok()
        .and_then(|bc| bc.map(|e| e.value.ca))
        .unwrap_or(false);

    Ok(CertInfo {
        subject: cert.subject.to_string(),
        issuer: cert.issuer.to_string(),
        serial: cert.serial.to_str_radix(16),
        not_before,
        not_after,
        days_until_expiry,
        san,
        key_algorithm,
        key_size,
        signature_algorithm: cert.signature_algorithm.algorithm.to_string(),
        is_ca,
        chain_position: position,
    })
}

/// Get key algorithm and size from certificate.
fn get_key_info(cert: &x509_parser::certificate::X509Certificate) -> (String, Option<u32>) {
    let algo = cert.public_key().algorithm.algorithm.to_string();

    // Try to determine key size
    #[allow(clippy::cast_possible_truncation)]
    let key_size = match algo.as_str() {
        // RSA OID: 1.2.840.113549.1.1.1
        "1.2.840.113549.1.1.1" => {
            // Approximate from subject public key length
            let bits = cert.public_key().subject_public_key.data.len() * 8;
            Some(bits as u32)
        }
        // EC P-256: 1.2.840.10045.3.1.7
        "1.2.840.10045.3.1.7" => Some(256),
        // EC P-384: 1.3.132.0.34
        "1.3.132.0.34" => Some(384),
        // EC P-521: 1.3.132.0.35
        "1.3.132.0.35" => Some(521),
        _ => None,
    };

    let algo_name = match algo.as_str() {
        "1.2.840.113549.1.1.1" => "RSA".to_string(),
        "1.2.840.10045.2.1" => "ECDSA".to_string(),
        "1.3.101.112" => "Ed25519".to_string(),
        _ => algo,
    };

    (algo_name, key_size)
}

/// Check for security issues.
fn check_security_issues(tls_result: &tls::TlsResult, chain: &[CertInfo]) -> Vec<String> {
    let mut warnings = Vec::new();

    // Check protocol version
    if tls_result.protocol_version.contains("1.0") || tls_result.protocol_version.contains("1.1") {
        warnings.push(format!(
            "Outdated TLS version: {}. Recommend TLS 1.2 or 1.3",
            tls_result.protocol_version
        ));
    }

    // Check certificate expiration
    for cert in chain {
        if cert.days_until_expiry < 0 {
            warnings.push(format!(
                "Certificate expired: {} (expired {} days ago)",
                cert.subject, -cert.days_until_expiry
            ));
        } else if cert.days_until_expiry < 30 {
            warnings.push(format!(
                "Certificate expiring soon: {} ({} days)",
                cert.subject, cert.days_until_expiry
            ));
        }
    }

    // Check key sizes
    for cert in chain {
        if let Some(size) = cert.key_size {
            if cert.key_algorithm == "RSA" && size < 2048 {
                warnings.push(format!(
                    "Weak RSA key size: {} bits for {}",
                    size, cert.subject
                ));
            }
        }
    }

    // Check cipher suite
    let cipher = &tls_result.cipher_suite;
    if cipher.contains("NULL") || cipher.contains("EXPORT") || cipher.contains("DES") {
        warnings.push(format!("Weak cipher suite: {cipher}"));
    }

    warnings
}

/// Check which TLS protocol versions are supported.
fn check_supported_protocols(
    hostname: &str,
    port: u16,
    sni: &str,
    timeout: Duration,
) -> Vec<String> {
    let mut supported = Vec::new();
    let addr = format!("{hostname}:{port}");

    // Resolve address once
    let socket_addr = match addr.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => return supported,
        },
        Err(_) => return supported,
    };

    // Check TLS 1.3
    if let Ok(stream) = TcpStream::connect_timeout(&socket_addr, timeout) {
        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();
        let inspector = TlsInspector::with_version(sni, "1.3");
        if inspector.inspect(stream).is_ok() {
            supported.push("TLS 1.3".to_string());
        }
    }

    // Check TLS 1.2
    if let Ok(stream) = TcpStream::connect_timeout(&socket_addr, timeout) {
        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();
        let inspector = TlsInspector::with_version(sni, "1.2");
        if inspector.inspect(stream).is_ok() {
            supported.push("TLS 1.2".to_string());
        }
    }

    supported
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target() {
        let (host, port) = parse_target("example.com");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);

        let (host, port) = parse_target("example.com:8443");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);

        let (host, port) = parse_target("https://example.com/path");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_probe_builder() {
        let probe = ServerProbe::new()
            .with_timeout(Duration::from_secs(30))
            .with_protocol_check(false)
            .with_lint(true)
            .with_sni("example.com");

        assert_eq!(probe.timeout, Duration::from_secs(30));
        assert!(!probe.check_protocols);
        assert!(probe.lint_certs);
        assert_eq!(probe.sni_hostname, Some("example.com".to_string()));
    }
}
