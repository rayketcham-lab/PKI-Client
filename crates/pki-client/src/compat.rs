//! Compatibility layer for pki-client.
//!
//! This module provides adapter types and functions that bridge the gap between
//! pki-client's expected API and the actual spork-core/pki-probe/pki-client-output APIs.

use anyhow::{anyhow, Context, Result};
use std::net::IpAddr;
use std::path::Path;
use url::Url;
use x509_parser::prelude::FromDer;

/// Validate a URL for SSRF safety before making a request.
///
/// This prevents Server-Side Request Forgery attacks where malicious certificates
/// could contain URLs pointing to internal services.
fn validate_url_for_ssrf(url_str: &str) -> Result<()> {
    let url = Url::parse(url_str).map_err(|e| anyhow!("Invalid URL '{}': {}", url_str, e))?;

    // Only allow HTTP and HTTPS schemes
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(anyhow!(
                "Unsafe URL scheme '{}' - only http/https allowed",
                scheme
            ));
        }
    }

    // Check host
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL missing host: {}", url_str))?;

    // Reject localhost and loopback
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" {
        return Err(anyhow!("URL points to localhost: {}", url_str));
    }

    // Try to parse as IP address and check for private ranges
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(&ip) {
            return Err(anyhow!(
                "URL points to private/internal IP address: {}",
                url_str
            ));
        }
    }

    // Check for common internal hostnames
    let host_lower = host.to_lowercase();
    if host_lower.ends_with(".local")
        || host_lower.ends_with(".internal")
        || host_lower.ends_with(".localdomain")
        || host_lower == "metadata.google.internal"
        || host_lower == "169.254.169.254"
    // Cloud metadata endpoint
    {
        return Err(anyhow!("URL points to internal hostname: {}", url_str));
    }

    // Check for suspicious ports (common internal services)
    if let Some(port) = url.port() {
        // Block common database/internal service ports
        let blocked_ports = [
            6379,  // Redis
            5432,  // PostgreSQL
            3306,  // MySQL
            27017, // MongoDB
            9200,  // Elasticsearch
            11211, // Memcached
            2379,  // etcd
            8500,  // Consul
            22,    // SSH
            23,    // Telnet
        ];
        if blocked_ports.contains(&port) {
            return Err(anyhow!(
                "URL uses blocked port {} (internal service): {}",
                port,
                url_str
            ));
        }
    }

    Ok(())
}

/// Check if an IP address is in a private/reserved range
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback()           // 127.0.0.0/8
                || ipv4.is_private()      // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || ipv4.is_link_local()   // 169.254.0.0/16
                || ipv4.is_broadcast()    // 255.255.255.255
                || ipv4.is_documentation() // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
                || ipv4.is_unspecified()  // 0.0.0.0
                || ipv4.octets()[0] == 100 && (ipv4.octets()[1] & 0xC0) == 64 // 100.64.0.0/10 (CGNAT)
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()        // ::1
                || ipv6.is_unspecified() // ::
                // Check for IPv4-mapped addresses (::ffff:x.x.x.x)
                || {
                    let segments = ipv6.segments();
                    segments[0..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff
                        && is_private_ip(&IpAddr::V4(std::net::Ipv4Addr::new(
                            (segments[6] >> 8) as u8,
                            segments[6] as u8,
                            (segments[7] >> 8) as u8,
                            segments[7] as u8,
                        )))
                }
                // Unique local addresses (fc00::/7)
                || (ipv6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local (fe80::/10)
                || (ipv6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

// Re-export types from pki_client_output and pki_probe
pub use pki_client_output::Certificate;
pub use pki_probe::{CertLinter, LintSeverity, ServerProbe};

/// Detected file type for PKI files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Variants defined for API completeness
pub enum DetectedFileType {
    /// X.509 Certificate
    Certificate,
    /// Certificate Signing Request
    Csr,
    /// Private Key
    PrivateKey,
    /// Public Key
    PublicKey,
    /// Certificate Revocation List
    Crl,
    /// PKCS#7/CMS structure
    Pkcs7,
    /// PKCS#12/PFX container
    Pkcs12,
    /// Unknown/unrecognized
    Unknown,
}

impl std::fmt::Display for DetectedFileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Certificate => write!(f, "Certificate"),
            Self::Csr => write!(f, "CSR"),
            Self::PrivateKey => write!(f, "Private Key"),
            Self::PublicKey => write!(f, "Public Key"),
            Self::Crl => write!(f, "CRL"),
            Self::Pkcs7 => write!(f, "PKCS#7"),
            Self::Pkcs12 => write!(f, "PKCS#12"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Detection result with confidence score.
#[allow(dead_code)] // Fields defined for API completeness
pub struct DetectionResult {
    /// Detected file type.
    pub file_type: DetectedFileType,
    /// Confidence score (0-100).
    pub confidence: u8,
}

impl DetectedFileType {
    /// Detect file type with confidence score.
    pub fn detect_with_confidence(data: &[u8], _path: &std::path::Path) -> DetectionResult {
        // Check PEM headers first (high confidence)
        if let Ok(text) = std::str::from_utf8(data) {
            if text.contains("-----BEGIN CERTIFICATE-----") {
                return DetectionResult {
                    file_type: Self::Certificate,
                    confidence: 100,
                };
            }
            if text.contains("-----BEGIN CERTIFICATE REQUEST-----")
                || text.contains("-----BEGIN NEW CERTIFICATE REQUEST-----")
            {
                return DetectionResult {
                    file_type: Self::Csr,
                    confidence: 100,
                };
            }
            if text.contains("-----BEGIN PRIVATE KEY-----")
                || text.contains("-----BEGIN RSA PRIVATE KEY-----")
                || text.contains("-----BEGIN EC PRIVATE KEY-----")
            {
                return DetectionResult {
                    file_type: Self::PrivateKey,
                    confidence: 100,
                };
            }
            if text.contains("-----BEGIN X509 CRL-----") {
                return DetectionResult {
                    file_type: Self::Crl,
                    confidence: 100,
                };
            }
        }

        // Try DER parsing — certificate first, then CSR
        if data.len() > 2 && data[0] == 0x30 {
            if x509_parser::parse_x509_certificate(data).is_ok() {
                return DetectionResult {
                    file_type: Self::Certificate,
                    confidence: 90,
                };
            }
            if x509_parser::certification_request::X509CertificationRequest::from_der(data).is_ok()
            {
                return DetectionResult {
                    file_type: Self::Csr,
                    confidence: 90,
                };
            }

            // Try PKCS#8 PrivateKeyInfo: SEQUENCE { INTEGER(0), SEQUENCE(AlgId), OCTET STRING }
            if is_pkcs8_private_key(data) {
                return DetectionResult {
                    file_type: Self::PrivateKey,
                    confidence: 85,
                };
            }
        }

        DetectionResult {
            file_type: Self::Unknown,
            confidence: 0,
        }
    }
}

/// Check if DER data looks like a PKCS#8 PrivateKeyInfo structure.
///
/// PKCS#8 PrivateKeyInfo is: SEQUENCE { version INTEGER, algorithmIdentifier SEQUENCE, privateKey OCTET STRING }
/// We validate the outer SEQUENCE tag, skip the length encoding, then check for
/// version INTEGER(0) followed by an AlgorithmIdentifier SEQUENCE.
fn is_pkcs8_private_key(data: &[u8]) -> bool {
    // Must start with SEQUENCE tag (0x30)
    if data.len() < 10 || data[0] != 0x30 {
        return false;
    }

    // Skip the outer SEQUENCE length to get to the body
    let body = match skip_der_tag_and_length(data) {
        Some(b) => b,
        None => return false,
    };

    // First element: version INTEGER = 0 → encoded as 0x02 0x01 0x00
    if body.len() < 5 || body[0] != 0x02 || body[1] != 0x01 || body[2] != 0x00 {
        return false;
    }

    // Second element: AlgorithmIdentifier SEQUENCE (tag 0x30)
    body[3] == 0x30
}

/// Skip the DER tag and length bytes, returning the body.
fn skip_der_tag_and_length(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 2 {
        return None;
    }
    // Skip tag byte
    let len_byte = data[1];
    if len_byte < 0x80 {
        // Short form: length in a single byte
        data.get(2..)
    } else {
        // Long form: number of length bytes encoded in low 7 bits
        let num_len_bytes = (len_byte & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 {
            return None;
        }
        data.get(2 + num_len_bytes..)
    }
}

/// Load a certificate from a file.
pub fn load_certificate(path: &Path) -> Result<Certificate> {
    let data = std::fs::read_to_string(path)
        .or_else(|_| {
            // Try binary read
            std::fs::read(path).map(|bytes| {
                if bytes.starts_with(b"-----BEGIN") {
                    String::from_utf8_lossy(&bytes).to_string()
                } else {
                    // DER encoded - convert to base64 for PEM-style parsing
                    format!(
                        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes)
                    )
                }
            })
        })
        .map_err(|e| anyhow!("Failed to read certificate file: {e}"))?;

    // Try PEM first
    if data.contains("-----BEGIN") {
        Certificate::from_pem(&data).map_err(|e| anyhow!("{e}"))
    } else {
        // Try DER
        let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data.trim())
            .unwrap_or_else(|_| data.as_bytes().to_vec());
        Certificate::from_der(&der).map_err(|e| anyhow!("{e}"))
    }
}

/// Detect file type from content.
#[allow(dead_code)] // Available for future use
pub fn detect_file_type(path: &Path) -> Result<DetectedFileType> {
    let data = std::fs::read(path).map_err(|e| anyhow!("Failed to read file: {e}"))?;

    // Check PEM headers
    if let Ok(text) = std::str::from_utf8(&data) {
        if text.contains("-----BEGIN CERTIFICATE-----") {
            return Ok(DetectedFileType::Certificate);
        }
        if text.contains("-----BEGIN CERTIFICATE REQUEST-----")
            || text.contains("-----BEGIN NEW CERTIFICATE REQUEST-----")
        {
            return Ok(DetectedFileType::Csr);
        }
        if text.contains("-----BEGIN PRIVATE KEY-----")
            || text.contains("-----BEGIN RSA PRIVATE KEY-----")
            || text.contains("-----BEGIN EC PRIVATE KEY-----")
            || text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        {
            return Ok(DetectedFileType::PrivateKey);
        }
        if text.contains("-----BEGIN PUBLIC KEY-----")
            || text.contains("-----BEGIN RSA PUBLIC KEY-----")
        {
            return Ok(DetectedFileType::PublicKey);
        }
        if text.contains("-----BEGIN X509 CRL-----") {
            return Ok(DetectedFileType::Crl);
        }
        if text.contains("-----BEGIN PKCS7-----") || text.contains("-----BEGIN CMS-----") {
            return Ok(DetectedFileType::Pkcs7);
        }
    }

    // Check DER by trying to parse
    if data.len() > 2 && data[0] == 0x30 {
        // SEQUENCE tag - could be certificate, CRL, etc.
        if x509_parser::parse_x509_certificate(&data).is_ok() {
            return Ok(DetectedFileType::Certificate);
        }
        // Try other types...
        return Ok(DetectedFileType::Unknown);
    }

    Ok(DetectedFileType::Unknown)
}

// ============================================================================
// Revocation checking stubs
// ============================================================================

/// Revocation status
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[allow(dead_code)] // Variants defined for API completeness
pub enum RevocationStatus {
    /// Certificate is good
    Good,
    /// Certificate is revoked
    Revoked {
        /// Revocation reason
        reason: Option<String>,
        /// Revocation time
        revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    },
    /// Status unknown
    Unknown {
        /// Reason status is unknown
        reason: String,
    },
    /// Error checking status
    Error(String),
}

impl std::fmt::Display for RevocationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Good => write!(f, "Good"),
            Self::Revoked { reason, .. } => {
                if let Some(r) = reason {
                    write!(f, "Revoked ({r})")
                } else {
                    write!(f, "Revoked")
                }
            }
            Self::Unknown { reason } => write!(f, "Unknown: {reason}"),
            Self::Error(e) => write!(f, "Error: {e}"),
        }
    }
}

impl RevocationStatus {
    /// Get exit code for shell scripting.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Good => 0,
            Self::Revoked { .. } => 1,
            Self::Unknown { .. } => 2,
            Self::Error(_) => 3,
        }
    }
}

/// OCSP checker - checks certificate revocation status via OCSP responders.
pub struct OcspChecker {
    timeout: std::time::Duration,
    client: reqwest::blocking::Client,
}

impl OcspChecker {
    /// Create a new OCSP checker with default timeout.
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());

        Self {
            timeout: std::time::Duration::from_secs(10),
            client,
        }
    }

    /// Set the timeout.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self.client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        self
    }

    /// Check certificate revocation status using OCSP responder URLs from the certificate.
    pub fn check(&self, cert: &Certificate, issuer: &Certificate) -> Result<RevocationStatus> {
        // Get OCSP responder URLs from certificate
        if cert.ocsp_urls.is_empty() {
            return Ok(RevocationStatus::Unknown {
                reason: "No OCSP responder URLs in certificate".to_string(),
            });
        }

        // Try each OCSP responder until one works
        let mut last_error = String::new();
        for url in &cert.ocsp_urls {
            match self.check_url(cert, issuer, url) {
                Ok(status) => return Ok(status),
                Err(e) => {
                    last_error = e.to_string();
                    continue;
                }
            }
        }

        Ok(RevocationStatus::Unknown {
            reason: format!("Failed to check all OCSP responders: {}", last_error),
        })
    }

    /// Check certificate revocation status using a specific OCSP responder URL.
    pub fn check_url(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
        url: &str,
    ) -> Result<RevocationStatus> {
        // SECURITY: Validate URL to prevent SSRF attacks
        validate_url_for_ssrf(url)
            .with_context(|| format!("OCSP URL validation failed for {}", url))?;

        // Build OCSP request
        let request_der = self.build_ocsp_request(cert, issuer)?;

        // Send OCSP request via HTTP POST
        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/ocsp-request")
            .header("Accept", "application/ocsp-response")
            .body(request_der)
            .send()
            .with_context(|| format!("Failed to send OCSP request to {}", url))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "OCSP responder returned HTTP {}: {}",
                response.status(),
                url
            ));
        }

        let response_der = response
            .bytes()
            .with_context(|| format!("Failed to read OCSP response from {}", url))?;

        // Parse OCSP response
        self.parse_ocsp_response(&response_der)
    }

    /// Build a DER-encoded OCSP request.
    fn build_ocsp_request(&self, cert: &Certificate, issuer: &Certificate) -> Result<Vec<u8>> {
        use sha1::Digest as _;

        // Get issuer name hash (SHA-1 for maximum compatibility)
        // We need the DER encoding of the issuer's subject name
        // Parse the issuer cert to get the raw subject DER
        let (_, issuer_x509) = x509_parser::parse_x509_certificate(&issuer.der)
            .map_err(|e| anyhow!("Failed to parse issuer certificate: {}", e))?;

        let issuer_name_der = issuer_x509.subject.as_raw();
        let issuer_key_der = &issuer_x509.public_key().subject_public_key.data;

        let issuer_name_hash = sha1::Sha1::digest(issuer_name_der);
        let issuer_key_hash = sha1::Sha1::digest(issuer_key_der.as_ref());

        // Parse serial number from hex string to bytes
        let serial_bytes =
            hex::decode(&cert.serial).unwrap_or_else(|_| cert.serial.as_bytes().to_vec());

        // Build CertID
        // CertID ::= SEQUENCE {
        //   hashAlgorithm  AlgorithmIdentifier (SHA-1),
        //   issuerNameHash OCTET STRING,
        //   issuerKeyHash  OCTET STRING,
        //   serialNumber   CertificateSerialNumber
        // }
        let mut cert_id = Vec::new();

        // AlgorithmIdentifier for SHA-1: SEQUENCE { OID, NULL }
        // SHA-1 OID: 1.3.14.3.2.26
        let sha1_algo = vec![
            0x30, 0x07, // SEQUENCE, length 7
            0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02,
            0x1A, // OID
                  // Note: NULL is optional for SHA-1
        ];
        cert_id.extend_from_slice(&sha1_algo);

        // issuerNameHash OCTET STRING
        cert_id.push(0x04);
        cert_id.push(issuer_name_hash.len() as u8);
        cert_id.extend_from_slice(&issuer_name_hash);

        // issuerKeyHash OCTET STRING
        cert_id.push(0x04);
        cert_id.push(issuer_key_hash.len() as u8);
        cert_id.extend_from_slice(&issuer_key_hash);

        // serialNumber INTEGER
        cert_id.push(0x02);
        self.encode_length(&mut cert_id, serial_bytes.len());
        cert_id.extend_from_slice(&serial_bytes);

        // Wrap CertID in SEQUENCE
        let mut cert_id_seq = vec![0x30];
        self.encode_length(&mut cert_id_seq, cert_id.len());
        cert_id_seq.extend_from_slice(&cert_id);

        // Build Request (just CertID, no extensions)
        // Request ::= SEQUENCE { reqCert CertID }
        let mut request = vec![0x30];
        self.encode_length(&mut request, cert_id_seq.len());
        request.extend_from_slice(&cert_id_seq);

        // Build requestList (SEQUENCE OF Request)
        let mut request_list = vec![0x30];
        self.encode_length(&mut request_list, request.len());
        request_list.extend_from_slice(&request);

        // Build TBSRequest (just requestList, no version/requestorName/extensions)
        let mut tbs_request = vec![0x30];
        self.encode_length(&mut tbs_request, request_list.len());
        tbs_request.extend_from_slice(&request_list);

        // Build OCSPRequest (just tbsRequest, no signature)
        let mut ocsp_request = vec![0x30];
        self.encode_length(&mut ocsp_request, tbs_request.len());
        ocsp_request.extend_from_slice(&tbs_request);

        Ok(ocsp_request)
    }

    /// Parse OCSP response and extract certificate status.
    fn parse_ocsp_response(&self, data: &[u8]) -> Result<RevocationStatus> {
        // OCSPResponse ::= SEQUENCE {
        //   responseStatus  OCSPResponseStatus,
        //   responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL
        // }
        if data.len() < 3 {
            return Err(anyhow!("OCSP response too short"));
        }

        // Check for SEQUENCE tag
        if data[0] != 0x30 {
            return Err(anyhow!("Invalid OCSP response format"));
        }

        // Parse outer SEQUENCE length
        let (content_start, _) = self.parse_length(&data[1..])?;
        let content = &data[1 + content_start..];

        // Parse responseStatus (ENUMERATED)
        if content.is_empty() || content[0] != 0x0A {
            return Err(anyhow!("Missing response status"));
        }

        let status_len = content[1] as usize;
        if content.len() < 2 + status_len {
            return Err(anyhow!("Invalid response status length"));
        }

        let status = content[2];

        // Check response status
        match status {
            0 => {} // Successful, continue parsing
            1 => return Err(anyhow!("OCSP: Malformed request")),
            2 => return Err(anyhow!("OCSP: Internal error")),
            3 => return Err(anyhow!("OCSP: Try later")),
            5 => return Err(anyhow!("OCSP: Signature required")),
            6 => return Err(anyhow!("OCSP: Unauthorized")),
            _ => return Err(anyhow!("OCSP: Unknown response status {}", status)),
        }

        // Parse responseBytes [0] EXPLICIT
        let response_bytes_start = 2 + status_len;
        if content.len() <= response_bytes_start {
            return Err(anyhow!("Missing response bytes"));
        }

        let rest = &content[response_bytes_start..];
        if rest.is_empty() || rest[0] != 0xA0 {
            return Err(anyhow!("Missing response bytes tag"));
        }

        // Parse through the nested structures to find certStatus
        // This is a simplified parser - we look for the certStatus tag patterns
        // [0] IMPLICIT NULL = good (0x80 0x00)
        // [1] IMPLICIT RevokedInfo = revoked (0xA1 ...)
        // [2] IMPLICIT UnknownInfo = unknown (0x82 0x00)

        // Search for cert status markers in the response
        for i in 0..rest.len().saturating_sub(1) {
            match rest[i] {
                0x80 if rest.get(i + 1) == Some(&0x00) => {
                    // Good
                    return Ok(RevocationStatus::Good);
                }
                0xA1 => {
                    // Revoked - extract revocation time if possible
                    // RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime, ... }
                    return Ok(RevocationStatus::Revoked {
                        reason: Some("Revoked".to_string()),
                        revoked_at: None, // Would need deeper parsing
                    });
                }
                0x82 if rest.get(i + 1) == Some(&0x00) => {
                    // Unknown
                    return Ok(RevocationStatus::Unknown {
                        reason: "OCSP responder returned unknown status".to_string(),
                    });
                }
                _ => {}
            }
        }

        // If we couldn't find a clear status, return unknown
        Ok(RevocationStatus::Unknown {
            reason: "Could not parse certificate status from OCSP response".to_string(),
        })
    }

    /// Encode ASN.1 length.
    fn encode_length(&self, buf: &mut Vec<u8>, len: usize) {
        if len < 128 {
            buf.push(len as u8);
        } else if len < 256 {
            buf.push(0x81);
            buf.push(len as u8);
        } else if len < 65536 {
            buf.push(0x82);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        } else {
            buf.push(0x83);
            buf.push((len >> 16) as u8);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        }
    }

    /// Parse ASN.1 length and return (bytes_consumed, length_value).
    fn parse_length(&self, data: &[u8]) -> Result<(usize, usize)> {
        if data.is_empty() {
            return Err(anyhow!("Empty length field"));
        }

        if data[0] < 128 {
            Ok((1, data[0] as usize))
        } else {
            let num_bytes = (data[0] & 0x7F) as usize;
            if data.len() < 1 + num_bytes {
                return Err(anyhow!("Truncated length field"));
            }

            let mut len = 0usize;
            for i in 0..num_bytes {
                len = (len << 8) | (data[1 + i] as usize);
            }

            Ok((1 + num_bytes, len))
        }
    }
}

impl Default for OcspChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// CRL checker - checks certificate revocation status via CRL distribution points.
pub struct CrlChecker {
    timeout: u64,
    client: reqwest::blocking::Client,
}

impl CrlChecker {
    /// Create a new CRL checker with default timeout.
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());

        Self {
            timeout: 10,
            client,
        }
    }

    /// Set the timeout in seconds.
    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        // Rebuild client with new timeout
        self.client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        self
    }

    /// Check certificate revocation status using CRL distribution points from the certificate.
    pub fn check(&self, cert: &Certificate) -> Result<RevocationStatus> {
        // Get CRL distribution points from certificate
        if cert.crl_distribution_points.is_empty() {
            return Ok(RevocationStatus::Unknown {
                reason: "No CRL distribution points in certificate".to_string(),
            });
        }

        // Try each CRL distribution point until one works
        let mut last_error = String::new();
        for url in &cert.crl_distribution_points {
            match self.check_url(cert, url) {
                Ok(status) => return Ok(status),
                Err(e) => {
                    last_error = e.to_string();
                    continue;
                }
            }
        }

        Ok(RevocationStatus::Unknown {
            reason: format!(
                "Failed to check all CRL distribution points: {}",
                last_error
            ),
        })
    }

    /// Check certificate revocation status using a specific CRL URL.
    pub fn check_url(&self, cert: &Certificate, url: &str) -> Result<RevocationStatus> {
        // Download CRL
        let crl_data = self.download_crl(url)?;

        // Parse CRL
        let crl = if crl_data.starts_with(b"-----BEGIN") {
            Crl::from_pem(&crl_data).map_err(|e| anyhow!("Failed to parse CRL: {}", e))?
        } else {
            Crl::from_der(&crl_data).map_err(|e| anyhow!("Failed to parse CRL: {}", e))?
        };

        // Check if CRL is expired (optional warning, still check)
        if crl.is_expired() {
            // CRL is expired, but we can still check if cert is in it
            // Log warning but continue
        }

        // Normalize certificate serial for comparison
        // Certificate serial is stored as hex string, e.g., "abc123"
        // CRL revoked cert serial is also stored as hex string
        let cert_serial = cert
            .serial
            .to_lowercase()
            .trim_start_matches('0')
            .to_string();

        // Check if certificate serial is in the revoked list
        for revoked in &crl.revoked_certificates {
            // Normalize the revoked serial for comparison
            let revoked_serial = revoked
                .serial
                .to_lowercase()
                .replace(":", "")
                .trim_start_matches('0')
                .to_string();

            if cert_serial == revoked_serial
                || cert.serial.to_lowercase() == revoked.serial.to_lowercase()
            {
                return Ok(RevocationStatus::Revoked {
                    reason: revoked.reason.clone(),
                    revoked_at: Some(revoked.revocation_date),
                });
            }
        }

        Ok(RevocationStatus::Good)
    }

    /// Download CRL from URL.
    fn download_crl(&self, url: &str) -> Result<Vec<u8>> {
        // SECURITY: Validate URL to prevent SSRF attacks
        validate_url_for_ssrf(url)
            .with_context(|| format!("CRL URL validation failed for {}", url))?;

        let response = self
            .client
            .get(url)
            .header("Accept", "application/pkix-crl, application/x-pkcs7-crl")
            .send()
            .with_context(|| format!("Failed to download CRL from {}", url))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to download CRL: HTTP {} from {}",
                response.status(),
                url
            ));
        }

        let bytes = response
            .bytes()
            .with_context(|| format!("Failed to read CRL response from {}", url))?;

        Ok(bytes.to_vec())
    }
}

impl Default for CrlChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Combined revocation checker
pub struct RevocationChecker {
    pub ocsp: OcspChecker,
    pub crl: CrlChecker,
}

impl RevocationChecker {
    pub fn new() -> Self {
        Self {
            ocsp: OcspChecker::new(),
            crl: CrlChecker::new(),
        }
    }

    pub fn check(&self, cert: &Certificate, issuer: Option<&Certificate>) -> RevocationStatus {
        // Try OCSP first, then CRL
        if let Some(issuer) = issuer {
            if let Ok(status) = self.ocsp.check(cert, issuer) {
                return status;
            }
        }
        if let Ok(status) = self.crl.check(cert) {
            return status;
        }
        RevocationStatus::Unknown {
            reason: "No revocation information available".to_string(),
        }
    }
}

impl Default for RevocationChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Revocation check method used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RevocationMethod {
    /// OCSP check
    Ocsp,
    /// CRL check
    Crl,
    /// Both methods checked
    Both,
}

impl std::fmt::Display for RevocationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ocsp => write!(f, "OCSP"),
            Self::Crl => write!(f, "CRL"),
            Self::Both => write!(f, "OCSP+CRL"),
        }
    }
}

/// Result of a revocation check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RevocationCheckResult {
    /// Revocation status
    pub status: RevocationStatus,
    /// Method used to check
    pub method: RevocationMethod,
    /// Response time in milliseconds
    pub response_time_ms: Option<u64>,
    /// URL checked (if applicable)
    pub url: Option<String>,
    /// Alias for url field
    pub source_url: Option<String>,
    /// When the check was performed
    pub checked_at: chrono::DateTime<chrono::Utc>,
    /// When the response is valid until
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Certificate serial number
    pub serial: String,
    /// Certificate subject
    pub subject: String,
}

// ============================================================================
// Chain building stubs
// ============================================================================

/// Chain builder result
#[allow(dead_code)] // Fields defined for API completeness
pub struct ChainBuildResult {
    pub chain: Vec<Certificate>,
    pub complete: bool,
    pub trusted: bool,
    pub warnings: Vec<String>,
}

/// Chain builder - builds certificate chains from a leaf to trust anchors.
#[derive(Clone)]
pub struct ChainBuilder {
    intermediates: Vec<Certificate>,
    trust_anchors: Vec<Certificate>,
    follow_aia_enabled: bool,
    use_system_trust: bool,
    max_chain_length: usize,
    client: Option<reqwest::blocking::Client>,
}

impl ChainBuilder {
    /// Create a new chain builder.
    pub fn new() -> Self {
        Self {
            intermediates: Vec::new(),
            trust_anchors: Vec::new(),
            follow_aia_enabled: true,
            use_system_trust: false,
            max_chain_length: 10,
            client: None,
        }
    }

    /// Enable or disable following AIA URLs to fetch intermediates.
    pub fn follow_aia(mut self, enable: bool) -> Self {
        self.follow_aia_enabled = enable;
        if enable && self.client.is_none() {
            self.client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .ok();
        }
        self
    }

    /// Load trust anchors from a PEM bundle file.
    pub fn with_trust_bundle(mut self, path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read trust bundle: {}", path.display()))?;
        let certs = Certificate::all_from_pem(&data)
            .map_err(|e| anyhow!("Failed to parse trust bundle: {}", e))?;
        self.trust_anchors.extend(certs);
        Ok(self)
    }

    /// Use system trust store (loads certificates from well-known locations).
    pub fn with_system_trust(mut self) -> Result<Self> {
        self.use_system_trust = true;
        // Try to load from common system paths
        let system_paths = [
            "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
            "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/CentOS
            "/etc/ssl/ca-bundle.pem",             // OpenSUSE
            "/etc/ssl/cert.pem",                  // Alpine, macOS
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // Fedora
        ];

        for path in &system_paths {
            let path = Path::new(path);
            if path.exists() {
                if let Ok(data) = std::fs::read_to_string(path) {
                    if let Ok(certs) = Certificate::all_from_pem(&data) {
                        self.trust_anchors.extend(certs);
                        break;
                    }
                }
            }
        }

        Ok(self)
    }

    /// Add an intermediate certificate to use when building chains.
    #[allow(dead_code)] // Available for future use
    pub fn add_intermediate(&mut self, cert: Certificate) {
        self.intermediates.push(cert);
    }

    /// Add a trust anchor (root CA certificate).
    #[allow(dead_code)] // Available for future use
    pub fn add_trust_anchor(&mut self, cert: Certificate) {
        self.trust_anchors.push(cert);
    }

    /// Build a certificate chain from the leaf certificate.
    pub fn build(&self, leaf: &Certificate) -> Result<ChainBuildResult> {
        let mut chain = vec![leaf.clone()];
        let mut warnings = Vec::new();
        let mut current = leaf.clone();

        // Keep building until we find a trust anchor or can't continue
        while chain.len() < self.max_chain_length {
            // Check if current cert is self-signed (root)
            if current.is_self_signed() {
                break;
            }

            // Check if current cert's issuer is a trust anchor
            if let Some(anchor) = self.find_issuer_in(&current, &self.trust_anchors) {
                chain.push(anchor);
                break;
            }

            // Try to find issuer in provided intermediates
            if let Some(issuer) = self.find_issuer_in(&current, &self.intermediates) {
                chain.push(issuer.clone());
                current = issuer;
                continue;
            }

            // Try to fetch issuer via AIA if enabled
            if self.follow_aia_enabled {
                if let Some(issuer) = self.fetch_issuer_via_aia(&current) {
                    chain.push(issuer.clone());
                    current = issuer;
                    continue;
                }
            }

            // Couldn't find issuer
            warnings.push(format!("Could not find issuer for: {}", current.subject));
            break;
        }

        // Check if chain is complete and trusted
        let last = chain.last().unwrap();
        let complete = last.is_self_signed() || self.is_trust_anchor(last);
        let trusted = self.is_trust_anchor(last);

        if chain.len() >= self.max_chain_length {
            warnings.push("Chain building stopped: maximum length reached".to_string());
        }

        Ok(ChainBuildResult {
            chain,
            complete,
            trusted,
            warnings,
        })
    }

    /// Find the issuer certificate in a collection.
    fn find_issuer_in(
        &self,
        cert: &Certificate,
        collection: &[Certificate],
    ) -> Option<Certificate> {
        for candidate in collection {
            if self.is_issuer_of(candidate, cert) {
                return Some(candidate.clone());
            }
        }
        None
    }

    /// Check if candidate is the issuer of cert.
    fn is_issuer_of(&self, candidate: &Certificate, cert: &Certificate) -> bool {
        // Check if candidate's subject matches cert's issuer
        if candidate.subject != cert.issuer {
            return false;
        }

        // Check key identifiers if available
        if let (Some(ref ski), Some(ref aki)) = (&candidate.subject_key_id, &cert.authority_key_id)
        {
            return ski == aki;
        }

        // Fallback: just check subject/issuer match
        true
    }

    /// Check if certificate is in the trust anchor list.
    fn is_trust_anchor(&self, cert: &Certificate) -> bool {
        for anchor in &self.trust_anchors {
            if anchor.fingerprint_sha256 == cert.fingerprint_sha256 {
                return true;
            }
        }
        false
    }

    /// Fetch issuer certificate via AIA CA Issuers URL.
    fn fetch_issuer_via_aia(&self, cert: &Certificate) -> Option<Certificate> {
        let client = self.client.as_ref()?;

        for url in &cert.ca_issuer_urls {
            if let Ok(response) = client.get(url).send() {
                if response.status().is_success() {
                    if let Ok(bytes) = response.bytes() {
                        // Try to parse as DER
                        if let Ok(issuer) = Certificate::from_der(&bytes) {
                            return Some(issuer);
                        }
                        // Try to parse as PEM
                        if let Ok(text) = std::str::from_utf8(&bytes) {
                            if let Ok(issuer) = Certificate::from_pem(text) {
                                return Some(issuer);
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

impl Default for ChainBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Chain validation result
pub struct ChainValidation {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub trusted_root: Option<Certificate>,
    trust_store: Option<TrustStore>,
    skip_time: bool,
}

impl ChainValidation {
    pub fn new() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            trusted_root: None,
            trust_store: None,
            skip_time: false,
        }
    }

    pub fn with_trust_store(mut self, store: TrustStore) -> Self {
        self.trust_store = Some(store);
        self
    }

    pub fn skip_time_check(mut self) -> Self {
        self.skip_time = true;
        self
    }

    pub fn validate(&self, chain: &[Certificate]) -> Self {
        // Convert compat Certificate DER bytes for spork-core validation
        let chain_der: Vec<&[u8]> = chain.iter().map(|c| c.raw_der()).collect();

        // Collect trust anchor DER bytes
        let trust_anchors: Vec<Vec<u8>> = self
            .trust_store
            .as_ref()
            .map(|ts| {
                ts.certificates()
                    .iter()
                    .map(|c| c.raw_der().to_vec())
                    .collect()
            })
            .unwrap_or_default();

        let mut options = spork_core::ChainValidationOptions::default();
        if self.skip_time {
            options.check_validity = false;
        }
        let result = spork_core::validate_chain_der(&chain_der, &trust_anchors, &options);

        let trusted_root = if result.valid {
            chain.last().cloned()
        } else {
            None
        };

        Self {
            valid: result.valid,
            errors: result.errors,
            warnings: result.warnings,
            trusted_root,
            trust_store: None,
            skip_time: false,
        }
    }
}

impl Default for ChainValidation {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Trust store stubs
// ============================================================================

/// Trust store (stub implementation)
#[allow(dead_code)] // Available for future use
pub struct TrustStore {
    certificates: Vec<Certificate>,
}

#[allow(dead_code)] // Methods available for future use
impl TrustStore {
    pub fn new() -> Self {
        Self {
            certificates: Vec::new(),
        }
    }

    pub fn system() -> Result<Self> {
        let mut store = Self::new();
        store.load_system()?;
        Ok(store)
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let mut store = Self::new();
        store.load_pem_bundle(path)?;
        Ok(store)
    }

    pub fn load_system(&mut self) -> Result<()> {
        let system_paths = [
            "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
            "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/CentOS
            "/etc/ssl/ca-bundle.pem",             // OpenSUSE
            "/etc/ssl/cert.pem",                  // Alpine, macOS
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // Fedora
        ];

        for path in &system_paths {
            let path = Path::new(path);
            if path.exists() {
                return self.load_pem_bundle(path);
            }
        }

        Ok(()) // No system trust store found — empty store
    }

    pub fn load_pem_bundle(&mut self, path: &Path) -> Result<()> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read trust bundle: {}", path.display()))?;
        let certs = Certificate::all_from_pem(&data)
            .map_err(|e| anyhow!("Failed to parse trust bundle: {e}"))?;
        self.certificates.extend(certs);
        Ok(())
    }

    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }

    pub fn add(&mut self, cert: Certificate) {
        self.certificates.push(cert);
    }
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CRL handling
// ============================================================================

/// CRL structure (stub)
pub struct Crl {
    pub issuer: String,
    pub this_update: chrono::DateTime<chrono::Utc>,
    pub next_update: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_certificates: Vec<RevokedCert>,
    pub version: Option<u8>,
    pub signature_algorithm: String,
    pub signature_oid: String,
    pub authority_key_id: Option<String>,
    pub crl_number: Option<String>,
    pub delta_crl_indicator: Option<String>,
    pub issuing_dist_point: Option<String>,
    pub extensions: Vec<CrlExtension>,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
    der: Vec<u8>,
}

/// CRL extension (stub)
pub struct CrlExtension {
    pub name: String,
    pub critical: bool,
    pub value: String,
}

impl Crl {
    pub fn from_pem(data: &[u8]) -> Result<Self, String> {
        let pem_data = pem::parse(data).map_err(|e| format!("Failed to parse PEM: {e}"))?;
        Self::from_der(pem_data.contents())
    }

    pub fn from_der(der: &[u8]) -> Result<Self, String> {
        let (_, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(der)
            .map_err(|e| format!("Failed to parse CRL: {e}"))?;

        let revoked = crl
            .iter_revoked_certificates()
            .map(|rc| RevokedCert {
                serial: rc.raw_serial_as_string(),
                revocation_date: chrono::DateTime::from_timestamp(
                    rc.revocation_date.timestamp(),
                    0,
                )
                .unwrap_or_else(chrono::Utc::now),
                reason: None,
                invalidity_date: None,
            })
            .collect();

        use sha1::Digest as _;
        let sha256_hash = sha2::Sha256::digest(der);
        let sha1_hash = sha1::Sha1::digest(der);

        fn format_fingerprint(hash: &[u8]) -> String {
            hex::encode(hash)
                .to_uppercase()
                .chars()
                .collect::<Vec<char>>()
                .chunks(2)
                .map(|c: &[char]| c.iter().collect::<String>())
                .collect::<Vec<String>>()
                .join(":")
        }

        let fingerprint_sha256 = format_fingerprint(&sha256_hash);
        let fingerprint_sha1 = format_fingerprint(&sha1_hash);

        // Access fields through the TBS (To-Be-Signed) structure
        let tbs = &crl.tbs_cert_list;
        let version = tbs.version.map(|v| v.0 as u8);

        Ok(Crl {
            issuer: tbs.issuer.to_string(),
            this_update: chrono::DateTime::from_timestamp(tbs.this_update.timestamp(), 0)
                .unwrap_or_else(chrono::Utc::now),
            next_update: tbs
                .next_update
                .and_then(|t| chrono::DateTime::from_timestamp(t.timestamp(), 0)),
            revoked_certificates: revoked,
            version,
            signature_algorithm: crl.signature_algorithm.algorithm.to_string(),
            signature_oid: crl.signature_algorithm.algorithm.to_string(),
            authority_key_id: None,
            crl_number: None,
            delta_crl_indicator: None,
            issuing_dist_point: None,
            extensions: Vec::new(),
            fingerprint_sha256,
            fingerprint_sha1,
            der: der.to_vec(),
        })
    }

    pub fn revoked_count(&self) -> usize {
        self.revoked_certificates.len()
    }

    pub fn raw_der(&self) -> &[u8] {
        &self.der
    }

    pub fn is_expired(&self) -> bool {
        if let Some(next) = self.next_update {
            chrono::Utc::now() > next
        } else {
            false
        }
    }

    pub fn days_until_next_update(&self) -> Option<i64> {
        self.next_update
            .map(|next| (next - chrono::Utc::now()).num_days())
    }
}

/// Revoked certificate entry
pub struct RevokedCert {
    pub serial: String,
    pub revocation_date: chrono::DateTime<chrono::Utc>,
    pub reason: Option<String>,
    pub invalidity_date: Option<chrono::DateTime<chrono::Utc>>,
}

/// Load CRL from file
pub fn load_crl(path: &Path) -> Result<Crl> {
    let data = std::fs::read(path)?;
    if data.starts_with(b"-----BEGIN") {
        Crl::from_pem(&data).map_err(|e| anyhow!("{e}"))
    } else {
        Crl::from_der(&data).map_err(|e| anyhow!("{e}"))
    }
}

// ============================================================================
// CSR handling
// ============================================================================

/// Format an iPAddress GeneralName octet string as a human-readable address.
fn format_ip_bytes(ip: &[u8]) -> String {
    match ip.len() {
        4 => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
        16 => {
            let parts: Vec<String> = ip
                .chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c.get(1).copied().unwrap_or(0)))
                .collect();
            parts.join(":")
        }
        _ => hex::encode(ip),
    }
}

/// CSR structure (stub)
pub struct Csr {
    pub subject: String,
    pub key_algorithm: String,
    pub key_size: Option<u32>,
    pub signature_algorithm: String,
    pub san: Vec<pki_client_output::SanEntry>,
    pub pem: String,
    der: Vec<u8>,
}

impl Csr {
    pub fn from_pem(data: &[u8]) -> Result<Self, String> {
        let pem_data = pem::parse(data).map_err(|e| format!("Failed to parse PEM: {e}"))?;
        let mut csr = Self::from_der(pem_data.contents())?;
        csr.pem = String::from_utf8_lossy(data).to_string();
        Ok(csr)
    }

    pub fn from_der(der: &[u8]) -> Result<Self, String> {
        let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(der)
            .map_err(|e| format!("Failed to parse CSR: {e}"))?;

        let spki = &csr.certification_request_info.subject_pki;
        let key_algo_oid = spki.algorithm.algorithm.to_string();

        // Derive the true key size by parsing the public key structure rather than
        // using the raw bit-string length, which includes DER encoding overhead.
        let key_size = spki.parsed().ok().and_then(|pk| {
            let bits = pk.key_size();
            if bits > 0 {
                Some(bits as u32)
            } else {
                None
            }
        });

        let sig_algo_oid = csr.signature_algorithm.algorithm.to_string();

        // Extract SAN entries from the extensionRequest attribute (PKCS#10, RFC 2986).
        // Without this, `pki csr show` silently omits SANs even when present.
        let mut san: Vec<pki_client_output::SanEntry> = Vec::new();
        if let Some(extensions) = csr.requested_extensions() {
            for ext in extensions {
                if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(alt) = ext {
                    for gn in &alt.general_names {
                        match gn {
                            x509_parser::prelude::GeneralName::DNSName(v) => {
                                san.push(pki_client_output::SanEntry::Dns((*v).to_string()));
                            }
                            x509_parser::prelude::GeneralName::RFC822Name(v) => {
                                san.push(pki_client_output::SanEntry::Email((*v).to_string()));
                            }
                            x509_parser::prelude::GeneralName::IPAddress(bytes) => {
                                san.push(pki_client_output::SanEntry::Ip(format_ip_bytes(bytes)));
                            }
                            x509_parser::prelude::GeneralName::URI(v) => {
                                san.push(pki_client_output::SanEntry::Uri((*v).to_string()));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok(Csr {
            subject: csr.certification_request_info.subject.to_string(),
            // Resolve the key algorithm OID to a human-readable name.
            key_algorithm: pki_client_output::key_algorithm_name(&key_algo_oid),
            key_size,
            // Resolve the signature algorithm OID to a human-readable name.
            signature_algorithm: pki_client_output::signature_name(&sig_algo_oid),
            san,
            pem: String::new(),
            der: der.to_vec(),
        })
    }

    pub fn raw_der(&self) -> &[u8] {
        &self.der
    }
}

/// Load CSR from file
pub fn load_csr(path: &Path) -> Result<Csr> {
    let data = std::fs::read(path)?;
    if data.starts_with(b"-----BEGIN") {
        Csr::from_pem(&data).map_err(|e| anyhow!("{e}"))
    } else {
        Csr::from_der(&data).map_err(|e| anyhow!("{e}"))
    }
}

/// CSR builder (stub)
#[allow(dead_code)] // Fields defined for API completeness
pub struct CsrBuilder {
    common_name: Option<String>,
    organization: Option<String>,
    organizational_unit: Option<String>,
    locality: Option<String>,
    state: Option<String>,
    country: Option<String>,
    email: Option<String>,
    san_dns: Vec<String>,
    san_ip: Vec<String>,
    san_email: Vec<String>,
}

impl CsrBuilder {
    pub fn new() -> Self {
        Self {
            common_name: None,
            organization: None,
            organizational_unit: None,
            locality: None,
            state: None,
            country: None,
            email: None,
            san_dns: Vec::new(),
            san_ip: Vec::new(),
            san_email: Vec::new(),
        }
    }

    pub fn common_name(mut self, cn: &str) -> Self {
        self.common_name = Some(cn.to_string());
        self
    }

    pub fn organization(mut self, org: &str) -> Self {
        self.organization = Some(org.to_string());
        self
    }

    pub fn organizational_unit(mut self, ou: &str) -> Self {
        self.organizational_unit = Some(ou.to_string());
        self
    }

    pub fn locality(mut self, locality: &str) -> Self {
        self.locality = Some(locality.to_string());
        self
    }

    pub fn state(mut self, state: &str) -> Self {
        self.state = Some(state.to_string());
        self
    }

    pub fn country(mut self, country: &str) -> Self {
        self.country = Some(country.to_string());
        self
    }

    #[allow(dead_code)] // Available for future use
    pub fn email(mut self, email: &str) -> Self {
        self.email = Some(email.to_string());
        self
    }

    #[allow(dead_code)] // Available for future use
    pub fn add_san(mut self, san: &str) -> Self {
        self.san_dns.push(san.to_string());
        self
    }

    pub fn add_dns_san(mut self, dns: &str) -> Self {
        self.san_dns.push(dns.to_string());
        self
    }

    pub fn add_ip_san(mut self, ip: &str) -> Self {
        self.san_ip.push(ip.to_string());
        self
    }

    pub fn add_email_san(mut self, email: &str) -> Self {
        self.san_email.push(email.to_string());
        self
    }

    /// Build the subject string from components.
    fn build_subject(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref cn) = self.common_name {
            parts.push(format!("CN={cn}"));
        }
        if let Some(ref org) = self.organization {
            parts.push(format!("O={org}"));
        }
        if let Some(ref ou) = self.organizational_unit {
            parts.push(format!("OU={ou}"));
        }
        if let Some(ref l) = self.locality {
            parts.push(format!("L={l}"));
        }
        if let Some(ref st) = self.state {
            parts.push(format!("ST={st}"));
        }
        if let Some(ref c) = self.country {
            parts.push(format!("C={c}"));
        }
        parts.join(", ")
    }

    #[allow(dead_code)] // Available for future use
    pub fn build(&self) -> Result<Csr> {
        Err(anyhow!(
            "CSR generation requires a private key. Use build_with_key() instead."
        ))
    }

    /// Build and sign the CSR using the provided private key
    pub fn build_with_key(&self, key: &PrivateKey) -> Result<Csr> {
        // Detect algorithm from key
        let algorithm = match key.algorithm {
            KeyAlgorithm::EcP256 => spork_core::AlgorithmId::EcdsaP256,
            KeyAlgorithm::EcP384 => spork_core::AlgorithmId::EcdsaP384,
            KeyAlgorithm::Rsa(bits) if bits >= 4096 => spork_core::AlgorithmId::Rsa4096,
            KeyAlgorithm::Rsa(_) => spork_core::AlgorithmId::Rsa2048,
            KeyAlgorithm::Ed25519 | KeyAlgorithm::Ed448 => {
                return Err(anyhow!(
                    "Ed25519/Ed448 not yet supported for CSR generation. Use EC P-256/P-384 or RSA."
                ));
            }
            #[cfg(feature = "pqc")]
            KeyAlgorithm::MlDsa(_) | KeyAlgorithm::SlhDsa(_) => {
                return Err(anyhow!(
                    "ML-DSA/SLH-DSA not yet supported for CSR generation."
                ));
            }
        };

        // Load key pair from PEM
        let key_pair = spork_core::KeyPair::from_pem(&key.pem, algorithm)
            .with_context(|| "Failed to parse private key")?;

        // Build distinguished name using spork-core::NameBuilder
        let cn = self.common_name.as_deref().unwrap_or("Unknown");
        let mut name_builder = spork_core::NameBuilder::new(cn);

        if let Some(ref org) = self.organization {
            name_builder = name_builder.organization(org);
        }
        if let Some(ref ou) = self.organizational_unit {
            name_builder = name_builder.organizational_unit(ou);
        }
        if let Some(ref locality) = self.locality {
            name_builder = name_builder.locality(locality);
        }
        if let Some(ref state) = self.state {
            name_builder = name_builder.state(state);
        }
        if let Some(ref country) = self.country {
            name_builder = name_builder.country(country);
        }

        let subject = name_builder.build();

        // Forward collected SANs to spork-core's builder. Without this chain the
        // --san flags on `pki csr create` are silently dropped (see #19).
        let dns_refs: Vec<&str> = self.san_dns.iter().map(String::as_str).collect();
        let ip_refs: Vec<&str> = self.san_ip.iter().map(String::as_str).collect();
        let email_refs: Vec<&str> = self.san_email.iter().map(String::as_str).collect();

        let csr_request = spork_core::CsrBuilder::new(subject)
            .with_san_dns_names(&dns_refs)
            .with_san_ips(&ip_refs)
            .with_san_emails(&email_refs)
            .build_and_sign(&key_pair)
            .with_context(|| "Failed to build and sign CSR")?;

        // Get PEM and DER output
        let pem = csr_request.to_pem();
        let der = csr_request.to_der().to_vec();

        // Parse back to get subject string and other info
        let subject_str = self.build_subject();
        let sig_algo = match algorithm {
            spork_core::AlgorithmId::EcdsaP256 => "ecdsa-with-SHA256".to_string(),
            spork_core::AlgorithmId::EcdsaP384 => "ecdsa-with-SHA384".to_string(),
            spork_core::AlgorithmId::Rsa2048 | spork_core::AlgorithmId::Rsa4096 => {
                "sha256WithRSAEncryption".to_string()
            }
            #[allow(unreachable_patterns)]
            _ => format!("{}", algorithm),
        };

        let mut san: Vec<pki_client_output::SanEntry> = Vec::new();
        for v in &self.san_dns {
            san.push(pki_client_output::SanEntry::Dns(v.clone()));
        }
        for v in &self.san_ip {
            san.push(pki_client_output::SanEntry::Ip(v.clone()));
        }
        for v in &self.san_email {
            san.push(pki_client_output::SanEntry::Email(v.clone()));
        }

        Ok(Csr {
            subject: subject_str,
            key_algorithm: format!("{}", algorithm),
            key_size: Some(key.bits),
            signature_algorithm: sig_algo,
            san,
            pem,
            der,
        })
    }
}

impl Default for CsrBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Key handling stubs
// ============================================================================

/// Key algorithm
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum KeyAlgorithm {
    /// RSA with key size
    Rsa(u32),
    /// EC P-256
    EcP256,
    /// EC P-384
    EcP384,
    /// Ed25519
    Ed25519,
    /// Ed448
    Ed448,
    /// ML-DSA (FIPS 204) with security level
    #[cfg(feature = "pqc")]
    MlDsa(u16),
    /// SLH-DSA (FIPS 205) with parameter set
    #[cfg(feature = "pqc")]
    SlhDsa(String),
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(bits) => write!(f, "RSA-{bits}"),
            Self::EcP256 => write!(f, "EC P-256"),
            Self::EcP384 => write!(f, "EC P-384"),
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::Ed448 => write!(f, "Ed448"),
            #[cfg(feature = "pqc")]
            Self::MlDsa(level) => write!(f, "ML-DSA-{level}"),
            #[cfg(feature = "pqc")]
            Self::SlhDsa(ref params) => write!(f, "SLH-DSA-{params}"),
        }
    }
}

impl KeyAlgorithm {
    /// Get security level assessment
    pub fn security_level(&self) -> &'static str {
        match self {
            Self::Rsa(bits) if *bits >= 4096 => "Strong (128-bit equivalent)",
            Self::Rsa(bits) if *bits >= 3072 => "Good (112-bit equivalent)",
            Self::Rsa(bits) if *bits >= 2048 => "Acceptable (currently)",
            Self::Rsa(_) => "WEAK - Upgrade immediately",
            Self::EcP256 => "Strong (128-bit equivalent)",
            Self::EcP384 => "Very Strong (192-bit equivalent)",
            Self::Ed25519 => "Strong (128-bit equivalent)",
            Self::Ed448 => "Very Strong (224-bit equivalent)",
            #[cfg(feature = "pqc")]
            Self::MlDsa(44) => "Strong (NIST Level 2, quantum-resistant)",
            #[cfg(feature = "pqc")]
            Self::MlDsa(65) => "Very Strong (NIST Level 3, quantum-resistant)",
            #[cfg(feature = "pqc")]
            Self::MlDsa(_) => "Very Strong (NIST Level 5, quantum-resistant)",
            #[cfg(feature = "pqc")]
            Self::SlhDsa(_) => "Strong (stateless hash-based, quantum-resistant)",
        }
    }
}

/// Private key
#[derive(Debug, serde::Serialize)]
pub struct PrivateKey {
    pub algorithm: KeyAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    #[serde(skip)]
    pub pem: String,
    /// Key size in bits (alias for display)
    pub bits: u32,
    /// Whether the key is encrypted
    pub encrypted: bool,
}

impl PrivateKey {
    /// Get security assessment for this key
    pub fn security_assessment(&self) -> String {
        match &self.algorithm {
            KeyAlgorithm::Rsa(bits) if *bits >= 4096 => "Strong".to_string(),
            KeyAlgorithm::Rsa(bits) if *bits >= 3072 => "Good".to_string(),
            KeyAlgorithm::Rsa(bits) if *bits >= 2048 => "Acceptable".to_string(),
            KeyAlgorithm::Rsa(_) => "WEAK - Upgrade immediately".to_string(),
            KeyAlgorithm::EcP256 => "Strong".to_string(),
            KeyAlgorithm::EcP384 => "Very Strong".to_string(),
            KeyAlgorithm::Ed25519 => "Strong".to_string(),
            KeyAlgorithm::Ed448 => "Very Strong".to_string(),
            #[cfg(feature = "pqc")]
            KeyAlgorithm::MlDsa(_) => "STRONG".to_string(),
            #[cfg(feature = "pqc")]
            KeyAlgorithm::SlhDsa(_) => "STRONG".to_string(),
        }
    }
}

/// Public key (stub)
#[allow(dead_code)] // Defined for API completeness
pub struct PublicKey {
    pub algorithm: KeyAlgorithm,
    pub key_size: Option<u32>,
    pub pem: String,
}

/// Generated key result for key gen command
pub struct GeneratedKey {
    pub algorithm: KeyAlgorithm,
    pub pem: String,
}

impl GeneratedKey {
    pub fn to_pem(&self) -> &str {
        &self.pem
    }
}

/// Load private key from file
pub fn load_private_key(path: &Path) -> Result<PrivateKey> {
    let data = std::fs::read_to_string(path)?;

    // Check if encrypted
    let encrypted = data.contains("ENCRYPTED");

    // Detect key type from PEM header and content
    // For PKCS#8 keys, we need to check the base64-encoded OID markers:
    // - P-256: contains "BggqhkjOPQMBBw" (OID 1.2.840.10045.3.1.7 = secp256r1)
    // - P-384: contains "BgUrgQQAIg" (OID 1.3.132.0.34 = secp384r1)
    // - EC public key: contains "BgcqhkjOPQIB" (OID 1.2.840.10045.2.1 = ecPublicKey)
    let (algorithm, bits) = if data.contains("RSA PRIVATE KEY") {
        // Traditional RSA key format
        let estimated_bits = if data.len() > 3000 {
            4096
        } else if data.len() > 1700 {
            2048
        } else {
            1024
        };
        (KeyAlgorithm::Rsa(estimated_bits), estimated_bits)
    } else if data.contains("EC PRIVATE KEY") {
        // Traditional EC key format - check curve
        if data.contains("secp384r1") || data.contains("P-384") || data.contains("BgUrgQQAIg") {
            (KeyAlgorithm::EcP384, 384)
        } else {
            (KeyAlgorithm::EcP256, 256)
        }
    } else if data.contains("GBSuBBAAi") || data.contains("BgUrgQQAIg") {
        // PKCS#8 EC P-384 key (secp384r1 OID in base64: 1.3.132.0.34)
        // "GBSuBBAAi" is the base64 pattern when OID crosses line boundaries
        (KeyAlgorithm::EcP384, 384)
    } else if data.contains("BggqhkjOPQMBBw") || data.contains("GCCqGSM49AwEH") {
        // PKCS#8 EC P-256 key (secp256r1 OID in base64: 1.2.840.10045.3.1.7)
        (KeyAlgorithm::EcP256, 256)
    } else if data.contains("BgcqhkjOPQIB") || data.contains("ByqGSM49AgE") {
        // Generic EC key in PKCS#8 (ecPublicKey OID) - default to P-256
        (KeyAlgorithm::EcP256, 256)
    } else if data.contains("1.3.101.112")
        || data.contains("Ed25519")
        || data.contains("MCowBQYDK2Vw")
    {
        // Ed25519 (OID 1.3.101.112 or base64 marker)
        (KeyAlgorithm::Ed25519, 256)
    } else if data.contains("1.3.101.113")
        || data.contains("Ed448")
        || data.contains("MEcwBQYDK2Vx")
    {
        // Ed448 (OID 1.3.101.113 or base64 marker)
        (KeyAlgorithm::Ed448, 456)
    } else if data.contains("PRIVATE KEY") {
        // Generic PKCS#8 - try to detect from key length
        // RSA keys are much larger than EC keys in PKCS#8 format
        if data.len() > 1500 {
            // Likely RSA
            let estimated_bits = if data.len() > 3000 { 4096 } else { 2048 };
            (KeyAlgorithm::Rsa(estimated_bits), estimated_bits)
        } else {
            // Small key - likely EC P-256
            (KeyAlgorithm::EcP256, 256)
        }
    } else {
        // Default to RSA-2048
        (KeyAlgorithm::Rsa(2048), 2048)
    };

    let curve = match algorithm {
        KeyAlgorithm::EcP256 => Some("P-256".to_string()),
        KeyAlgorithm::EcP384 => Some("P-384".to_string()),
        _ => None,
    };

    Ok(PrivateKey {
        algorithm,
        key_size: Some(bits),
        curve,
        pem: data,
        bits,
        encrypted,
    })
}

/// Generate an EC key
pub fn generate_ec(curve: &str) -> Result<GeneratedKey> {
    let algo_id = match curve.to_lowercase().as_str() {
        "p256" | "prime256v1" | "secp256r1" => spork_core::AlgorithmId::EcdsaP256,
        "p384" | "secp384r1" => spork_core::AlgorithmId::EcdsaP384,
        other => {
            return Err(anyhow!(
                "Unsupported EC curve: {}. Use p256 or p384.",
                other
            ))
        }
    };

    let keypair = spork_core::KeyPair::generate(algo_id)?;
    let pem = keypair.private_key_pem()?;
    let pem_string = (*pem).clone();

    let algorithm = match curve.to_lowercase().as_str() {
        "p256" | "prime256v1" | "secp256r1" => KeyAlgorithm::EcP256,
        _ => KeyAlgorithm::EcP384,
    };

    Ok(GeneratedKey {
        algorithm,
        pem: pem_string,
    })
}

/// Generate an Ed25519 key
pub fn generate_ed25519() -> Result<GeneratedKey> {
    // spork-core doesn't support Ed25519 yet
    Err(anyhow!(
        "Ed25519 key generation not yet supported in spork-core. Use EC P-384 instead."
    ))
}

/// Generate an RSA key
pub fn generate_rsa(bits: u32) -> Result<GeneratedKey> {
    let algo_id = if bits >= 4096 {
        spork_core::AlgorithmId::Rsa4096
    } else if bits >= 3072 {
        spork_core::AlgorithmId::Rsa3072
    } else {
        spork_core::AlgorithmId::Rsa2048
    };

    let keypair = spork_core::KeyPair::generate(algo_id)?;
    let pem = keypair.private_key_pem()?;
    let pem_string = (*pem).clone();

    Ok(GeneratedKey {
        algorithm: KeyAlgorithm::Rsa(bits),
        pem: pem_string,
    })
}

/// Generate a PQC key (ML-DSA or SLH-DSA)
#[cfg(feature = "pqc")]
pub fn generate_pqc(algo_name: &str) -> Result<GeneratedKey> {
    let (algo_id, key_algo) = match algo_name {
        "ml-dsa-44" => (spork_core::AlgorithmId::MlDsa44, KeyAlgorithm::MlDsa(44)),
        "ml-dsa-65" => (spork_core::AlgorithmId::MlDsa65, KeyAlgorithm::MlDsa(65)),
        "ml-dsa-87" => (spork_core::AlgorithmId::MlDsa87, KeyAlgorithm::MlDsa(87)),
        "slh-dsa-128s" => (
            spork_core::AlgorithmId::SlhDsaSha2_128s,
            KeyAlgorithm::SlhDsa("SHA2-128s".to_string()),
        ),
        "slh-dsa-192s" => (
            spork_core::AlgorithmId::SlhDsaSha2_192s,
            KeyAlgorithm::SlhDsa("SHA2-192s".to_string()),
        ),
        "slh-dsa-256s" => (
            spork_core::AlgorithmId::SlhDsaSha2_256s,
            KeyAlgorithm::SlhDsa("SHA2-256s".to_string()),
        ),
        other => return Err(anyhow!("Unknown PQC algorithm: {}", other)),
    };

    let keypair = spork_core::KeyPair::generate(algo_id)?;
    let pem = keypair.private_key_pem()?;
    let pem_string = (*pem).clone();

    Ok(GeneratedKey {
        algorithm: key_algo,
        pem: pem_string,
    })
}

/// Generate a private key (generic)
#[allow(dead_code)] // Available for future use
pub fn generate_key(algorithm: KeyAlgorithm, bits: Option<u32>) -> Result<PrivateKey> {
    let generated = match algorithm {
        KeyAlgorithm::Rsa(b) => generate_rsa(bits.unwrap_or(b))?,
        KeyAlgorithm::EcP256 => generate_ec("p256")?,
        KeyAlgorithm::EcP384 => generate_ec("p384")?,
        KeyAlgorithm::Ed25519 => generate_ed25519()?,
        KeyAlgorithm::Ed448 => return Err(anyhow!("Ed448 key generation not supported")),
        #[cfg(feature = "pqc")]
        KeyAlgorithm::MlDsa(_) | KeyAlgorithm::SlhDsa(_) => {
            return Err(anyhow!("ML-DSA/SLH-DSA key generation not yet supported"))
        }
    };

    let bits_val = match generated.algorithm {
        KeyAlgorithm::Rsa(b) => b,
        KeyAlgorithm::EcP256 => 256,
        KeyAlgorithm::EcP384 => 384,
        KeyAlgorithm::Ed25519 => 256,
        KeyAlgorithm::Ed448 => 456,
        #[cfg(feature = "pqc")]
        KeyAlgorithm::MlDsa(level) => match level {
            44 => 1312,
            65 => 1952,
            _ => 2592,
        },
        #[cfg(feature = "pqc")]
        KeyAlgorithm::SlhDsa(_) => 0,
    };

    let curve = match generated.algorithm {
        KeyAlgorithm::EcP256 => Some("P-256".to_string()),
        KeyAlgorithm::EcP384 => Some("P-384".to_string()),
        _ => None,
    };

    Ok(PrivateKey {
        algorithm: generated.algorithm,
        key_size: Some(bits_val),
        curve,
        pem: generated.pem,
        bits: bits_val,
        encrypted: false,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Issue #235: Audit compat.rs for unused stubs ─────────────────────
    //
    // The following items in compat.rs are marked #[allow(dead_code)] but are
    // NOT used anywhere in the codebase:
    //   - detect_file_type() standalone function (only detect_with_confidence is used)
    //   - generate_key() (commands use generate_rsa/generate_ec/generate_ed25519 directly)
    //   - PublicKey struct (only PrivateKey is used)
    //
    // These are intentionally kept for API completeness (annotated with
    // "Available for future use") so we test them here to ensure they don't rot.

    #[test]
    fn test_ssrf_validation_rejects_localhost() {
        assert!(validate_url_for_ssrf("http://localhost/path").is_err());
        assert!(validate_url_for_ssrf("http://127.0.0.1/path").is_err());
        assert!(validate_url_for_ssrf("http://[::1]/path").is_err());
    }

    #[test]
    fn test_ssrf_validation_rejects_private_ips() {
        assert!(validate_url_for_ssrf("http://10.0.0.1/path").is_err());
        assert!(validate_url_for_ssrf("http://172.16.0.1/path").is_err());
        assert!(validate_url_for_ssrf("http://192.168.1.1/path").is_err());
    }

    #[test]
    fn test_ssrf_validation_rejects_internal_hostnames() {
        assert!(validate_url_for_ssrf("http://host.local/path").is_err());
        assert!(validate_url_for_ssrf("http://host.internal/path").is_err());
        assert!(validate_url_for_ssrf("http://metadata.google.internal/").is_err());
    }

    #[test]
    fn test_ssrf_validation_rejects_blocked_ports() {
        assert!(validate_url_for_ssrf("http://example.com:6379/path").is_err()); // Redis
        assert!(validate_url_for_ssrf("http://example.com:5432/path").is_err()); // PostgreSQL
        assert!(validate_url_for_ssrf("http://example.com:22/path").is_err()); // SSH
    }

    #[test]
    fn test_ssrf_validation_rejects_unsafe_schemes() {
        assert!(validate_url_for_ssrf("ftp://example.com/path").is_err());
        assert!(validate_url_for_ssrf("file:///etc/passwd").is_err());
        assert!(validate_url_for_ssrf("gopher://example.com/").is_err());
    }

    #[test]
    fn test_ssrf_validation_accepts_safe_urls() {
        assert!(validate_url_for_ssrf("http://example.com/crl").is_ok());
        assert!(validate_url_for_ssrf("https://ocsp.example.com/").is_ok());
        assert!(validate_url_for_ssrf("http://crl.pki.example.com/ca.crl").is_ok());
    }

    #[test]
    fn test_is_private_ip_v4() {
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"172.16.5.5".parse().unwrap()));
        assert!(is_private_ip(&"192.168.1.100".parse().unwrap()));
        assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"169.254.1.1".parse().unwrap()));

        // Not private
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ip_v6() {
        assert!(is_private_ip(&"::1".parse().unwrap()));
        assert!(is_private_ip(&"::".parse().unwrap()));
        assert!(is_private_ip(&"fc00::1".parse().unwrap()));
        assert!(is_private_ip(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_detected_file_type_display() {
        assert_eq!(format!("{}", DetectedFileType::Certificate), "Certificate");
        assert_eq!(format!("{}", DetectedFileType::Csr), "CSR");
        assert_eq!(format!("{}", DetectedFileType::PrivateKey), "Private Key");
        assert_eq!(format!("{}", DetectedFileType::PublicKey), "Public Key");
        assert_eq!(format!("{}", DetectedFileType::Crl), "CRL");
        assert_eq!(format!("{}", DetectedFileType::Pkcs7), "PKCS#7");
        assert_eq!(format!("{}", DetectedFileType::Pkcs12), "PKCS#12");
        assert_eq!(format!("{}", DetectedFileType::Unknown), "Unknown");
    }

    #[test]
    fn test_detect_with_confidence_pem_certificate() {
        let data = b"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----";
        let result =
            DetectedFileType::detect_with_confidence(data, std::path::Path::new("test.pem"));
        assert_eq!(result.file_type, DetectedFileType::Certificate);
        assert_eq!(result.confidence, 100);
    }

    #[test]
    fn test_detect_with_confidence_pem_csr() {
        let data =
            b"-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----";
        let result =
            DetectedFileType::detect_with_confidence(data, std::path::Path::new("test.csr"));
        assert_eq!(result.file_type, DetectedFileType::Csr);
        assert_eq!(result.confidence, 100);
    }

    #[test]
    fn test_detect_with_confidence_pem_private_key() {
        let data = b"-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----";
        let result =
            DetectedFileType::detect_with_confidence(data, std::path::Path::new("test.key"));
        assert_eq!(result.file_type, DetectedFileType::PrivateKey);
        assert_eq!(result.confidence, 100);
    }

    #[test]
    fn test_detect_with_confidence_pem_crl() {
        let data = b"-----BEGIN X509 CRL-----\nMIIB...\n-----END X509 CRL-----";
        let result =
            DetectedFileType::detect_with_confidence(data, std::path::Path::new("test.crl"));
        assert_eq!(result.file_type, DetectedFileType::Crl);
        assert_eq!(result.confidence, 100);
    }

    #[test]
    fn test_detect_with_confidence_unknown() {
        let data = b"This is not a PKI file";
        let result =
            DetectedFileType::detect_with_confidence(data, std::path::Path::new("test.txt"));
        assert_eq!(result.file_type, DetectedFileType::Unknown);
        assert_eq!(result.confidence, 0);
    }

    #[test]
    fn test_revocation_status_display() {
        assert_eq!(format!("{}", RevocationStatus::Good), "Good");
        assert_eq!(
            format!(
                "{}",
                RevocationStatus::Revoked {
                    reason: Some("keyCompromise".to_string()),
                    revoked_at: None,
                }
            ),
            "Revoked (keyCompromise)"
        );
        assert_eq!(
            format!(
                "{}",
                RevocationStatus::Revoked {
                    reason: None,
                    revoked_at: None,
                }
            ),
            "Revoked"
        );
        assert_eq!(
            format!(
                "{}",
                RevocationStatus::Unknown {
                    reason: "no OCSP".to_string()
                }
            ),
            "Unknown: no OCSP"
        );
        assert_eq!(
            format!("{}", RevocationStatus::Error("timeout".to_string())),
            "Error: timeout"
        );
    }

    #[test]
    fn test_revocation_status_exit_codes() {
        assert_eq!(RevocationStatus::Good.exit_code(), 0);
        assert_eq!(
            RevocationStatus::Revoked {
                reason: None,
                revoked_at: None
            }
            .exit_code(),
            1
        );
        assert_eq!(
            RevocationStatus::Unknown {
                reason: "test".to_string()
            }
            .exit_code(),
            2
        );
        assert_eq!(RevocationStatus::Error("test".to_string()).exit_code(), 3);
    }

    #[test]
    fn test_key_algorithm_display() {
        assert_eq!(format!("{}", KeyAlgorithm::Rsa(2048)), "RSA-2048");
        assert_eq!(format!("{}", KeyAlgorithm::EcP256), "EC P-256");
        assert_eq!(format!("{}", KeyAlgorithm::EcP384), "EC P-384");
        assert_eq!(format!("{}", KeyAlgorithm::Ed25519), "Ed25519");
        assert_eq!(format!("{}", KeyAlgorithm::Ed448), "Ed448");
    }

    #[test]
    fn test_key_algorithm_security_levels() {
        assert_eq!(
            KeyAlgorithm::Rsa(4096).security_level(),
            "Strong (128-bit equivalent)"
        );
        assert_eq!(
            KeyAlgorithm::Rsa(3072).security_level(),
            "Good (112-bit equivalent)"
        );
        assert_eq!(
            KeyAlgorithm::Rsa(2048).security_level(),
            "Acceptable (currently)"
        );
        assert_eq!(
            KeyAlgorithm::Rsa(1024).security_level(),
            "WEAK - Upgrade immediately"
        );
        assert_eq!(
            KeyAlgorithm::EcP256.security_level(),
            "Strong (128-bit equivalent)"
        );
        assert_eq!(
            KeyAlgorithm::EcP384.security_level(),
            "Very Strong (192-bit equivalent)"
        );
        assert_eq!(
            KeyAlgorithm::Ed25519.security_level(),
            "Strong (128-bit equivalent)"
        );
    }

    #[test]
    fn test_revocation_method_display() {
        assert_eq!(format!("{}", RevocationMethod::Ocsp), "OCSP");
        assert_eq!(format!("{}", RevocationMethod::Crl), "CRL");
        assert_eq!(format!("{}", RevocationMethod::Both), "OCSP+CRL");
    }

    #[test]
    fn test_chain_builder_defaults() {
        let builder = ChainBuilder::new();
        // Default should have no intermediates and no trust anchors
        assert!(builder.intermediates.is_empty());
        assert!(builder.trust_anchors.is_empty());
        assert!(builder.follow_aia_enabled);
        assert!(!builder.use_system_trust);
        assert_eq!(builder.max_chain_length, 10);
    }

    #[test]
    fn test_chain_builder_follow_aia_toggle() {
        let builder = ChainBuilder::new().follow_aia(false);
        assert!(!builder.follow_aia_enabled);

        let builder = ChainBuilder::new().follow_aia(true);
        assert!(builder.follow_aia_enabled);
    }

    #[test]
    fn test_chain_validation_defaults() {
        let validation = ChainValidation::new();
        assert!(validation.valid);
        assert!(validation.errors.is_empty());
        assert!(validation.warnings.is_empty());
        assert!(validation.trusted_root.is_none());
    }

    #[test]
    fn test_trust_store_empty() {
        let store = TrustStore::new();
        assert!(store.certificates().is_empty());
    }

    #[test]
    fn test_ocsp_checker_default_creation() {
        let checker = OcspChecker::new();
        assert_eq!(checker.timeout, std::time::Duration::from_secs(10));
    }

    #[test]
    fn test_ocsp_checker_custom_timeout() {
        let checker = OcspChecker::new().with_timeout(std::time::Duration::from_secs(30));
        assert_eq!(checker.timeout, std::time::Duration::from_secs(30));
    }

    #[test]
    fn test_crl_checker_default_creation() {
        let checker = CrlChecker::new();
        assert_eq!(checker.timeout, 10);
    }

    #[test]
    fn test_crl_checker_custom_timeout() {
        let checker = CrlChecker::new().with_timeout(60);
        assert_eq!(checker.timeout, 60);
    }

    #[test]
    fn test_revocation_checker_creation() {
        let _ = RevocationChecker::new();
    }

    #[test]
    fn test_csr_builder_subject_construction() {
        let builder = CsrBuilder::new()
            .common_name("example.com")
            .organization("ACME Inc")
            .organizational_unit("IT")
            .locality("San Francisco")
            .state("California")
            .country("US");

        let subject = builder.build_subject();
        assert!(subject.contains("CN=example.com"));
        assert!(subject.contains("O=ACME Inc"));
        assert!(subject.contains("OU=IT"));
        assert!(subject.contains("L=San Francisco"));
        assert!(subject.contains("ST=California"));
        assert!(subject.contains("C=US"));
    }

    #[test]
    fn test_csr_builder_dns_and_ip_sans() {
        let builder = CsrBuilder::new()
            .common_name("example.com")
            .add_dns_san("example.com")
            .add_dns_san("www.example.com")
            .add_ip_san("192.168.1.1")
            .add_email_san("admin@example.com");

        assert_eq!(builder.san_dns.len(), 2);
        assert_eq!(builder.san_ip.len(), 1);
        assert_eq!(builder.san_email.len(), 1);
    }

    #[test]
    fn test_generate_ec_p256() {
        let result = generate_ec("p256");
        assert!(result.is_ok(), "EC P-256 key generation should succeed");
        let key = result.unwrap();
        assert_eq!(key.algorithm, KeyAlgorithm::EcP256);
        assert!(key.pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn test_generate_ec_p384() {
        let result = generate_ec("p384");
        assert!(result.is_ok(), "EC P-384 key generation should succeed");
        let key = result.unwrap();
        assert_eq!(key.algorithm, KeyAlgorithm::EcP384);
    }

    #[test]
    fn test_generate_ec_unsupported_curve() {
        let result = generate_ec("p521");
        assert!(result.is_err(), "P-521 should not be supported");
    }

    #[test]
    fn test_generate_ed25519_not_supported() {
        let result = generate_ed25519();
        assert!(result.is_err(), "Ed25519 is not yet supported");
    }

    #[test]
    fn test_private_key_security_assessment() {
        let key = PrivateKey {
            algorithm: KeyAlgorithm::EcP256,
            key_size: Some(256),
            curve: Some("P-256".to_string()),
            pem: String::new(),
            bits: 256,
            encrypted: false,
        };
        assert_eq!(key.security_assessment(), "Strong");

        let weak_key = PrivateKey {
            algorithm: KeyAlgorithm::Rsa(1024),
            key_size: Some(1024),
            curve: None,
            pem: String::new(),
            bits: 1024,
            encrypted: false,
        };
        assert_eq!(weak_key.security_assessment(), "WEAK - Upgrade immediately");
    }

    #[test]
    fn test_detect_der_private_key_pkcs8() {
        // Generate a real PKCS#8 DER private key
        let kp = spork_core::KeyPair::generate(spork_core::AlgorithmId::EcdsaP256).unwrap();
        let der_bytes = kp.private_key_der().unwrap();

        let result =
            DetectedFileType::detect_with_confidence(&der_bytes, std::path::Path::new("key.der"));
        assert_eq!(result.file_type, DetectedFileType::PrivateKey);
        assert!(
            result.confidence >= 80,
            "confidence should be >= 80, got {}",
            result.confidence
        );
    }

    #[test]
    fn test_is_pkcs8_private_key_valid() {
        let kp = spork_core::KeyPair::generate(spork_core::AlgorithmId::EcdsaP256).unwrap();
        let der_bytes = kp.private_key_der().unwrap();
        assert!(is_pkcs8_private_key(&der_bytes));
    }

    #[test]
    fn test_is_pkcs8_private_key_rejects_garbage() {
        assert!(!is_pkcs8_private_key(b"not a key"));
        assert!(!is_pkcs8_private_key(&[]));
        assert!(!is_pkcs8_private_key(&[0x30, 0x00])); // empty sequence
    }

    #[test]
    fn test_cgnat_ip_is_private() {
        // 100.64.0.0/10 (CGNAT) should be considered private
        assert!(is_private_ip(&"100.64.0.1".parse().unwrap()));
        assert!(is_private_ip(&"100.100.100.100".parse().unwrap()));
        // But regular public IPs should not be
        assert!(!is_private_ip(&"100.0.0.1".parse().unwrap()));
    }
}
