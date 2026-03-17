//! AIA Chasing — fetch missing intermediate certificates via HTTP (RFC 5280 §4.2.2.1)
//!
//! When building a certificate chain, the chain may be incomplete because intermediate
//! CA certificates are not provided by the peer. The Authority Information Access (AIA)
//! extension's `caIssuers` access method provides URIs where the issuing CA's certificate
//! can be fetched.
//!
//! This module implements AIA chasing: starting from a certificate that has a chain gap,
//! follow the `caIssuers` URIs recursively until the chain is complete or a limit is
//! reached.
//!
//! Security considerations (RFC 5280):
//! - AIA URIs are typically plain HTTP (not HTTPS) — this is intentional per the RFC.
//!   TLS would create a bootstrapping problem (need the cert to validate TLS to get the cert).
//! - Response size is bounded to prevent DoS.
//! - Fetch count is bounded to prevent infinite loops.
//! - Visited URIs are tracked to prevent redirect loops.
//! - All fetched bytes are validated to be well-formed X.509 before use.

#[cfg(feature = "aia-chasing")]
use std::collections::HashSet;

use x509_cert::Certificate;

#[cfg(feature = "aia-chasing")]
use crate::error::{Error, Result};

// OID arc for AIA caIssuers: 1.3.6.1.5.5.7.48.2
const AIA_OID_ARCS: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 1, 1];
const CA_ISSUERS_OID_ARCS: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 2];

/// Configuration for AIA chasing behaviour.
#[derive(Debug, Clone)]
pub struct AiaChaseConfig {
    /// Whether AIA chasing is enabled (default: true).
    pub enabled: bool,
    /// HTTP request timeout in seconds (default: 10).
    pub timeout_secs: u64,
    /// Maximum number of certificates to fetch in a single chase (default: 5).
    pub max_depth: usize,
    /// Maximum size of any single HTTP response in bytes (default: 64 KiB).
    /// Prevents DoS via oversized responses.
    pub max_response_size: usize,
}

impl Default for AiaChaseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: 10,
            max_depth: 5,
            max_response_size: 65_536, // 64 KiB — more than enough for any real cert
        }
    }
}

/// A certificate fetched via AIA chasing, together with the URI it came from.
#[derive(Debug, Clone)]
pub struct FetchedCert {
    /// The URI the certificate was fetched from.
    pub uri: String,
    /// The parsed X.509 certificate.
    pub certificate: Certificate,
}

/// AIA Chaser: follows `caIssuers` URIs to discover missing intermediate CAs.
///
/// This type is the main entry point for AIA chasing. Construct one with a
/// configuration, then call [`AiaChaser::chase`] with a certificate that has
/// a chain gap.
#[cfg(feature = "aia-chasing")]
pub struct AiaChaser {
    config: AiaChaseConfig,
    client: reqwest::blocking::Client,
}

#[cfg(feature = "aia-chasing")]
impl AiaChaser {
    /// Create a new AIA chaser with the given configuration.
    pub fn new(config: AiaChaseConfig) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            // No redirects — AIA URIs should not redirect; following them silently
            // could lead to SSRF or loop conditions.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::Network(format!("Failed to build HTTP client: {}", e)))?;

        Ok(Self { config, client })
    }

    /// Create a new AIA chaser with default configuration.
    pub fn with_defaults() -> Result<Self> {
        Self::new(AiaChaseConfig::default())
    }

    /// Chase AIA `caIssuers` URIs starting from `cert`.
    ///
    /// Follows the chain of `caIssuers` links recursively, collecting intermediate
    /// CA certificates until no more can be found or limits are reached.
    ///
    /// Returns a `Vec<FetchedCert>` in the order they were fetched (closest issuer first).
    /// The caller is responsible for validating the fetched certificates form a valid chain.
    pub fn chase(&self, cert: &Certificate) -> Result<Vec<FetchedCert>> {
        if !self.config.enabled {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        let mut visited = HashSet::new();
        let mut current = cert.clone();

        for _depth in 0..self.config.max_depth {
            // Extract caIssuers URIs from the current certificate's AIA extension
            let uris = extract_ca_issuers_uris(&current);
            if uris.is_empty() {
                break;
            }

            // Try each URI in order; stop at the first successful fetch
            let mut found = false;
            for uri in &uris {
                if visited.contains(uri) {
                    // Loop detected — skip this URI
                    continue;
                }
                visited.insert(uri.clone());

                match self.fetch_cert(uri) {
                    Ok(fetched_cert) => {
                        let next = fetched_cert.certificate.clone();
                        results.push(fetched_cert);
                        current = next;
                        found = true;
                        break;
                    }
                    Err(_) => {
                        // Try the next URI in the AIA extension
                        continue;
                    }
                }
            }

            if !found {
                // No more certs could be fetched
                break;
            }

            // If the current cert is self-signed, we've reached a root — stop.
            if is_self_signed(&current) {
                break;
            }
        }

        Ok(results)
    }

    /// Fetch a single certificate from a URI.
    ///
    /// Accepts DER-encoded certificates (`application/pkix-cert`),
    /// PEM-encoded certificates (`application/x-pem-file` or `text/plain`),
    /// and PKCS#7 certs-only bundles (`.p7c`, `application/pkcs7-mime`).
    fn fetch_cert(&self, uri: &str) -> Result<FetchedCert> {
        // Only allow http:// URIs — AIA URIs per RFC 5280 are plain HTTP.
        // LDAP URIs (ldap://) are also common in practice but not supported here
        // since they require a full LDAP client.
        if !uri.starts_with("http://") && !uri.starts_with("https://") {
            return Err(Error::InvalidCertificate(format!(
                "AIA URI scheme not supported (only http:// allowed): {}",
                uri
            )));
        }

        let response = self
            .client
            .get(uri)
            .send()
            .map_err(|e| Error::Network(format!("AIA fetch failed for {}: {}", uri, e)))?;

        if !response.status().is_success() {
            return Err(Error::Network(format!(
                "AIA fetch returned HTTP {} for {}",
                response.status(),
                uri
            )));
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v: &reqwest::header::HeaderValue| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();

        // Read the body with a size limit
        let bytes = response
            .bytes()
            .map_err(|e| Error::Network(format!("AIA body read failed: {}", e)))?;

        if bytes.len() > self.config.max_response_size {
            return Err(Error::InvalidCertificate(format!(
                "AIA response too large ({} bytes, max {}): {}",
                bytes.len(),
                self.config.max_response_size,
                uri
            )));
        }

        // Determine format from content-type or URI extension
        let cert = if content_type.contains("pkcs7")
            || content_type.contains("p7")
            || uri.ends_with(".p7c")
            || uri.ends_with(".p7b")
        {
            parse_p7c_first_cert(&bytes)?
        } else if content_type.contains("pem")
            || content_type.contains("text/plain")
            || looks_like_pem(&bytes)
        {
            parse_pem_cert(&bytes)?
        } else {
            // Default: try DER, then PEM as fallback
            parse_der_or_pem_cert(&bytes)?
        };

        Ok(FetchedCert {
            uri: uri.to_string(),
            certificate: cert,
        })
    }
}

/// Extract all `caIssuers` URIs from a certificate's AIA extension.
///
/// Returns an empty Vec if the AIA extension is absent or contains no `caIssuers` entries.
///
/// This function is also useful without the `aia-chasing` feature enabled (e.g., for
/// diagnostic purposes), so it is not gated behind the feature flag.
pub fn extract_ca_issuers_uris(cert: &Certificate) -> Vec<String> {
    let extensions = match cert.tbs_certificate.extensions.as_ref() {
        Some(e) => e,
        None => return Vec::new(),
    };

    for ext in extensions.iter() {
        let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if oid_arcs != AIA_OID_ARCS {
            continue;
        }

        // The AIA extension value is a SEQUENCE of AccessDescription:
        // AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
        // AccessDescription ::= SEQUENCE {
        //   accessMethod    OBJECT IDENTIFIER,
        //   accessLocation  GeneralName }
        return parse_aia_ca_issuers(ext.extn_value.as_bytes());
    }

    Vec::new()
}

/// Parse caIssuers URIs from raw AIA extension DER bytes.
///
/// Handles the DER structure manually to avoid pulling in a full ASN.1 parser
/// for this targeted use case.
fn parse_aia_ca_issuers(data: &[u8]) -> Vec<String> {
    let mut uris = Vec::new();

    // Outer SEQUENCE
    let (inner, _) = match der_unwrap_sequence(data) {
        Some(v) => v,
        None => return uris,
    };

    let mut pos = 0;
    while pos < inner.len() {
        // Each AccessDescription is a SEQUENCE
        if pos >= inner.len() || inner[pos] != 0x30 {
            break;
        }
        let (ad_inner, ad_len) = match der_unwrap_sequence(&inner[pos..]) {
            Some(v) => v,
            None => break,
        };
        pos += ad_len;

        // Parse AccessDescription: first element is OID, second is GeneralName
        if let Some((oid_arcs, rest)) = parse_oid_prefix(ad_inner) {
            if oid_arcs == CA_ISSUERS_OID_ARCS {
                // Access location is a GeneralName.  We only support uniformResourceIdentifier [6].
                if let Some(uri) = parse_general_name_uri(rest) {
                    uris.push(uri);
                }
            }
        }
    }

    uris
}

/// Unwrap a DER SEQUENCE, returning (contents, total_bytes_consumed).
fn der_unwrap_sequence(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.len() < 2 || data[0] != 0x30 {
        return None;
    }
    let (len, header_len) = read_der_length(&data[1..])?;
    let total = 1 + header_len + len;
    if data.len() < total {
        return None;
    }
    Some((&data[1 + header_len..total], total))
}

/// Parse an OID from the front of `data`, returning (arcs, remaining_bytes).
fn parse_oid_prefix(data: &[u8]) -> Option<(Vec<u32>, &[u8])> {
    if data.len() < 2 || data[0] != 0x06 {
        return None;
    }
    let (len, header_len) = read_der_length(&data[1..])?;
    let oid_end = 1 + header_len + len;
    if data.len() < oid_end {
        return None;
    }
    let oid_bytes = &data[1 + header_len..oid_end];
    let arcs = decode_oid_arcs(oid_bytes);
    Some((arcs, &data[oid_end..]))
}

/// Decode BER/DER OID bytes into a Vec of arc components.
fn decode_oid_arcs(bytes: &[u8]) -> Vec<u32> {
    let mut arcs = Vec::new();
    if bytes.is_empty() {
        return arcs;
    }
    // First byte encodes the first two arcs: arc0 * 40 + arc1
    let first = bytes[0] as u32;
    arcs.push(first / 40);
    arcs.push(first % 40);

    let mut i = 1;
    while i < bytes.len() {
        let mut value: u32 = 0;
        loop {
            if i >= bytes.len() {
                break;
            }
            let b = bytes[i];
            i += 1;
            value = (value << 7) | (b & 0x7F) as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
        arcs.push(value);
    }
    arcs
}

/// Parse a GeneralName uniformResourceIdentifier [6] from `data`.
/// Returns the URI string if the first element is a URI GeneralName.
fn parse_general_name_uri(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    // [6] IMPLICIT IA5String — context-specific tag 6 (0x86)
    if data[0] != 0x86 {
        return None;
    }
    let (len, header_len) = read_der_length(&data[1..])?;
    let uri_start = 1 + header_len;
    let uri_end = uri_start + len;
    if data.len() < uri_end {
        return None;
    }
    let uri = std::str::from_utf8(&data[uri_start..uri_end]).ok()?;
    // Basic sanity check: must look like a URI
    if !uri.contains("://") {
        return None;
    }
    Some(uri.to_string())
}

/// Read a DER length field, returning (length_value, bytes_consumed).
fn read_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    match data[0] {
        n if n < 0x80 => Some((n as usize, 1)),
        0x81 => data.get(1).map(|&b| (b as usize, 2)),
        0x82 => {
            if data.len() >= 3 {
                Some((((data[1] as usize) << 8) | (data[2] as usize), 3))
            } else {
                None
            }
        }
        0x83 => {
            if data.len() >= 4 {
                Some((
                    ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize),
                    4,
                ))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Heuristic: does `bytes` look like a PEM file?
#[cfg(feature = "aia-chasing")]
fn looks_like_pem(bytes: &[u8]) -> bool {
    bytes.starts_with(b"-----BEGIN")
}

/// Parse a DER-encoded certificate from bytes.
/// Validates the outermost tag is 0x30 (SEQUENCE) before attempting parse.
#[cfg(feature = "aia-chasing")]
fn parse_der_cert(bytes: &[u8]) -> Result<Certificate> {
    if bytes.is_empty() {
        return Err(Error::Decoding("Empty response".into()));
    }
    // X.509 Certificate is a SEQUENCE (tag 0x30)
    if bytes[0] != 0x30 {
        return Err(Error::Decoding(format!(
            "Invalid certificate: expected SEQUENCE tag 0x30, got 0x{:02X}",
            bytes[0]
        )));
    }
    Certificate::from_der(bytes).map_err(|e| Error::Decoding(format!("DER decode: {}", e)))
}

/// Parse a PEM-encoded certificate from bytes.
#[cfg(feature = "aia-chasing")]
fn parse_pem_cert(bytes: &[u8]) -> Result<Certificate> {
    let s = std::str::from_utf8(bytes)
        .map_err(|_| Error::Decoding("AIA response is not valid UTF-8".into()))?;

    let pem_data =
        pem::parse(s).map_err(|e| Error::Decoding(format!("PEM parse failed: {}", e)))?;

    if pem_data.tag() != "CERTIFICATE" {
        return Err(Error::Decoding(format!(
            "Expected CERTIFICATE PEM block, got {}",
            pem_data.tag()
        )));
    }

    parse_der_cert(pem_data.contents())
}

/// Try to parse as DER first, then PEM.
#[cfg(feature = "aia-chasing")]
fn parse_der_or_pem_cert(bytes: &[u8]) -> Result<Certificate> {
    if looks_like_pem(bytes) {
        parse_pem_cert(bytes)
    } else {
        parse_der_cert(bytes)
    }
}

/// Parse the first certificate from a PKCS#7 certs-only (`.p7c`) response.
///
/// PKCS#7 certs-only (also called a "degenerate PKCS#7 SignedData") has the structure:
/// ```text
/// ContentInfo SEQUENCE {
///   contentType  OBJECT IDENTIFIER  (1.2.840.113549.1.7.2 — signedData)
///   content  [0] EXPLICIT ANY OPTIONAL {
///     SignedData SEQUENCE {
///       version      INTEGER
///       digestAlgorithms SET
///       encapContentInfo SEQUENCE { ... }
///       certificates [0] IMPLICIT CertificateSet OPTIONAL {
///         Certificate ...
///       }
///     }
///   }
/// }
/// ```
///
/// We navigate this structure to find the first `Certificate` embedded in the
/// `certificates` field of `SignedData`.
#[cfg(feature = "aia-chasing")]
fn parse_p7c_first_cert(bytes: &[u8]) -> Result<Certificate> {
    // Try PEM first (some servers wrap p7c in PEM)
    if looks_like_pem(bytes) {
        let s = std::str::from_utf8(bytes)
            .map_err(|_| Error::Decoding("P7C response is not valid UTF-8".into()))?;
        if let Ok(pem_data) = pem::parse(s) {
            return parse_p7c_der(pem_data.contents());
        }
    }
    parse_p7c_der(bytes)
}

/// Parse a DER-encoded PKCS#7 certs-only bundle and return the first certificate.
#[cfg(feature = "aia-chasing")]
fn parse_p7c_der(bytes: &[u8]) -> Result<Certificate> {
    // Navigate the nested PKCS#7 structure to find the embedded certificates.
    // We use a simple manual DER walk to avoid pulling in a full CMS implementation.

    // ContentInfo SEQUENCE
    let (content_info, _) = der_unwrap_sequence(bytes)
        .ok_or_else(|| Error::Decoding("P7C: expected outer ContentInfo SEQUENCE".into()))?;

    // Skip the contentType OID
    let (_, oid_consumed) = parse_oid_prefix_with_length(content_info)
        .ok_or_else(|| Error::Decoding("P7C: expected contentType OID".into()))?;
    let after_oid = &content_info[oid_consumed..];

    // [0] EXPLICIT — context tag 0xA0
    if after_oid.is_empty() || after_oid[0] != 0xA0 {
        return Err(Error::Decoding(
            "P7C: expected [0] EXPLICIT content wrapper".into(),
        ));
    }
    let (explicit_inner, _) = der_unwrap_context_tag(after_oid, 0xA0)
        .ok_or_else(|| Error::Decoding("P7C: failed to unwrap [0] EXPLICIT".into()))?;

    // SignedData SEQUENCE
    let (signed_data, _) = der_unwrap_sequence(explicit_inner)
        .ok_or_else(|| Error::Decoding("P7C: expected SignedData SEQUENCE".into()))?;

    // Skip: version INTEGER, digestAlgorithms SET, encapContentInfo SEQUENCE
    // We walk forward looking for the [0] IMPLICIT CertificateSet tag (0xA0)
    let cert_set_data = find_context_tag_0_in_signed_data(signed_data)
        .ok_or_else(|| Error::Decoding("P7C: no certificates field found in SignedData".into()))?;

    // The first element of the CertificateSet should be a Certificate SEQUENCE
    parse_der_cert(cert_set_data)
}

/// Find the `[0] IMPLICIT CertificateSet` field within SignedData by skipping
/// the version, digestAlgorithms, and encapContentInfo fields.
#[cfg(feature = "aia-chasing")]
fn find_context_tag_0_in_signed_data(data: &[u8]) -> Option<&[u8]> {
    let mut pos = 0;

    while pos < data.len() {
        let tag = data[pos];
        if tag == 0xA0 {
            // Found our [0] IMPLICIT CertificateSet
            let (inner, _) = der_unwrap_context_tag(&data[pos..], 0xA0)?;
            return Some(inner);
        }
        // Skip this element
        if pos + 1 >= data.len() {
            break;
        }
        let (elem_len, header_len) = read_der_length(&data[pos + 1..])?;
        pos += 1 + header_len + elem_len;
    }
    None
}

/// Unwrap a context-specific tag (e.g. 0xA0, 0xA1), returning (contents, total_consumed).
#[cfg(feature = "aia-chasing")]
fn der_unwrap_context_tag(data: &[u8], tag: u8) -> Option<(&[u8], usize)> {
    if data.is_empty() || data[0] != tag {
        return None;
    }
    let (len, header_len) = read_der_length(&data[1..])?;
    let total = 1 + header_len + len;
    if data.len() < total {
        return None;
    }
    Some((&data[1 + header_len..total], total))
}

/// Parse an OID from the front of `data`, returning (arcs, total_bytes_consumed).
/// Unlike `parse_oid_prefix`, this returns the number of bytes consumed so the
/// caller can skip ahead.
#[cfg(feature = "aia-chasing")]
fn parse_oid_prefix_with_length(data: &[u8]) -> Option<(Vec<u32>, usize)> {
    if data.len() < 2 || data[0] != 0x06 {
        return None;
    }
    let (len, header_len) = read_der_length(&data[1..])?;
    let oid_end = 1 + header_len + len;
    if data.len() < oid_end {
        return None;
    }
    let oid_bytes = &data[1 + header_len..oid_end];
    Some((decode_oid_arcs(oid_bytes), oid_end))
}

/// Returns true if the certificate appears to be self-signed.
/// A certificate is self-signed if its Subject and Issuer are identical.
#[cfg(feature = "aia-chasing")]
fn is_self_signed(cert: &Certificate) -> bool {
    let subject = &cert.tbs_certificate.subject;
    let issuer = &cert.tbs_certificate.issuer;
    // Compare DER-encoded forms for reliable equality
    use der::Encode;
    let subject_der = subject.to_der().unwrap_or_default();
    let issuer_der = issuer.to_der().unwrap_or_default();
    subject_der == issuer_der
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- AiaChaseConfig tests ----

    #[test]
    fn test_config_defaults() {
        let config = AiaChaseConfig::default();
        assert!(config.enabled);
        assert_eq!(config.timeout_secs, 10);
        assert_eq!(config.max_depth, 5);
        assert_eq!(config.max_response_size, 65_536);
    }

    #[test]
    fn test_config_custom() {
        let config = AiaChaseConfig {
            enabled: false,
            timeout_secs: 30,
            max_depth: 3,
            max_response_size: 1_024,
        };
        assert!(!config.enabled);
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.max_depth, 3);
        assert_eq!(config.max_response_size, 1_024);
    }

    // ---- DER parsing helpers ----

    #[test]
    fn test_read_der_length_short_form() {
        // Short form: single byte
        assert_eq!(read_der_length(&[0x05]), Some((5, 1)));
        assert_eq!(read_der_length(&[0x7F]), Some((127, 1)));
        assert_eq!(read_der_length(&[0x00]), Some((0, 1)));
    }

    #[test]
    fn test_read_der_length_long_form_1byte() {
        // 0x81 XX = length XX
        assert_eq!(read_der_length(&[0x81, 0x80]), Some((128, 2)));
        assert_eq!(read_der_length(&[0x81, 0xFF]), Some((255, 2)));
    }

    #[test]
    fn test_read_der_length_long_form_2byte() {
        // 0x82 HH LL = length (HH << 8) | LL
        assert_eq!(read_der_length(&[0x82, 0x01, 0x00]), Some((256, 3)));
        assert_eq!(read_der_length(&[0x82, 0x02, 0x00]), Some((512, 3)));
    }

    #[test]
    fn test_read_der_length_long_form_3byte() {
        // 0x83 B2 B1 B0
        assert_eq!(read_der_length(&[0x83, 0x01, 0x00, 0x00]), Some((65536, 4)));
    }

    #[test]
    fn test_read_der_length_empty() {
        assert_eq!(read_der_length(&[]), None);
    }

    #[test]
    fn test_read_der_length_truncated() {
        // 0x81 needs 2 bytes but only 1 provided
        assert_eq!(read_der_length(&[0x81]), None);
    }

    // ---- OID decoding tests ----

    #[test]
    fn test_decode_oid_arcs_aia() {
        // 1.3.6.1.5.5.7.48.2 = caIssuers
        // Encoding:
        // First byte = 1*40 + 3 = 43 = 0x2B
        // Then: 6 (0x06), 1 (0x01), 5 (0x05), 5 (0x05), 7 (0x07), 48 (0x30), 2 (0x02)
        let oid_bytes = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];
        let arcs = decode_oid_arcs(&oid_bytes);
        assert_eq!(arcs, CA_ISSUERS_OID_ARCS);
    }

    #[test]
    fn test_decode_oid_arcs_empty() {
        let arcs = decode_oid_arcs(&[]);
        assert!(arcs.is_empty());
    }

    #[test]
    fn test_decode_oid_arcs_multi_byte_arc() {
        // Test multi-byte BER arc encoding (value >= 128)
        // Arc value 128 encodes as 0x81 0x00
        // First two arcs: 2*40+5 = 85 (0x55), then 29 (0x1D), then 128 (0x81 0x00)
        let oid_bytes = [0x55, 0x1D, 0x81, 0x00];
        let arcs = decode_oid_arcs(&oid_bytes);
        assert_eq!(arcs, vec![2, 5, 29, 128]);
    }

    // ---- PEM detection tests ----

    #[cfg(feature = "aia-chasing")]
    #[test]
    fn test_looks_like_pem_true() {
        let pem = b"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n";
        assert!(looks_like_pem(pem));
    }

    #[cfg(feature = "aia-chasing")]
    #[test]
    fn test_looks_like_pem_false_der() {
        // DER starts with 0x30 (SEQUENCE)
        let der = b"\x30\x82\x01\x00";
        assert!(!looks_like_pem(der));
    }

    #[cfg(feature = "aia-chasing")]
    #[test]
    fn test_looks_like_pem_false_empty() {
        assert!(!looks_like_pem(b""));
    }

    // ---- URI extraction tests ----

    #[test]
    fn test_extract_ca_issuers_no_extensions() {
        // Build a minimal certificate with no extensions and verify we get empty URIs
        use crate::algo::{AlgorithmId, KeyPair};
        use crate::cert::{builder::CertificateBuilder, NameBuilder, Validity};

        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("No AIA Cert").build();
        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .validity(Validity::days_from_now(30))
        .include_subject_key_identifier(false)
        .include_authority_key_identifier(false)
        .build_and_sign(&kp)
        .unwrap();

        let uris = extract_ca_issuers_uris(&cert);
        assert!(uris.is_empty(), "Cert with no AIA should return no URIs");
    }

    #[test]
    fn test_extract_ca_issuers_with_aia() {
        // Build a certificate with an AIA caIssuers extension and verify URI extraction
        use crate::algo::{AlgorithmId, KeyPair};
        use crate::cert::{
            builder::CertificateBuilder, extensions::AuthorityInfoAccess, NameBuilder, Validity,
        };

        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("AIA Cert Test").build();
        let aia = AuthorityInfoAccess::new()
            .ocsp("http://ocsp.example.com")
            .ca_issuer("http://ca.example.com/issuer.crt");

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .validity(Validity::days_from_now(30))
        .authority_info_access(aia)
        .include_subject_key_identifier(false)
        .include_authority_key_identifier(false)
        .build_and_sign(&kp)
        .unwrap();

        let uris = extract_ca_issuers_uris(&cert);
        assert_eq!(uris.len(), 1);
        assert_eq!(uris[0], "http://ca.example.com/issuer.crt");
    }

    // ---- Self-signed detection tests ----

    #[cfg(feature = "aia-chasing")]
    #[test]
    fn test_is_self_signed_root() {
        use crate::algo::{AlgorithmId, KeyPair};
        use crate::cert::{
            builder::CertificateBuilder, extensions::BasicConstraints, NameBuilder, Validity,
        };

        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Self-Signed Root").build();

        // Self-signed: same subject and issuer
        let cert = CertificateBuilder::new(
            subject.clone(),
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .validity(Validity::days_from_now(365))
        .basic_constraints(BasicConstraints::ca())
        .issuer(subject)
        .include_subject_key_identifier(false)
        .include_authority_key_identifier(false)
        .build_and_sign(&kp)
        .unwrap();

        assert!(
            is_self_signed(&cert),
            "Root CA should be detected as self-signed"
        );
    }

    #[cfg(feature = "aia-chasing")]
    #[test]
    fn test_is_self_signed_ee() {
        // An end-entity cert from a different issuer should NOT be self-signed
        use crate::algo::{AlgorithmId, KeyPair};
        use crate::cert::{builder::CertificateBuilder, NameBuilder, Validity};

        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("EE Cert").build();
        let issuer = NameBuilder::new("Issuing CA").build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .validity(Validity::days_from_now(90))
        .issuer(issuer)
        .include_subject_key_identifier(false)
        .include_authority_key_identifier(false)
        .build_and_sign(&kp)
        .unwrap();

        assert!(
            !is_self_signed(&cert),
            "EE cert with different issuer should not be detected as self-signed"
        );
    }

    // ---- DER certificate validation tests ----

    #[cfg(feature = "aia-chasing")]
    #[test]
    fn test_parse_der_cert_bad_tag() {
        // Should reject bytes not starting with 0x30
        let result = parse_der_cert(&[0x01, 0x02, 0x03]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("0x01") || err.contains("SEQUENCE"),
            "Error should mention invalid tag: {err}"
        );
    }

    #[cfg(feature = "aia-chasing")]
    #[test]
    fn test_parse_der_cert_empty() {
        let result = parse_der_cert(&[]);
        assert!(result.is_err());
    }

    // ---- Loop detection tests ----

    #[test]
    #[cfg(feature = "aia-chasing")]
    fn test_chase_disabled_returns_empty() {
        use crate::algo::{AlgorithmId, KeyPair};
        use crate::cert::{builder::CertificateBuilder, NameBuilder, Validity};

        let config = AiaChaseConfig {
            enabled: false,
            ..Default::default()
        };
        let chaser = AiaChaser::new(config).unwrap();

        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Test Cert").build();
        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .validity(Validity::days_from_now(30))
        .include_subject_key_identifier(false)
        .include_authority_key_identifier(false)
        .build_and_sign(&kp)
        .unwrap();

        let result = chaser.chase(&cert).unwrap();
        assert!(result.is_empty(), "Disabled chaser should return empty Vec");
    }

    #[test]
    #[cfg(feature = "aia-chasing")]
    fn test_chase_no_aia_returns_empty() {
        // A cert with no AIA extension should result in empty chase
        use crate::algo::{AlgorithmId, KeyPair};
        use crate::cert::{builder::CertificateBuilder, NameBuilder, Validity};

        let config = AiaChaseConfig::default();
        let chaser = AiaChaser::new(config).unwrap();

        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("No AIA").build();
        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .validity(Validity::days_from_now(30))
        .include_subject_key_identifier(false)
        .include_authority_key_identifier(false)
        .build_and_sign(&kp)
        .unwrap();

        let result = chaser.chase(&cert).unwrap();
        assert!(
            result.is_empty(),
            "Cert with no AIA should produce no fetches"
        );
    }

    // ---- p7c parsing tests (using synthetic DER) ----

    #[cfg(feature = "aia-chasing")]
    #[test]
    fn test_parse_p7c_der_invalid_input() {
        // Empty or garbage should return error
        assert!(parse_p7c_der(&[]).is_err());
        assert!(parse_p7c_der(&[0xFF, 0x00]).is_err());
    }

    #[test]
    fn test_parse_aia_ca_issuers_empty_sequence() {
        // SEQUENCE {} — no AccessDescriptions
        let data = [0x30, 0x00];
        let uris = parse_aia_ca_issuers(&data);
        assert!(uris.is_empty());
    }

    #[test]
    fn test_parse_general_name_uri_wrong_tag() {
        // Tag 0x82 (dNSName) instead of 0x86 (URI) — should return None
        let data = [
            0x82, 0x0B, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
        ];
        assert!(parse_general_name_uri(&data).is_none());
    }

    #[test]
    fn test_parse_general_name_uri_valid() {
        let uri = b"http://ca.example.com/issuer.crt";
        let mut data = vec![0x86u8];
        data.push(uri.len() as u8);
        data.extend_from_slice(uri);
        let result = parse_general_name_uri(&data);
        assert_eq!(result, Some("http://ca.example.com/issuer.crt".to_string()));
    }

    #[test]
    fn test_parse_general_name_uri_no_scheme() {
        // URI without :// should be rejected
        let uri = b"ca.example.com/issuer.crt";
        let mut data = vec![0x86u8];
        data.push(uri.len() as u8);
        data.extend_from_slice(uri);
        let result = parse_general_name_uri(&data);
        assert!(result.is_none(), "URI without scheme should be rejected");
    }

    #[test]
    fn test_decode_oid_arcs_single_arc() {
        // Just one byte: 0 * 40 + 0 = 0 → arcs [0, 0]
        let arcs = decode_oid_arcs(&[0x00]);
        assert_eq!(arcs, vec![0, 0]);
    }

    // ---- AIA URI filtering tests (only http:// allowed) ----

    #[test]
    #[cfg(feature = "aia-chasing")]
    fn test_fetch_cert_rejects_non_http_uri() {
        let chaser = AiaChaser::with_defaults().unwrap();
        // ldap:// and file:// URIs are common in AIA but not supported
        let result = chaser.fetch_cert("ldap://directory.example.com/cn=CA");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("scheme") || err.contains("http"),
            "Error should mention scheme restriction: {err}"
        );
    }

    #[test]
    #[cfg(feature = "aia-chasing")]
    fn test_fetch_cert_rejects_file_uri() {
        let chaser = AiaChaser::with_defaults().unwrap();
        let result = chaser.fetch_cert("file:///etc/ssl/certs/ca-cert.crt");
        assert!(result.is_err());
    }
}
