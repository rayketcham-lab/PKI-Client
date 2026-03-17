//! DANE (DNS-Based Authentication of Named Entities) — RFC 6698/7671
//!
//! Provides TLSA record types, certificate matching logic, and record generation
//! for DNS-based certificate pinning. Domain owners publish TLSA records in DNS
//! to specify which certificates are valid for their services.
//!
//! ## TLSA Record Format (RFC 6698 §2.1)
//! ```text
//! _port._protocol.hostname. IN TLSA usage selector matching_type cert_data
//! ```
//!
//! ## Supported Configurations
//! - **Usage**: PKIX-TA (0), PKIX-EE (1), DANE-TA (2), DANE-EE (3)
//! - **Selector**: Full certificate (0), SubjectPublicKeyInfo (1)
//! - **Matching type**: Exact (0), SHA-256 (1), SHA-512 (2)

use crate::digest;
use crate::error::{Error, Result};

/// TLSA certificate usage field (RFC 6698 §2.1.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsaUsage {
    /// CA constraint — must match a CA cert in the PKIX chain
    PkixTa = 0,
    /// Service certificate constraint — must match the EE cert + PKIX validation
    PkixEe = 1,
    /// Trust anchor assertion — CA cert used as DANE-only trust anchor
    DaneTa = 2,
    /// Domain-issued certificate — EE cert, DANE-only trust (no PKIX required)
    DaneEe = 3,
}

impl TlsaUsage {
    /// Parse from u8 value
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::PkixTa),
            1 => Ok(Self::PkixEe),
            2 => Ok(Self::DaneTa),
            3 => Ok(Self::DaneEe),
            _ => Err(Error::InvalidCertificate(format!(
                "Invalid TLSA usage: {} (must be 0-3)",
                v
            ))),
        }
    }

    /// Whether this usage requires PKIX (traditional CA) validation
    pub fn requires_pkix(&self) -> bool {
        matches!(self, Self::PkixTa | Self::PkixEe)
    }

    /// Whether this usage matches a CA certificate (vs end-entity)
    pub fn matches_ca(&self) -> bool {
        matches!(self, Self::PkixTa | Self::DaneTa)
    }
}

impl std::fmt::Display for TlsaUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PkixTa => write!(f, "PKIX-TA (0)"),
            Self::PkixEe => write!(f, "PKIX-EE (1)"),
            Self::DaneTa => write!(f, "DANE-TA (2)"),
            Self::DaneEe => write!(f, "DANE-EE (3)"),
        }
    }
}

/// TLSA selector field (RFC 6698 §2.1.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsaSelector {
    /// Full certificate DER
    FullCertificate = 0,
    /// SubjectPublicKeyInfo DER
    SubjectPublicKeyInfo = 1,
}

impl TlsaSelector {
    /// Parse from u8 value
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::FullCertificate),
            1 => Ok(Self::SubjectPublicKeyInfo),
            _ => Err(Error::InvalidCertificate(format!(
                "Invalid TLSA selector: {} (must be 0-1)",
                v
            ))),
        }
    }
}

impl std::fmt::Display for TlsaSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FullCertificate => write!(f, "Full certificate (0)"),
            Self::SubjectPublicKeyInfo => write!(f, "SubjectPublicKeyInfo (1)"),
        }
    }
}

/// TLSA matching type field (RFC 6698 §2.1.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsaMatchingType {
    /// Exact match — full data comparison
    Exact = 0,
    /// SHA-256 hash
    Sha256 = 1,
    /// SHA-512 hash
    Sha512 = 2,
}

impl TlsaMatchingType {
    /// Parse from u8 value
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Exact),
            1 => Ok(Self::Sha256),
            2 => Ok(Self::Sha512),
            _ => Err(Error::InvalidCertificate(format!(
                "Invalid TLSA matching type: {} (must be 0-2)",
                v
            ))),
        }
    }
}

impl std::fmt::Display for TlsaMatchingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact => write!(f, "Exact (0)"),
            Self::Sha256 => write!(f, "SHA-256 (1)"),
            Self::Sha512 => write!(f, "SHA-512 (2)"),
        }
    }
}

/// A TLSA record (RFC 6698 §2.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsaRecord {
    pub usage: TlsaUsage,
    pub selector: TlsaSelector,
    pub matching_type: TlsaMatchingType,
    /// Certificate association data (hash or raw bytes depending on matching_type)
    pub cert_association_data: Vec<u8>,
}

impl TlsaRecord {
    /// Create a new TLSA record
    pub fn new(
        usage: TlsaUsage,
        selector: TlsaSelector,
        matching_type: TlsaMatchingType,
        cert_association_data: Vec<u8>,
    ) -> Self {
        Self {
            usage,
            selector,
            matching_type,
            cert_association_data,
        }
    }
}

impl std::fmt::Display for TlsaRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.usage as u8,
            self.selector as u8,
            self.matching_type as u8,
            hex::encode(&self.cert_association_data)
        )
    }
}

/// Extract SubjectPublicKeyInfo DER from a certificate DER.
///
/// Parses the outer Certificate SEQUENCE to find the TBSCertificate,
/// then extracts the subjectPublicKeyInfo field (RFC 5280 §4.1).
fn extract_spki_from_cert_der(cert_der: &[u8]) -> Result<Vec<u8>> {
    // Parse using x509-cert to reliably extract SPKI
    use der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| Error::Decoding(format!("Failed to parse certificate DER: {}", e)))?;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::Encoding(format!("Failed to encode SPKI: {}", e)))?;
    Ok(spki)
}

/// Select the data to match from a certificate based on the selector.
fn select_data(cert_der: &[u8], selector: TlsaSelector) -> Result<Vec<u8>> {
    match selector {
        TlsaSelector::FullCertificate => Ok(cert_der.to_vec()),
        TlsaSelector::SubjectPublicKeyInfo => extract_spki_from_cert_der(cert_der),
    }
}

/// Compute the association data by applying the matching type to selected data.
fn compute_association_data(data: &[u8], matching_type: TlsaMatchingType) -> Vec<u8> {
    match matching_type {
        TlsaMatchingType::Exact => data.to_vec(),
        TlsaMatchingType::Sha256 => digest::sha256(data),
        TlsaMatchingType::Sha512 => digest::sha512(data),
    }
}

/// Check if a certificate matches a TLSA record.
///
/// Applies the record's selector to extract the relevant data from the certificate,
/// then applies the matching type and compares against the record's association data.
pub fn match_certificate(cert_der: &[u8], record: &TlsaRecord) -> Result<bool> {
    let selected = select_data(cert_der, record.selector)?;
    let computed = compute_association_data(&selected, record.matching_type);
    Ok(computed == record.cert_association_data)
}

/// Generate a TLSA record from a certificate.
///
/// Applies the given selector and matching type to produce the association data.
pub fn generate_tlsa_record(
    cert_der: &[u8],
    usage: TlsaUsage,
    selector: TlsaSelector,
    matching_type: TlsaMatchingType,
) -> Result<TlsaRecord> {
    let selected = select_data(cert_der, selector)?;
    let association_data = compute_association_data(&selected, matching_type);
    Ok(TlsaRecord::new(
        usage,
        selector,
        matching_type,
        association_data,
    ))
}

/// Construct the TLSA DNS domain name per RFC 6698 §3.
///
/// Format: `_port._protocol.hostname`
///
/// # Examples
/// ```ignore
/// assert_eq!(tlsa_domain_name("example.com", 443, "tcp"), "_443._tcp.example.com");
/// ```
pub fn tlsa_domain_name(hostname: &str, port: u16, protocol: &str) -> String {
    format!("_{}._{}.{}", port, protocol, hostname)
}

/// Format a TLSA record as RDATA string (for DNS zone files).
///
/// Output: `"usage selector matching_type hex_data"`
pub fn format_tlsa_rdata(record: &TlsaRecord) -> String {
    format!(
        "{} {} {} {}",
        record.usage as u8,
        record.selector as u8,
        record.matching_type as u8,
        hex::encode(&record.cert_association_data)
    )
}

/// Parse TLSA RDATA from a string.
///
/// Expected format: `"usage selector matching_type hex_data"`
pub fn parse_tlsa_rdata(rdata: &str) -> Result<TlsaRecord> {
    let parts: Vec<&str> = rdata.split_whitespace().collect();
    if parts.len() != 4 {
        return Err(Error::Decoding(format!(
            "Invalid TLSA RDATA: expected 4 fields, got {}",
            parts.len()
        )));
    }

    let usage = parts[0]
        .parse::<u8>()
        .map_err(|e| Error::Decoding(format!("Invalid usage field: {}", e)))?;
    let selector = parts[1]
        .parse::<u8>()
        .map_err(|e| Error::Decoding(format!("Invalid selector field: {}", e)))?;
    let matching_type = parts[2]
        .parse::<u8>()
        .map_err(|e| Error::Decoding(format!("Invalid matching type field: {}", e)))?;
    let data = hex::decode(parts[3])
        .map_err(|e| Error::Decoding(format!("Invalid hex association data: {}", e)))?;

    Ok(TlsaRecord::new(
        TlsaUsage::from_u8(usage)?,
        TlsaSelector::from_u8(selector)?,
        TlsaMatchingType::from_u8(matching_type)?,
        data,
    ))
}

/// Result of DANE verification against a certificate chain.
#[derive(Debug)]
pub struct DaneVerificationResult {
    /// Whether any TLSA record matched
    pub matched: bool,
    /// Index of the matching record in the input slice (if matched)
    pub matching_record_index: Option<usize>,
    /// Index of the matching certificate in the chain (if matched)
    pub matching_cert_index: Option<usize>,
    /// Human-readable status
    pub status: String,
}

/// Verify a certificate chain against a set of TLSA records.
///
/// Per RFC 7671 §5, if multiple TLSA records are present, a match against
/// any one record is sufficient (logical OR).
///
/// The chain is ordered `[end_entity, intermediate..., root]`.
///
/// This function implements the matching logic only — it does NOT perform
/// PKIX path validation (the caller should handle that for usage 0/1).
pub fn verify_dane(
    cert_chain: &[Vec<u8>],
    records: &[TlsaRecord],
) -> Result<DaneVerificationResult> {
    if cert_chain.is_empty() {
        return Err(Error::InvalidCertificate(
            "Empty certificate chain for DANE verification".into(),
        ));
    }
    if records.is_empty() {
        return Ok(DaneVerificationResult {
            matched: false,
            matching_record_index: None,
            matching_cert_index: None,
            status: "No TLSA records to verify against".into(),
        });
    }

    for (ri, record) in records.iter().enumerate() {
        // Determine which certificates to check based on usage
        let cert_indices: Vec<usize> = if record.usage.matches_ca() {
            // CA usage (0, 2): check all certs except the first (EE)
            if cert_chain.len() > 1 {
                (1..cert_chain.len()).collect()
            } else {
                // Single cert chain — check it anyway (self-signed CA)
                vec![0]
            }
        } else {
            // EE usage (1, 3): check only the first cert (end entity)
            vec![0]
        };

        for &ci in &cert_indices {
            if let Ok(true) = match_certificate(&cert_chain[ci], record) {
                return Ok(DaneVerificationResult {
                    matched: true,
                    matching_record_index: Some(ri),
                    matching_cert_index: Some(ci),
                    status: format!(
                        "DANE verified: record {} ({}) matched cert {} in chain",
                        ri, record.usage, ci
                    ),
                });
            }
        }
    }

    Ok(DaneVerificationResult {
        matched: false,
        matching_record_index: None,
        matching_cert_index: None,
        status: "No TLSA record matched any certificate in the chain".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate a self-signed certificate DER for testing
    fn test_cert_der() -> Vec<u8> {
        use crate::algo::{AlgorithmId, KeyPair};
        use crate::cert::builder::CertificateBuilder;
        use crate::cert::name::DistinguishedName;
        use crate::cert::{encode_certificate_der, Validity};

        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let pub_key = kp.public_key_der().unwrap();
        let subject = DistinguishedName::simple("dane-test.example.com");
        let cert = CertificateBuilder::new(subject, pub_key, AlgorithmId::EcdsaP256)
            .validity(Validity::days_from_now(90))
            .build_and_sign(&kp)
            .unwrap();
        encode_certificate_der(&cert).unwrap()
    }

    // ---- SHA-256 certificate hash matching ----

    #[test]
    fn test_sha256_full_cert_match() {
        let cert_der = test_cert_der();
        let record = generate_tlsa_record(
            &cert_der,
            TlsaUsage::DaneEe,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
        )
        .unwrap();

        assert!(match_certificate(&cert_der, &record).unwrap());
        assert_eq!(record.cert_association_data.len(), 32); // SHA-256 = 32 bytes
    }

    // ---- SHA-512 certificate hash matching ----

    #[test]
    fn test_sha512_full_cert_match() {
        let cert_der = test_cert_der();
        let record = generate_tlsa_record(
            &cert_der,
            TlsaUsage::DaneEe,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha512,
        )
        .unwrap();

        assert!(match_certificate(&cert_der, &record).unwrap());
        assert_eq!(record.cert_association_data.len(), 64); // SHA-512 = 64 bytes
    }

    // ---- Exact match ----

    #[test]
    fn test_exact_full_cert_match() {
        let cert_der = test_cert_der();
        let record = generate_tlsa_record(
            &cert_der,
            TlsaUsage::DaneEe,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Exact,
        )
        .unwrap();

        assert!(match_certificate(&cert_der, &record).unwrap());
        assert_eq!(record.cert_association_data, cert_der);
    }

    // ---- SPKI selector with SHA-256 ----

    #[test]
    fn test_spki_sha256_match() {
        let cert_der = test_cert_der();
        let record = generate_tlsa_record(
            &cert_der,
            TlsaUsage::DaneEe,
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
        )
        .unwrap();

        assert!(match_certificate(&cert_der, &record).unwrap());
        assert_eq!(record.cert_association_data.len(), 32);
    }

    // ---- SPKI selector with SHA-512 ----

    #[test]
    fn test_spki_sha512_match() {
        let cert_der = test_cert_der();
        let record = generate_tlsa_record(
            &cert_der,
            TlsaUsage::DaneEe,
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha512,
        )
        .unwrap();

        assert!(match_certificate(&cert_der, &record).unwrap());
        assert_eq!(record.cert_association_data.len(), 64);
    }

    // ---- Mismatched data returns false ----

    #[test]
    fn test_mismatch_returns_false() {
        let cert_der = test_cert_der();
        let record = TlsaRecord::new(
            TlsaUsage::DaneEe,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            vec![0xFF; 32], // Wrong hash
        );

        assert!(!match_certificate(&cert_der, &record).unwrap());
    }

    // ---- TLSA domain name formatting ----

    #[test]
    fn test_tlsa_domain_name() {
        assert_eq!(
            tlsa_domain_name("example.com", 443, "tcp"),
            "_443._tcp.example.com"
        );
        assert_eq!(
            tlsa_domain_name("mail.example.com", 25, "tcp"),
            "_25._tcp.mail.example.com"
        );
        assert_eq!(
            tlsa_domain_name("example.com", 853, "tcp"),
            "_853._tcp.example.com"
        );
    }

    // ---- TLSA rdata formatting and parsing roundtrip ----

    #[test]
    fn test_tlsa_rdata_roundtrip() {
        let cert_der = test_cert_der();
        let record = generate_tlsa_record(
            &cert_der,
            TlsaUsage::DaneEe,
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
        )
        .unwrap();

        let rdata = format_tlsa_rdata(&record);
        let parsed = parse_tlsa_rdata(&rdata).unwrap();
        assert_eq!(parsed, record);
    }

    // ---- Generate + verify roundtrip ----

    #[test]
    fn test_generate_verify_roundtrip() {
        let cert_der = test_cert_der();
        let record = generate_tlsa_record(
            &cert_der,
            TlsaUsage::DaneEe,
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
        )
        .unwrap();

        let result = verify_dane(&[cert_der], &[record]).unwrap();
        assert!(result.matched);
        assert_eq!(result.matching_record_index, Some(0));
        assert_eq!(result.matching_cert_index, Some(0));
    }

    // ---- Invalid matching type error ----

    #[test]
    fn test_invalid_matching_type() {
        assert!(TlsaMatchingType::from_u8(3).is_err());
        assert!(TlsaMatchingType::from_u8(255).is_err());
    }

    // ---- Invalid usage error ----

    #[test]
    fn test_invalid_usage() {
        assert!(TlsaUsage::from_u8(4).is_err());
        assert!(TlsaUsage::from_u8(255).is_err());
    }

    // ---- Invalid selector error ----

    #[test]
    fn test_invalid_selector() {
        assert!(TlsaSelector::from_u8(2).is_err());
        assert!(TlsaSelector::from_u8(255).is_err());
    }

    // ---- Empty cert chain error ----

    #[test]
    fn test_empty_chain_error() {
        let record = TlsaRecord::new(
            TlsaUsage::DaneEe,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            vec![0; 32],
        );

        assert!(verify_dane(&[], &[record]).is_err());
    }

    // ---- Multiple TLSA records (any-match semantics per RFC 7671) ----

    #[test]
    fn test_multiple_records_any_match() {
        let cert_der = test_cert_der();

        // First record: wrong hash (won't match)
        let bad_record = TlsaRecord::new(
            TlsaUsage::DaneEe,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            vec![0xAB; 32],
        );

        // Second record: correct (will match)
        let good_record = generate_tlsa_record(
            &cert_der,
            TlsaUsage::DaneEe,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
        )
        .unwrap();

        let result = verify_dane(&[cert_der], &[bad_record, good_record]).unwrap();
        assert!(result.matched);
        assert_eq!(result.matching_record_index, Some(1)); // Second record matched
    }

    // ---- CA usage checks intermediate certs ----

    #[test]
    fn test_ca_usage_matches_intermediate() {
        use crate::algo::{AlgorithmId, KeyPair};
        use crate::cert::builder::CertificateBuilder;
        use crate::cert::extensions::{BasicConstraints, KeyUsage, KeyUsageFlags};
        use crate::cert::name::DistinguishedName;
        use crate::cert::{encode_certificate_der, Validity};

        // Generate CA cert
        let ca_kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_pub = ca_kp.public_key_der().unwrap();
        let ca_subject = DistinguishedName::simple("Test CA");
        let ca_cert = CertificateBuilder::new(ca_subject, ca_pub, AlgorithmId::EcdsaP256)
            .validity(Validity::years_from_now(10))
            .basic_constraints(BasicConstraints {
                ca: true,
                path_len_constraint: None,
            })
            .key_usage(KeyUsage::new(KeyUsageFlags::ca_default()))
            .build_and_sign(&ca_kp)
            .unwrap();
        let ca_der = encode_certificate_der(&ca_cert).unwrap();

        // Generate EE cert
        let ee_kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ee_pub = ee_kp.public_key_der().unwrap();
        let ee_subject = DistinguishedName::simple("ee.example.com");
        let ee_cert = CertificateBuilder::new(ee_subject, ee_pub, AlgorithmId::EcdsaP256)
            .validity(Validity::days_from_now(90))
            .build_and_sign(&ca_kp)
            .unwrap();
        let ee_der = encode_certificate_der(&ee_cert).unwrap();

        // DANE-TA record for the CA cert
        let record = generate_tlsa_record(
            &ca_der,
            TlsaUsage::DaneTa,
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
        )
        .unwrap();

        // Chain: [EE, CA]
        let result = verify_dane(&[ee_der, ca_der], &[record]).unwrap();
        assert!(result.matched);
        assert_eq!(result.matching_cert_index, Some(1)); // Matched the CA cert
    }

    // ---- No records returns not-matched ----

    #[test]
    fn test_no_records_returns_not_matched() {
        let cert_der = test_cert_der();
        let result = verify_dane(&[cert_der], &[]).unwrap();
        assert!(!result.matched);
    }

    // ---- Display/formatting ----

    #[test]
    fn test_tlsa_record_display() {
        let record = TlsaRecord::new(
            TlsaUsage::DaneEe,
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
            vec![0xAB, 0xCD, 0xEF],
        );

        let display = format!("{}", record);
        assert_eq!(display, "3 1 1 abcdef");
    }

    // ---- parse_tlsa_rdata error cases ----

    #[test]
    fn test_parse_rdata_too_few_fields() {
        assert!(parse_tlsa_rdata("3 1 1").is_err());
    }

    #[test]
    fn test_parse_rdata_invalid_hex() {
        assert!(parse_tlsa_rdata("3 1 1 not_hex!").is_err());
    }

    #[test]
    fn test_parse_rdata_invalid_usage() {
        assert!(parse_tlsa_rdata("5 1 1 abcdef").is_err());
    }
}
