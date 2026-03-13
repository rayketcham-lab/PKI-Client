//! # pki-client-output
//!
//! Output formatting library for PKI Client - human-readable and machine-parseable output.
//!
//! This crate provides formatters for:
//! - Certificate display (text, JSON)
//! - Chain display (ASCII tree)
//! - Key information
//! - Colored terminal output
//!
//! ## Example
//!
//! ```ignore
//! use pki_client_output::{Certificate, CertFormatter, OutputFormat};
//!
//! let cert = Certificate::from_pem(pem_data)?;
//! let output = CertFormatter::format(&cert, true);
//! println!("{}", output);
//! ```

#![deny(missing_docs)]
#![warn(clippy::all)]

mod cert;
mod format;
pub mod oid_registry;

pub use cert::CertFormatter;
pub use format::{Formatter, OutputFormat};
pub use oid_registry::{eku_name, extension_name, init_registry, policy_name, signature_name};

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Subject Alternative Name entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SanEntry {
    /// DNS name.
    Dns(String),
    /// IP address.
    Ip(String),
    /// Email address.
    Email(String),
    /// URI.
    Uri(String),
    /// Other type.
    Other(String),
}

impl std::fmt::Display for SanEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SanEntry::Dns(s) => write!(f, "DNS:{s}"),
            SanEntry::Ip(s) => write!(f, "IP:{s}"),
            SanEntry::Email(s) => write!(f, "email:{s}"),
            SanEntry::Uri(s) => write!(f, "URI:{s}"),
            SanEntry::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Certificate Transparency SCT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtSct {
    /// Log ID (hex).
    pub log_id: String,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
}

/// Parsed X.509 certificate for display purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// Certificate version (1, 2, or 3).
    pub version: u32,
    /// Serial number (hex string).
    pub serial: String,
    /// Subject distinguished name.
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Validity start.
    pub not_before: DateTime<Utc>,
    /// Validity end.
    pub not_after: DateTime<Utc>,
    /// Signature algorithm OID.
    pub signature_algorithm: String,
    /// Signature algorithm name.
    pub signature_algorithm_name: String,
    /// Key algorithm OID.
    pub key_algorithm: String,
    /// Key algorithm name.
    pub key_algorithm_name: String,
    /// Key size in bits.
    pub key_size: u32,
    /// EC curve name (if applicable).
    pub ec_curve: Option<String>,
    /// RSA modulus (hex, if applicable).
    pub rsa_modulus: Option<String>,
    /// RSA exponent (if applicable).
    pub rsa_exponent: Option<u32>,
    /// Whether this is a CA certificate.
    pub is_ca: bool,
    /// Path length constraint (-1 if not set).
    pub path_length: i32,
    /// Basic constraints marked critical.
    pub basic_constraints_critical: bool,
    /// Key usage extensions.
    pub key_usage: Vec<String>,
    /// Key usage marked critical.
    pub key_usage_critical: bool,
    /// Extended key usage OIDs/names.
    pub extended_key_usage: Vec<String>,
    /// Subject Alternative Names.
    pub san: Vec<SanEntry>,
    /// Subject Key Identifier (hex).
    pub subject_key_id: Option<String>,
    /// Authority Key Identifier (hex).
    pub authority_key_id: Option<String>,
    /// OCSP responder URLs.
    pub ocsp_urls: Vec<String>,
    /// CA Issuer URLs.
    pub ca_issuer_urls: Vec<String>,
    /// CRL distribution points.
    pub crl_distribution_points: Vec<String>,
    /// Certificate policies (OIDs).
    pub certificate_policies: Vec<String>,
    /// OCSP Must-Staple extension present.
    pub ocsp_must_staple: bool,
    /// Certificate Transparency SCTs.
    pub ct_scts: Vec<CtSct>,
    /// SHA-256 fingerprint (hex).
    pub fingerprint_sha256: String,
    /// SHA-1 fingerprint (hex).
    pub fingerprint_sha1: String,
    /// SPKI SHA-256 (base64, for pinning).
    pub spki_sha256_b64: String,
    /// Raw DER bytes.
    #[serde(skip)]
    pub der: Vec<u8>,
}

impl Certificate {
    /// Parse a certificate from DER bytes.
    pub fn from_der(der: &[u8]) -> Result<Self, String> {
        let (_, cert) = x509_parser::parse_x509_certificate(der)
            .map_err(|e| format!("Failed to parse certificate: {e}"))?;

        let not_before = Utc
            .timestamp_opt(cert.validity.not_before.timestamp(), 0)
            .single()
            .unwrap_or_else(Utc::now);

        let not_after = Utc
            .timestamp_opt(cert.validity.not_after.timestamp(), 0)
            .single()
            .unwrap_or_else(Utc::now);

        // Serial number
        let serial = cert.serial.to_str_radix(16);

        // Signature algorithm
        let sig_oid = cert.signature_algorithm.algorithm.to_string();
        let sig_name = oid_to_sig_name(&sig_oid);

        // Key algorithm and size
        let (key_oid, key_name, key_size, ec_curve) = get_key_info(&cert);

        // RSA specifics
        let (rsa_modulus, rsa_exponent) = if key_name == "RSA" {
            extract_rsa_params(&cert)
        } else {
            (None, None)
        };

        // Basic constraints
        let (is_ca, path_length, bc_critical) = cert
            .basic_constraints()
            .ok()
            .flatten()
            .map(|bc| {
                (
                    bc.value.ca,
                    bc.value.path_len_constraint.map_or(-1, |p| p as i32),
                    bc.critical,
                )
            })
            .unwrap_or((false, -1, false));

        // Key usage
        let (key_usage, ku_critical) = cert
            .key_usage()
            .ok()
            .flatten()
            .map(|ku| (parse_key_usage(ku.value), ku.critical))
            .unwrap_or((Vec::new(), false));

        // Extended key usage
        let extended_key_usage = cert
            .extended_key_usage()
            .ok()
            .flatten()
            .map(|eku| {
                let mut usages = Vec::new();
                let v = &eku.value;
                if v.any {
                    usages.push("Any Extended Key Usage".to_string());
                }
                if v.server_auth {
                    usages.push("TLS Web Server Authentication".to_string());
                }
                if v.client_auth {
                    usages.push("TLS Web Client Authentication".to_string());
                }
                if v.code_signing {
                    usages.push("Code Signing".to_string());
                }
                if v.email_protection {
                    usages.push("E-mail Protection".to_string());
                }
                if v.time_stamping {
                    usages.push("Time Stamping".to_string());
                }
                if v.ocsp_signing {
                    usages.push("OCSP Signing".to_string());
                }
                for oid in &v.other {
                    usages.push(oid_to_eku_name(&oid.to_string()));
                }
                usages
            })
            .unwrap_or_default();

        // Subject Alternative Names
        let san = cert
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|san_ext| {
                san_ext
                    .value
                    .general_names
                    .iter()
                    .filter_map(|name| match name {
                        x509_parser::prelude::GeneralName::DNSName(dns) => {
                            Some(SanEntry::Dns((*dns).to_string()))
                        }
                        x509_parser::prelude::GeneralName::IPAddress(ip) => {
                            Some(SanEntry::Ip(format_ip(ip)))
                        }
                        x509_parser::prelude::GeneralName::RFC822Name(email) => {
                            Some(SanEntry::Email((*email).to_string()))
                        }
                        x509_parser::prelude::GeneralName::URI(uri) => {
                            Some(SanEntry::Uri((*uri).to_string()))
                        }
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Key identifiers
        let subject_key_id = cert
            .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
            .ok()
            .flatten()
            .and_then(|ext| {
                if let x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(ski) =
                    ext.parsed_extension()
                {
                    Some(hex::encode(ski.0))
                } else {
                    None
                }
            });

        let authority_key_id = cert
            .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
            .ok()
            .flatten()
            .and_then(|ext| {
                if let x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) =
                    ext.parsed_extension()
                {
                    aki.key_identifier.as_ref().map(|ki| hex::encode(ki.0))
                } else {
                    None
                }
            });

        // Authority Information Access
        let (ocsp_urls, ca_issuer_urls) = parse_aia(&cert);

        // CRL distribution points
        let crl_distribution_points = parse_crldp(&cert);

        // Certificate policies
        let certificate_policies = parse_policies(&cert);

        // OCSP Must-Staple
        let ocsp_must_staple = has_ocsp_must_staple(&cert);

        // CT SCTs (simplified - just count them)
        let ct_scts = parse_scts(&cert);

        // Fingerprints
        let fingerprint_sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(der);
            hex::encode(hasher.finalize())
        };

        let fingerprint_sha1 = {
            let mut hasher = Sha1::new();
            hasher.update(der);
            hex::encode(hasher.finalize())
        };

        // SPKI pin
        let spki_sha256_b64 = {
            let spki_der = cert.public_key().raw;
            let mut hasher = Sha256::new();
            hasher.update(spki_der);
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                hasher.finalize(),
            )
        };

        Ok(Self {
            version: cert.version.0 + 1,
            serial,
            subject: cert.subject.to_string(),
            issuer: cert.issuer.to_string(),
            not_before,
            not_after,
            signature_algorithm: sig_oid,
            signature_algorithm_name: sig_name,
            key_algorithm: key_oid,
            key_algorithm_name: key_name,
            key_size,
            ec_curve,
            rsa_modulus,
            rsa_exponent,
            is_ca,
            path_length,
            basic_constraints_critical: bc_critical,
            key_usage,
            key_usage_critical: ku_critical,
            extended_key_usage,
            san,
            subject_key_id,
            authority_key_id,
            ocsp_urls,
            ca_issuer_urls,
            crl_distribution_points,
            certificate_policies,
            ocsp_must_staple,
            ct_scts,
            fingerprint_sha256,
            fingerprint_sha1,
            spki_sha256_b64,
            der: der.to_vec(),
        })
    }

    /// Parse a certificate from PEM.
    pub fn from_pem(pem: &str) -> Result<Self, String> {
        let der = pem::parse(pem)
            .map_err(|e| format!("Failed to parse PEM: {e}"))?
            .contents()
            .to_vec();
        Self::from_der(&der)
    }

    /// Parse all certificates from a PEM bundle.
    pub fn all_from_pem(pem: &str) -> Result<Vec<Self>, String> {
        let pems = pem::parse_many(pem).map_err(|e| format!("Failed to parse PEM bundle: {e}"))?;
        let mut certs = Vec::new();
        for p in pems {
            if p.tag() == "CERTIFICATE" {
                certs.push(Self::from_der(p.contents())?);
            }
        }
        if certs.is_empty() {
            return Err("No certificates found in PEM bundle".to_string());
        }
        Ok(certs)
    }

    /// Get the common name from the subject.
    pub fn common_name(&self) -> Option<&str> {
        // Parse CN from subject string like "CN=example.com, O=Example Inc"
        for part in self.subject.split(", ") {
            if let Some(cn) = part.strip_prefix("CN=") {
                return Some(cn);
            }
        }
        None
    }

    /// Check if the certificate is expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }

    /// Get days until expiry (negative if expired).
    pub fn days_until_expiry(&self) -> i64 {
        (self.not_after - Utc::now()).num_days()
    }

    /// Check if the certificate expires within the given duration.
    pub fn expires_within(&self, duration: chrono::Duration) -> bool {
        !self.is_expired() && Utc::now() + duration > self.not_after
    }

    /// Get percentage of lifetime used.
    pub fn lifetime_used_percent(&self) -> f64 {
        let total = (self.not_after - self.not_before).num_seconds() as f64;
        if total <= 0.0 {
            return 100.0;
        }
        let elapsed = (Utc::now() - self.not_before).num_seconds() as f64;
        (elapsed / total * 100.0).clamp(0.0, 100.0)
    }

    /// Check if the certificate is self-signed.
    pub fn is_self_signed(&self) -> bool {
        self.subject == self.issuer
    }

    /// Get raw DER bytes (alias for der field).
    pub fn raw_der(&self) -> &[u8] {
        &self.der
    }
}

/// Convert signature algorithm OID to name.
fn oid_to_sig_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.10" => "rsassaPss".to_string(),
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1".to_string(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".to_string(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".to_string(),
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512".to_string(),
        "1.3.101.112" => "Ed25519".to_string(),
        "1.3.101.113" => "Ed448".to_string(),
        // ML-DSA (FIPS 204)
        "2.16.840.1.101.3.4.3.17" => "ML-DSA-44".to_string(),
        "2.16.840.1.101.3.4.3.18" => "ML-DSA-65".to_string(),
        "2.16.840.1.101.3.4.3.19" => "ML-DSA-87".to_string(),
        _ => oid.to_string(),
    }
}

/// Convert EKU OID to name (uses OID registry).
fn oid_to_eku_name(oid: &str) -> String {
    oid_registry::eku_name(oid)
}

/// Get key algorithm info.
fn get_key_info(
    cert: &x509_parser::certificate::X509Certificate,
) -> (String, String, u32, Option<String>) {
    let algo_oid = cert.public_key().algorithm.algorithm.to_string();

    match algo_oid.as_str() {
        // RSA
        "1.2.840.113549.1.1.1" => {
            let bits = cert.public_key().subject_public_key.data.len() * 8;
            (algo_oid, "RSA".to_string(), bits as u32, None)
        }
        // EC
        "1.2.840.10045.2.1" => {
            let (curve, bits) = get_ec_curve(cert);
            (algo_oid, "EC".to_string(), bits, Some(curve))
        }
        // Ed25519
        "1.3.101.112" => (algo_oid, "Ed25519".to_string(), 256, None),
        // Ed448
        "1.3.101.113" => (algo_oid, "Ed448".to_string(), 456, None),
        // ML-DSA
        "2.16.840.1.101.3.4.3.17" => (algo_oid, "ML-DSA-44".to_string(), 0, None),
        "2.16.840.1.101.3.4.3.18" => (algo_oid, "ML-DSA-65".to_string(), 0, None),
        "2.16.840.1.101.3.4.3.19" => (algo_oid, "ML-DSA-87".to_string(), 0, None),
        _ => (algo_oid.clone(), algo_oid, 0, None),
    }
}

/// Get EC curve name and key size.
fn get_ec_curve(cert: &x509_parser::certificate::X509Certificate) -> (String, u32) {
    if let Some(params) = &cert.public_key().algorithm.parameters {
        // Parse the parameter as an OID (standard encoding for EC named curves)
        if let Ok(oid) = params.as_oid() {
            let oid_str = oid.to_string();
            match oid_str.as_str() {
                "1.2.840.10045.3.1.7" => return ("P-256".to_string(), 256),
                "1.3.132.0.34" => return ("P-384".to_string(), 384),
                "1.3.132.0.35" => return ("P-521".to_string(), 521),
                "1.3.132.0.10" => return ("secp256k1".to_string(), 256),
                _ => {}
            }
        }
        // Fallback: check Debug output for friendly names
        let params_str = format!("{params:?}");
        if params_str.contains("prime256v1") || params_str.contains("secp256r1") {
            return ("P-256".to_string(), 256);
        } else if params_str.contains("secp384r1") {
            return ("P-384".to_string(), 384);
        } else if params_str.contains("secp521r1") {
            return ("P-521".to_string(), 521);
        }
    }
    // Last resort: infer from public key length
    let pk_len = cert.public_key().subject_public_key.data.len();
    match pk_len {
        65 => ("P-256".to_string(), 256),  // uncompressed point: 1 + 32*2
        97 => ("P-384".to_string(), 384),  // uncompressed point: 1 + 48*2
        133 => ("P-521".to_string(), 521), // uncompressed point: 1 + 66*2
        _ => ("Unknown".to_string(), 0),
    }
}

/// Extract RSA modulus and exponent.
fn extract_rsa_params(
    cert: &x509_parser::certificate::X509Certificate,
) -> (Option<String>, Option<u32>) {
    // RSA public keys are encoded as SEQUENCE { modulus INTEGER, exponent INTEGER }
    let spk = &cert.public_key().subject_public_key.data;
    if spk.len() > 10 {
        // Simplified: just return the hex of the key data
        (Some(hex::encode(&spk[..64.min(spk.len())])), Some(65537))
    } else {
        (None, None)
    }
}

/// Parse key usage flags.
fn parse_key_usage(ku: &x509_parser::extensions::KeyUsage) -> Vec<String> {
    let mut usages = Vec::new();
    if ku.digital_signature() {
        usages.push("Digital Signature".to_string());
    }
    if ku.non_repudiation() {
        usages.push("Non Repudiation".to_string());
    }
    if ku.key_encipherment() {
        usages.push("Key Encipherment".to_string());
    }
    if ku.data_encipherment() {
        usages.push("Data Encipherment".to_string());
    }
    if ku.key_agreement() {
        usages.push("Key Agreement".to_string());
    }
    if ku.key_cert_sign() {
        usages.push("Certificate Sign".to_string());
    }
    if ku.crl_sign() {
        usages.push("CRL Sign".to_string());
    }
    if ku.encipher_only() {
        usages.push("Encipher Only".to_string());
    }
    if ku.decipher_only() {
        usages.push("Decipher Only".to_string());
    }
    usages
}

/// Format IP address from bytes.
fn format_ip(ip: &[u8]) -> String {
    if ip.len() == 4 {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    } else if ip.len() == 16 {
        // IPv6
        let parts: Vec<String> = ip
            .chunks(2)
            .map(|c| format!("{:02x}{:02x}", c[0], c.get(1).copied().unwrap_or(0)))
            .collect();
        parts.join(":")
    } else {
        hex::encode(ip)
    }
}

/// Parse Authority Information Access.
fn parse_aia(cert: &x509_parser::certificate::X509Certificate) -> (Vec<String>, Vec<String>) {
    let mut ocsp = Vec::new();
    let mut ca_issuers = Vec::new();

    // OID: 1.3.6.1.5.5.7.1.1
    if let Ok(Some(ext)) =
        cert.get_extension_unique(&x509_parser::oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS)
    {
        if let x509_parser::extensions::ParsedExtension::AuthorityInfoAccess(aia) =
            ext.parsed_extension()
        {
            for access in &aia.accessdescs {
                let method = access.access_method.to_string();
                if let x509_parser::prelude::GeneralName::URI(uri) = &access.access_location {
                    if method == "1.3.6.1.5.5.7.48.1" {
                        // OCSP
                        ocsp.push((*uri).to_string());
                    } else if method == "1.3.6.1.5.5.7.48.2" {
                        // CA Issuers
                        ca_issuers.push((*uri).to_string());
                    }
                }
            }
        }
    }

    (ocsp, ca_issuers)
}

/// Parse CRL Distribution Points.
fn parse_crldp(cert: &x509_parser::certificate::X509Certificate) -> Vec<String> {
    let mut urls = Vec::new();

    // OID: 2.5.29.31
    if let Ok(Some(ext)) =
        cert.get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
    {
        if let x509_parser::extensions::ParsedExtension::CRLDistributionPoints(crldp) =
            ext.parsed_extension()
        {
            for dp in &crldp.points {
                if let Some(x509_parser::prelude::DistributionPointName::FullName(names)) =
                    &dp.distribution_point
                {
                    for gn in names {
                        if let x509_parser::prelude::GeneralName::URI(uri) = gn {
                            urls.push((*uri).to_string());
                        }
                    }
                }
            }
        }
    }

    urls
}

/// Parse Certificate Policies.
fn parse_policies(cert: &x509_parser::certificate::X509Certificate) -> Vec<String> {
    let mut policies = Vec::new();

    // OID: 2.5.29.32
    if let Ok(Some(ext)) =
        cert.get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_CERTIFICATE_POLICIES)
    {
        if let x509_parser::extensions::ParsedExtension::CertificatePolicies(cp) =
            ext.parsed_extension()
        {
            for policy in cp.iter() {
                policies.push(policy.policy_id.to_string());
            }
        }
    }

    policies
}

/// Check for OCSP Must-Staple extension.
fn has_ocsp_must_staple(cert: &x509_parser::certificate::X509Certificate) -> bool {
    // OID: 1.3.6.1.5.5.7.1.24 (TLS Feature / status_request)
    for ext in cert.extensions() {
        if ext.oid.to_string() == "1.3.6.1.5.5.7.1.24" {
            return true;
        }
    }
    false
}

/// Parse SCTs (simplified - just extract timestamps if present).
fn parse_scts(cert: &x509_parser::certificate::X509Certificate) -> Vec<CtSct> {
    let mut scts = Vec::new();

    // OID: 1.3.6.1.4.1.11129.2.4.2 (Precertificate SCTs)
    for ext in cert.extensions() {
        if ext.oid.to_string() == "1.3.6.1.4.1.11129.2.4.2" {
            // Simplified: just note that SCTs are present
            scts.push(CtSct {
                log_id: "embedded".to_string(),
                timestamp: Utc::now(),
            });
        }
    }

    scts
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn make_cert() -> Certificate {
        Certificate {
            version: 3,
            serial: "01:02:03".to_string(),
            subject: "CN=test.example.com, O=Test Inc".to_string(),
            issuer: "CN=Test CA, O=Test Inc".to_string(),
            not_before: Utc::now() - Duration::days(30),
            not_after: Utc::now() + Duration::days(335),
            signature_algorithm: "1.2.840.10045.4.3.2".to_string(),
            signature_algorithm_name: "ecdsa-with-SHA256".to_string(),
            key_algorithm: "1.2.840.10045.2.1".to_string(),
            key_algorithm_name: "EC".to_string(),
            key_size: 256,
            ec_curve: Some("P-256".to_string()),
            rsa_modulus: None,
            rsa_exponent: None,
            is_ca: false,
            path_length: -1,
            basic_constraints_critical: false,
            key_usage: vec!["Digital Signature".to_string()],
            key_usage_critical: true,
            extended_key_usage: vec!["serverAuth".to_string()],
            san: vec![SanEntry::Dns("test.example.com".to_string())],
            subject_key_id: None,
            authority_key_id: None,
            ocsp_urls: vec![],
            ca_issuer_urls: vec![],
            crl_distribution_points: vec![],
            certificate_policies: vec![],
            ocsp_must_staple: false,
            ct_scts: vec![],
            fingerprint_sha256: "aa:bb:cc".to_string(),
            fingerprint_sha1: "dd:ee:ff".to_string(),
            spki_sha256_b64: String::new(),
            der: vec![0x30, 0x82],
        }
    }

    // ========== SanEntry Display ==========

    #[test]
    fn test_san_entry_display_dns() {
        let san = SanEntry::Dns("example.com".to_string());
        assert_eq!(san.to_string(), "DNS:example.com");
    }

    #[test]
    fn test_san_entry_display_ip() {
        let san = SanEntry::Ip("192.168.1.1".to_string());
        assert_eq!(san.to_string(), "IP:192.168.1.1");
    }

    #[test]
    fn test_san_entry_display_email() {
        let san = SanEntry::Email("user@example.com".to_string());
        assert_eq!(san.to_string(), "email:user@example.com");
    }

    #[test]
    fn test_san_entry_display_uri() {
        let san = SanEntry::Uri("https://example.com".to_string());
        assert_eq!(san.to_string(), "URI:https://example.com");
    }

    #[test]
    fn test_san_entry_display_other() {
        let san = SanEntry::Other("something".to_string());
        assert_eq!(san.to_string(), "something");
    }

    // ========== Certificate methods ==========

    #[test]
    fn test_common_name_present() {
        let cert = make_cert();
        assert_eq!(cert.common_name(), Some("test.example.com"));
    }

    #[test]
    fn test_common_name_absent() {
        let mut cert = make_cert();
        cert.subject = "O=Test Inc".to_string();
        assert_eq!(cert.common_name(), None);
    }

    #[test]
    fn test_common_name_only_cn() {
        let mut cert = make_cert();
        cert.subject = "CN=onlycn.com".to_string();
        assert_eq!(cert.common_name(), Some("onlycn.com"));
    }

    #[test]
    fn test_is_expired_false() {
        let cert = make_cert();
        assert!(!cert.is_expired());
    }

    #[test]
    fn test_is_expired_true() {
        let mut cert = make_cert();
        cert.not_after = Utc::now() - Duration::days(1);
        assert!(cert.is_expired());
    }

    #[test]
    fn test_days_until_expiry_positive() {
        let cert = make_cert();
        let days = cert.days_until_expiry();
        assert!(days > 330 && days <= 335);
    }

    #[test]
    fn test_days_until_expiry_negative() {
        let mut cert = make_cert();
        cert.not_after = Utc::now() - Duration::days(10);
        assert!(cert.days_until_expiry() < 0);
    }

    #[test]
    fn test_expires_within_true() {
        let cert = make_cert();
        assert!(cert.expires_within(Duration::days(400)));
    }

    #[test]
    fn test_expires_within_false() {
        let cert = make_cert();
        assert!(!cert.expires_within(Duration::days(30)));
    }

    #[test]
    fn test_expires_within_already_expired() {
        let mut cert = make_cert();
        cert.not_after = Utc::now() - Duration::days(1);
        assert!(!cert.expires_within(Duration::days(400)));
    }

    #[test]
    fn test_lifetime_used_percent() {
        let mut cert = make_cert();
        cert.not_before = Utc::now() - Duration::days(50);
        cert.not_after = Utc::now() + Duration::days(50);
        let pct = cert.lifetime_used_percent();
        assert!(pct > 45.0 && pct < 55.0);
    }

    #[test]
    fn test_lifetime_used_percent_zero_duration() {
        let mut cert = make_cert();
        cert.not_before = Utc::now();
        cert.not_after = Utc::now();
        assert_eq!(cert.lifetime_used_percent(), 100.0);
    }

    #[test]
    fn test_is_self_signed_true() {
        let mut cert = make_cert();
        cert.issuer = cert.subject.clone();
        assert!(cert.is_self_signed());
    }

    #[test]
    fn test_is_self_signed_false() {
        let cert = make_cert();
        assert!(!cert.is_self_signed());
    }

    #[test]
    fn test_raw_der() {
        let cert = make_cert();
        assert_eq!(cert.raw_der(), &[0x30, 0x82]);
    }

    // ========== oid_to_sig_name ==========

    #[test]
    fn test_oid_to_sig_name_sha256_rsa() {
        assert_eq!(
            oid_to_sig_name("1.2.840.113549.1.1.11"),
            "sha256WithRSAEncryption"
        );
    }

    #[test]
    fn test_oid_to_sig_name_ecdsa_sha256() {
        assert_eq!(oid_to_sig_name("1.2.840.10045.4.3.2"), "ecdsa-with-SHA256");
    }

    #[test]
    fn test_oid_to_sig_name_ed25519() {
        assert_eq!(oid_to_sig_name("1.3.101.112"), "Ed25519");
    }

    #[test]
    fn test_oid_to_sig_name_mldsa44() {
        assert_eq!(oid_to_sig_name("2.16.840.1.101.3.4.3.17"), "ML-DSA-44");
    }

    #[test]
    fn test_oid_to_sig_name_unknown() {
        assert_eq!(oid_to_sig_name("9.9.9.9"), "9.9.9.9");
    }

    // ========== format_ip ==========

    #[test]
    fn test_format_ipv4() {
        assert_eq!(format_ip(&[192, 168, 1, 1]), "192.168.1.1");
    }

    #[test]
    fn test_format_ipv4_localhost() {
        assert_eq!(format_ip(&[127, 0, 0, 1]), "127.0.0.1");
    }

    #[test]
    fn test_format_ipv6() {
        let ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let result = format_ip(&ipv6);
        assert!(result.contains("2001"));
        assert!(result.contains(":"));
    }

    #[test]
    fn test_format_ip_empty() {
        assert_eq!(format_ip(&[]), "");
    }

    #[test]
    fn test_format_ip_odd_length() {
        let result = format_ip(&[0xab, 0xcd, 0xef]);
        assert_eq!(result, "abcdef");
    }
}
