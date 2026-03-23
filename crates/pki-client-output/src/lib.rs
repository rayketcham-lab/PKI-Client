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
pub use oid_registry::{
    eku_name, extension_name, init_registry, key_algorithm_name, policy_name, signature_name,
};

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
            let bits = parse_rsa_modulus_bits(&cert.public_key().subject_public_key.data);
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

/// Parse RSA public key BIT STRING to extract modulus bit length.
///
/// The BIT STRING content is: SEQUENCE { INTEGER (modulus), INTEGER (exponent) }
/// We parse past the DER encoding to get the actual modulus byte count.
fn parse_rsa_modulus_bits(data: &[u8]) -> usize {
    // Skip SEQUENCE tag + length
    if data.len() < 4 || data[0] != 0x30 {
        return data.len() * 8; // fallback
    }
    let (seq_hdr, ok) = skip_der_tag_length(data);
    if !ok {
        return data.len() * 8;
    }
    let inner = &data[seq_hdr..];

    // First element is INTEGER (modulus)
    if inner.is_empty() || inner[0] != 0x02 {
        return data.len() * 8;
    }
    let (int_hdr, ok) = skip_der_tag_length(inner);
    if !ok {
        return data.len() * 8;
    }
    let mut modulus_len = inner.len() - int_hdr;
    // Parse actual length from the DER length field
    if inner.len() > 1 {
        let len_byte = inner[1];
        if len_byte < 0x80 {
            modulus_len = len_byte as usize;
        } else {
            let num_bytes = (len_byte & 0x7f) as usize;
            if inner.len() >= 2 + num_bytes {
                let mut len = 0usize;
                for i in 0..num_bytes {
                    len = (len << 8) | inner[2 + i] as usize;
                }
                modulus_len = len;
            }
        }
    }
    let modulus_start = int_hdr;
    // Skip leading zero byte (DER sign padding for positive integers)
    if modulus_len > 0 && modulus_start < inner.len() && inner[modulus_start] == 0x00 {
        modulus_len -= 1;
    }
    modulus_len * 8
}

/// Skip a DER tag + length, returning (header_size, success).
fn skip_der_tag_length(data: &[u8]) -> (usize, bool) {
    if data.len() < 2 {
        return (0, false);
    }
    let len_byte = data[1];
    if len_byte < 0x80 {
        (2, true)
    } else {
        let num = (len_byte & 0x7f) as usize;
        if data.len() < 2 + num {
            (0, false)
        } else {
            (2 + num, true)
        }
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

/// Parse RSA modulus and exponent from the SubjectPublicKey BIT STRING content.
///
/// The data is DER-encoded: `SEQUENCE { INTEGER (modulus), INTEGER (exponent) }`.
/// Returns `(modulus_hex_uppercase, exponent)` or `None` if parsing fails.
fn parse_rsa_spk(data: &[u8]) -> (Option<String>, Option<u32>) {
    // Need at least SEQUENCE tag+len + INTEGER tag+len
    if data.len() < 10 || data[0] != 0x30 {
        return (None, None);
    }

    // Skip SEQUENCE header
    let (seq_hdr, ok) = skip_der_tag_length(data);
    if !ok {
        return (None, None);
    }
    let inner = &data[seq_hdr..];

    // First INTEGER: modulus
    if inner.is_empty() || inner[0] != 0x02 {
        return (None, None);
    }
    let (mod_hdr, ok) = skip_der_tag_length(inner);
    if !ok {
        return (None, None);
    }
    let mod_len = parse_der_length(&inner[1..]);
    if mod_len == 0 || mod_hdr + mod_len > inner.len() {
        return (None, None);
    }
    let mut mod_bytes = &inner[mod_hdr..mod_hdr + mod_len];
    // Skip leading 0x00 padding (DER sign byte for positive integers)
    if mod_bytes.len() > 1 && mod_bytes[0] == 0x00 {
        mod_bytes = &mod_bytes[1..];
    }
    let modulus_hex = hex::encode(mod_bytes).to_uppercase();

    // Second INTEGER: exponent
    let exp_start = mod_hdr + mod_len;
    if exp_start >= inner.len() || inner[exp_start] != 0x02 {
        return (Some(modulus_hex), None);
    }
    let exp_data = &inner[exp_start..];
    let (exp_hdr, ok) = skip_der_tag_length(exp_data);
    if !ok {
        return (Some(modulus_hex), None);
    }
    let exp_len = parse_der_length(&exp_data[1..]);
    if exp_len == 0 || exp_hdr + exp_len > exp_data.len() {
        return (Some(modulus_hex), None);
    }
    let exp_bytes = &exp_data[exp_hdr..exp_hdr + exp_len];
    let mut exponent: u32 = 0;
    for &b in exp_bytes {
        exponent = exponent.checked_shl(8).unwrap_or(0) | b as u32;
    }

    (Some(modulus_hex), Some(exponent))
}

/// Parse a DER length field (starting after the tag byte).
fn parse_der_length(len_data: &[u8]) -> usize {
    if len_data.is_empty() {
        return 0;
    }
    let first = len_data[0];
    if first < 0x80 {
        first as usize
    } else {
        let num_bytes = (first & 0x7f) as usize;
        if len_data.len() < 1 + num_bytes {
            return 0;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | len_data[1 + i] as usize;
        }
        len
    }
}

/// Extract RSA modulus and exponent from an X.509 certificate.
fn extract_rsa_params(
    cert: &x509_parser::certificate::X509Certificate,
) -> (Option<String>, Option<u32>) {
    let spk = &cert.public_key().subject_public_key.data;
    parse_rsa_spk(spk)
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

    // ========== parse_rsa_spk ==========

    /// Helper: build DER-encoded RSA SPK from raw modulus bytes and exponent.
    fn build_rsa_spk_der(modulus: &[u8], exponent: u32) -> Vec<u8> {
        // Encode modulus INTEGER (add leading 0x00 if high bit set)
        let needs_pad = modulus[0] & 0x80 != 0;
        let mod_content_len = modulus.len() + if needs_pad { 1 } else { 0 };
        let mut mod_int = vec![0x02]; // INTEGER tag
        encode_der_length(&mut mod_int, mod_content_len);
        if needs_pad {
            mod_int.push(0x00);
        }
        mod_int.extend_from_slice(modulus);

        // Encode exponent INTEGER
        let exp_bytes: Vec<u8> = {
            let be = exponent.to_be_bytes();
            let start = be.iter().position(|&b| b != 0).unwrap_or(3);
            be[start..].to_vec()
        };
        let mut exp_int = vec![0x02]; // INTEGER tag
        encode_der_length(&mut exp_int, exp_bytes.len());
        exp_int.extend_from_slice(&exp_bytes);

        // Wrap in SEQUENCE
        let seq_content_len = mod_int.len() + exp_int.len();
        let mut seq = vec![0x30]; // SEQUENCE tag
        encode_der_length(&mut seq, seq_content_len);
        seq.extend_from_slice(&mod_int);
        seq.extend_from_slice(&exp_int);
        seq
    }

    /// Helper: encode DER length.
    fn encode_der_length(buf: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            buf.push(len as u8);
        } else if len < 0x100 {
            buf.push(0x81);
            buf.push(len as u8);
        } else if len < 0x10000 {
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

    #[test]
    fn test_parse_rsa_spk_2048_modulus_matches_openssl() {
        // Real RSA 2048 SPK inner SEQUENCE bytes (from openssl-generated cert)
        let spk_hex = "3082010a0282010100bbfa2bdcd579de46b3d45a44e0b1c2574b8937897b74e4c07a81a89c4502df8d10454b8243882b6594de27f4699655fd9a466faaaaf4297542d048abd6474a9bbca29af581825079d12bdc6651e077c32e98fa0421de1d1bd5b6ec8df72c142e47ada78f9a2b45f2a95b97765b9a711195ac0abbdf11533615facb94625d5a56f2544d2377d67756298b22bbbc75a6a16178bbe2a0239283b771433d6deb13e472d747db2fc89637eaefb310cd78bc576e3629fab17c0b77a1597ab7569df34100ccdc7d5b932a9ef2390a18cfe21598f687db0cc986ba315af458e52a7e3f4988cde47aff531a35cc2be427d6958df3bae962985355a4f8c73a6fe9166ec8c30203010001";
        let spk_bytes = hex::decode(spk_hex).unwrap();

        let (modulus, exponent) = parse_rsa_spk(&spk_bytes);

        let expected_modulus = "BBFA2BDCD579DE46B3D45A44E0B1C2574B8937897B74E4C07A81A89C4502DF8D10454B8243882B6594DE27F4699655FD9A466FAAAAF4297542D048ABD6474A9BBCA29AF581825079D12BDC6651E077C32E98FA0421DE1D1BD5B6EC8DF72C142E47ADA78F9A2B45F2A95B97765B9A711195AC0ABBDF11533615FACB94625D5A56F2544D2377D67756298B22BBBC75A6A16178BBE2A0239283B771433D6DEB13E472D747DB2FC89637EAEFB310CD78BC576E3629FAB17C0B77A1597AB7569DF34100CCDC7D5B932A9EF2390A18CFE21598F687DB0CC986BA315AF458E52A7E3F4988CDE47AFF531A35CC2BE427D6958DF3BAE962985355A4F8C73A6FE9166EC8C3";
        assert_eq!(modulus.as_deref(), Some(expected_modulus));
        assert_eq!(exponent, Some(65537));
    }

    #[test]
    fn test_parse_rsa_spk_4096_modulus_matches_openssl() {
        // Real RSA 4096 SPK inner SEQUENCE bytes
        let spk_hex = "3082020a0282020100f43f2d8c931e9542498a75b9091e4ee972761a2531c603f7a6b76bb8cff7f8a2f6725ec8006412c33c2aaab7e509c96614c1b8389cf9c40a22ead36d4f42d7c1eb022eb09f01cd9f6fd61b3bcb5cf8736b408e2b309b207c44273204e9857d3ca867cf44d0315188bda8d086efff8867a895da040b24f4ecab62279a491de4b861defe2785e9d53d97607da476c1e63d93d5119a6a91b461c7261e9bc588ac1d1b355b420af9c1a84ad008bc2d7d271d43dc12f2d17af1f0712da60b840a9013bee11225c43d4bc45726f231d734758a3375e7aed53961d45c863fcb57e6c161df35b137f8651bb919e5b65ce4b3e40a28e45f9055d19bcc0720e2274cd0fdc41652c5f8e67a66ad6f0ed2192ec62f2ba9238235c4d5ec6a76cdab64d2da7e32b263d8faa05d7a0ac28ad4ae7fd5bfff5884db18835924a61487b42e878569e31b2a2364f3c72c914bb44e62a0eb68e5a883c3c0fb3bb0e59eceba02036bb9f3cf30e7296c75a334f249b9d6028862603b6519cb380b4c4f63b96feb5dfd0a20b7a993b85c18fca3e38b2c8e89b17ec2fbcaac4f48fadeaaada40b3c5e366b24ce0af4a57e888e2f58669158a3b1bb4cb53f1b45fb6796cbe287ba9ebd16d83903045bb2302b9416d48806f4d3029bceb357f31c3b773f87b9d64aefe5be365dc07901b5d13da33f99d7a8723726419e93aee302201b5be0cb2450d4b3c24c6f0203010001";
        let spk_bytes = hex::decode(spk_hex).unwrap();

        let (modulus, exponent) = parse_rsa_spk(&spk_bytes);

        let expected_modulus = "F43F2D8C931E9542498A75B9091E4EE972761A2531C603F7A6B76BB8CFF7F8A2F6725EC8006412C33C2AAAB7E509C96614C1B8389CF9C40A22EAD36D4F42D7C1EB022EB09F01CD9F6FD61B3BCB5CF8736B408E2B309B207C44273204E9857D3CA867CF44D0315188BDA8D086EFFF8867A895DA040B24F4ECAB62279A491DE4B861DEFE2785E9D53D97607DA476C1E63D93D5119A6A91B461C7261E9BC588AC1D1B355B420AF9C1A84AD008BC2D7D271D43DC12F2D17AF1F0712DA60B840A9013BEE11225C43D4BC45726F231D734758A3375E7AED53961D45C863FCB57E6C161DF35B137F8651BB919E5B65CE4B3E40A28E45F9055D19BCC0720E2274CD0FDC41652C5F8E67A66AD6F0ED2192EC62F2BA9238235C4D5EC6A76CDAB64D2DA7E32B263D8FAA05D7A0AC28AD4AE7FD5BFFF5884DB18835924A61487B42E878569E31B2A2364F3C72C914BB44E62A0EB68E5A883C3C0FB3BB0E59ECEBA02036BB9F3CF30E7296C75A334F249B9D6028862603B6519CB380B4C4F63B96FEB5DFD0A20B7A993B85C18FCA3E38B2C8E89B17EC2FBCAAC4F48FADEAAADA40B3C5E366B24CE0AF4A57E888E2F58669158A3B1BB4CB53F1B45FB6796CBE287BA9EBD16D83903045BB2302B9416D48806F4D3029BCEB357F31C3B773F87B9D64AEFE5BE365DC07901B5D13DA33F99D7A8723726419E93AEE302201B5BE0CB2450D4B3C24C6F";
        assert_eq!(modulus.as_deref(), Some(expected_modulus));
        assert_eq!(exponent, Some(65537));
    }

    #[test]
    fn test_parse_rsa_spk_exponent_3() {
        // Construct a small synthetic RSA SPK with exponent 3
        let mod_bytes = vec![0xAB; 128]; // fake 1024-bit modulus (high bit set)
        let spk = build_rsa_spk_der(&mod_bytes, 3);

        let (modulus, exponent) = parse_rsa_spk(&spk);

        let expected_hex = "AB".repeat(128);
        assert_eq!(modulus.as_deref(), Some(expected_hex.as_str()));
        assert_eq!(exponent, Some(3));
    }

    #[test]
    fn test_parse_rsa_spk_modulus_no_padding_byte() {
        // Modulus with high bit clear — no 0x00 padding in DER
        let mod_bytes = vec![0x7F; 64]; // high bit clear
        let spk = build_rsa_spk_der(&mod_bytes, 65537);

        let (modulus, exponent) = parse_rsa_spk(&spk);

        let expected_hex = "7F".repeat(64);
        assert_eq!(modulus.as_deref(), Some(expected_hex.as_str()));
        assert_eq!(exponent, Some(65537));
    }

    #[test]
    fn test_parse_rsa_spk_empty_input() {
        let (modulus, exponent) = parse_rsa_spk(&[]);
        assert_eq!(modulus, None);
        assert_eq!(exponent, None);
    }

    #[test]
    fn test_parse_rsa_spk_garbage_input() {
        let (modulus, exponent) = parse_rsa_spk(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(modulus, None);
        assert_eq!(exponent, None);
    }

    #[test]
    fn test_parse_rsa_spk_too_short() {
        // Valid SEQUENCE tag but truncated
        let (modulus, exponent) = parse_rsa_spk(&[0x30, 0x03, 0x02, 0x01, 0x00]);
        assert_eq!(modulus, None);
        assert_eq!(exponent, None);
    }

    #[test]
    fn test_parse_rsa_spk_uppercase_hex() {
        // Verify output is uppercase (matching openssl -modulus format)
        let mod_bytes = vec![0xab; 128];
        let spk = build_rsa_spk_der(&mod_bytes, 65537);
        let (modulus, _) = parse_rsa_spk(&spk);
        let m = modulus.unwrap();
        // Must be uppercase
        assert_eq!(m, m.to_uppercase());
        // Must not contain lowercase
        assert!(!m.chars().any(|c| c.is_ascii_lowercase()));
    }
}
