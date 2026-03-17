//! Certificate operations - X.509 building, CSR parsing, extensions
//!
//! Implements RFC 5280 (X.509 PKI) and RFC 2986 (PKCS#10 CSR)

pub mod aia_chaser;
mod builder;
mod csr;
pub mod ct;
pub mod dane;
pub mod extensions;
pub mod identity;
mod name;
pub mod p7c;
pub mod path_builder;
pub mod policy_tree;
pub mod trust_anchor;
pub mod verify;

pub use builder::CertificateBuilder;
pub use csr::{CertificateRequest, CsrBuilder};
pub use extensions::{
    AuthorityInfoAccess, AuthorityKeyIdentifier, BasicConstraints, CdpAiaConfig,
    CertificatePolicies, CrlDistributionPoints, ExtendedKeyUsage, KeyUsage, KeyUsageFlags,
    SporkIssuanceInfo, SubjectAltName, SubjectInformationAccess, SubjectKeyIdentifier,
};
pub use name::{DistinguishedName, NameBuilder};
pub use p7c::build_p7c;
pub use policy_tree::{process_policy_tree, PolicyValidationResult};
pub use trust_anchor::{
    CertPathControls, TaAction, TaAuditEntry, TaState, TrustAnchorId, TrustAnchorInfo,
    TrustAnchorManager, TrustAnchorStore, TrustAnchorSummary,
};

use chrono::{DateTime, Months, Utc};
use der::{Decode, Encode};
use x509_cert::Certificate;

use crate::error::{Error, Result};

/// Default clock skew tolerance: 5 minutes before issuance time.
///
/// Enterprise CAs (Entrust, DigiCert, etc.) typically backdate `notBefore` by 5-30 minutes
/// to handle clock drift between the CA and relying parties. Without this, a client whose
/// clock is even slightly behind the CA would reject a freshly-issued certificate as
/// "not yet valid". RFC 5280 Section 4.1.2.5 defines the Validity field but leaves the
/// backdate policy to the CA operator. The CA/Browser Forum BRs only require that
/// `notBefore` is not before the date of the CSR.
///
/// 5 minutes is conservative — covers typical NTP drift without excessive backdating.
pub const DEFAULT_BACKDATE_SECONDS: i64 = 300;

/// Validity period for certificates
#[derive(Debug, Clone)]
pub struct Validity {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl Validity {
    /// Create validity from duration in days starting now.
    /// Applies default 5-minute backdate for clock skew tolerance.
    pub fn days_from_now(days: u32) -> Self {
        let not_before = Utc::now() - chrono::Duration::seconds(DEFAULT_BACKDATE_SECONDS);
        let not_after = Utc::now() + chrono::Duration::days(days as i64);
        Self {
            not_before,
            not_after,
        }
    }

    /// Create validity from duration in years starting now (accounts for leap years).
    /// Applies default 5-minute backdate for clock skew tolerance.
    pub fn years_from_now(years: u32) -> Self {
        let now = Utc::now();
        let not_before = now - chrono::Duration::seconds(DEFAULT_BACKDATE_SECONDS);
        // Use Months to properly handle calendar years including leap years
        let not_after = now
            .checked_add_months(Months::new(years * 12))
            .unwrap_or_else(|| now + chrono::Duration::days((years * 365) as i64));
        Self {
            not_before,
            not_after,
        }
    }

    /// Create validity from duration in months starting now (accounts for varying month lengths).
    /// Applies default 5-minute backdate for clock skew tolerance.
    pub fn months_from_now(months: u32) -> Self {
        let now = Utc::now();
        let not_before = now - chrono::Duration::seconds(DEFAULT_BACKDATE_SECONDS);
        let not_after = now
            .checked_add_months(Months::new(months))
            .unwrap_or_else(|| now + chrono::Duration::days((months * 30) as i64));
        Self {
            not_before,
            not_after,
        }
    }

    /// Create validity with a custom backdate (in seconds).
    /// Use `backdate_seconds = 0` for exact `notBefore = now` behavior.
    pub fn days_from_now_with_backdate(days: u32, backdate_seconds: i64) -> Self {
        let now = Utc::now();
        let not_before = now - chrono::Duration::seconds(backdate_seconds);
        let not_after = now + chrono::Duration::days(days as i64);
        Self {
            not_before,
            not_after,
        }
    }

    /// Create validity from specific dates (no automatic backdate — caller controls both ends)
    pub fn new(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> Result<Self> {
        if not_after <= not_before {
            return Err(Error::InvalidCertificate(
                "not_after must be after not_before".into(),
            ));
        }
        Ok(Self {
            not_before,
            not_after,
        })
    }

    /// Standard CA validity (20 years with 5-minute backdate)
    pub fn ca_default() -> Self {
        Self::years_from_now(20)
    }

    /// Standard end-entity validity (1 year with 5-minute backdate)
    pub fn ee_default() -> Self {
        Self::years_from_now(1)
    }

    /// Create validity from duration in hours starting now.
    /// Applies default 5-minute backdate for clock skew tolerance.
    /// Use for short-lived certificates (zero-trust, ephemeral workloads).
    pub fn hours_from_now(hours: u32) -> Self {
        let now = Utc::now();
        let not_before = now - chrono::Duration::seconds(DEFAULT_BACKDATE_SECONDS);
        let not_after = now + chrono::Duration::hours(hours as i64);
        Self {
            not_before,
            not_after,
        }
    }

    /// Create validity from duration in minutes starting now.
    /// Applies reduced 1-minute backdate (short-lived certs assume tighter clock sync).
    /// Use for ultra-short-lived certificates (service mesh, CI/CD tokens).
    pub fn minutes_from_now(minutes: u32) -> Self {
        let now = Utc::now();
        // Short-lived certs use reduced backdate (1 minute vs 5 minutes)
        let not_before = now - chrono::Duration::seconds(60);
        let not_after = now + chrono::Duration::minutes(minutes as i64);
        Self {
            not_before,
            not_after,
        }
    }

    /// Short-lived certificate default (24 hours with 5-minute backdate).
    /// Modern zero-trust pattern: certificates expire before revocation is needed.
    pub fn short_lived_default() -> Self {
        Self::hours_from_now(24)
    }

    /// Duration of this validity period
    pub fn duration(&self) -> chrono::Duration {
        self.not_after - self.not_before
    }

    /// Whether this is a short-lived certificate (validity <= 7 days).
    /// Short-lived certs may skip CRL/OCSP embedding since they expire
    /// before revocation propagation is practical.
    pub fn is_short_lived(&self) -> bool {
        self.duration() <= chrono::Duration::days(7)
    }

    /// Check if currently valid
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now <= self.not_after
    }
}

/// Serial number generator
#[derive(Debug, Clone)]
pub struct SerialNumber(pub Vec<u8>);

impl SerialNumber {
    /// Generate random 20-byte (160-bit) serial number.
    ///
    /// RFC 5280 §4.1.2.2: Serial numbers MUST be positive integers with at
    /// least 64 bits of entropy. We use 159 bits (20 bytes, high bit cleared)
    /// which exceeds the minimum by 2.5x. Maximum encoding is 20 octets.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = vec![0u8; 20];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        // Ensure positive (clear high bit)
        bytes[0] &= 0x7F;
        // Ensure non-zero
        if bytes.iter().all(|&b| b == 0) {
            bytes[19] = 1;
        }
        Self(bytes)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 20 {
            return Err(Error::InvalidCertificate(
                "Serial must be 1-20 bytes".into(),
            ));
        }
        Ok(Self(bytes))
    }

    /// Create sequential serial
    pub fn sequential(n: u64) -> Self {
        Self(n.to_be_bytes().to_vec())
    }
}

impl AsRef<[u8]> for SerialNumber {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Parse a PEM-encoded certificate
pub fn parse_certificate_pem(pem: &str) -> Result<Certificate> {
    let pem_data = pem::parse(pem).map_err(|e| Error::Decoding(format!("PEM parse: {}", e)))?;

    if pem_data.tag() != "CERTIFICATE" {
        return Err(Error::Decoding(format!(
            "Expected CERTIFICATE, got {}",
            pem_data.tag()
        )));
    }

    Certificate::from_der(pem_data.contents()).map_err(|e| Error::Decoding(e.to_string()))
}

/// Parse a DER-encoded certificate
pub fn parse_certificate_der(der: &[u8]) -> Result<Certificate> {
    Certificate::from_der(der).map_err(|e| Error::Decoding(e.to_string()))
}

/// Extract Subject Alternative Names from a DER-encoded certificate.
/// Returns (dns_names, ip_addresses, emails).
pub fn extract_sans_from_der(der: &[u8]) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
    let cert = parse_certificate_der(der)?;
    let mut dns_names = Vec::new();
    let mut ips = Vec::new();
    let mut emails = Vec::new();

    if let Some(exts) = cert.tbs_certificate.extensions.as_ref() {
        for ext in exts.iter() {
            if ext.extn_id == extensions::oid::SUBJECT_ALT_NAME {
                // Parse GeneralNames from the extension value
                let value = ext.extn_value.as_bytes();
                parse_general_names(value, &mut dns_names, &mut ips, &mut emails);
            }
        }
    }

    Ok((dns_names, ips, emails))
}

/// Parse ASN.1 GeneralNames sequence into typed SAN lists.
/// GeneralName ::= CHOICE {
///   rfc822Name      [1] IA5String,
///   dNSName         [2] IA5String,
///   iPAddress       [7] OCTET STRING }
fn parse_general_names(
    data: &[u8],
    dns_names: &mut Vec<String>,
    ips: &mut Vec<String>,
    emails: &mut Vec<String>,
) {
    // data is DER-encoded SEQUENCE of GeneralName
    if data.len() < 2 || data[0] != 0x30 {
        return;
    }
    let (seq_len, offset) = match read_der_length(&data[1..]) {
        Some(v) => v,
        None => return,
    };
    let seq_start = 1 + offset;
    let seq_end = (seq_start + seq_len).min(data.len());
    let mut pos = seq_start;
    while pos < seq_end {
        if pos >= data.len() {
            break;
        }
        let tag = data[pos];
        pos += 1;
        let (val_len, len_size) = match read_der_length(&data[pos..]) {
            Some(v) => v,
            None => break,
        };
        pos += len_size;
        let val_end = (pos + val_len).min(data.len());
        let value = &data[pos..val_end];

        match tag {
            0x81 => {
                // [1] rfc822Name
                if let Ok(s) = std::str::from_utf8(value) {
                    emails.push(s.to_string());
                }
            }
            0x82 => {
                // [2] dNSName
                if let Ok(s) = std::str::from_utf8(value) {
                    dns_names.push(s.to_string());
                }
            }
            0x87 => {
                // [7] iPAddress
                if value.len() == 4 {
                    ips.push(format!(
                        "{}.{}.{}.{}",
                        value[0], value[1], value[2], value[3]
                    ));
                } else if value.len() == 16 {
                    let addr = std::net::Ipv6Addr::new(
                        u16::from_be_bytes([value[0], value[1]]),
                        u16::from_be_bytes([value[2], value[3]]),
                        u16::from_be_bytes([value[4], value[5]]),
                        u16::from_be_bytes([value[6], value[7]]),
                        u16::from_be_bytes([value[8], value[9]]),
                        u16::from_be_bytes([value[10], value[11]]),
                        u16::from_be_bytes([value[12], value[13]]),
                        u16::from_be_bytes([value[14], value[15]]),
                    );
                    ips.push(addr.to_string());
                }
            }
            _ => {} // Skip other GeneralName types (URI, directoryName, etc.)
        }
        pos = val_end;
    }
}

/// Read a DER length field, returning (length, bytes_consumed).
fn read_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0] as usize;
    if first < 0x80 {
        Some((first, 1))
    } else if first == 0x81 {
        data.get(1).map(|&b| (b as usize, 2))
    } else if first == 0x82 {
        if data.len() >= 3 {
            Some((((data[1] as usize) << 8) | (data[2] as usize), 3))
        } else {
            None
        }
    } else {
        None
    }
}

/// Encode certificate to DER
pub fn encode_certificate_der(cert: &Certificate) -> Result<Vec<u8>> {
    cert.to_der().map_err(|e| Error::Encoding(e.to_string()))
}

/// Encode certificate to PEM
pub fn encode_certificate_pem(cert: &Certificate) -> Result<String> {
    let der = encode_certificate_der(cert)?;
    Ok(pem::encode(&pem::Pem::new("CERTIFICATE", der)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validity_days_from_now() {
        let v = Validity::days_from_now(365);
        assert!(v.is_valid());
        assert!(v.not_after > v.not_before);
    }

    #[test]
    fn test_validity_backdate_applied() {
        let before = Utc::now();
        let v = Validity::days_from_now(365);
        // not_before should be ~5 minutes before now (DEFAULT_BACKDATE_SECONDS)
        assert!(
            v.not_before < before,
            "not_before should be before current time (backdate applied)"
        );
        let backdate = before - v.not_before;
        // Should be approximately DEFAULT_BACKDATE_SECONDS (300s = 5 min)
        assert!(
            backdate.num_seconds() >= 299 && backdate.num_seconds() <= 301,
            "Backdate should be ~300 seconds, got {}",
            backdate.num_seconds()
        );
    }

    #[test]
    fn test_validity_custom_backdate() {
        let before = Utc::now();
        // Zero backdate — notBefore should be at or after current time
        let v = Validity::days_from_now_with_backdate(365, 0);
        assert!(v.not_before >= before - chrono::Duration::seconds(1));

        // 30-minute backdate (Entrust-style)
        let v2 = Validity::days_from_now_with_backdate(365, 1800);
        let backdate = before - v2.not_before;
        assert!(
            backdate.num_seconds() >= 1799 && backdate.num_seconds() <= 1801,
            "Custom 30-min backdate should be ~1800s, got {}",
            backdate.num_seconds()
        );
    }

    #[test]
    fn test_validity_years_has_backdate() {
        let now = Utc::now();
        let v = Validity::years_from_now(1);
        assert!(v.not_before < now, "years_from_now should have backdate");
    }

    #[test]
    fn test_validity_months_has_backdate() {
        let now = Utc::now();
        let v = Validity::months_from_now(6);
        assert!(v.not_before < now, "months_from_now should have backdate");
    }

    #[test]
    fn test_validity_explicit_dates_no_backdate() {
        // Validity::new() uses exact dates — no automatic backdate
        let nb = Utc::now();
        let na = nb + chrono::Duration::days(365);
        let v = Validity::new(nb, na).unwrap();
        assert_eq!(v.not_before, nb, "Explicit dates should not be modified");
    }

    #[test]
    fn test_serial_random() {
        let s1 = SerialNumber::random();
        let s2 = SerialNumber::random();
        assert_ne!(s1.0, s2.0);
        assert!(s1.0[0] & 0x80 == 0); // Positive
    }

    #[test]
    fn test_extract_sans_from_self_signed_cert() {
        use crate::algo::AlgorithmId;
        use crate::algo::KeyPair;
        use crate::cert::builder::CertificateBuilder;
        use crate::cert::extensions::SubjectAltName;
        use crate::cert::name::DistinguishedName;

        let keypair = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let pub_key = keypair.public_key_der().unwrap();

        let san = SubjectAltName::new()
            .dns("test.example.com")
            .dns("*.example.com")
            .ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, 1, 1,
            )));

        let subject = DistinguishedName::simple("test.example.com");
        let cert = CertificateBuilder::new(subject, pub_key, AlgorithmId::EcdsaP256)
            .subject_alt_name(san)
            .validity(Validity::days_from_now(90))
            .build_and_sign(&keypair)
            .unwrap();

        let cert_der = encode_certificate_der(&cert).unwrap();
        let (dns, ips, emails) = extract_sans_from_der(&cert_der).unwrap();

        assert_eq!(dns, vec!["test.example.com", "*.example.com"]);
        assert_eq!(ips, vec!["192.168.1.1"]);
        assert!(emails.is_empty());
    }

    #[test]
    fn test_extract_sans_from_cert_no_san() {
        use crate::algo::AlgorithmId;
        use crate::algo::KeyPair;
        use crate::cert::builder::CertificateBuilder;
        use crate::cert::name::DistinguishedName;

        let keypair = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let pub_key = keypair.public_key_der().unwrap();
        let subject = DistinguishedName::simple("no-san.example.com");

        let cert = CertificateBuilder::new(subject, pub_key, AlgorithmId::EcdsaP256)
            .validity(Validity::days_from_now(90))
            .build_and_sign(&keypair)
            .unwrap();

        let cert_der = encode_certificate_der(&cert).unwrap();
        let (dns, ips, emails) = extract_sans_from_der(&cert_der).unwrap();

        assert!(dns.is_empty());
        assert!(ips.is_empty());
        assert!(emails.is_empty());
    }

    // --- Short-lived certificate tests ---

    #[test]
    fn test_validity_hours_from_now() {
        let v = Validity::hours_from_now(24);
        assert!(v.is_valid());
        // Duration should be ~24 hours + 5 min backdate
        let dur = v.not_after - v.not_before;
        let hours = dur.num_hours();
        assert!(
            (24..=25).contains(&hours),
            "Expected ~24h duration, got {hours}h"
        );
    }

    #[test]
    fn test_validity_minutes_from_now() {
        let v = Validity::minutes_from_now(30);
        assert!(v.is_valid());
        // Duration should be ~31 minutes (30 + 1 min reduced backdate)
        let dur = v.not_after - v.not_before;
        let mins = dur.num_minutes();
        assert!(
            (30..=32).contains(&mins),
            "Expected ~31min duration, got {mins}min"
        );
    }

    #[test]
    fn test_validity_minutes_reduced_backdate() {
        let now = Utc::now();
        let v = Validity::minutes_from_now(10);
        // Minutes uses 1-minute backdate, not 5-minute
        let backdate = now - v.not_before;
        assert!(
            backdate.num_seconds() >= 59 && backdate.num_seconds() <= 62,
            "Minutes backdate should be ~60s, got {}s",
            backdate.num_seconds()
        );
    }

    #[test]
    fn test_short_lived_default() {
        let v = Validity::short_lived_default();
        assert!(v.is_valid());
        let dur = v.not_after - v.not_before;
        // Should be ~24 hours
        assert!(dur.num_hours() >= 24 && dur.num_hours() <= 25);
    }

    #[test]
    fn test_is_short_lived_true() {
        // 1-hour cert is short-lived
        let v = Validity::hours_from_now(1);
        assert!(v.is_short_lived());

        // 24-hour cert is short-lived
        let v = Validity::hours_from_now(24);
        assert!(v.is_short_lived());

        // 6-day cert is short-lived
        let v = Validity::days_from_now(6);
        assert!(v.is_short_lived());
    }

    #[test]
    fn test_is_short_lived_false() {
        // 30-day cert is NOT short-lived
        let v = Validity::days_from_now(30);
        assert!(!v.is_short_lived());

        // 90-day cert is NOT short-lived
        let v = Validity::days_from_now(90);
        assert!(!v.is_short_lived());

        // 1-year cert is NOT short-lived
        let v = Validity::years_from_now(1);
        assert!(!v.is_short_lived());
    }

    #[test]
    fn test_validity_duration() {
        let v = Validity::days_from_now(30);
        let dur = v.duration();
        // 30 days + 5 min backdate = ~30 days
        assert!(dur.num_days() >= 30 && dur.num_days() <= 31);
    }
}
