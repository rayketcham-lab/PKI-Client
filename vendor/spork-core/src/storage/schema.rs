//! Storage Schema Definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::RevocationReason;
use crate::algo::AlgorithmId;
use crate::ca::{CaType, CertificateProfile};

/// Certificate record for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRecord {
    /// Serial number (hex)
    pub serial: String,
    /// Subject CN
    pub subject_cn: String,
    /// Full subject DN (RFC 2253 format)
    pub subject_dn: String,
    /// Issuer CN
    pub issuer_cn: String,
    /// Issuer CA ID
    pub issuer_id: String,
    /// Certificate DER (base64)
    pub certificate_der_b64: String,
    /// Public key algorithm
    pub algorithm: AlgorithmId,
    /// Certificate profile
    pub profile: CertificateProfile,
    /// Not before
    pub not_before: DateTime<Utc>,
    /// Not after
    pub not_after: DateTime<Utc>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Subject Alternative Names (JSON array)
    pub san_json: Option<String>,
    /// Is revoked
    pub revoked: bool,
    /// Custom metadata (JSON)
    pub metadata: Option<String>,
}

impl CertificateRecord {
    /// Check if certificate is currently valid
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        !self.revoked && now >= self.not_before && now <= self.not_after
    }

    /// Check if certificate is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }
}

/// Revocation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// Certificate serial number
    pub serial: String,
    /// Revocation reason
    pub reason: RevocationReason,
    /// Revocation timestamp
    pub revoked_at: DateTime<Utc>,
    /// Invalidity date (optional, for key compromise)
    pub invalidity_date: Option<DateTime<Utc>>,
    /// Issuer CA ID
    pub issuer_id: String,
    /// Operator who revoked
    pub revoked_by: Option<String>,
    /// Comment
    pub comment: Option<String>,
}

/// CA state record for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaStateRecord {
    /// Unique CA identifier
    pub ca_id: String,
    /// CA type
    pub ca_type: CaType,
    /// CA common name
    pub common_name: String,
    /// CA certificate DER (base64)
    pub certificate_der_b64: String,
    /// Encrypted private key (base64)
    pub encrypted_private_key_b64: String,
    /// Key encryption nonce (base64)
    pub key_nonce_b64: String,
    /// Algorithm
    pub algorithm: AlgorithmId,
    /// Current serial counter
    pub serial_counter: u64,
    /// Parent CA ID (for intermediates)
    pub parent_ca_id: Option<String>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last used timestamp
    pub last_used_at: DateTime<Utc>,
    /// Is active
    pub active: bool,
}

/// Certificate search filters
#[allow(dead_code)] // Builder-pattern query filter — used in tests, ready for API/WebUI wiring
#[derive(Debug, Default)]
pub struct CertificateFilter {
    /// Filter by issuer CA ID
    pub issuer_id: Option<String>,
    /// Filter by subject CN (substring match)
    pub subject_cn: Option<String>,
    /// Filter by profile
    pub profile: Option<CertificateProfile>,
    /// Include expired certificates
    pub include_expired: bool,
    /// Include revoked certificates
    pub include_revoked: bool,
    /// Created after
    pub created_after: Option<DateTime<Utc>>,
    /// Created before
    pub created_before: Option<DateTime<Utc>>,
    /// Maximum results
    pub limit: Option<usize>,
}

#[allow(dead_code)]
impl CertificateFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn issuer(mut self, id: impl Into<String>) -> Self {
        self.issuer_id = Some(id.into());
        self
    }

    pub fn subject_contains(mut self, cn: impl Into<String>) -> Self {
        self.subject_cn = Some(cn.into());
        self
    }

    pub fn profile(mut self, profile: CertificateProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    pub fn include_expired(mut self, include: bool) -> Self {
        self.include_expired = include;
        self
    }

    pub fn include_revoked(mut self, include: bool) -> Self {
        self.include_revoked = include;
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(not_before_days: i64, not_after_days: i64, revoked: bool) -> CertificateRecord {
        CertificateRecord {
            serial: "01".to_string(),
            subject_cn: "test".to_string(),
            subject_dn: "CN=test".to_string(),
            issuer_cn: "CA".to_string(),
            issuer_id: "ca-1".to_string(),
            certificate_der_b64: String::new(),
            algorithm: AlgorithmId::EcdsaP256,
            profile: CertificateProfile::TlsServer,
            not_before: Utc::now() + chrono::Duration::days(not_before_days),
            not_after: Utc::now() + chrono::Duration::days(not_after_days),
            created_at: Utc::now(),
            san_json: None,
            revoked,
            metadata: None,
        }
    }

    #[test]
    fn test_certificate_record_validity() {
        let record = make_record(-1, 365, false);
        assert!(record.is_valid());
        assert!(!record.is_expired());
    }

    #[test]
    fn test_certificate_expired() {
        let record = make_record(-365, -1, false);
        assert!(record.is_expired());
        assert!(!record.is_valid());
    }

    #[test]
    fn test_certificate_not_yet_valid() {
        let record = make_record(1, 365, false);
        assert!(!record.is_valid());
        assert!(!record.is_expired());
    }

    #[test]
    fn test_certificate_revoked_not_valid() {
        let record = make_record(-1, 365, true);
        assert!(!record.is_valid());
        assert!(!record.is_expired());
    }

    #[test]
    fn test_certificate_filter_builder() {
        let filter = CertificateFilter::new()
            .issuer("ca-root")
            .subject_contains("example")
            .profile(CertificateProfile::TlsServer)
            .include_expired(true)
            .include_revoked(false)
            .limit(50);

        assert_eq!(filter.issuer_id.as_deref(), Some("ca-root"));
        assert_eq!(filter.subject_cn.as_deref(), Some("example"));
        assert_eq!(filter.profile, Some(CertificateProfile::TlsServer));
        assert!(filter.include_expired);
        assert!(!filter.include_revoked);
        assert_eq!(filter.limit, Some(50));
    }

    #[test]
    fn test_certificate_filter_defaults() {
        let filter = CertificateFilter::default();
        assert!(filter.issuer_id.is_none());
        assert!(filter.subject_cn.is_none());
        assert!(filter.profile.is_none());
        assert!(!filter.include_expired);
        assert!(!filter.include_revoked);
        assert!(filter.created_after.is_none());
        assert!(filter.created_before.is_none());
        assert!(filter.limit.is_none());
    }

    #[test]
    fn test_revocation_record_fields() {
        let record = RevocationRecord {
            serial: "FF01".to_string(),
            reason: RevocationReason::KeyCompromise,
            revoked_at: Utc::now(),
            invalidity_date: Some(Utc::now() - chrono::Duration::days(3)),
            issuer_id: "ca-1".to_string(),
            revoked_by: Some("admin".to_string()),
            comment: Some("Key leaked".to_string()),
        };

        assert_eq!(record.serial, "FF01");
        assert_eq!(record.reason, RevocationReason::KeyCompromise);
        assert!(record.invalidity_date.is_some());
        assert_eq!(record.revoked_by.as_deref(), Some("admin"));
        assert_eq!(record.comment.as_deref(), Some("Key leaked"));
    }

    #[test]
    fn test_certificate_record_serde_roundtrip() {
        let record = make_record(-1, 365, false);
        let json = serde_json::to_string(&record).unwrap();
        let restored: CertificateRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.serial, record.serial);
        assert_eq!(restored.subject_cn, record.subject_cn);
        assert_eq!(restored.revoked, record.revoked);
    }

    #[test]
    fn test_ca_state_record_serde_roundtrip() {
        let state = CaStateRecord {
            ca_id: "root-1".to_string(),
            ca_type: CaType::Root,
            common_name: "Test Root CA".to_string(),
            certificate_der_b64: "base64cert".to_string(),
            encrypted_private_key_b64: "base64key".to_string(),
            key_nonce_b64: "base64nonce".to_string(),
            algorithm: AlgorithmId::EcdsaP384,
            serial_counter: 100,
            parent_ca_id: None,
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            active: true,
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: CaStateRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.ca_id, "root-1");
        assert_eq!(restored.serial_counter, 100);
        assert!(restored.parent_ca_id.is_none());
        assert!(restored.active);
    }
}
