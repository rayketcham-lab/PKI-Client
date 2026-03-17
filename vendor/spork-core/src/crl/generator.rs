//! CRL generation orchestrator
//!
//! Thin wrapper around CrlBuilder and DeltaCrlBuilder that coordinates
//! CA key loading, revocation collection, and CRL signing.

use chrono::{DateTime, Utc};

use crate::algo::KeyPair;
use crate::cert::DistinguishedName;
use crate::error::Result;

use super::{Crl, CrlBuilder, DeltaCrl, DeltaCrlBuilder, RevocationReason, RevokedCertificate};

/// Input for a revoked certificate entry in CRL generation
#[derive(Debug, Clone)]
pub struct RevocationEntry {
    /// Certificate serial number (big-endian bytes)
    pub serial: Vec<u8>,
    /// When the certificate was revoked
    pub revoked_at: DateTime<Utc>,
    /// Reason for revocation
    pub reason: Option<RevocationReason>,
    /// When key was actually compromised (optional)
    pub invalidity_date: Option<DateTime<Utc>>,
}

impl RevocationEntry {
    /// Create a new revocation entry
    pub fn new(serial: Vec<u8>, revoked_at: DateTime<Utc>) -> Self {
        Self {
            serial,
            revoked_at,
            reason: None,
            invalidity_date: None,
        }
    }

    /// Set the revocation reason
    pub fn with_reason(mut self, reason: RevocationReason) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Convert to a RevokedCertificate for CrlBuilder
    pub fn to_revoked_certificate(&self) -> RevokedCertificate {
        let mut cert = RevokedCertificate::new(self.serial.clone(), self.revoked_at);
        if let Some(reason) = self.reason {
            cert = cert.with_reason(reason);
        }
        if let Some(inv_date) = self.invalidity_date {
            cert = cert.with_invalidity_date(inv_date);
        }
        cert
    }
}

/// CRL generation orchestrator
///
/// Coordinates CRL building and signing for a specific CA.
pub struct CrlGenerator {
    issuer_dn: DistinguishedName,
    issuer_key: KeyPair,
    next_update_hours: i64,
    issuer_key_id: Option<Vec<u8>>,
    /// Previous CRL number for monotonicity enforcement (RFC 5280 §5.2.3)
    previous_crl_number: Option<u64>,
}

impl CrlGenerator {
    /// Create a new CRL generator for a CA
    pub fn new(issuer_dn: DistinguishedName, issuer_key: KeyPair) -> Self {
        Self {
            issuer_dn,
            issuer_key,
            next_update_hours: 24,
            issuer_key_id: None,
            previous_crl_number: None,
        }
    }

    /// Set the CRL validity period in hours (default: 24)
    pub fn with_next_update_hours(mut self, hours: i64) -> Self {
        self.next_update_hours = hours;
        self
    }

    /// Set the Authority Key Identifier for CRL extensions
    pub fn with_issuer_key_id(mut self, key_id: Vec<u8>) -> Self {
        self.issuer_key_id = Some(key_id);
        self
    }

    /// Set the previous CRL number for monotonicity enforcement (RFC 5280 §5.2.3).
    ///
    /// When set, the generator will reject CRL numbers that are not strictly
    /// greater than this value.
    pub fn with_previous_crl_number(mut self, previous: u64) -> Self {
        self.previous_crl_number = Some(previous);
        self
    }

    /// Generate a full (base) CRL
    ///
    /// Includes all currently revoked certificates for this CA.
    pub fn generate_full_crl(
        &self,
        crl_number: u64,
        revocations: Vec<RevocationEntry>,
    ) -> Result<Crl> {
        let revoked_certs: Vec<RevokedCertificate> = revocations
            .iter()
            .map(|r| r.to_revoked_certificate())
            .collect();

        let mut builder = CrlBuilder::new(self.issuer_dn.clone())
            .crl_number(crl_number)
            .next_update_hours(self.next_update_hours)
            .add_revoked_list(revoked_certs);

        if let Some(ref key_id) = self.issuer_key_id {
            builder = builder.issuer_key_id(key_id.clone());
        }
        if let Some(prev) = self.previous_crl_number {
            builder = builder.previous_crl_number(prev);
        }

        builder.build_and_sign(&self.issuer_key)
    }

    /// Generate a delta CRL
    ///
    /// Contains only revocations that occurred since the specified base CRL.
    pub fn generate_delta_crl(
        &self,
        base_crl_number: u64,
        delta_crl_number: u64,
        new_revocations: Vec<RevocationEntry>,
        delta_validity_hours: i64,
    ) -> Result<DeltaCrl> {
        let revoked_certs: Vec<RevokedCertificate> = new_revocations
            .iter()
            .map(|r| r.to_revoked_certificate())
            .collect();

        let mut builder = DeltaCrlBuilder::new(self.issuer_dn.clone(), base_crl_number)
            .delta_crl_number(delta_crl_number)
            .next_update_hours(delta_validity_hours)
            .add_revocations(revoked_certs);

        if let Some(ref key_id) = self.issuer_key_id {
            builder = builder.issuer_key_id(key_id.clone());
        }

        builder.build_and_sign(&self.issuer_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algo::AlgorithmId;
    use crate::cert::NameBuilder;

    fn test_generator(algo: AlgorithmId) -> CrlGenerator {
        let dn = NameBuilder::new("Test CA")
            .organization("SPORK Test")
            .build();
        let key = KeyPair::generate(algo).unwrap();
        CrlGenerator::new(dn, key)
    }

    #[test]
    fn test_empty_crl_p256() {
        let gen = test_generator(AlgorithmId::EcdsaP256);
        let crl = gen.generate_full_crl(1, vec![]).unwrap();
        assert_eq!(crl.crl_number, 1);
        assert_eq!(crl.revoked_count, 0);
        assert!(crl.pem.contains("BEGIN X509 CRL"));
        assert!(crl.pem.contains("END X509 CRL"));
        assert!(!crl.der.is_empty());
    }

    #[test]
    fn test_empty_crl_p384() {
        let gen = test_generator(AlgorithmId::EcdsaP384);
        let crl = gen.generate_full_crl(1, vec![]).unwrap();
        assert_eq!(crl.crl_number, 1);
        assert!(crl.pem.contains("BEGIN X509 CRL"));
    }

    #[test]
    fn test_crl_with_revocations() {
        let gen = test_generator(AlgorithmId::EcdsaP256);
        let revocations = vec![
            RevocationEntry::new(vec![0x01], Utc::now())
                .with_reason(RevocationReason::KeyCompromise),
            RevocationEntry::new(vec![0x02, 0x03], Utc::now())
                .with_reason(RevocationReason::Superseded),
            RevocationEntry::new(vec![0x10], Utc::now()),
        ];

        let crl = gen.generate_full_crl(5, revocations).unwrap();
        assert_eq!(crl.crl_number, 5);
        assert_eq!(crl.revoked_count, 3);
        assert!(crl.pem.contains("BEGIN X509 CRL"));
    }

    #[test]
    fn test_crl_number_increments() {
        let gen = test_generator(AlgorithmId::EcdsaP256);

        let crl1 = gen.generate_full_crl(1, vec![]).unwrap();
        let crl2 = gen.generate_full_crl(2, vec![]).unwrap();

        assert_eq!(crl1.crl_number, 1);
        assert_eq!(crl2.crl_number, 2);
        // Different CRLs should have different DER
        assert_ne!(crl1.der, crl2.der);
    }

    #[test]
    fn test_delta_crl() {
        let gen = test_generator(AlgorithmId::EcdsaP256);
        let new_revocations = vec![RevocationEntry::new(vec![0x05], Utc::now())
            .with_reason(RevocationReason::CessationOfOperation)];

        let delta = gen.generate_delta_crl(10, 11, new_revocations, 6).unwrap();
        assert_eq!(delta.base_crl_number, 10);
        assert_eq!(delta.delta_crl_number, 11);
        assert_eq!(delta.revoked_count, 1);
        assert!(delta.pem.contains("BEGIN X509 CRL"));
    }

    #[test]
    fn test_delta_crl_empty() {
        let gen = test_generator(AlgorithmId::EcdsaP256);
        let delta = gen.generate_delta_crl(5, 6, vec![], 6).unwrap();
        assert_eq!(delta.base_crl_number, 5);
        assert_eq!(delta.delta_crl_number, 6);
        assert_eq!(delta.revoked_count, 0);
    }

    #[test]
    fn test_custom_validity() {
        let gen = test_generator(AlgorithmId::EcdsaP256).with_next_update_hours(168); // 7 days
        let crl = gen.generate_full_crl(1, vec![]).unwrap();
        assert!(crl.next_update.is_some());
        // next_update should be ~168 hours from now
        let diff = crl.next_update.unwrap() - Utc::now();
        assert!(diff.num_hours() >= 167 && diff.num_hours() <= 169);
    }

    #[test]
    fn test_with_authority_key_id() {
        let gen =
            test_generator(AlgorithmId::EcdsaP256).with_issuer_key_id(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let crl = gen.generate_full_crl(1, vec![]).unwrap();
        assert!(!crl.der.is_empty());
    }

    #[test]
    fn test_revocation_entry_builder() {
        let entry = RevocationEntry::new(vec![0x01], Utc::now())
            .with_reason(RevocationReason::KeyCompromise);
        assert_eq!(entry.reason, Some(RevocationReason::KeyCompromise));

        let cert = entry.to_revoked_certificate();
        assert_eq!(cert.serial, vec![0x01]);
    }

    // ── RFC 5280 §5.2.3: CRL monotonicity via generator ─────────────────

    #[test]
    fn test_generator_enforces_monotonicity() {
        let gen = test_generator(AlgorithmId::EcdsaP256).with_previous_crl_number(10);

        // CRL number 5 with previous 10 — should fail
        let result = gen.generate_full_crl(5, vec![]);
        assert!(
            result.is_err(),
            "Generator should reject non-monotonic CRL number"
        );

        // CRL number 11 with previous 10 — should succeed
        let gen2 = test_generator(AlgorithmId::EcdsaP256).with_previous_crl_number(10);
        let result = gen2.generate_full_crl(11, vec![]);
        assert!(
            result.is_ok(),
            "Generator should accept monotonic CRL number"
        );
    }
}
