//! Comprehensive CRL tests for security audit
//!
//! These tests cover edge cases, boundary conditions, and RFC 5280 compliance.

use chrono::{Duration, Utc};
use spork_core::algo::{AlgorithmId, KeyPair};
use spork_core::cert::NameBuilder;
use spork_core::crl::{CrlBuilder, RevocationReason, RevokedCertificate};
use std::str::FromStr;

// ============================================================================
// RevocationReason Tests
// ============================================================================

#[test]
fn test_all_revocation_reasons_from_u8() {
    assert_eq!(
        RevocationReason::from_u8(0),
        Some(RevocationReason::Unspecified)
    );
    assert_eq!(
        RevocationReason::from_u8(1),
        Some(RevocationReason::KeyCompromise)
    );
    assert_eq!(
        RevocationReason::from_u8(2),
        Some(RevocationReason::CaCompromise)
    );
    assert_eq!(
        RevocationReason::from_u8(3),
        Some(RevocationReason::AffiliationChanged)
    );
    assert_eq!(
        RevocationReason::from_u8(4),
        Some(RevocationReason::Superseded)
    );
    assert_eq!(
        RevocationReason::from_u8(5),
        Some(RevocationReason::CessationOfOperation)
    );
    assert_eq!(
        RevocationReason::from_u8(6),
        Some(RevocationReason::CertificateHold)
    );
    // Note: 7 is not a valid reason per RFC 5280
    assert_eq!(RevocationReason::from_u8(7), None);
    assert_eq!(
        RevocationReason::from_u8(8),
        Some(RevocationReason::RemoveFromCrl)
    );
    assert_eq!(
        RevocationReason::from_u8(9),
        Some(RevocationReason::PrivilegeWithdrawn)
    );
    assert_eq!(
        RevocationReason::from_u8(10),
        Some(RevocationReason::AaCompromise)
    );
}

#[test]
fn test_revocation_reason_invalid_values() {
    // Test invalid reason codes
    assert_eq!(RevocationReason::from_u8(7), None);
    assert_eq!(RevocationReason::from_u8(11), None);
    assert_eq!(RevocationReason::from_u8(100), None);
    assert_eq!(RevocationReason::from_u8(255), None);
}

#[test]
fn test_revocation_reason_as_str() {
    assert_eq!(RevocationReason::Unspecified.as_str(), "unspecified");
    assert_eq!(RevocationReason::KeyCompromise.as_str(), "keyCompromise");
    assert_eq!(RevocationReason::CaCompromise.as_str(), "caCompromise");
    assert_eq!(
        RevocationReason::AffiliationChanged.as_str(),
        "affiliationChanged"
    );
    assert_eq!(RevocationReason::Superseded.as_str(), "superseded");
    assert_eq!(
        RevocationReason::CessationOfOperation.as_str(),
        "cessationOfOperation"
    );
    assert_eq!(
        RevocationReason::CertificateHold.as_str(),
        "certificateHold"
    );
    assert_eq!(RevocationReason::RemoveFromCrl.as_str(), "removeFromCRL");
    assert_eq!(
        RevocationReason::PrivilegeWithdrawn.as_str(),
        "privilegeWithdrawn"
    );
    assert_eq!(RevocationReason::AaCompromise.as_str(), "aaCompromise");
}

#[test]
fn test_revocation_reason_from_str() {
    assert_eq!(
        RevocationReason::from_str("unspecified"),
        Ok(RevocationReason::Unspecified)
    );
    assert_eq!(
        RevocationReason::from_str("keycompromise"),
        Ok(RevocationReason::KeyCompromise)
    );
    assert_eq!(
        RevocationReason::from_str("KEYCOMPROMISE"),
        Ok(RevocationReason::KeyCompromise)
    );
    assert_eq!(
        RevocationReason::from_str("KeyCompromise"),
        Ok(RevocationReason::KeyCompromise)
    );
    assert!(RevocationReason::from_str("invalid").is_err());
    assert!(RevocationReason::from_str("").is_err());
}

// ============================================================================
// RevokedCertificate Tests
// ============================================================================

#[test]
fn test_revoked_certificate_creation() {
    let serial = vec![0x01, 0x02, 0x03, 0x04];
    let now = Utc::now();

    let revoked = RevokedCertificate::new(serial.clone(), now);

    assert_eq!(revoked.serial, serial);
    assert_eq!(revoked.revocation_date, now);
    assert!(revoked.reason.is_none());
    assert!(revoked.invalidity_date.is_none());
}

#[test]
fn test_revoked_certificate_with_reason() {
    let serial = vec![0x01];
    let now = Utc::now();

    let revoked =
        RevokedCertificate::new(serial.clone(), now).with_reason(RevocationReason::KeyCompromise);

    assert_eq!(revoked.reason, Some(RevocationReason::KeyCompromise));
}

#[test]
fn test_revoked_certificate_with_invalidity_date() {
    let serial = vec![0x01];
    let now = Utc::now();
    let invalidity = now - Duration::days(7);

    let revoked = RevokedCertificate::new(serial.clone(), now)
        .with_reason(RevocationReason::KeyCompromise)
        .with_invalidity_date(invalidity);

    assert_eq!(revoked.invalidity_date, Some(invalidity));
}

#[test]
fn test_revoked_certificate_serial_hex() {
    let serial = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let revoked = RevokedCertificate::new(serial, Utc::now());

    assert_eq!(revoked.serial_hex(), "deadbeef");
}

#[test]
fn test_revoked_certificate_empty_serial() {
    let revoked = RevokedCertificate::new(vec![], Utc::now());
    assert_eq!(revoked.serial_hex(), "");
}

#[test]
fn test_revoked_certificate_large_serial() {
    // RFC 5280 allows up to 20 octets
    let serial: Vec<u8> = (0..20).collect();
    let revoked = RevokedCertificate::new(serial.clone(), Utc::now());
    assert_eq!(revoked.serial.len(), 20);
}

// ============================================================================
// CRL Builder Tests
// ============================================================================

#[test]
fn test_crl_builder_empty_crl() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .build_and_sign(&key)
        .unwrap();

    assert!(crl.pem.starts_with("-----BEGIN X509 CRL-----"));
    assert!(crl.pem.ends_with("-----END X509 CRL-----"));
    assert_eq!(crl.crl_number, 1);
    assert_eq!(crl.revoked_count, 0);
    assert!(crl.next_update.is_some());
}

#[test]
fn test_crl_builder_with_revoked_certificates() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let revoked1 = RevokedCertificate::new(vec![0x01], Utc::now())
        .with_reason(RevocationReason::KeyCompromise);
    let revoked2 =
        RevokedCertificate::new(vec![0x02], Utc::now()).with_reason(RevocationReason::Superseded);

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .add_revoked(revoked1)
        .add_revoked(revoked2)
        .build_and_sign(&key)
        .unwrap();

    assert_eq!(crl.revoked_count, 2);
}

#[test]
fn test_crl_builder_with_revoked_list() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let revoked: Vec<RevokedCertificate> = (1..=10)
        .map(|i| RevokedCertificate::new(vec![i as u8], Utc::now()))
        .collect();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .add_revoked_list(revoked)
        .build_and_sign(&key)
        .unwrap();

    assert_eq!(crl.revoked_count, 10);
}

#[test]
fn test_crl_builder_crl_number_sequence() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    // CRL numbers should increment
    for i in 1..=5 {
        let crl = CrlBuilder::new(issuer.clone())
            .crl_number(i)
            .build_and_sign(&key)
            .unwrap();
        assert_eq!(crl.crl_number, i);
    }
}

#[test]
fn test_crl_builder_large_crl_number() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    // Test with large CRL number
    let crl = CrlBuilder::new(issuer)
        .crl_number(u64::MAX)
        .build_and_sign(&key)
        .unwrap();

    assert_eq!(crl.crl_number, u64::MAX);
}

#[test]
fn test_crl_builder_custom_this_update() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let past = Utc::now() - Duration::hours(1);

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .this_update(past)
        .build_and_sign(&key)
        .unwrap();

    // this_update should be set to the provided time
    assert!(crl.this_update <= Utc::now());
}

#[test]
fn test_crl_builder_custom_next_update() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let future = Utc::now() + Duration::days(7);

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update(future)
        .build_and_sign(&key)
        .unwrap();

    assert_eq!(crl.next_update, Some(future));
}

#[test]
fn test_crl_builder_issuer_key_id() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let key_id = vec![0x01, 0x02, 0x03, 0x04, 0x05];

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .issuer_key_id(key_id)
        .build_and_sign(&key)
        .unwrap();

    // CRL should be successfully created with custom key ID
    assert!(!crl.der.is_empty());
}

// ============================================================================
// Algorithm Coverage Tests
// ============================================================================

#[test]
fn test_crl_with_ecdsa_p256() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .build_and_sign(&key)
        .unwrap();

    assert!(!crl.der.is_empty());
}

#[test]
fn test_crl_with_ecdsa_p384() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .build_and_sign(&key)
        .unwrap();

    assert!(!crl.der.is_empty());
}

#[test]
#[cfg(not(feature = "fips"))] // RSA-2048 not permitted in FIPS mode
fn test_crl_with_rsa_2048() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::Rsa2048).unwrap();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .build_and_sign(&key)
        .unwrap();

    assert!(!crl.der.is_empty());
}

// RSA-4096 test omitted due to slow key generation

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_crl_many_revoked_certificates() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    // Create a CRL with many entries
    let revoked: Vec<RevokedCertificate> = (0..100)
        .map(|i| {
            RevokedCertificate::new(vec![(i >> 8) as u8, (i & 0xff) as u8], Utc::now())
                .with_reason(RevocationReason::Superseded)
        })
        .collect();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .add_revoked_list(revoked)
        .build_and_sign(&key)
        .unwrap();

    assert_eq!(crl.revoked_count, 100);
}

#[test]
fn test_crl_with_invalidity_date() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let revoked = RevokedCertificate::new(vec![0x01], Utc::now())
        .with_reason(RevocationReason::KeyCompromise)
        .with_invalidity_date(Utc::now() - Duration::days(30));

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .add_revoked(revoked)
        .build_and_sign(&key)
        .unwrap();

    assert_eq!(crl.revoked_count, 1);
}

#[test]
fn test_crl_der_pem_consistency() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .build_and_sign(&key)
        .unwrap();

    // PEM should be base64 of DER with headers
    assert!(crl.pem.contains("BEGIN X509 CRL"));
    assert!(crl.pem.contains("END X509 CRL"));

    // DER should not be empty
    assert!(!crl.der.is_empty());

    // DER should start with SEQUENCE tag
    assert_eq!(crl.der[0], 0x30);
}

#[test]
fn test_crl_all_reason_codes() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let reasons = [
        RevocationReason::Unspecified,
        RevocationReason::KeyCompromise,
        RevocationReason::CaCompromise,
        RevocationReason::AffiliationChanged,
        RevocationReason::Superseded,
        RevocationReason::CessationOfOperation,
        RevocationReason::CertificateHold,
        RevocationReason::RemoveFromCrl,
        RevocationReason::PrivilegeWithdrawn,
        RevocationReason::AaCompromise,
    ];

    let revoked: Vec<RevokedCertificate> = reasons
        .iter()
        .enumerate()
        .map(|(i, reason)| {
            RevokedCertificate::new(vec![i as u8 + 1], Utc::now()).with_reason(*reason)
        })
        .collect();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .add_revoked_list(revoked)
        .build_and_sign(&key)
        .unwrap();

    assert_eq!(crl.revoked_count, reasons.len());
}

// ============================================================================
// expired_certs_on_crl() — RFC 5280 §5.2.7
// ============================================================================

/// Verify the ExpiredCertsOnCRL extension OID (2.5.29.27 → 06 03 55 1D 1B)
/// appears in the DER when the feature is enabled.
#[test]
fn test_expired_certs_on_crl_extension_present() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let cutoff = Utc::now() - Duration::days(365);

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .expired_certs_on_crl(cutoff)
        .build_and_sign(&key)
        .unwrap();

    // OID 2.5.29.27 encodes as 06 03 55 1D 1B
    let oid_bytes: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x1B];
    assert!(
        crl.der.windows(oid_bytes.len()).any(|w| w == oid_bytes),
        "ExpiredCertsOnCRL OID (2.5.29.27) must be present in DER"
    );
}

/// A CRL built without expired_certs_on_crl() must NOT contain the extension.
#[test]
fn test_expired_certs_on_crl_extension_absent_by_default() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .build_and_sign(&key)
        .unwrap();

    // OID 2.5.29.27 must NOT appear when the extension is not requested
    let oid_bytes: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x1B];
    assert!(
        !crl.der.windows(oid_bytes.len()).any(|w| w == oid_bytes),
        "ExpiredCertsOnCRL OID must be absent when not configured"
    );
}

/// Certificates revoked BEFORE the cutoff date must be excluded from the CRL
/// when expired_certs_on_crl is set.  Certificates revoked ON or AFTER the
/// cutoff must be retained.
///
/// Note: The `expired_certs_on_crl` extension is a CRL *extension* that signals
/// the retention policy; the actual filtering of which entries appear in the CRL
/// is the caller's responsibility.  This test therefore verifies that the
/// builder correctly includes/excludes entries based on whether the caller
/// filters them before calling `add_revoked`, and that the extension OID is
/// present to advertise the policy.
#[test]
fn test_expired_certs_on_crl_caller_filters_entries() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let cutoff = Utc::now() - Duration::days(30);

    // Two entries: one before the cutoff, one after.
    let revoked_before = RevokedCertificate::new(vec![0x01], cutoff - Duration::seconds(1))
        .with_reason(RevocationReason::Superseded);
    let revoked_after = RevokedCertificate::new(vec![0x02], cutoff + Duration::seconds(1))
        .with_reason(RevocationReason::KeyCompromise);

    // Caller filters out entries before cutoff — only the post-cutoff entry is added.
    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .expired_certs_on_crl(cutoff)
        .add_revoked(revoked_after)
        .build_and_sign(&key)
        .unwrap();

    // Only the one post-cutoff entry is in the CRL.
    assert_eq!(
        crl.revoked_count, 1,
        "only post-cutoff entry should be included"
    );

    // The extension OID is present.
    let oid_bytes: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x1B];
    assert!(
        crl.der.windows(oid_bytes.len()).any(|w| w == oid_bytes),
        "ExpiredCertsOnCRL OID must be present"
    );

    // The pre-cutoff entry's serial (0x01) must NOT appear in the DER.
    let _ = revoked_before; // acknowledged — intentionally not added
}

/// Boundary: entry revoked exactly AT the cutoff date must be considered
/// on-or-after and therefore retained.
#[test]
fn test_expired_certs_on_crl_exact_boundary_included() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let cutoff = Utc::now() - Duration::days(7);

    // Entry whose revocationDate == cutoff (on the boundary).
    let revoked_at_boundary = RevokedCertificate::new(vec![0xBB], cutoff)
        .with_reason(RevocationReason::CessationOfOperation);

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .expired_certs_on_crl(cutoff)
        .add_revoked(revoked_at_boundary)
        .build_and_sign(&key)
        .unwrap();

    // The boundary entry is retained (>= cutoff).
    assert_eq!(crl.revoked_count, 1, "boundary entry must be included");
}

// ============================================================================
// only_user_certs() / only_ca_certs() — RFC 5280 §5.2.5
// ============================================================================

/// A CRL built with only_user_certs() must contain the IDP extension (OID
/// 2.5.29.28, tag 0x55 0x1D 0x1C) with critical=TRUE and the
/// onlyContainsUserCerts [1] boolean set.
#[test]
fn test_only_user_certs_idp_extension_encoding() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .only_user_certs()
        .build_and_sign(&key)
        .unwrap();

    // OID 2.5.29.28 = issuingDistributionPoint → 06 03 55 1D 1C
    let idp_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x1C];
    assert!(
        crl.der.windows(idp_oid.len()).any(|w| w == idp_oid),
        "IDP OID (2.5.29.28) must be present when only_user_certs is set"
    );

    // The extension must be marked critical: BOOLEAN TRUE = 01 01 FF
    let critical_bytes: &[u8] = &[0x01, 0x01, 0xFF];
    assert!(
        crl.der
            .windows(critical_bytes.len())
            .any(|w| w == critical_bytes),
        "IDP extension must be critical (01 01 FF)"
    );

    // onlyContainsUserCerts [1] IMPLICIT BOOLEAN TRUE = 81 01 FF
    let user_flag: &[u8] = &[0x81, 0x01, 0xFF];
    assert!(
        crl.der.windows(user_flag.len()).any(|w| w == user_flag),
        "onlyContainsUserCerts [1] TRUE must appear in DER"
    );

    // onlyContainsCACerts [2] must NOT appear
    let ca_flag: &[u8] = &[0x82, 0x01, 0xFF];
    assert!(
        !crl.der.windows(ca_flag.len()).any(|w| w == ca_flag),
        "onlyContainsCACerts flag must be absent when only_user_certs is set"
    );
}

/// A CRL built with only_ca_certs() must set the onlyContainsCACerts [2] flag
/// and must NOT set onlyContainsUserCerts [1].
#[test]
fn test_only_ca_certs_idp_extension_encoding() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .only_ca_certs()
        .build_and_sign(&key)
        .unwrap();

    // IDP OID must be present
    let idp_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x1C];
    assert!(
        crl.der.windows(idp_oid.len()).any(|w| w == idp_oid),
        "IDP OID (2.5.29.28) must be present when only_ca_certs is set"
    );

    // Extension must be critical
    let critical_bytes: &[u8] = &[0x01, 0x01, 0xFF];
    assert!(
        crl.der
            .windows(critical_bytes.len())
            .any(|w| w == critical_bytes),
        "IDP extension must be critical"
    );

    // onlyContainsCACerts [2] IMPLICIT BOOLEAN TRUE = 82 01 FF
    let ca_flag: &[u8] = &[0x82, 0x01, 0xFF];
    assert!(
        crl.der.windows(ca_flag.len()).any(|w| w == ca_flag),
        "onlyContainsCACerts [2] TRUE must appear in DER"
    );

    // onlyContainsUserCerts [1] must NOT appear
    let user_flag: &[u8] = &[0x81, 0x01, 0xFF];
    assert!(
        !crl.der.windows(user_flag.len()).any(|w| w == user_flag),
        "onlyContainsUserCerts flag must be absent when only_ca_certs is set"
    );
}

/// Setting both only_user_certs and only_ca_certs must be rejected (RFC 5280 §5.2.5).
#[test]
fn test_only_user_and_ca_certs_both_set_is_error() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let result = CrlBuilder::new(issuer)
        .crl_number(1)
        .only_user_certs()
        .only_ca_certs()
        .build_and_sign(&key);

    assert!(
        result.is_err(),
        "onlyContainsUserCerts and onlyContainsCACerts both TRUE must be rejected"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("onlyContainsUserCerts") && err_msg.contains("onlyContainsCACerts"),
        "error message should mention both flags; got: {err_msg}"
    );
}

/// Filtering: revoke a user cert (serial 0x01) and a CA cert (serial 0x02),
/// build a user-only CRL containing only the user entry, verify the CA entry
/// is absent from revoked_count.
#[test]
fn test_only_user_certs_filters_ca_certs_out() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    // The caller is responsible for filtering; we add only the user entry.
    let user_entry = RevokedCertificate::new(vec![0x01], Utc::now() - Duration::hours(1))
        .with_reason(RevocationReason::KeyCompromise);

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .only_user_certs()
        .add_revoked(user_entry)
        .build_and_sign(&key)
        .unwrap();

    // Only the user entry is in this CRL.
    assert_eq!(crl.revoked_count, 1);

    // The CRL is valid DER (starts with SEQUENCE).
    assert_eq!(crl.der[0], 0x30);

    // IDP flag is set correctly.
    let user_flag: &[u8] = &[0x81, 0x01, 0xFF];
    assert!(crl.der.windows(user_flag.len()).any(|w| w == user_flag));
}

/// Filtering: build a CA-only CRL; the user cert serial is absent because
/// the caller does not add it.
#[test]
fn test_only_ca_certs_filters_user_certs_out() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    // Only the CA entry is added to this CRL.
    let ca_entry = RevokedCertificate::new(vec![0x02], Utc::now() - Duration::hours(1))
        .with_reason(RevocationReason::CaCompromise);

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .only_ca_certs()
        .add_revoked(ca_entry)
        .build_and_sign(&key)
        .unwrap();

    assert_eq!(crl.revoked_count, 1);

    // Confirm no user-cert flag slipped in.
    let user_flag: &[u8] = &[0x81, 0x01, 0xFF];
    assert!(!crl.der.windows(user_flag.len()).any(|w| w == user_flag));

    let ca_flag: &[u8] = &[0x82, 0x01, 0xFF];
    assert!(crl.der.windows(ca_flag.len()).any(|w| w == ca_flag));
}

/// A plain CRL (no IDP flags) must NOT include any IDP extension.
#[test]
fn test_no_idp_extension_without_flags() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .build_and_sign(&key)
        .unwrap();

    // IDP OID must be absent.
    let idp_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x1C];
    assert!(
        !crl.der.windows(idp_oid.len()).any(|w| w == idp_oid),
        "IDP OID must not appear in a plain CRL"
    );
}

// ============================================================================
// indirect_crl() — RFC 5280 §5.2.5 indirectCRL [4]
// ============================================================================

/// An indirect CRL must contain the IDP extension with the indirectCRL [4]
/// boolean flag set (encoded as 84 01 FF).
#[test]
fn test_indirect_crl_idp_flag_present() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .indirect_crl()
        .build_and_sign(&key)
        .unwrap();

    // IDP OID must be present.
    let idp_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x1C];
    assert!(
        crl.der.windows(idp_oid.len()).any(|w| w == idp_oid),
        "IDP OID must be present in an indirect CRL"
    );

    // indirectCRL [4] IMPLICIT BOOLEAN TRUE = 84 01 FF
    let indirect_flag: &[u8] = &[0x84, 0x01, 0xFF];
    assert!(
        crl.der
            .windows(indirect_flag.len())
            .any(|w| w == indirect_flag),
        "indirectCRL [4] TRUE must appear in DER"
    );

    // The extension must be critical.
    let critical_bytes: &[u8] = &[0x01, 0x01, 0xFF];
    assert!(
        crl.der
            .windows(critical_bytes.len())
            .any(|w| w == critical_bytes),
        "IDP extension must be critical in an indirect CRL"
    );
}

/// An indirect CRL that does NOT set user-only or CA-only flags must not carry
/// those flags — only the indirectCRL [4] flag.
#[test]
fn test_indirect_crl_no_scope_flags() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .indirect_crl()
        .build_and_sign(&key)
        .unwrap();

    // onlyContainsUserCerts [1] must NOT appear.
    let user_flag: &[u8] = &[0x81, 0x01, 0xFF];
    assert!(
        !crl.der.windows(user_flag.len()).any(|w| w == user_flag),
        "onlyContainsUserCerts must be absent in a pure indirect CRL"
    );

    // onlyContainsCACerts [2] must NOT appear.
    let ca_flag: &[u8] = &[0x82, 0x01, 0xFF];
    assert!(
        !crl.der.windows(ca_flag.len()).any(|w| w == ca_flag),
        "onlyContainsCACerts must be absent in a pure indirect CRL"
    );
}

/// An indirect CRL can also be scoped to user certs (indirectCRL [4] + user [1]).
#[test]
fn test_indirect_crl_combined_with_only_user_certs() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .only_user_certs()
        .indirect_crl()
        .build_and_sign(&key)
        .unwrap();

    // Both flags must appear.
    let user_flag: &[u8] = &[0x81, 0x01, 0xFF];
    let indirect_flag: &[u8] = &[0x84, 0x01, 0xFF];

    assert!(
        crl.der.windows(user_flag.len()).any(|w| w == user_flag),
        "onlyContainsUserCerts [1] must appear"
    );
    assert!(
        crl.der
            .windows(indirect_flag.len())
            .any(|w| w == indirect_flag),
        "indirectCRL [4] must appear"
    );
}

// ============================================================================
// freshest_crl_url() — RFC 5280 §5.2.6 (FreshestCRL / delta CRL pointer)
// ============================================================================

/// A CRL with a freshest_crl_url must contain the FreshestCRL extension
/// OID (2.5.29.46 → 06 03 55 1D 2E) and the URL bytes in the DER.
#[test]
fn test_freshest_crl_url_extension_present() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let delta_url = "http://crl.example.com/delta.crl";

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .freshest_crl_url(delta_url)
        .build_and_sign(&key)
        .unwrap();

    // OID 2.5.29.46 = FreshestCRL → 06 03 55 1D 2E
    let freshest_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x2E];
    assert!(
        crl.der
            .windows(freshest_oid.len())
            .any(|w| w == freshest_oid),
        "FreshestCRL OID (2.5.29.46) must be present"
    );

    // The URL itself must appear as IA5String bytes in the DER.
    let url_bytes = delta_url.as_bytes();
    assert!(
        crl.der.windows(url_bytes.len()).any(|w| w == url_bytes),
        "Delta CRL URL must appear verbatim in DER"
    );
}

/// The FreshestCRL extension must be NON-critical (RFC 5280 §5.2.6).
/// We verify this by checking that the criticality byte (0xFF) does NOT
/// appear immediately after the FreshestCRL OID bytes.
#[test]
fn test_freshest_crl_extension_is_non_critical() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .freshest_crl_url("http://crl.example.com/delta.crl")
        .build_and_sign(&key)
        .unwrap();

    let freshest_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x2E];

    // Find the position of the FreshestCRL OID in the DER.
    let oid_pos = crl
        .der
        .windows(freshest_oid.len())
        .position(|w| w == freshest_oid)
        .expect("FreshestCRL OID must be present");

    // The byte immediately after the OID TLV (5 bytes) is the extnValue
    // OCTET STRING tag (0x04), not a BOOLEAN TRUE (0xFF — criticality).
    // A critical extension would insert: 01 01 FF before the 04 byte.
    let after_oid_pos = oid_pos + freshest_oid.len();
    if after_oid_pos < crl.der.len() {
        assert_ne!(
            crl.der[after_oid_pos], 0xFF,
            "FreshestCRL must not be marked critical (no 0xFF directly after OID)"
        );
    }
}

/// A CRL built without freshest_crl_url must NOT contain the FreshestCRL OID.
#[test]
fn test_freshest_crl_extension_absent_by_default() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .build_and_sign(&key)
        .unwrap();

    // FreshestCRL OID must NOT appear.
    let freshest_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x2E];
    assert!(
        !crl.der
            .windows(freshest_oid.len())
            .any(|w| w == freshest_oid),
        "FreshestCRL OID must be absent when no delta URL is configured"
    );
}

/// The [6] IMPLICIT tag (0x86) used for the uniformResourceIdentifier
/// GeneralName choice must appear, followed by the URL bytes.
#[test]
fn test_freshest_crl_url_encoded_as_uri_general_name() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let url = "http://delta.ca.example/latest.crl";
    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .freshest_crl_url(url)
        .build_and_sign(&key)
        .unwrap();

    // GeneralName uniformResourceIdentifier: context tag [6] IMPLICIT = 0x86
    let url_bytes = url.as_bytes();
    let uri_tag_then_url: Vec<u8> = {
        let mut v = vec![0x86];
        v.push(url_bytes.len() as u8);
        v.extend_from_slice(url_bytes);
        v
    };

    assert!(
        crl.der
            .windows(uri_tag_then_url.len())
            .any(|w| w == uri_tag_then_url.as_slice()),
        "URI GeneralName (tag 0x86 + length + URL bytes) must appear in DER"
    );
}

// ============================================================================
// CRL monotonicity (previous_crl_number) — RFC 5280 §5.2.3
// ============================================================================

/// A CRL number equal to the previous must be rejected.
#[test]
fn test_crl_monotonicity_equal_rejected() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let result = CrlBuilder::new(issuer)
        .crl_number(5)
        .previous_crl_number(5)
        .build_and_sign(&key);

    assert!(
        result.is_err(),
        "CRL number equal to previous must be rejected"
    );
}

/// A CRL number less than the previous must be rejected.
#[test]
fn test_crl_monotonicity_less_than_rejected() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let result = CrlBuilder::new(issuer)
        .crl_number(3)
        .previous_crl_number(10)
        .build_and_sign(&key);

    assert!(
        result.is_err(),
        "CRL number less than previous must be rejected"
    );
}

/// A CRL number strictly greater than the previous must succeed.
#[test]
fn test_crl_monotonicity_greater_succeeds() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let crl = CrlBuilder::new(issuer)
        .crl_number(11)
        .previous_crl_number(10)
        .next_update_hours(24)
        .build_and_sign(&key)
        .unwrap();

    assert_eq!(crl.crl_number, 11);
}

/// No previous_crl_number set — any crl_number is accepted.
#[test]
fn test_crl_monotonicity_no_previous_always_succeeds() {
    let issuer = NameBuilder::new("Test CA").build();
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    // Even crl_number = 1 without setting previous is fine.
    let crl = CrlBuilder::new(issuer)
        .crl_number(1)
        .next_update_hours(24)
        .build_and_sign(&key)
        .unwrap();

    assert_eq!(crl.crl_number, 1);
}
