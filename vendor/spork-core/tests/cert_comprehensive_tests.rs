//! Comprehensive Certificate Builder tests for security audit
//!
//! These tests cover edge cases, boundary conditions, and RFC 5280 compliance.
#![allow(unused_imports)]

use chrono::{Datelike, Duration, Utc};
use der::Encode;
use spork_core::algo::{AlgorithmId, KeyPair};
use spork_core::cert::{
    extensions::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsageFlags, SubjectAltName},
    CertificateBuilder, NameBuilder, SerialNumber, Validity,
};

// ============================================================================
// SerialNumber Tests
// ============================================================================

#[test]
fn test_serial_number_random_uniqueness() {
    let s1 = SerialNumber::random();
    let s2 = SerialNumber::random();
    let s3 = SerialNumber::random();

    // All should be different
    assert_ne!(s1.as_ref(), s2.as_ref());
    assert_ne!(s2.as_ref(), s3.as_ref());
    assert_ne!(s1.as_ref(), s3.as_ref());
}

#[test]
fn test_serial_number_size() {
    let serial = SerialNumber::random();
    // RFC 5280: serial numbers up to 20 octets
    assert!(serial.as_ref().len() <= 20);
    // Should not be empty
    assert!(!serial.as_ref().is_empty());
}

#[test]
fn test_serial_number_from_bytes() {
    let bytes = vec![0x01, 0x02, 0x03, 0x04];
    let serial = SerialNumber::from_bytes(bytes.clone()).unwrap();
    assert_eq!(serial.as_ref(), &bytes[..]);
}

#[test]
fn test_serial_number_sequential() {
    let serial = SerialNumber::sequential(12345);
    assert!(!serial.as_ref().is_empty());
}

// ============================================================================
// DistinguishedName Tests
// ============================================================================

#[test]
fn test_name_builder_minimal() {
    let name = NameBuilder::new("Test").build();
    // Should have at least a CN
    assert!(!name.common_name.is_empty());
}

#[test]
fn test_name_builder_full() {
    let name = NameBuilder::new("Test CA")
        .organization("Test Org")
        .organizational_unit("PKI Team")
        .country("US")
        .state("California")
        .locality("San Francisco")
        .build();

    assert_eq!(name.common_name, "Test CA");
    assert_eq!(name.organization, Some("Test Org".to_string()));
    assert_eq!(name.organizational_unit, Some("PKI Team".to_string()));
    assert_eq!(name.country, Some("US".to_string()));
    assert_eq!(name.state, Some("California".to_string()));
    assert_eq!(name.locality, Some("San Francisco".to_string()));
}

#[test]
fn test_name_to_der_roundtrip() {
    let name = NameBuilder::new("Test CA")
        .organization("Test Org")
        .country("US")
        .build();

    let der = name.to_der().unwrap();
    // DER should not be empty and start with SEQUENCE
    assert!(!der.is_empty());
    assert_eq!(der[0], 0x30);
}

// ============================================================================
// Validity Tests
// ============================================================================

#[test]
fn test_validity_ee_default() {
    let validity = Validity::ee_default();
    let now = Utc::now();

    // Basic sanity checks
    assert!(validity.not_before <= now);
    assert!(validity.not_after > now);

    // The base time for not_after is `now` (without backdate), so derive it
    // from not_before + 5min backdate to avoid midnight boundary flakiness.
    let base_time = validity.not_before + chrono::Duration::seconds(300);

    // Verify exactly 1 calendar year (proper month arithmetic, not just 365 days)
    assert_eq!(
        validity.not_after.year() - base_time.year(),
        1,
        "EE validity should be exactly 1 calendar year"
    );

    // Month should match between base time and not_after
    assert_eq!(
        validity.not_after.month(),
        base_time.month(),
        "Month should match for 1-year validity"
    );

    // Day should match or be Feb 28 if started on Feb 29 (leap year edge case)
    let day_matches = validity.not_after.day() == base_time.day()
        || (base_time.month() == 2 && base_time.day() == 29 && validity.not_after.day() == 28);
    assert!(
        day_matches,
        "Day should match for 1-year validity (or Feb 29->28)"
    );
}

#[test]
fn test_validity_ca_default() {
    let validity = Validity::ca_default();
    let now = Utc::now();

    // Basic sanity checks
    assert!(validity.not_before <= now);
    assert!(validity.not_after > now);

    // The base time for not_after is `now` (without backdate), so derive it
    // from not_before + 5min backdate to avoid midnight boundary flakiness.
    let base_time = validity.not_before + chrono::Duration::seconds(300);

    // Verify exactly 20 calendar years (proper month arithmetic including leap years)
    assert_eq!(
        validity.not_after.year() - base_time.year(),
        20,
        "CA validity should be exactly 20 calendar years"
    );

    // Month should match
    assert_eq!(
        validity.not_after.month(),
        base_time.month(),
        "Month should match for 20-year validity"
    );

    // Day should match or handle Feb 29 edge case
    let day_matches = validity.not_after.day() == base_time.day()
        || (base_time.month() == 2 && base_time.day() == 29 && validity.not_after.day() == 28);
    assert!(
        day_matches,
        "Day should match for 20-year validity (or Feb 29->28)"
    );

    // Verify we have MORE days than naive 20*365 (due to leap years).
    // Use base_time for a stable comparison (not_before has backdate).
    let diff = validity.not_after - base_time;
    assert!(
        diff.num_days() >= 20 * 365,
        "20 calendar years should include leap days, got {} days",
        diff.num_days()
    );

    // In 20 years there are 4-5 leap years, so expect 7304-7306 days
    assert!(
        diff.num_days() >= 7304 && diff.num_days() <= 7306,
        "Expected 7304-7306 days for 20 calendar years, got {}",
        diff.num_days()
    );
}

#[test]
fn test_validity_years_from_now_leap_year_handling() {
    // Test that years_from_now properly handles calendar years
    let validity = Validity::years_from_now(4);

    // In 4 years, we cross exactly 1 leap year (usually)
    let diff = validity.not_after - validity.not_before;

    // 4 calendar years should be more than 4*365 (due to leap year)
    assert!(
        diff.num_days() > 4 * 365,
        "4 years should include at least one leap day, got {} days",
        diff.num_days()
    );

    // Year should increment by exactly 4
    assert_eq!(validity.not_after.year() - validity.not_before.year(), 4);
}

#[test]
fn test_validity_months_from_now() {
    // Test 6 months
    let validity = Validity::months_from_now(6);
    let diff = validity.not_after - validity.not_before;

    // 6 months is roughly 180-184 days
    assert!(
        diff.num_days() >= 180 && diff.num_days() <= 185,
        "6 months should be 180-185 days, got {}",
        diff.num_days()
    );

    // Test 12 months equals 1 year
    let validity_12m = Validity::months_from_now(12);
    assert_eq!(
        validity_12m.not_after.year() - validity_12m.not_before.year(),
        1,
        "12 months should equal 1 calendar year"
    );

    // Test 24 months equals 2 years
    let validity_24m = Validity::months_from_now(24);
    assert_eq!(
        validity_24m.not_after.year() - validity_24m.not_before.year(),
        2,
        "24 months should equal 2 calendar years"
    );
}

#[test]
fn test_validity_days_from_now() {
    // Test specific day counts
    let validity = Validity::days_from_now(90);
    let diff = validity.not_after - validity.not_before;

    assert_eq!(
        diff.num_days(),
        90,
        "days_from_now(90) should be exactly 90 days"
    );

    // Test 365 days (not a calendar year!)
    let validity_365 = Validity::days_from_now(365);
    let diff_365 = validity_365.not_after - validity_365.not_before;
    assert_eq!(
        diff_365.num_days(),
        365,
        "days_from_now(365) should be exactly 365 days"
    );
}

#[test]
fn test_validity_custom() {
    let not_before = Utc::now();
    let not_after = Utc::now() + Duration::days(30);

    let validity = Validity::new(not_before, not_after).unwrap();
    assert_eq!(validity.not_before, not_before);
    assert_eq!(validity.not_after, not_after);
}

#[test]
fn test_validity_invalid_dates() {
    let now = Utc::now();
    let past = now - Duration::days(1);

    // not_after before not_before should fail
    let result = Validity::new(now, past);
    assert!(result.is_err(), "Should reject not_after before not_before");

    // Same date should also fail
    let result = Validity::new(now, now);
    assert!(
        result.is_err(),
        "Should reject equal not_before and not_after"
    );
}

#[test]
fn test_validity_is_valid() {
    // Currently valid
    let validity = Validity::days_from_now(30);
    assert!(
        validity.is_valid(),
        "30-day validity should be currently valid"
    );

    // Create expired validity manually
    let past = Utc::now() - Duration::days(10);
    let expired = Validity::new(past - Duration::days(30), past).unwrap();
    assert!(!expired.is_valid(), "Expired validity should return false");
}

// ============================================================================
// BasicConstraints Tests
// ============================================================================

#[test]
fn test_basic_constraints_ca() {
    let bc = BasicConstraints::ca();
    assert!(bc.ca);
    assert!(bc.path_len_constraint.is_none());
}

#[test]
fn test_basic_constraints_ca_with_path_len() {
    let bc = BasicConstraints::ca_with_path_len(2);
    assert!(bc.ca);
    assert_eq!(bc.path_len_constraint, Some(2));
}

#[test]
fn test_basic_constraints_end_entity() {
    let bc = BasicConstraints::end_entity();
    assert!(!bc.ca);
    assert!(bc.path_len_constraint.is_none());
}

// ============================================================================
// KeyUsage Tests
// ============================================================================

#[test]
fn test_key_usage_ca_default() {
    let flags = KeyUsageFlags::ca_default();
    // Should have some bits set
    assert!(!flags.is_empty());
}

#[test]
fn test_key_usage_tls_server() {
    let flags = KeyUsageFlags::tls_server();
    assert!(!flags.is_empty());
}

#[test]
fn test_key_usage_to_der() {
    let ku = KeyUsage::new(KeyUsageFlags::ca_default());
    let der = ku.to_der().unwrap();
    assert!(!der.is_empty());
}

// ============================================================================
// ExtendedKeyUsage Tests
// ============================================================================

#[test]
fn test_eku_tls_server() {
    let eku = ExtendedKeyUsage::tls_server();
    assert!(!eku.usages.is_empty());
}

#[test]
fn test_eku_tls_client() {
    let eku = ExtendedKeyUsage::tls_client();
    assert!(!eku.usages.is_empty());
}

#[test]
fn test_eku_code_signing() {
    let eku = ExtendedKeyUsage::code_signing();
    assert!(!eku.usages.is_empty());
}

#[test]
fn test_eku_tls_server_client() {
    let eku = ExtendedKeyUsage::tls_server_client();
    // Should have both server and client auth
    assert!(eku.usages.len() >= 2);
}

// ============================================================================
// SubjectAltName Tests
// ============================================================================

#[test]
fn test_san_dns_name() {
    let san = SubjectAltName::new().dns("example.com");
    assert_eq!(san.dns_names.len(), 1);
    assert_eq!(san.dns_names[0], "example.com");
}

#[test]
fn test_san_multiple_dns() {
    let san = SubjectAltName::new()
        .dns("example.com")
        .dns("www.example.com")
        .dns("mail.example.com");
    assert_eq!(san.dns_names.len(), 3);
}

#[test]
fn test_san_ip_address() {
    let san = SubjectAltName::new().ip("192.168.1.1".parse().unwrap());
    assert_eq!(san.ip_addresses.len(), 1);
}

#[test]
fn test_san_email() {
    let san = SubjectAltName::new().email("test@example.com");
    assert_eq!(san.emails.len(), 1);
}

#[test]
fn test_san_combined() {
    let san = SubjectAltName::new()
        .dns("example.com")
        .email("admin@example.com")
        .ip("10.0.0.1".parse().unwrap());

    assert_eq!(san.dns_names.len(), 1);
    assert_eq!(san.emails.len(), 1);
    assert_eq!(san.ip_addresses.len(), 1);
}

// ============================================================================
// CertificateBuilder Tests
// ============================================================================

#[test]
fn test_self_signed_certificate() {
    let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let subject = NameBuilder::new("Test CA")
        .organization("Test Org")
        .country("US")
        .build();

    let cert = CertificateBuilder::new(
        subject,
        kp.public_key_der().unwrap(),
        AlgorithmId::EcdsaP256,
    )
    .validity(Validity::ca_default())
    .basic_constraints(BasicConstraints::ca())
    .key_usage(KeyUsage::new(KeyUsageFlags::ca_default()))
    .build_and_sign(&kp)
    .unwrap();

    // Verify it's a v3 certificate
    assert_eq!(cert.tbs_certificate.version, x509_cert::Version::V3);

    // Verify extensions are present
    assert!(cert.tbs_certificate.extensions.is_some());
}

#[test]
fn test_end_entity_certificate() {
    let ca_kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let ee_kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let issuer = NameBuilder::new("Test CA").build();
    let subject = NameBuilder::new("test.example.com").build();

    let cert = CertificateBuilder::new(
        subject,
        ee_kp.public_key_der().unwrap(),
        AlgorithmId::EcdsaP256,
    )
    .issuer(issuer)
    .validity(Validity::ee_default())
    .basic_constraints(BasicConstraints::end_entity())
    .key_usage(KeyUsage::new(KeyUsageFlags::tls_server()))
    .extended_key_usage(ExtendedKeyUsage::tls_server())
    .subject_alt_name(SubjectAltName::new().dns("test.example.com"))
    .build_and_sign(&ca_kp)
    .unwrap();

    assert!(cert.tbs_certificate.extensions.is_some());
}

#[test]
fn test_certificate_with_custom_serial() {
    let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let subject = NameBuilder::new("Test").build();

    let serial = SerialNumber::sequential(12345);

    let cert = CertificateBuilder::new(
        subject,
        kp.public_key_der().unwrap(),
        AlgorithmId::EcdsaP256,
    )
    .serial(serial)
    .build_and_sign(&kp)
    .unwrap();

    // Certificate should be created successfully
    assert_eq!(cert.tbs_certificate.version, x509_cert::Version::V3);
}

#[test]
fn test_certificate_der_encoding() {
    let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let subject = NameBuilder::new("Test").build();

    let cert = CertificateBuilder::new(
        subject,
        kp.public_key_der().unwrap(),
        AlgorithmId::EcdsaP256,
    )
    .basic_constraints(BasicConstraints::end_entity())
    .build_and_sign(&kp)
    .unwrap();

    // Should encode to valid DER
    let der = cert.to_der().unwrap();
    assert!(!der.is_empty());
    // Should start with SEQUENCE
    assert_eq!(der[0], 0x30);
}

// ============================================================================
// Algorithm Coverage
// ============================================================================

#[test]
fn test_certificate_ecdsa_p256() {
    let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let subject = NameBuilder::new("Test").build();

    let cert = CertificateBuilder::new(
        subject,
        kp.public_key_der().unwrap(),
        AlgorithmId::EcdsaP256,
    )
    .build_and_sign(&kp)
    .unwrap();

    assert!(!cert.to_der().unwrap().is_empty());
}

#[test]
fn test_certificate_ecdsa_p384() {
    let kp = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();
    let subject = NameBuilder::new("Test").build();

    let cert = CertificateBuilder::new(
        subject,
        kp.public_key_der().unwrap(),
        AlgorithmId::EcdsaP384,
    )
    .build_and_sign(&kp)
    .unwrap();

    assert!(!cert.to_der().unwrap().is_empty());
}

#[test]
#[cfg(not(feature = "fips"))] // RSA-2048 not permitted in FIPS mode
fn test_certificate_rsa_2048() {
    let kp = KeyPair::generate(AlgorithmId::Rsa2048).unwrap();
    let subject = NameBuilder::new("Test").build();

    let cert = CertificateBuilder::new(subject, kp.public_key_der().unwrap(), AlgorithmId::Rsa2048)
        .build_and_sign(&kp)
        .unwrap();

    assert!(!cert.to_der().unwrap().is_empty());
}

// ============================================================================
// Extension Inclusion Tests
// ============================================================================

#[test]
fn test_certificate_without_ski() {
    let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let subject = NameBuilder::new("Test").build();

    let cert = CertificateBuilder::new(
        subject,
        kp.public_key_der().unwrap(),
        AlgorithmId::EcdsaP256,
    )
    .include_subject_key_identifier(false)
    .build_and_sign(&kp)
    .unwrap();

    // Certificate should still be valid
    assert_eq!(cert.tbs_certificate.version, x509_cert::Version::V3);
}

#[test]
fn test_certificate_without_aki() {
    let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let subject = NameBuilder::new("Test").build();

    let cert = CertificateBuilder::new(
        subject,
        kp.public_key_der().unwrap(),
        AlgorithmId::EcdsaP256,
    )
    .include_authority_key_identifier(false)
    .build_and_sign(&kp)
    .unwrap();

    assert_eq!(cert.tbs_certificate.version, x509_cert::Version::V3);
}

#[test]
fn test_certificate_custom_authority_key_id() {
    let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let subject = NameBuilder::new("Test").build();

    let key_id = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];

    let cert = CertificateBuilder::new(
        subject,
        kp.public_key_der().unwrap(),
        AlgorithmId::EcdsaP256,
    )
    .authority_key_identifier(key_id)
    .build_and_sign(&kp)
    .unwrap();

    assert!(cert.tbs_certificate.extensions.is_some());
}

// ============================================================================
// Intermediate CA Tests
// ============================================================================

#[test]
fn test_intermediate_ca_certificate() {
    let root_kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let intermediate_kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let root_subject = NameBuilder::new("Root CA").organization("Test Org").build();

    let intermediate_subject = NameBuilder::new("Intermediate CA")
        .organization("Test Org")
        .build();

    // Create root CA first
    let _root_cert = CertificateBuilder::new(
        root_subject.clone(),
        root_kp.public_key_der().unwrap(),
        AlgorithmId::EcdsaP256,
    )
    .validity(Validity::ca_default())
    .basic_constraints(BasicConstraints::ca())
    .key_usage(KeyUsage::new(KeyUsageFlags::ca_default()))
    .build_and_sign(&root_kp)
    .unwrap();

    // Create intermediate CA signed by root
    let intermediate_cert = CertificateBuilder::new(
        intermediate_subject,
        intermediate_kp.public_key_der().unwrap(),
        AlgorithmId::EcdsaP256,
    )
    .issuer(root_subject)
    .validity(Validity::ca_default())
    .basic_constraints(BasicConstraints::ca_with_path_len(0)) // Can only issue end-entity certs
    .key_usage(KeyUsage::new(KeyUsageFlags::ca_default()))
    .build_and_sign(&root_kp)
    .unwrap();

    assert!(intermediate_cert.tbs_certificate.extensions.is_some());
}
