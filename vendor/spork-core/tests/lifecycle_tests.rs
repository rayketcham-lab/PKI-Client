//! Certificate Lifecycle Integration Tests
//!
//! Tests the complete PKI lifecycle: Issue → Verify → Revoke → CRL → Verify Revoked.
//! Covers RFC 5280 revocation reasons, CRL generation, serial matching, and
//! multi-CA revocation scenarios.

#![cfg(feature = "ceremony")]

use chrono::Utc;
use der::{Decode, Encode};
use x509_cert::crl::CertificateList;
use x509_cert::Certificate;

use spork_core::algo::{AlgorithmId, KeyPair};
use spork_core::ca::{CertificateProfile, IssuanceRequest};
use spork_core::cert::{CsrBuilder, NameBuilder, Validity};
use spork_core::crl::{
    generator::{CrlGenerator, RevocationEntry},
    CrlBuilder, RevocationReason, RevokedCertificate,
};
use spork_core::{
    validate_chain, CaCeremony, CaConfig, CertificateAuthority, ChainValidationOptions,
    SubjectAltName,
};

// ============================================================================
// Helpers
// ============================================================================

fn root_ca(name: &str, algo: AlgorithmId) -> (Certificate, CertificateAuthority) {
    let config = CaConfig::root(name, algo).with_subject(
        NameBuilder::new(name)
            .organization("SPORK Lifecycle Test")
            .country("US")
            .build(),
    );
    let result = CaCeremony::init_root(config).unwrap();
    (result.ca.certificate.clone(), result.ca)
}

fn intermediate_ca(
    name: &str,
    algo: AlgorithmId,
    parent: &mut CertificateAuthority,
) -> (Certificate, CertificateAuthority) {
    let config = CaConfig::intermediate(name, algo).with_subject(
        NameBuilder::new(name)
            .organization("SPORK Lifecycle Test")
            .country("US")
            .build(),
    );
    let result = CaCeremony::init_intermediate(config, parent).unwrap();
    (result.ca.certificate.clone(), result.ca)
}

fn issue_tls_cert(ca: &mut CertificateAuthority, cn: &str) -> spork_core::ca::IssuedCertificate {
    let ee_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let ee_subject = NameBuilder::new(cn)
        .organization("Test Corp")
        .country("US")
        .build();
    let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

    let san = SubjectAltName::new().dns(cn);
    let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
        .with_san(san)
        .with_validity(Validity::days_from_now(365));

    ca.issue_certificate(request).unwrap()
}

fn default_opts() -> ChainValidationOptions {
    ChainValidationOptions::default()
}

/// Sign a CRL with a standalone key (CRL signing key is separate from CA signing key
/// in real deployments; here we use a fresh key since the CRL builder validates the
/// serial list content, not the signer identity)
fn sign_crl(
    issuer_name: spork_core::cert::DistinguishedName,
    crl_number: u64,
    revoked: Vec<RevokedCertificate>,
    algo: AlgorithmId,
) -> spork_core::crl::Crl {
    let crl_key = KeyPair::generate(algo).unwrap();
    CrlBuilder::new(issuer_name)
        .crl_number(crl_number)
        .next_update_hours(24)
        .add_revoked_list(revoked)
        .build_and_sign(&crl_key)
        .unwrap()
}

/// Parse a CRL PEM and extract the list of revoked serial numbers (hex)
fn extract_revoked_serials_from_pem(crl_pem: &str) -> Vec<String> {
    let b64: String = crl_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .expect("CRL PEM base64 decode failed");

    let crl = CertificateList::from_der(&der).expect("CRL DER parse failed");

    let mut serials = Vec::new();
    if let Some(revoked_list) = crl.tbs_cert_list.revoked_certificates.as_ref() {
        for entry in revoked_list.iter() {
            let serial_bytes = entry.serial_number.as_bytes();
            serials.push(hex::encode(serial_bytes));
        }
    }
    serials
}

// ============================================================================
// Full Lifecycle: Issue → Verify → Revoke → CRL → Verify in CRL
// ============================================================================

#[test]
fn test_full_lifecycle_issue_revoke_crl_p256() {
    // 1. Create CA hierarchy
    let (root_cert, mut root_ca) = root_ca("Lifecycle Root CA", AlgorithmId::EcdsaP256);
    let (_int_cert, mut int_ca) =
        intermediate_ca("Lifecycle Issuing CA", AlgorithmId::EcdsaP256, &mut root_ca);

    // 2. Issue a TLS certificate
    let issued = issue_tls_cert(&mut int_ca, "lifecycle-test.example.com");
    assert!(!issued.serial_hex.is_empty());
    assert_eq!(issued.subject_cn, "lifecycle-test.example.com");

    // 3. Verify the certificate is valid in the chain
    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();
    let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];
    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(result.valid, "Chain should be valid: {:?}", result.errors);

    // 4. Revoke the certificate and generate a CRL
    let serial_bytes = hex::decode(&issued.serial_hex).unwrap();
    let revoked = RevokedCertificate::new(serial_bytes, Utc::now())
        .with_reason(RevocationReason::KeyCompromise);

    let issuer_name = NameBuilder::new("Lifecycle Issuing CA")
        .organization("SPORK Lifecycle Test")
        .country("US")
        .build();

    let crl = sign_crl(issuer_name, 1, vec![revoked], AlgorithmId::EcdsaP256);

    // 5. Verify the revoked serial appears in the CRL
    assert_eq!(crl.revoked_count, 1);
    let crl_serials = extract_revoked_serials_from_pem(&crl.pem);
    assert!(
        crl_serials.contains(&issued.serial_hex),
        "CRL should contain revoked serial {}. CRL contains: {:?}",
        issued.serial_hex,
        crl_serials
    );
}

#[test]
fn test_full_lifecycle_multiple_certs_partial_revoke() {
    // 1. Setup CA
    let (_root_cert, mut root_ca) = root_ca("Multi Root CA", AlgorithmId::EcdsaP256);
    let (_int_cert, mut int_ca) =
        intermediate_ca("Multi Issuing CA", AlgorithmId::EcdsaP256, &mut root_ca);

    // 2. Issue 5 certificates
    let certs: Vec<_> = (1..=5)
        .map(|i| issue_tls_cert(&mut int_ca, &format!("server-{}.example.com", i)))
        .collect();

    // Verify all have unique serials
    let serials: Vec<_> = certs.iter().map(|c| c.serial_hex.clone()).collect();
    let unique: std::collections::HashSet<_> = serials.iter().collect();
    assert_eq!(unique.len(), 5, "All serials must be unique");

    // 3. Revoke certs 1, 3, 5 with different reasons
    let revoked_entries: Vec<_> = vec![
        (0, RevocationReason::KeyCompromise),
        (2, RevocationReason::Superseded),
        (4, RevocationReason::CessationOfOperation),
    ]
    .into_iter()
    .map(|(idx, reason)| {
        let serial_bytes = hex::decode(&certs[idx].serial_hex).unwrap();
        RevokedCertificate::new(serial_bytes, Utc::now()).with_reason(reason)
    })
    .collect();

    let issuer_name = NameBuilder::new("Multi Issuing CA")
        .organization("SPORK Lifecycle Test")
        .country("US")
        .build();

    let crl = sign_crl(issuer_name, 1, revoked_entries, AlgorithmId::EcdsaP256);

    // 4. Verify CRL contains exactly the 3 revoked serials
    assert_eq!(crl.revoked_count, 3);

    let crl_serials = extract_revoked_serials_from_pem(&crl.pem);
    assert!(crl_serials.contains(&certs[0].serial_hex));
    assert!(crl_serials.contains(&certs[2].serial_hex));
    assert!(crl_serials.contains(&certs[4].serial_hex));

    // 5. Verify non-revoked certs are NOT in the CRL
    assert!(!crl_serials.contains(&certs[1].serial_hex));
    assert!(!crl_serials.contains(&certs[3].serial_hex));
}

#[test]
fn test_lifecycle_all_revocation_reasons() {
    let (_root_cert, mut root_ca) = root_ca("Reason Root CA", AlgorithmId::EcdsaP256);
    let (_int_cert, mut int_ca) =
        intermediate_ca("Reason Issuing CA", AlgorithmId::EcdsaP256, &mut root_ca);

    let reasons = vec![
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

    let mut revoked_entries = Vec::new();
    let mut issued_serials = Vec::new();

    for (i, reason) in reasons.iter().enumerate() {
        let cert = issue_tls_cert(&mut int_ca, &format!("reason-{}.example.com", i));
        issued_serials.push(cert.serial_hex.clone());

        let serial_bytes = hex::decode(&cert.serial_hex).unwrap();
        revoked_entries
            .push(RevokedCertificate::new(serial_bytes, Utc::now()).with_reason(*reason));
    }

    let issuer_name = NameBuilder::new("Reason Issuing CA")
        .organization("SPORK Lifecycle Test")
        .country("US")
        .build();

    let crl = sign_crl(issuer_name, 1, revoked_entries, AlgorithmId::EcdsaP256);

    // All 10 reasons should be in the CRL
    assert_eq!(crl.revoked_count, 10);

    let crl_serials = extract_revoked_serials_from_pem(&crl.pem);
    for serial in &issued_serials {
        assert!(
            crl_serials.contains(serial),
            "Missing serial {} from CRL",
            serial
        );
    }
}

#[test]
fn test_lifecycle_crl_number_increments_on_new_revocation() {
    let (_root_cert, mut root_ca) = root_ca("Inc Root CA", AlgorithmId::EcdsaP256);
    let (_int_cert, mut int_ca) =
        intermediate_ca("Inc Issuing CA", AlgorithmId::EcdsaP256, &mut root_ca);

    let issuer_name = NameBuilder::new("Inc Issuing CA")
        .organization("SPORK Lifecycle Test")
        .country("US")
        .build();

    // Issue and revoke cert 1 → CRL #1
    let cert1 = issue_tls_cert(&mut int_ca, "crl-inc-1.example.com");
    let serial1 = hex::decode(&cert1.serial_hex).unwrap();
    let revoked1 =
        RevokedCertificate::new(serial1, Utc::now()).with_reason(RevocationReason::Superseded);

    let crl1 = sign_crl(
        issuer_name.clone(),
        1,
        vec![revoked1.clone()],
        AlgorithmId::EcdsaP256,
    );

    assert_eq!(crl1.crl_number, 1);
    assert_eq!(crl1.revoked_count, 1);

    // Issue and revoke cert 2 → CRL #2 should contain BOTH revoked serials
    let cert2 = issue_tls_cert(&mut int_ca, "crl-inc-2.example.com");
    let serial2 = hex::decode(&cert2.serial_hex).unwrap();
    let revoked2 =
        RevokedCertificate::new(serial2, Utc::now()).with_reason(RevocationReason::KeyCompromise);

    let crl2 = sign_crl(
        issuer_name,
        2,
        vec![revoked1, revoked2],
        AlgorithmId::EcdsaP256,
    );

    assert_eq!(crl2.crl_number, 2);
    assert_eq!(crl2.revoked_count, 2);
    assert!(crl2.crl_number > crl1.crl_number);

    let crl2_serials = extract_revoked_serials_from_pem(&crl2.pem);
    assert!(crl2_serials.contains(&cert1.serial_hex));
    assert!(crl2_serials.contains(&cert2.serial_hex));
}

#[test]
fn test_lifecycle_multi_ca_revocations() {
    // Test that revocations are correctly scoped to their issuing CA
    let (_root_cert, mut root_ca) = root_ca("Multi-CA Root", AlgorithmId::EcdsaP256);
    let (_ca1_cert, mut ca1) =
        intermediate_ca("TLS Issuing CA", AlgorithmId::EcdsaP256, &mut root_ca);
    let (_ca2_cert, mut ca2) =
        intermediate_ca("Email Issuing CA", AlgorithmId::EcdsaP256, &mut root_ca);

    // Issue certs from both CAs
    let tls_cert = issue_tls_cert(&mut ca1, "web.example.com");
    let email_cert = issue_tls_cert(&mut ca2, "mail.example.com");

    // Revoke only the TLS cert
    let tls_serial = hex::decode(&tls_cert.serial_hex).unwrap();
    let tls_revoked =
        RevokedCertificate::new(tls_serial, Utc::now()).with_reason(RevocationReason::Superseded);

    // CA1's CRL should have the TLS cert
    let ca1_issuer = NameBuilder::new("TLS Issuing CA")
        .organization("SPORK Lifecycle Test")
        .country("US")
        .build();

    let ca1_crl = sign_crl(ca1_issuer, 1, vec![tls_revoked], AlgorithmId::EcdsaP256);

    assert_eq!(ca1_crl.revoked_count, 1);
    let ca1_serials = extract_revoked_serials_from_pem(&ca1_crl.pem);
    assert!(ca1_serials.contains(&tls_cert.serial_hex));
    assert!(!ca1_serials.contains(&email_cert.serial_hex));

    // CA2's CRL should be empty (no revocations)
    let ca2_issuer = NameBuilder::new("Email Issuing CA")
        .organization("SPORK Lifecycle Test")
        .country("US")
        .build();

    let ca2_crl = sign_crl(ca2_issuer, 1, vec![], AlgorithmId::EcdsaP256);
    assert_eq!(ca2_crl.revoked_count, 0);
}

/// RSA-2048 lifecycle (non-FIPS only — FIPS requires 3072-bit minimum)
#[cfg(not(feature = "fips"))]
#[test]
fn test_lifecycle_rsa_chain_revocation() {
    let (root_cert, mut root_ca) = root_ca("RSA Lifecycle Root", AlgorithmId::Rsa2048);
    let (_int_cert, mut int_ca) =
        intermediate_ca("RSA Lifecycle Issuing", AlgorithmId::Rsa2048, &mut root_ca);

    // Issue
    let ee_key = KeyPair::generate(AlgorithmId::Rsa2048).unwrap();
    let ee_subject = NameBuilder::new("rsa-lifecycle.example.com")
        .organization("Test Corp")
        .build();
    let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();
    let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
        .with_san(SubjectAltName::new().dns("rsa-lifecycle.example.com"))
        .with_validity(Validity::days_from_now(365));
    let issued = int_ca.issue_certificate(request).unwrap();

    // Verify chain
    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();
    let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];
    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(
        result.valid,
        "RSA chain should be valid: {:?}",
        result.errors
    );

    // Revoke and CRL (RSA-signed CRL)
    let serial_bytes = hex::decode(&issued.serial_hex).unwrap();
    let revoked = RevokedCertificate::new(serial_bytes, Utc::now())
        .with_reason(RevocationReason::KeyCompromise);

    let issuer_name = NameBuilder::new("RSA Lifecycle Issuing")
        .organization("Test Corp")
        .build();

    let crl = sign_crl(issuer_name, 1, vec![revoked], AlgorithmId::Rsa2048);

    assert_eq!(crl.revoked_count, 1);
    let crl_serials = extract_revoked_serials_from_pem(&crl.pem);
    assert!(crl_serials.contains(&issued.serial_hex));
}

/// RSA-4096 lifecycle (FIPS-compliant — runs under all feature sets)
#[test]
fn test_lifecycle_rsa4096_chain_revocation() {
    let (root_cert, mut root_ca) = root_ca("RSA4096 Lifecycle Root", AlgorithmId::Rsa4096);
    let (_int_cert, mut int_ca) = intermediate_ca(
        "RSA4096 Lifecycle Issuing",
        AlgorithmId::Rsa4096,
        &mut root_ca,
    );

    let ee_key = KeyPair::generate(AlgorithmId::Rsa4096).unwrap();
    let ee_subject = NameBuilder::new("rsa4096-lifecycle.example.com")
        .organization("Test Corp")
        .build();
    let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();
    let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
        .with_san(SubjectAltName::new().dns("rsa4096-lifecycle.example.com"))
        .with_validity(Validity::days_from_now(365));
    let issued = int_ca.issue_certificate(request).unwrap();

    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();
    let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];
    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(
        result.valid,
        "RSA-4096 chain should be valid: {:?}",
        result.errors
    );

    let serial_bytes = hex::decode(&issued.serial_hex).unwrap();
    let revoked = RevokedCertificate::new(serial_bytes, Utc::now())
        .with_reason(RevocationReason::KeyCompromise);

    let issuer_name = NameBuilder::new("RSA4096 Lifecycle Issuing")
        .organization("Test Corp")
        .build();

    let crl = sign_crl(issuer_name, 1, vec![revoked], AlgorithmId::Rsa4096);

    assert_eq!(crl.revoked_count, 1);
    let crl_serials = extract_revoked_serials_from_pem(&crl.pem);
    assert!(crl_serials.contains(&issued.serial_hex));
}

#[test]
fn test_lifecycle_p384_chain_revocation() {
    let (root_cert, mut root_ca) = root_ca("P384 Lifecycle Root", AlgorithmId::EcdsaP384);
    let (_int_cert, mut int_ca) = intermediate_ca(
        "P384 Lifecycle Issuing",
        AlgorithmId::EcdsaP384,
        &mut root_ca,
    );

    let issued = issue_tls_cert(&mut int_ca, "p384-lifecycle.example.com");

    // Verify chain
    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();
    let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];
    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(result.valid, "P-384 chain valid: {:?}", result.errors);

    // Revoke and CRL (P-384 signed CRL)
    let serial_bytes = hex::decode(&issued.serial_hex).unwrap();
    let revoked = RevokedCertificate::new(serial_bytes, Utc::now())
        .with_reason(RevocationReason::AffiliationChanged);

    let issuer_name = NameBuilder::new("P384 Lifecycle Issuing")
        .organization("SPORK Lifecycle Test")
        .country("US")
        .build();

    let crl = sign_crl(issuer_name, 1, vec![revoked], AlgorithmId::EcdsaP384);

    assert_eq!(crl.revoked_count, 1);
    let crl_serials = extract_revoked_serials_from_pem(&crl.pem);
    assert!(crl_serials.contains(&issued.serial_hex));
}

#[test]
fn test_lifecycle_batch_issue_batch_revoke() {
    let (_root_cert, mut root_ca) = root_ca("Batch Root", AlgorithmId::EcdsaP256);
    let (_int_cert, mut int_ca) =
        intermediate_ca("Batch Issuing CA", AlgorithmId::EcdsaP256, &mut root_ca);

    // Issue 20 certificates
    let certs: Vec<_> = (1..=20)
        .map(|i| issue_tls_cert(&mut int_ca, &format!("batch-{:02}.example.com", i)))
        .collect();

    assert_eq!(certs.len(), 20);

    // Revoke every other cert (10 total) with varied reasons
    let reasons = [
        RevocationReason::Superseded,
        RevocationReason::KeyCompromise,
        RevocationReason::CessationOfOperation,
        RevocationReason::AffiliationChanged,
        RevocationReason::Unspecified,
    ];

    let revoked_indices: Vec<usize> = (0..20).step_by(2).collect();
    let revoked_entries: Vec<_> = revoked_indices
        .iter()
        .enumerate()
        .map(|(i, &idx)| {
            let serial_bytes = hex::decode(&certs[idx].serial_hex).unwrap();
            RevokedCertificate::new(serial_bytes, Utc::now())
                .with_reason(reasons[i % reasons.len()])
        })
        .collect();

    let issuer_name = NameBuilder::new("Batch Issuing CA")
        .organization("SPORK Lifecycle Test")
        .country("US")
        .build();

    let crl = sign_crl(issuer_name, 1, revoked_entries, AlgorithmId::EcdsaP256);

    assert_eq!(crl.revoked_count, 10);

    let crl_serials = extract_revoked_serials_from_pem(&crl.pem);
    // Check revoked certs are in CRL
    for &idx in &revoked_indices {
        assert!(
            crl_serials.contains(&certs[idx].serial_hex),
            "Revoked cert {} should be in CRL",
            idx
        );
    }
    // Check non-revoked certs are NOT in CRL
    let active_indices: Vec<usize> = (1..20).step_by(2).collect();
    for &idx in &active_indices {
        assert!(
            !crl_serials.contains(&certs[idx].serial_hex),
            "Active cert {} should NOT be in CRL",
            idx
        );
    }
}

// ============================================================================
// Cross-Service CRL Integration (Issue #263)
// Uses CrlGenerator with the CA's own identity for realistic CRL generation,
// verifies CRL DER structure via x509_cert parsing, and tests delta CRLs.
// ============================================================================

#[test]
fn test_crl_generator_full_lifecycle() {
    // 1. Create CA hierarchy
    let (root_cert, mut root_ca) = root_ca("CRLGen Root CA", AlgorithmId::EcdsaP256);
    let (_int_cert, mut int_ca) =
        intermediate_ca("CRLGen Issuing CA", AlgorithmId::EcdsaP256, &mut root_ca);

    // 2. Issue several certificates
    let cert1 = issue_tls_cert(&mut int_ca, "crlgen-1.example.com");
    let cert2 = issue_tls_cert(&mut int_ca, "crlgen-2.example.com");
    let cert3 = issue_tls_cert(&mut int_ca, "crlgen-3.example.com");

    // 3. Verify all certs are valid
    for cert in &[&cert1, &cert2, &cert3] {
        let ee_cert = spork_core::cert::parse_certificate_pem(&cert.pem).unwrap();
        let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];
        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "Cert should be valid: {:?}", result.errors);
    }

    // 4. Create CRL generator using CA's issuer DN and a signing key
    let issuer_dn = NameBuilder::new("CRLGen Issuing CA")
        .organization("SPORK Lifecycle Test")
        .country("US")
        .build();
    let crl_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let generator = CrlGenerator::new(issuer_dn, crl_key).with_next_update_hours(24);

    // 5. Generate empty CRL first (no revocations yet)
    let empty_crl = generator.generate_full_crl(1, vec![]).unwrap();
    assert_eq!(empty_crl.crl_number, 1);
    assert_eq!(empty_crl.revoked_count, 0);
    assert!(empty_crl.pem.contains("BEGIN X509 CRL"));

    // Parse the CRL DER and verify structure
    let parsed_empty = CertificateList::from_der(&empty_crl.der).unwrap();
    assert!(
        parsed_empty.tbs_cert_list.revoked_certificates.is_none()
            || parsed_empty
                .tbs_cert_list
                .revoked_certificates
                .as_ref()
                .unwrap()
                .is_empty()
    );

    // 6. Revoke cert1 (key compromise) and cert3 (superseded)
    let revocations = vec![
        RevocationEntry::new(hex::decode(&cert1.serial_hex).unwrap(), Utc::now())
            .with_reason(RevocationReason::KeyCompromise),
        RevocationEntry::new(hex::decode(&cert3.serial_hex).unwrap(), Utc::now())
            .with_reason(RevocationReason::Superseded),
    ];

    let crl = generator.generate_full_crl(2, revocations).unwrap();
    assert_eq!(crl.crl_number, 2);
    assert_eq!(crl.revoked_count, 2);

    // 7. Parse CRL DER and verify revoked serials
    let parsed = CertificateList::from_der(&crl.der).unwrap();
    let revoked_list = parsed
        .tbs_cert_list
        .revoked_certificates
        .as_ref()
        .expect("CRL should have revoked entries");
    assert_eq!(revoked_list.len(), 2);

    let crl_serials = extract_revoked_serials_from_pem(&crl.pem);
    assert!(crl_serials.contains(&cert1.serial_hex));
    assert!(!crl_serials.contains(&cert2.serial_hex));
    assert!(crl_serials.contains(&cert3.serial_hex));

    // 8. Generate delta CRL — new revocation of cert2
    let delta_revocations =
        vec![
            RevocationEntry::new(hex::decode(&cert2.serial_hex).unwrap(), Utc::now())
                .with_reason(RevocationReason::CessationOfOperation),
        ];

    let delta = generator
        .generate_delta_crl(2, 3, delta_revocations, 6)
        .unwrap();
    assert_eq!(delta.base_crl_number, 2);
    assert_eq!(delta.delta_crl_number, 3);
    assert_eq!(delta.revoked_count, 1);

    // Delta CRL should only contain cert2
    let delta_serials = extract_revoked_serials_from_pem(&delta.pem);
    assert!(delta_serials.contains(&cert2.serial_hex));
    assert!(!delta_serials.contains(&cert1.serial_hex));
}

#[test]
fn test_crl_issuer_dn_matches_ca() {
    // Verifies that the CRL's issuer DN matches the issuing CA's subject DN
    let (_root_cert, mut root_ca) = root_ca("DN Match Root CA", AlgorithmId::EcdsaP256);
    let (_int_cert, mut int_ca) =
        intermediate_ca("DN Match Issuing CA", AlgorithmId::EcdsaP256, &mut root_ca);

    let cert = issue_tls_cert(&mut int_ca, "dn-match.example.com");

    let issuer_dn = NameBuilder::new("DN Match Issuing CA")
        .organization("SPORK Lifecycle Test")
        .country("US")
        .build();
    let crl_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let generator =
        CrlGenerator::new(issuer_dn, crl_key).with_issuer_key_id(vec![0xDE, 0xAD, 0xBE, 0xEF]);

    let revocations =
        vec![
            RevocationEntry::new(hex::decode(&cert.serial_hex).unwrap(), Utc::now())
                .with_reason(RevocationReason::KeyCompromise),
        ];

    let crl = generator.generate_full_crl(1, revocations).unwrap();

    // Parse and verify the CRL issuer contains our CA's CN
    let parsed = CertificateList::from_der(&crl.der).unwrap();
    let issuer_der = parsed.tbs_cert_list.issuer.to_der().unwrap();
    // The issuer DN should contain "DN Match Issuing CA"
    let issuer_str = String::from_utf8_lossy(&issuer_der);
    assert!(
        issuer_str.contains("DN Match Issuing CA"),
        "CRL issuer should contain CA CN"
    );

    // Verify nextUpdate is set
    assert!(crl.next_update.is_some());
    let diff = crl.next_update.unwrap() - Utc::now();
    assert!(diff.num_hours() >= 23, "CRL should be valid for ~24h");
}
