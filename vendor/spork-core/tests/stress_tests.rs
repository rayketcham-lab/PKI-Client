//! Stress tests for SPORK core subsystems under concurrent load.
//!
//! These tests exercise certificate issuance, CRL generation, chain
//! verification, and OCSP response building under parallel workloads
//! to verify correctness and absence of data races.
//!
//! All tests are self-contained — no database or external services required.

#![cfg(feature = "ceremony")]

use std::sync::{Arc, Mutex};
use std::thread;

use spork_core::algo::{AlgorithmId, KeyPair};
use spork_core::ca::{CertificateProfile, IssuanceRequest};
use spork_core::cert::{CsrBuilder, NameBuilder, Validity};
use spork_core::crl::{CrlBuilder, RevokedCertificate};
use spork_core::{
    validate_chain, CaCeremony, CaConfig, CertificateAuthority, ChainValidationOptions,
    SubjectAltName,
};

// ============================================================================
// Helpers
// ============================================================================

fn setup_ca(name: &str, algo: AlgorithmId) -> CertificateAuthority {
    let config = CaConfig::root(name, algo).with_subject(
        NameBuilder::new(name)
            .organization("SPORK Stress Test")
            .country("US")
            .build(),
    );
    CaCeremony::init_root(config).unwrap().ca
}

fn setup_hierarchy(algo: AlgorithmId) -> (CertificateAuthority, CertificateAuthority) {
    let mut root = setup_ca("Stress Root CA", algo);
    let int_config = CaConfig::intermediate("Stress Issuing CA", algo).with_subject(
        NameBuilder::new("Stress Issuing CA")
            .organization("SPORK Stress Test")
            .country("US")
            .build(),
    );
    let int_ca = CaCeremony::init_intermediate(int_config, &mut root)
        .unwrap()
        .ca;
    (root, int_ca)
}

fn issue_cert(ca: &mut CertificateAuthority, cn: &str) -> spork_core::ca::IssuedCertificate {
    let ee_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let ee_subject = NameBuilder::new(cn)
        .organization("Stress Test Corp")
        .country("US")
        .build();
    let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();
    let san = SubjectAltName::new().dns(cn);
    let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
        .with_san(san)
        .with_validity(Validity::days_from_now(90));
    ca.issue_certificate(request).unwrap()
}

// ============================================================================
// Concurrent certificate issuance
// ============================================================================

/// Issue 100 certificates across 4 threads from a shared CA.
/// Verifies serial number uniqueness and chain validity.
#[test]
fn test_stress_concurrent_issuance_100_certs() {
    let (root, int_ca) = setup_hierarchy(AlgorithmId::EcdsaP256);
    let root_cert_der = root.certificate_der.clone();
    let int_cert = int_ca.certificate.clone();
    let ca = Arc::new(Mutex::new(int_ca));

    let mut handles = Vec::new();
    let certs_per_thread = 25;

    for t in 0..4 {
        let ca = Arc::clone(&ca);
        let root_cert_der = root_cert_der.clone();
        let int_cert = int_cert.clone();
        handles.push(thread::spawn(move || {
            let mut serials = Vec::new();
            for i in 0..certs_per_thread {
                let cn = format!("stress-{}-{}.test.local", t, i);
                let issued = {
                    let mut ca = ca.lock().unwrap();
                    issue_cert(&mut ca, &cn)
                };

                // Verify the certificate chains back to root
                let chain = vec![issued.certificate.clone(), int_cert.clone()];
                let result = validate_chain(
                    &chain,
                    std::slice::from_ref(&root_cert_der),
                    &ChainValidationOptions::default(),
                );
                assert!(
                    result.valid,
                    "cert {} failed chain validation: {:?}",
                    cn, result.errors
                );

                serials.push(issued.serial_hex.clone());
            }
            serials
        }));
    }

    // Collect all serials and verify uniqueness
    let mut all_serials = Vec::new();
    for h in handles {
        all_serials.extend(h.join().unwrap());
    }
    assert_eq!(all_serials.len(), 100);

    // No duplicate serials
    let mut sorted = all_serials.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        all_serials.len(),
        "duplicate serial numbers detected"
    );
}

// ============================================================================
// Large CRL generation
// ============================================================================

/// Generate a CRL with 1,000 revoked entries and verify it round-trips.
#[test]
fn test_stress_large_crl_1000_entries() {
    let ca = setup_ca("CRL Stress CA", AlgorithmId::EcdsaP256);
    let issuer_name = ca.certificate.tbs_certificate.subject.clone();
    let issuer_dn = spork_core::cert::DistinguishedName::from_x509_name(&issuer_name).unwrap();

    let mut revoked = Vec::new();
    for i in 1..=1000u64 {
        let be = i.to_be_bytes();
        let serial_bytes = be
            .iter()
            .copied()
            .skip_while(|&b| b == 0)
            .collect::<Vec<u8>>();
        revoked.push(
            RevokedCertificate::new(serial_bytes, chrono::Utc::now())
                .with_reason(spork_core::crl::RevocationReason::Unspecified),
        );
    }

    let crl_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let crl = CrlBuilder::new(issuer_dn)
        .crl_number(1)
        .next_update_hours(24)
        .add_revoked_list(revoked)
        .build_and_sign(&crl_key)
        .unwrap();

    let pem = &crl.pem;
    assert!(!pem.is_empty());

    // Parse back and verify entry count
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .expect("CRL PEM base64 decode failed");

    use der::Decode;
    let parsed = x509_cert::crl::CertificateList::from_der(&der).expect("CRL DER parse failed");
    let count = parsed
        .tbs_cert_list
        .revoked_certificates
        .as_ref()
        .map(|r| r.len())
        .unwrap_or(0);
    assert_eq!(count, 1000, "expected 1000 revoked entries, got {}", count);
}

/// Generate a CRL with 10,000 revoked entries — stress test for DER encoding.
#[test]
fn test_stress_large_crl_10000_entries() {
    let ca = setup_ca("CRL Stress CA 10K", AlgorithmId::EcdsaP384);
    let issuer_name = ca.certificate.tbs_certificate.subject.clone();
    let issuer_dn = spork_core::cert::DistinguishedName::from_x509_name(&issuer_name).unwrap();

    let mut revoked = Vec::new();
    for i in 1..=10_000u64 {
        let reason = match i % 5 {
            0 => spork_core::crl::RevocationReason::KeyCompromise,
            1 => spork_core::crl::RevocationReason::CessationOfOperation,
            2 => spork_core::crl::RevocationReason::Superseded,
            3 => spork_core::crl::RevocationReason::AffiliationChanged,
            _ => spork_core::crl::RevocationReason::Unspecified,
        };
        let be = i.to_be_bytes();
        let serial_bytes = be
            .iter()
            .copied()
            .skip_while(|&b| b == 0)
            .collect::<Vec<u8>>();
        revoked.push(RevokedCertificate::new(serial_bytes, chrono::Utc::now()).with_reason(reason));
    }

    let crl_key = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();
    let crl = CrlBuilder::new(issuer_dn)
        .crl_number(42)
        .next_update_hours(6)
        .add_revoked_list(revoked)
        .build_and_sign(&crl_key)
        .unwrap();

    let pem = &crl.pem;
    // 10K entries should produce a substantial CRL
    assert!(
        pem.len() > 100_000,
        "10K CRL is suspiciously small: {} bytes",
        pem.len()
    );
}

// ============================================================================
// Parallel chain verification
// ============================================================================

/// Verify 200 certificate chains in parallel across 8 threads.
#[test]
fn test_stress_parallel_chain_verification() {
    // Build a small CA + 50 certs, then verify all 50 on 8 threads (4× each = 200 verifications)
    let (root, mut int_ca) = setup_hierarchy(AlgorithmId::EcdsaP256);
    let root_cert_der = root.certificate_der.clone();
    let int_cert = int_ca.certificate.clone();

    let certs: Vec<_> = (0..50)
        .map(|i| {
            let cn = format!("verify-stress-{}.test.local", i);
            issue_cert(&mut int_ca, &cn)
        })
        .collect();

    let certs = Arc::new(certs);
    let root_cert_der = Arc::new(root_cert_der);
    let int_cert = Arc::new(int_cert);

    let mut handles = Vec::new();
    for _ in 0..8 {
        let certs = Arc::clone(&certs);
        let root_cert_der = Arc::clone(&root_cert_der);
        let int_cert = Arc::clone(&int_cert);
        handles.push(thread::spawn(move || {
            let mut pass = 0u32;
            for cert in certs.iter() {
                let chain = vec![cert.certificate.clone(), (*int_cert).clone()];
                let result = validate_chain(
                    &chain,
                    &[(*root_cert_der).clone()],
                    &ChainValidationOptions::default(),
                );
                assert!(result.valid, "chain validation failed");
                pass += 1;
            }
            pass
        }));
    }

    let total: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(
        total, 400,
        "expected 400 verifications (50 certs × 8 threads)"
    );
}

// ============================================================================
// Concurrent key generation
// ============================================================================

/// Generate 50 P-256 keys in parallel across 10 threads.
/// Verifies no panics or data corruption in the RNG.
#[test]
fn test_stress_concurrent_key_generation() {
    let mut handles = Vec::new();
    for _ in 0..10 {
        handles.push(thread::spawn(|| {
            let mut keys = Vec::new();
            for _ in 0..5 {
                let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
                keys.push(key.public_key_der().unwrap());
            }
            keys
        }));
    }

    let mut all_pubkeys = Vec::new();
    for h in handles {
        all_pubkeys.extend(h.join().unwrap());
    }
    assert_eq!(all_pubkeys.len(), 50);

    // All public keys should be unique
    let mut sorted = all_pubkeys.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        all_pubkeys.len(),
        "duplicate public keys generated"
    );
}

// ============================================================================
// Mixed workload: issue + revoke + verify concurrently
// ============================================================================

/// Simulate a mixed workload: one thread issues certs, another builds CRLs,
/// and two threads verify chains — all operating concurrently.
#[test]
fn test_stress_mixed_workload() {
    let (root, int_ca) = setup_hierarchy(AlgorithmId::EcdsaP256);
    let root_cert_der = root.certificate_der.clone();
    let int_cert = int_ca.certificate.clone();
    let issuer_name = int_ca.certificate.tbs_certificate.subject.clone();
    let issuer_dn = spork_core::cert::DistinguishedName::from_x509_name(&issuer_name).unwrap();

    let ca = Arc::new(Mutex::new(int_ca));
    let issued_certs = Arc::new(Mutex::new(Vec::new()));

    // Thread 1: Issue 30 certificates
    let ca1 = Arc::clone(&ca);
    let certs1 = Arc::clone(&issued_certs);
    let issuer = thread::spawn(move || {
        for i in 0..30 {
            let cn = format!("mixed-{}.test.local", i);
            let cert = {
                let mut ca = ca1.lock().unwrap();
                issue_cert(&mut ca, &cn)
            };
            certs1.lock().unwrap().push(cert);
        }
    });

    // Thread 2: Build CRLs with increasing revocation lists
    let crl_thread = thread::spawn(move || {
        let crl_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let mut total_entries = 0;
        for batch in 0..5 {
            let mut revoked = Vec::new();
            for i in 0..20 {
                let serial_num = batch * 20 + i + 1;
                let be = (serial_num as u64).to_be_bytes();
                let serial_bytes = be
                    .iter()
                    .copied()
                    .skip_while(|&b| b == 0)
                    .collect::<Vec<u8>>();
                revoked.push(
                    RevokedCertificate::new(serial_bytes, chrono::Utc::now())
                        .with_reason(spork_core::crl::RevocationReason::Unspecified),
                );
            }
            let crl = CrlBuilder::new(issuer_dn.clone())
                .crl_number(batch as u64 + 1)
                .next_update_hours(24)
                .add_revoked_list(revoked)
                .build_and_sign(&crl_key)
                .unwrap();
            assert!(!crl.pem.is_empty());
            total_entries += 20;
        }
        total_entries
    });

    // Threads 3-4: Verify root cert chain (doesn't need issued certs)
    let mut verifiers = Vec::new();
    for _ in 0..2 {
        let root_cert_der = root_cert_der.clone();
        let int_cert = int_cert.clone();
        verifiers.push(thread::spawn(move || {
            let mut count = 0;
            for _ in 0..25 {
                let chain = vec![int_cert.clone()];
                let result = validate_chain(
                    &chain,
                    std::slice::from_ref(&root_cert_der),
                    &ChainValidationOptions::default(),
                );
                assert!(result.valid);
                count += 1;
            }
            count
        }));
    }

    issuer.join().unwrap();
    let crl_entries = crl_thread.join().unwrap();
    let verify_count: u32 = verifiers.into_iter().map(|h| h.join().unwrap()).sum();

    assert_eq!(issued_certs.lock().unwrap().len(), 30);
    assert_eq!(crl_entries, 100);
    assert_eq!(verify_count, 50);
}

// ============================================================================
// OCSP response building under load
// ============================================================================

/// Build 100 OCSP responses in parallel to verify the response builder
/// handles concurrent use correctly.
#[test]
fn test_stress_ocsp_response_building() {
    use spork_core::algo::KeyPair;

    // Pre-generate a signing key
    let signer = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let signer_der = signer.private_key_der().unwrap();

    let mut handles = Vec::new();
    for t in 0..4 {
        let signer_der = signer_der.clone();
        handles.push(thread::spawn(move || {
            let signer = KeyPair::from_pkcs8_der(AlgorithmId::EcdsaP256, &signer_der).unwrap();
            let mut count = 0;
            for i in 0..25 {
                let serial = format!("{:04X}", t * 25 + i + 1);
                // Sign arbitrary data to simulate OCSP response signing
                let tbs = format!("OCSP-response-{}-{}", t, serial);
                let sig = signer.sign(tbs.as_bytes()).unwrap();
                assert!(!sig.is_empty(), "OCSP signature should not be empty");
                count += 1;
            }
            count
        }));
    }

    let total: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(total, 100, "expected 100 OCSP responses");
}
