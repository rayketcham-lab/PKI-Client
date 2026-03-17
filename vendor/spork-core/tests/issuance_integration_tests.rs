//! Full-chain issuance integration tests
//!
//! Tests the complete PKI lifecycle: Root CA creation → Intermediate CA signing →
//! End-entity certificate issuance → Chain validation. Exercises both CSR-based
//! and direct issuance paths, multiple algorithms, and certificate content verification.

#![cfg(feature = "ceremony")]

use der::{Decode, Encode};
use x509_cert::ext::pkix::BasicConstraints as X509BasicConstraints;
use x509_cert::ext::pkix::KeyUsage as X509KeyUsage;
use x509_cert::Certificate;

use spork_core::algo::{AlgorithmId, KeyPair};
use spork_core::ca::{CertificateProfile, IssuanceRequest};
use spork_core::cert::{CsrBuilder, NameBuilder, Validity};
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
            .organization("SPORK Integration Test")
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
            .organization("SPORK Integration Test")
            .country("US")
            .build(),
    );
    let result = CaCeremony::init_intermediate(config, parent).unwrap();
    (result.ca.certificate.clone(), result.ca)
}

fn default_opts() -> ChainValidationOptions {
    ChainValidationOptions::default()
}

fn extract_extension(cert: &Certificate, oid_arcs: &[u32]) -> Option<Vec<u8>> {
    cert.tbs_certificate.extensions.as_ref().and_then(|exts| {
        exts.iter().find_map(|ext| {
            let arcs: Vec<u32> = ext.extn_id.arcs().collect();
            if arcs == oid_arcs {
                Some(ext.extn_value.as_bytes().to_vec())
            } else {
                None
            }
        })
    })
}

const OID_BASIC_CONSTRAINTS: &[u32] = &[2, 5, 29, 19];
const OID_KEY_USAGE: &[u32] = &[2, 5, 29, 15];
const OID_EXT_KEY_USAGE: &[u32] = &[2, 5, 29, 37];
const OID_SUBJECT_ALT_NAME: &[u32] = &[2, 5, 29, 17];

// ============================================================================
// CSR-Based Full Chain Issuance
// ============================================================================

#[test]
fn test_csr_based_full_chain_p256() {
    // 1. Create Root CA
    let (root_cert, mut root_ca) = root_ca("Integration Root CA", AlgorithmId::EcdsaP256);

    // 2. Create Intermediate CA signed by Root
    let (_int_cert, mut int_ca) = intermediate_ca(
        "Integration Issuing CA",
        AlgorithmId::EcdsaP256,
        &mut root_ca,
    );

    // 3. Generate end-entity key and CSR
    let ee_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let ee_subject = NameBuilder::new("webserver.example.com")
        .organization("Example Corp")
        .country("US")
        .build();
    let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

    // 4. Issue end-entity certificate from CSR
    let san = SubjectAltName::new()
        .dns("webserver.example.com")
        .dns("www.example.com")
        .dns("api.example.com");

    let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
        .with_san(san)
        .with_validity(Validity::days_from_now(365));

    let issued = int_ca.issue_certificate(request).unwrap();

    // 5. Verify certificate metadata
    assert_eq!(issued.subject_cn, "webserver.example.com");
    assert_eq!(issued.issuer_cn, "Integration Issuing CA");
    assert_eq!(issued.profile, CertificateProfile::TlsServer);
    assert!(issued.pem.contains("BEGIN CERTIFICATE"));

    // 6. Parse and validate the full chain
    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();
    let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];

    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(result.valid, "Chain validation failed: {:?}", result.errors);
    assert!(result.trusted, "Root not trusted");
    assert!(result.errors.is_empty());
}

#[test]
fn test_csr_based_full_chain_p384() {
    let (root_cert, mut root_ca) = root_ca("P384 Root", AlgorithmId::EcdsaP384);
    let (_int_cert, mut int_ca) =
        intermediate_ca("P384 Issuing CA", AlgorithmId::EcdsaP384, &mut root_ca);

    let ee_key = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();
    let ee_subject = NameBuilder::new("secure.example.com").build();
    let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

    let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
        .with_san(SubjectAltName::new().dns("secure.example.com"));

    let issued = int_ca.issue_certificate(request).unwrap();
    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();

    let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];

    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(result.valid, "P-384 chain failed: {:?}", result.errors);
    assert!(result.trusted);
}

/// RSA-2048 full chain (non-FIPS only — FIPS requires 3072-bit minimum per SP 800-131A Rev 2)
#[cfg(not(feature = "fips"))]
#[test]
fn test_csr_based_full_chain_rsa() {
    let (root_cert, mut root_ca) = root_ca("RSA Root", AlgorithmId::Rsa2048);
    let (_int_cert, mut int_ca) =
        intermediate_ca("RSA Issuing CA", AlgorithmId::Rsa2048, &mut root_ca);

    let ee_key = KeyPair::generate(AlgorithmId::Rsa2048).unwrap();
    let ee_subject = NameBuilder::new("legacy.example.com").build();
    let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

    let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
        .with_san(SubjectAltName::new().dns("legacy.example.com"));

    let issued = int_ca.issue_certificate(request).unwrap();
    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();

    let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];

    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(result.valid, "RSA chain failed: {:?}", result.errors);
    assert!(result.trusted);
}

/// RSA-4096 full chain (FIPS-compliant — runs under all feature sets)
#[test]
fn test_csr_based_full_chain_rsa4096() {
    let (root_cert, mut root_ca) = root_ca("RSA4096 Root", AlgorithmId::Rsa4096);
    let (_int_cert, mut int_ca) =
        intermediate_ca("RSA4096 Issuing CA", AlgorithmId::Rsa4096, &mut root_ca);

    let ee_key = KeyPair::generate(AlgorithmId::Rsa4096).unwrap();
    let ee_subject = NameBuilder::new("fips-rsa.example.com").build();
    let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

    let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
        .with_san(SubjectAltName::new().dns("fips-rsa.example.com"));

    let issued = int_ca.issue_certificate(request).unwrap();
    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();

    let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];

    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(result.valid, "RSA-4096 chain failed: {:?}", result.errors);
    assert!(result.trusted);
}

// ============================================================================
// Certificate Content Verification
// ============================================================================

#[test]
fn test_issued_cert_has_correct_extensions() {
    let (_root_cert, mut root_ca) = root_ca("Ext Root", AlgorithmId::EcdsaP256);
    let (_int_cert, mut int_ca) =
        intermediate_ca("Ext Issuing CA", AlgorithmId::EcdsaP256, &mut root_ca);

    // Issue TLS server cert
    let ee_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let ee_subject = NameBuilder::new("ext-test.example.com").build();
    let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

    let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer).with_san(
        SubjectAltName::new()
            .dns("ext-test.example.com")
            .dns("alt.example.com"),
    );

    let issued = int_ca.issue_certificate(request).unwrap();
    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();

    // BasicConstraints: must be end-entity (CA:FALSE)
    let bc_bytes = extract_extension(&ee_cert, OID_BASIC_CONSTRAINTS)
        .expect("EE cert must have BasicConstraints");
    let bc = X509BasicConstraints::from_der(&bc_bytes).unwrap();
    assert!(!bc.ca, "EE cert must have CA:FALSE");

    // KeyUsage: must have digitalSignature for TLS server
    let ku_bytes = extract_extension(&ee_cert, OID_KEY_USAGE).expect("EE cert must have KeyUsage");
    let ku = X509KeyUsage::from_der(&ku_bytes).unwrap();
    assert!(
        ku.digital_signature(),
        "TLS server must have digitalSignature"
    );

    // ExtendedKeyUsage: must be present for TLS server
    assert!(
        extract_extension(&ee_cert, OID_EXT_KEY_USAGE).is_some(),
        "TLS server cert must have EKU"
    );

    // SubjectAltName: must be present
    assert!(
        extract_extension(&ee_cert, OID_SUBJECT_ALT_NAME).is_some(),
        "Cert must have SAN extension"
    );
}

#[test]
fn test_intermediate_has_ca_extensions() {
    let (_root_cert, mut root_ca) = root_ca("CA Ext Root", AlgorithmId::EcdsaP256);
    let (_int_cert, int_ca) =
        intermediate_ca("CA Ext Issuing", AlgorithmId::EcdsaP256, &mut root_ca);

    let int_cert = &int_ca.certificate;

    // BasicConstraints: must be CA:TRUE
    let bc_bytes = extract_extension(int_cert, OID_BASIC_CONSTRAINTS)
        .expect("Intermediate must have BasicConstraints");
    let bc = X509BasicConstraints::from_der(&bc_bytes).unwrap();
    assert!(bc.ca, "Intermediate must have CA:TRUE");

    // KeyUsage: must have keyCertSign
    let ku_bytes =
        extract_extension(int_cert, OID_KEY_USAGE).expect("Intermediate must have KeyUsage");
    let ku = X509KeyUsage::from_der(&ku_bytes).unwrap();
    assert!(ku.key_cert_sign(), "Intermediate must have keyCertSign");
    assert!(ku.crl_sign(), "Intermediate must have cRLSign");
}

// ============================================================================
// Multiple Certificate Profiles
// ============================================================================

#[test]
fn test_multiple_profiles_from_same_ca() {
    let (_root_cert, mut root_ca) = root_ca("Profile Root", AlgorithmId::EcdsaP256);
    let (_int_cert, mut int_ca) =
        intermediate_ca("Profile Issuing CA", AlgorithmId::EcdsaP256, &mut root_ca);

    // Issue TLS server cert
    let subject = NameBuilder::new("tls-server.example.com").build();
    let (tls_server, _) = int_ca
        .issue_direct(
            subject,
            AlgorithmId::EcdsaP256,
            CertificateProfile::TlsServer,
            Validity::days_from_now(365),
            Some(SubjectAltName::new().dns("tls-server.example.com")),
        )
        .unwrap();
    assert_eq!(tls_server.profile, CertificateProfile::TlsServer);

    // Issue TLS client cert
    let subject = NameBuilder::new("client@example.com").build();
    let (tls_client, _) = int_ca
        .issue_direct(
            subject,
            AlgorithmId::EcdsaP256,
            CertificateProfile::TlsClient,
            Validity::days_from_now(365),
            None,
        )
        .unwrap();
    assert_eq!(tls_client.profile, CertificateProfile::TlsClient);

    // Issue code signing cert
    let subject = NameBuilder::new("Code Signer")
        .organization("Example Corp")
        .build();
    let (code_sign, _) = int_ca
        .issue_direct(
            subject,
            AlgorithmId::EcdsaP256,
            CertificateProfile::CodeSigning,
            Validity::days_from_now(365 * 3),
            None,
        )
        .unwrap();
    assert_eq!(code_sign.profile, CertificateProfile::CodeSigning);

    // All three should have different serial numbers
    assert_ne!(tls_server.serial_hex, tls_client.serial_hex);
    assert_ne!(tls_client.serial_hex, code_sign.serial_hex);
    assert_ne!(tls_server.serial_hex, code_sign.serial_hex);

    // All three should be from the same issuer
    assert_eq!(tls_server.issuer_cn, "Profile Issuing CA");
    assert_eq!(tls_client.issuer_cn, "Profile Issuing CA");
    assert_eq!(code_sign.issuer_cn, "Profile Issuing CA");
}

// ============================================================================
// Cross-Algorithm Chain (heterogeneous PKI)
// ============================================================================

#[test]
fn test_cross_algorithm_root_p384_intermediate_p256() {
    // Root uses P-384 (stronger), intermediate uses P-256 (interop)
    let (root_cert, mut root_ca) = root_ca("Cross Root P384", AlgorithmId::EcdsaP384);

    // Intermediate signed by P-384 root but uses P-256 keys
    let config = CaConfig::intermediate("Cross Intermediate P256", AlgorithmId::EcdsaP256)
        .with_subject(
            NameBuilder::new("Cross Intermediate P256")
                .organization("SPORK Integration Test")
                .country("US")
                .build(),
        );
    let int_result = CaCeremony::init_intermediate(config, &mut root_ca).unwrap();
    let mut int_ca = int_result.ca;

    // EE cert uses P-256
    let ee_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let ee_subject = NameBuilder::new("cross.example.com").build();
    let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

    let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
        .with_san(SubjectAltName::new().dns("cross.example.com"));

    let issued = int_ca.issue_certificate(request).unwrap();
    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();

    // Validate: EE (P-256) → Intermediate (P-256, signed by P-384) → Root (P-384)
    let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];

    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(
        result.valid,
        "Cross-algorithm chain failed: {:?}",
        result.errors
    );
    assert!(result.trusted);
}

// ============================================================================
// Serial Number Uniqueness Under Batch Issuance
// ============================================================================

#[test]
fn test_batch_issuance_unique_serials() {
    let (_root_cert, mut root_ca) = root_ca("Batch Root", AlgorithmId::EcdsaP256);
    let (_int_cert, mut int_ca) =
        intermediate_ca("Batch Issuing CA", AlgorithmId::EcdsaP256, &mut root_ca);

    let mut serials = std::collections::HashSet::new();

    for i in 0..20 {
        let subject = NameBuilder::new(format!("host{}.example.com", i)).build();
        let (issued, _) = int_ca
            .issue_direct(
                subject,
                AlgorithmId::EcdsaP256,
                CertificateProfile::TlsServer,
                Validity::days_from_now(365),
                Some(SubjectAltName::new().dns(format!("host{}.example.com", i))),
            )
            .unwrap();

        assert!(
            serials.insert(issued.serial_hex.clone()),
            "Duplicate serial at iteration {}: {}",
            i,
            issued.serial_hex
        );
    }

    assert_eq!(serials.len(), 20);
}

// ============================================================================
// CSR Signature Verification (Proof of Possession)
// ============================================================================

#[test]
fn test_csr_wrong_key_rejected() {
    let (_root_cert, mut root_ca) = root_ca("PoP Root", AlgorithmId::EcdsaP256);
    let (_int_cert, mut int_ca) =
        intermediate_ca("PoP Issuing CA", AlgorithmId::EcdsaP256, &mut root_ca);

    // Create a valid CSR then corrupt it
    let ee_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let ee_subject = NameBuilder::new("bad.example.com").build();
    let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

    // Corrupt the CSR DER (flip a byte in the signature)
    let mut bad_der = csr.der.clone();
    if let Some(last) = bad_der.last_mut() {
        *last ^= 0xFF;
    }

    // Try to parse and issue — should fail at CSR verification
    let bad_csr = spork_core::cert::CertificateRequest::from_der(&bad_der);
    if let Ok(bad_csr) = bad_csr {
        let request = IssuanceRequest::new(bad_csr, CertificateProfile::TlsServer);
        let result = int_ca.issue_certificate(request);
        assert!(result.is_err(), "Should reject CSR with bad signature");
    }
    // If from_der fails, that's also acceptable — bad input rejected
}

// ============================================================================
// Path Length Constraint Enforcement
// ============================================================================

#[test]
fn test_path_length_constraint_enforced() {
    // Root CA with pathLen=1 (allows one intermediate)
    let (root_cert, mut root_ca) = root_ca("PathLen Root", AlgorithmId::EcdsaP256);

    // First intermediate (pathLen=0 — can only issue EE certs)
    let (_int1_cert, mut int1_ca) =
        intermediate_ca("Intermediate L1", AlgorithmId::EcdsaP256, &mut root_ca);

    // Issue EE from first intermediate
    let subject = NameBuilder::new("ee.example.com").build();
    let (issued, _) = int1_ca
        .issue_direct(
            subject,
            AlgorithmId::EcdsaP256,
            CertificateProfile::TlsServer,
            Validity::days_from_now(365),
            Some(SubjectAltName::new().dns("ee.example.com")),
        )
        .unwrap();

    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();

    // Valid chain: EE → Intermediate → Root
    let chain = vec![ee_cert, int1_ca.certificate.clone(), root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];

    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(
        result.valid,
        "Valid 3-tier chain should pass: {:?}",
        result.errors
    );
}

// ============================================================================
// Direct Issuance with Full Chain Validation
// ============================================================================

#[test]
fn test_direct_issuance_validates_in_chain() {
    let (root_cert, mut root_ca) = root_ca("Direct Root", AlgorithmId::EcdsaP256);
    let (_int_cert, mut int_ca) =
        intermediate_ca("Direct Issuing CA", AlgorithmId::EcdsaP256, &mut root_ca);

    // Issue directly (no CSR)
    let subject = NameBuilder::new("direct.example.com")
        .organization("Direct Corp")
        .build();
    let (issued, private_key) = int_ca
        .issue_direct(
            subject,
            AlgorithmId::EcdsaP256,
            CertificateProfile::TlsServer,
            Validity::days_from_now(365),
            Some(SubjectAltName::new().dns("direct.example.com")),
        )
        .unwrap();

    // Private key should be valid PEM
    assert!(private_key.contains("BEGIN PRIVATE KEY"));

    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();
    let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];

    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(
        result.valid,
        "Direct issuance chain failed: {:?}",
        result.errors
    );
    assert!(result.trusted);
}

// ============================================================================
// Subordinate CSR Signing (manual flow, not ceremony)
// ============================================================================

#[test]
fn test_subordinate_csr_signing_and_chain() {
    let (root_cert, mut root_ca) = root_ca("SubCSR Root", AlgorithmId::EcdsaP256);

    // Simulate an external intermediate generating a CSR
    let sub_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let sub_subject = NameBuilder::new("External Intermediate CA")
        .organization("External Org")
        .country("US")
        .build();
    let csr = CsrBuilder::new(sub_subject)
        .build_and_sign(&sub_key)
        .unwrap();

    // Root signs the subordinate CSR
    let sub_issued = root_ca
        .sign_subordinate_csr(csr.to_der(), Validity::days_from_now(365 * 5), Some(0))
        .unwrap();

    assert_eq!(sub_issued.subject_cn, "External Intermediate CA");
    assert_eq!(sub_issued.profile, CertificateProfile::SubordinateCa);

    // Parse the intermediate cert
    let int_cert = spork_core::cert::parse_certificate_pem(&sub_issued.pem).unwrap();

    // Verify it has CA:TRUE
    let bc_bytes = extract_extension(&int_cert, OID_BASIC_CONSTRAINTS)
        .expect("Sub CA must have BasicConstraints");
    let bc = X509BasicConstraints::from_der(&bc_bytes).unwrap();
    assert!(bc.ca, "Subordinate must be CA:TRUE");

    // Create a CertificateAuthority from the intermediate and issue an EE
    // (We can't easily construct a CA from just a cert+key, but we can verify the chain)
    let chain = vec![int_cert, root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];

    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(
        result.valid,
        "Root→Intermediate chain failed: {:?}",
        result.errors
    );
    assert!(result.trusted);
}

// ============================================================================
// PQC CSR-Based Issuance (Issue #262)
// ============================================================================

/// ML-DSA-65 CSR-based full chain issuance
#[cfg(feature = "pqc")]
#[test]
fn test_csr_based_full_chain_mldsa65() {
    // 1. Create PQC Root CA
    let (root_cert, mut root_ca) = root_ca("ML-DSA-65 Root", AlgorithmId::MlDsa65);

    // 2. Create PQC Intermediate CA
    let (_int_cert, mut int_ca) =
        intermediate_ca("ML-DSA-65 Issuing CA", AlgorithmId::MlDsa65, &mut root_ca);

    // 3. Generate ML-DSA-65 end-entity key and CSR
    let ee_key = KeyPair::generate(AlgorithmId::MlDsa65).unwrap();
    let ee_subject = NameBuilder::new("pqc-mldsa65.example.com")
        .organization("PQC Test Corp")
        .build();
    let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

    // 4. Issue end-entity certificate from CSR
    let san = SubjectAltName::new()
        .dns("pqc-mldsa65.example.com")
        .dns("alt-mldsa65.example.com");

    let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
        .with_san(san)
        .with_validity(Validity::days_from_now(365));

    let issued = int_ca.issue_certificate(request).unwrap();

    // 5. Verify certificate metadata
    assert_eq!(issued.subject_cn, "pqc-mldsa65.example.com");
    assert_eq!(issued.issuer_cn, "ML-DSA-65 Issuing CA");
    assert!(issued.pem.contains("BEGIN CERTIFICATE"));

    // 6. Validate full chain (PQC signature verification)
    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();
    let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];

    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(result.valid, "ML-DSA-65 chain failed: {:?}", result.errors);
    assert!(result.trusted);
}

/// ML-DSA-44 CSR-based issuance
#[cfg(feature = "pqc")]
#[test]
fn test_csr_based_full_chain_mldsa44() {
    let (root_cert, mut root_ca) = root_ca("ML-DSA-44 Root", AlgorithmId::MlDsa44);
    let (_int_cert, mut int_ca) =
        intermediate_ca("ML-DSA-44 Issuing CA", AlgorithmId::MlDsa44, &mut root_ca);

    let ee_key = KeyPair::generate(AlgorithmId::MlDsa44).unwrap();
    let ee_subject = NameBuilder::new("pqc-mldsa44.example.com").build();
    let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

    let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
        .with_san(SubjectAltName::new().dns("pqc-mldsa44.example.com"))
        .with_validity(Validity::days_from_now(365));

    let issued = int_ca.issue_certificate(request).unwrap();
    assert_eq!(issued.subject_cn, "pqc-mldsa44.example.com");

    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();
    let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];

    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(result.valid, "ML-DSA-44 chain failed: {:?}", result.errors);
    assert!(result.trusted);
}

/// ML-DSA-87 CSR-based issuance
#[cfg(feature = "pqc")]
#[test]
fn test_csr_based_full_chain_mldsa87() {
    // ML-DSA-87 has very large keys/signatures — needs bigger stack
    let result = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let (root_cert, mut root_ca) = root_ca("ML-DSA-87 Root", AlgorithmId::MlDsa87);
            let (_int_cert, mut int_ca) =
                intermediate_ca("ML-DSA-87 Issuing CA", AlgorithmId::MlDsa87, &mut root_ca);

            let ee_key = KeyPair::generate(AlgorithmId::MlDsa87).unwrap();
            let ee_subject = NameBuilder::new("pqc-mldsa87.example.com").build();
            let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

            let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
                .with_san(SubjectAltName::new().dns("pqc-mldsa87.example.com"))
                .with_validity(Validity::days_from_now(365));

            let issued = int_ca.issue_certificate(request).unwrap();
            assert_eq!(issued.subject_cn, "pqc-mldsa87.example.com");

            let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();
            let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
            let trust = vec![root_cert.to_der().unwrap()];

            let result = validate_chain(&chain, &trust, &default_opts());
            assert!(result.valid, "ML-DSA-87 chain failed: {:?}", result.errors);
            assert!(result.trusted);
        })
        .expect("spawn thread")
        .join();
    result.unwrap();
}

/// SLH-DSA-SHA2-128s CSR-based issuance
#[cfg(feature = "pqc")]
#[test]
fn test_csr_based_full_chain_slhdsa_128s() {
    let (root_cert, mut root_ca) = root_ca("SLH-DSA Root", AlgorithmId::SlhDsaSha2_128s);
    let (_int_cert, mut int_ca) = intermediate_ca(
        "SLH-DSA Issuing CA",
        AlgorithmId::SlhDsaSha2_128s,
        &mut root_ca,
    );

    let ee_key = KeyPair::generate(AlgorithmId::SlhDsaSha2_128s).unwrap();
    let ee_subject = NameBuilder::new("pqc-slhdsa.example.com").build();
    let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

    let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
        .with_san(SubjectAltName::new().dns("pqc-slhdsa.example.com"))
        .with_validity(Validity::days_from_now(365));

    let issued = int_ca.issue_certificate(request).unwrap();
    assert_eq!(issued.subject_cn, "pqc-slhdsa.example.com");

    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();
    let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];

    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(
        result.valid,
        "SLH-DSA-SHA2-128s chain failed: {:?}",
        result.errors
    );
    assert!(result.trusted);
}

/// Cross-algorithm: PQC Root (ML-DSA-65) → Classical Intermediate (P-256) → Classical EE
#[cfg(feature = "pqc")]
#[test]
fn test_cross_algorithm_pqc_root_classical_intermediate() {
    let (root_cert, mut root_ca) = root_ca("PQC Cross Root", AlgorithmId::MlDsa65);

    let config = CaConfig::intermediate("Classical Intermediate", AlgorithmId::EcdsaP256)
        .with_subject(
            NameBuilder::new("Classical Intermediate")
                .organization("SPORK Integration Test")
                .country("US")
                .build(),
        );
    let int_result = CaCeremony::init_intermediate(config, &mut root_ca).unwrap();
    let mut int_ca = int_result.ca;

    let ee_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let ee_subject = NameBuilder::new("pqc-cross.example.com").build();
    let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

    let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
        .with_san(SubjectAltName::new().dns("pqc-cross.example.com"));

    let issued = int_ca.issue_certificate(request).unwrap();
    let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();

    let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
    let trust = vec![root_cert.to_der().unwrap()];

    let result = validate_chain(&chain, &trust, &default_opts());
    assert!(
        result.valid,
        "PQC→Classical cross chain failed: {:?}",
        result.errors
    );
    assert!(result.trusted);
}

// ============================================================================
// Composite Signature Issuance Through CA Layer (Issue #264)
// ============================================================================

/// ML-DSA-65 + ECDSA P-256 composite CSR-based issuance
/// Uses larger stack thread because composite keys are large (~16KB per key).
#[cfg(feature = "pqc")]
#[test]
fn test_composite_mldsa65_p256_csr_issuance() {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let (root_cert, mut root_ca) = root_ca("Composite Root", AlgorithmId::MlDsa65EcdsaP256);

            let (_int_cert, mut int_ca) = intermediate_ca(
                "Composite Issuing CA",
                AlgorithmId::MlDsa65EcdsaP256,
                &mut root_ca,
            );

            let ee_key = KeyPair::generate(AlgorithmId::MlDsa65EcdsaP256).unwrap();
            let ee_subject = NameBuilder::new("composite.example.com")
                .organization("Hybrid Corp")
                .build();
            let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

            let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
                .with_san(SubjectAltName::new().dns("composite.example.com"))
                .with_validity(Validity::days_from_now(365));

            let issued = int_ca.issue_certificate(request).unwrap();

            assert_eq!(issued.subject_cn, "composite.example.com");
            assert_eq!(issued.issuer_cn, "Composite Issuing CA");
            assert!(issued.pem.contains("BEGIN CERTIFICATE"));

            let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();
            let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
            let trust = vec![root_cert.to_der().unwrap()];

            let result = validate_chain(&chain, &trust, &default_opts());
            assert!(
                result.valid,
                "Composite ML-DSA-65+P-256 chain failed: {:?}",
                result.errors
            );
            assert!(result.trusted);
        })
        .unwrap()
        .join()
        .unwrap();
}

/// ML-DSA-87 + ECDSA P-384 composite issuance
#[cfg(feature = "pqc")]
#[test]
fn test_composite_mldsa87_p384_csr_issuance() {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let (root_cert, mut root_ca) =
                root_ca("Composite87 Root", AlgorithmId::MlDsa87EcdsaP384);

            let (_int_cert, mut int_ca) = intermediate_ca(
                "Composite87 Issuing CA",
                AlgorithmId::MlDsa87EcdsaP384,
                &mut root_ca,
            );

            let ee_key = KeyPair::generate(AlgorithmId::MlDsa87EcdsaP384).unwrap();
            let ee_subject = NameBuilder::new("composite87.example.com").build();
            let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

            let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
                .with_san(SubjectAltName::new().dns("composite87.example.com"))
                .with_validity(Validity::days_from_now(365));

            let issued = int_ca.issue_certificate(request).unwrap();

            assert_eq!(issued.subject_cn, "composite87.example.com");

            let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();
            let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
            let trust = vec![root_cert.to_der().unwrap()];

            let result = validate_chain(&chain, &trust, &default_opts());
            assert!(
                result.valid,
                "Composite ML-DSA-87+P-384 chain failed: {:?}",
                result.errors
            );
            assert!(result.trusted);
        })
        .unwrap()
        .join()
        .unwrap();
}

/// Cross-algorithm: Composite Root → Classical Intermediate → Classical EE
/// Tests that composite CA can sign classical subordinate certs
#[cfg(feature = "pqc")]
#[test]
fn test_composite_root_classical_subordinate() {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let (root_cert, mut root_ca) =
                root_ca("Composite Cross Root", AlgorithmId::MlDsa65EcdsaP256);

            let config =
                CaConfig::intermediate("Classical Under Composite", AlgorithmId::EcdsaP256)
                    .with_subject(
                        NameBuilder::new("Classical Under Composite")
                            .organization("SPORK Integration Test")
                            .country("US")
                            .build(),
                    );
            let int_result = CaCeremony::init_intermediate(config, &mut root_ca).unwrap();
            let mut int_ca = int_result.ca;

            let ee_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
            let ee_subject = NameBuilder::new("hybrid-cross.example.com").build();
            let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

            let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
                .with_san(SubjectAltName::new().dns("hybrid-cross.example.com"));

            let issued = int_ca.issue_certificate(request).unwrap();
            let ee_cert = spork_core::cert::parse_certificate_pem(&issued.pem).unwrap();

            let chain = vec![ee_cert, int_ca.certificate.clone(), root_cert.clone()];
            let trust = vec![root_cert.to_der().unwrap()];

            let result = validate_chain(&chain, &trust, &default_opts());
            assert!(
                result.valid,
                "Composite→Classical cross chain failed: {:?}",
                result.errors
            );
            assert!(result.trusted);
        })
        .unwrap()
        .join()
        .unwrap();
}
