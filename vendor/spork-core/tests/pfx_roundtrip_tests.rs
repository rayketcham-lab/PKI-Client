//! PFX/PKCS#12 import→sign→export round-trip integration tests
//!
//! Verifies that key material survives serialization round-trips without
//! corruption. Tests cover:
//!
//! - PKCS#8 DER export → re-import → sign with imported key
//! - PKCS#8 PEM export → re-import → sign with re-imported key
//! - Multiple algorithms: ECDSA P-256, ECDSA P-384, RSA-4096
//! - Certificate chain building and validation: Root→Intermediate→Leaf
//! - Key/cert association: cert's public key matches key pair's public key
//! - SoftwareKeyStore export/import round-trip via `export_private_key()`
//! - Cross-algorithm chain verification (mixed signing algorithms)
//!
//! These tests use `spork-core` APIs directly — no HTTP, no file I/O.

use der::{Decode, Encode};
use x509_cert::Certificate;

use spork_core::algo::{AlgorithmId, KeyPair};
use spork_core::cert::{
    extensions::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsageFlags},
    CertificateBuilder, DistinguishedName, NameBuilder, Validity,
};
use spork_core::hsm::{KeySpec, KeyStore, SoftwareKeyStore};
use spork_core::{validate_chain, ChainValidationOptions};

// ============================================================================
// Helpers
// ============================================================================

/// Build a minimal subject DN for tests.
fn subject(cn: &str) -> DistinguishedName {
    NameBuilder::new(cn).build()
}

/// Build a subject DN with org and country (for end-entity / TLS certs).
fn subject_with_org(cn: &str, org: &str) -> DistinguishedName {
    NameBuilder::new(cn).organization(org).country("US").build()
}

/// One-year validity, backdated 5 minutes as normal.
fn one_year() -> Validity {
    Validity::years_from_now(1)
}

/// Short validity: 1 day. Avoids wall-clock issues in fast tests.
fn one_day() -> Validity {
    Validity::days_from_now(1)
}

/// Key-usage flags for a CA certificate.
fn ca_key_usage() -> KeyUsage {
    KeyUsage::new(KeyUsageFlags::new(
        KeyUsageFlags::KEY_CERT_SIGN | KeyUsageFlags::CRL_SIGN,
    ))
}

/// Key-usage flags for a digital-signature end-entity cert.
fn ee_key_usage() -> KeyUsage {
    KeyUsage::new(KeyUsageFlags::new(KeyUsageFlags::DIGITAL_SIGNATURE))
}

/// Build a self-signed root CA certificate for the given key pair.
///
/// Disables AKI on self-signed roots so the builder does not
/// attempt to embed an authority key identifier that points to itself —
/// all standards-compliant validators accept a root without AKI.
fn build_self_signed_root(key: &KeyPair, cn: &str) -> Certificate {
    CertificateBuilder::new(
        subject(cn),
        key.public_key_der().unwrap(),
        key.algorithm_id(),
    )
    .validity(one_year())
    .basic_constraints(BasicConstraints::ca())
    .key_usage(ca_key_usage())
    .include_authority_key_identifier(false) // self-signed: no AKI needed
    .build_and_sign(key)
    .unwrap()
}

/// Build an intermediate CA certificate signed by `issuer_key`.
/// The intermediate's public key comes from `subject_key`.
fn build_intermediate(
    subject_key: &KeyPair,
    issuer_key: &KeyPair,
    subject_cn: &str,
    issuer_cn: &str,
) -> Certificate {
    CertificateBuilder::new(
        subject(subject_cn),
        subject_key.public_key_der().unwrap(),
        subject_key.algorithm_id(),
    )
    .validity(one_year())
    .issuer(subject(issuer_cn))
    .basic_constraints(BasicConstraints::ca_with_path_len(0))
    .key_usage(ca_key_usage())
    .include_authority_key_identifier(false)
    .build_and_sign(issuer_key)
    .unwrap()
}

/// Build an end-entity TLS leaf certificate signed by `issuer_key`.
fn build_leaf(
    subject_key: &KeyPair,
    issuer_key: &KeyPair,
    subject_cn: &str,
    issuer_cn: &str,
) -> Certificate {
    CertificateBuilder::new(
        subject_with_org(subject_cn, "Test Corp"),
        subject_key.public_key_der().unwrap(),
        subject_key.algorithm_id(),
    )
    .validity(one_day())
    .issuer(subject(issuer_cn))
    .basic_constraints(BasicConstraints::end_entity())
    .key_usage(ee_key_usage())
    .extended_key_usage(ExtendedKeyUsage::tls_server())
    .include_authority_key_identifier(false)
    .build_and_sign(issuer_key)
    .unwrap()
}

/// Serialize a `Certificate` to DER bytes.
fn cert_to_der(cert: &Certificate) -> Vec<u8> {
    cert.to_der().expect("Certificate must DER-encode cleanly")
}

/// Deserialize DER bytes back to a `Certificate`.
fn cert_from_der(der: &[u8]) -> Certificate {
    Certificate::from_der(der).expect("DER bytes must parse as Certificate")
}

// ============================================================================
// Test 1: ECDSA P-256 PKCS#8 DER round-trip
// ============================================================================

/// Generate ECDSA P-256 key → export as PKCS#8 DER → import into a new
/// KeyPair → sign data with the imported key → verify with the original
/// public key.
#[test]
fn test_pkcs8_der_roundtrip_ecdsa_p256() {
    let original = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let original_pub_der = original.public_key_der().unwrap();

    // Export private key as PKCS#8 DER
    let pkcs8_der = original.private_key_der().unwrap();
    assert!(!pkcs8_der.is_empty(), "PKCS#8 DER must not be empty");

    // Import into a new KeyPair
    let imported = KeyPair::from_pkcs8_der(AlgorithmId::EcdsaP256, &pkcs8_der).unwrap();
    assert_eq!(imported.algorithm_id(), AlgorithmId::EcdsaP256);

    // Verify that the imported key produces the same public key
    let imported_pub_der = imported.public_key_der().unwrap();
    assert_eq!(
        original_pub_der, imported_pub_der,
        "Public key must be identical after import"
    );

    // Sign with imported key, verify with original public key
    let message = b"ECDSA P-256 round-trip test message";
    let signature = imported.sign(message).unwrap();
    assert!(
        original.verify(message, &signature).unwrap(),
        "Signature from imported key must verify against original public key"
    );

    // Cross-check: original key's signature verifies against imported key
    let sig2 = original.sign(message).unwrap();
    assert!(
        imported.verify(message, &sig2).unwrap(),
        "Signature from original key must verify against imported key"
    );
}

// ============================================================================
// Test 2: RSA-4096 PKCS#8 DER round-trip
// ============================================================================

/// RSA-4096 key generation is intentionally slow (~1–2 s) but RSA round-trips
/// are required for PKCS#12 use-cases in the enterprise (Windows PKI uses RSA
/// heavily). This test is intentionally not marked `#[ignore]` so CI catches
/// regressions — adjust if CI wall-time becomes a concern.
#[test]
fn test_pkcs8_der_roundtrip_rsa4096() {
    let original = KeyPair::generate(AlgorithmId::Rsa4096).unwrap();
    let original_pub_der = original.public_key_der().unwrap();

    let pkcs8_der = original.private_key_der().unwrap();
    assert!(!pkcs8_der.is_empty(), "RSA PKCS#8 DER must not be empty");
    // RSA-4096 PKCS#8 DER is typically 2370–2400 bytes; guard against truncation
    assert!(
        pkcs8_der.len() >= 2300,
        "RSA-4096 PKCS#8 DER unexpectedly small: {} bytes",
        pkcs8_der.len()
    );

    let imported = KeyPair::from_pkcs8_der(AlgorithmId::Rsa4096, &pkcs8_der).unwrap();
    assert_eq!(imported.algorithm_id(), AlgorithmId::Rsa4096);

    let imported_pub_der = imported.public_key_der().unwrap();
    assert_eq!(
        original_pub_der, imported_pub_der,
        "RSA-4096 public key must be identical after import"
    );

    let message = b"RSA-4096 round-trip test message";
    let signature = imported.sign(message).unwrap();
    assert!(
        original.verify(message, &signature).unwrap(),
        "RSA-4096 signature from imported key must verify against original"
    );
}

// ============================================================================
// Test 3: ECDSA P-384 PKCS#8 DER round-trip
// ============================================================================

#[test]
fn test_pkcs8_der_roundtrip_ecdsa_p384() {
    let original = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();
    let original_pub_der = original.public_key_der().unwrap();

    let pkcs8_der = original.private_key_der().unwrap();
    assert!(!pkcs8_der.is_empty(), "P-384 PKCS#8 DER must not be empty");

    let imported = KeyPair::from_pkcs8_der(AlgorithmId::EcdsaP384, &pkcs8_der).unwrap();
    assert_eq!(imported.algorithm_id(), AlgorithmId::EcdsaP384);

    let imported_pub_der = imported.public_key_der().unwrap();
    assert_eq!(
        original_pub_der, imported_pub_der,
        "P-384 public key must be identical after import"
    );

    let message = b"ECDSA P-384 round-trip test message";
    let signature = imported.sign(message).unwrap();
    assert!(
        original.verify(message, &signature).unwrap(),
        "P-384 signature from imported key must verify against original"
    );
}

// ============================================================================
// Test 4: Certificate chain building and validation Root→Intermediate→Leaf
// ============================================================================

/// Build a three-level PKI hierarchy entirely in memory, serialize each
/// certificate to DER, parse them back, and validate the chain using
/// `validate_chain`. Proves the builder produces a structurally sound chain
/// that the verifier accepts.
#[test]
fn test_chain_building_root_intermediate_leaf() {
    // Root CA (ECDSA P-256, self-signed)
    let root_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let root_cert = build_self_signed_root(&root_key, "Test Root CA");
    let root_der = cert_to_der(&root_cert);

    // Intermediate CA (P-256, signed by root)
    let int_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let int_cert = build_intermediate(&int_key, &root_key, "Test Issuing CA", "Test Root CA");
    let int_der = cert_to_der(&int_cert);

    // Leaf / end-entity (P-256, signed by intermediate)
    let leaf_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let leaf_cert = build_leaf(&leaf_key, &int_key, "test.example.com", "Test Issuing CA");
    let leaf_der = cert_to_der(&leaf_cert);

    // Parse all three back from DER
    let root_parsed = cert_from_der(&root_der);
    let int_parsed = cert_from_der(&int_der);
    let leaf_parsed = cert_from_der(&leaf_der);

    // Chain order: leaf, intermediate, root (end-entity first)
    let chain = vec![leaf_parsed, int_parsed, root_parsed.clone()];
    let trust_anchors = vec![root_der.clone()];

    let opts = ChainValidationOptions {
        check_signatures: true,
        check_validity: true,
        check_constraints: true,
        at_time: None,
        check_policies: false,
        ..Default::default()
    };

    let result = validate_chain(&chain, &trust_anchors, &opts);

    assert!(
        result.valid,
        "Three-level chain must validate. Errors: {:?}",
        result.errors
    );
    assert!(
        result.trusted,
        "Root must be recognised as a trust anchor. Warnings: {:?}",
        result.warnings
    );
    assert!(
        result.errors.is_empty(),
        "No validation errors expected, got: {:?}",
        result.errors
    );
}

// ============================================================================
// Test 5: Key/cert association — cert public key matches key pair public key
// ============================================================================

/// Generate a key pair, build a self-signed certificate, parse the cert back
/// from DER, and confirm that the SPKI bytes in the certificate match those
/// exported from the KeyPair directly. This catches any encoding discrepancy
/// between the key-pair exporter and the cert builder's SPKI encoder.
#[test]
fn test_cert_public_key_matches_keypair_p256() {
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let pub_der_from_keypair = key.public_key_der().unwrap();

    let cert = build_self_signed_root(&key, "P-256 Association Test");
    let cert_der = cert_to_der(&cert);
    let cert_parsed = cert_from_der(&cert_der);

    // Extract SPKI from the parsed certificate and encode to DER
    let cert_spki_der = cert_parsed
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap();

    assert_eq!(
        pub_der_from_keypair, cert_spki_der,
        "SPKI in certificate must exactly match public key exported from KeyPair"
    );
}

#[test]
fn test_cert_public_key_matches_keypair_p384() {
    let key = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();
    let pub_der_from_keypair = key.public_key_der().unwrap();

    let cert = build_self_signed_root(&key, "P-384 Association Test");
    let cert_der = cert_to_der(&cert);
    let cert_parsed = cert_from_der(&cert_der);

    let cert_spki_der = cert_parsed
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap();

    assert_eq!(
        pub_der_from_keypair, cert_spki_der,
        "P-384 SPKI in certificate must match key pair public key"
    );
}

// ============================================================================
// Test 6: SoftwareKeyStore export/import round-trip
// ============================================================================

/// Prove that `SoftwareKeyStore::new_exportable()` correctly exposes key
/// material via `export_private_key()` and that the exported DER can be
/// imported back into a fresh `KeyPair` that signs verifiably.
#[test]
fn test_software_keystore_export_import_ecdsa_p256() {
    let store = SoftwareKeyStore::new_exportable();

    // Generate key inside the store
    let key_id = store.generate_key("test-p256", KeySpec::EcdsaP256).unwrap();

    // Export public key for later comparison
    let pub_der_from_store = store.public_key_der(&key_id).unwrap();

    // Sign data through the store
    let message = b"KeyStore export round-trip message";
    let sig_from_store = store.sign(&key_id, message).unwrap();

    // Export the private key DER
    let exported_der = store.export_private_key(&key_id).unwrap();
    assert!(
        !exported_der.is_empty(),
        "Exported PKCS#8 DER must not be empty"
    );

    // Import into a standalone KeyPair
    let imported = KeyPair::from_pkcs8_der(AlgorithmId::EcdsaP256, &exported_der).unwrap();
    assert_eq!(imported.algorithm_id(), AlgorithmId::EcdsaP256);

    // Public key must match what the store reported
    let imported_pub_der = imported.public_key_der().unwrap();
    assert_eq!(
        pub_der_from_store, imported_pub_der,
        "Exported public key must match store's public key"
    );

    // Verify the signature produced by the store with the imported key
    assert!(
        imported.verify(message, &sig_from_store).unwrap(),
        "Store signature must verify against imported KeyPair"
    );

    // Sign with the imported key and verify via the store
    let sig_from_import = imported.sign(message).unwrap();
    assert!(
        store.verify(&key_id, message, &sig_from_import).unwrap(),
        "Imported key signature must verify via the store"
    );
}

#[test]
fn test_software_keystore_export_import_ecdsa_p384() {
    let store = SoftwareKeyStore::new_exportable();
    let key_id = store.generate_key("test-p384", KeySpec::EcdsaP384).unwrap();

    let pub_der_from_store = store.public_key_der(&key_id).unwrap();
    let message = b"P-384 KeyStore export round-trip";
    let sig_from_store = store.sign(&key_id, message).unwrap();

    let exported_der = store.export_private_key(&key_id).unwrap();
    let imported = KeyPair::from_pkcs8_der(AlgorithmId::EcdsaP384, &exported_der).unwrap();

    assert_eq!(imported.public_key_der().unwrap(), pub_der_from_store);
    assert!(
        imported.verify(message, &sig_from_store).unwrap(),
        "P-384 store signature must verify against imported key"
    );
}

/// Verify that a non-exportable `SoftwareKeyStore` correctly refuses export.
#[test]
fn test_software_keystore_non_exportable_refuses_export() {
    let store = SoftwareKeyStore::new(); // not exportable
    let key_id = store
        .generate_key("restricted", KeySpec::EcdsaP256)
        .unwrap();

    let result = store.export_private_key(&key_id);
    assert!(
        result.is_err(),
        "Non-exportable store must return an error on export"
    );
}

// ============================================================================
// Test 7: PEM round-trip
// ============================================================================

/// Export private key as PKCS#8 PEM → parse PEM back → verify signing still
/// works. The PEM label must be `PRIVATE KEY` per RFC 5958.
#[test]
fn test_pem_roundtrip_ecdsa_p256() {
    let original = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let pub_der_original = original.public_key_der().unwrap();

    // Export as PEM
    let pem_string = original.private_key_pem().unwrap();
    let pem_str: &str = &pem_string;
    assert!(
        pem_str.contains("-----BEGIN PRIVATE KEY-----"),
        "PEM must start with PKCS#8 header, got: {}",
        &pem_str[..pem_str.len().min(80)]
    );
    assert!(
        pem_str.contains("-----END PRIVATE KEY-----"),
        "PEM must end with PKCS#8 footer"
    );

    // Import from PEM
    let imported = KeyPair::from_pem(pem_str, AlgorithmId::EcdsaP256).unwrap();
    assert_eq!(imported.algorithm_id(), AlgorithmId::EcdsaP256);

    // Public key must match
    let pub_der_imported = imported.public_key_der().unwrap();
    assert_eq!(
        pub_der_original, pub_der_imported,
        "Public key must be identical after PEM round-trip"
    );

    // Signing must work
    let message = b"PEM round-trip test message";
    let sig = imported.sign(message).unwrap();
    assert!(
        original.verify(message, &sig).unwrap(),
        "PEM-imported key must produce valid signatures"
    );
}

#[test]
fn test_pem_roundtrip_ecdsa_p384() {
    let original = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();
    let pub_der_original = original.public_key_der().unwrap();

    let pem_string = original.private_key_pem().unwrap();
    let pem_str: &str = &pem_string;

    let imported = KeyPair::from_pem(pem_str, AlgorithmId::EcdsaP384).unwrap();
    assert_eq!(imported.public_key_der().unwrap(), pub_der_original);

    let message = b"P-384 PEM round-trip";
    let sig = imported.sign(message).unwrap();
    assert!(
        original.verify(message, &sig).unwrap(),
        "P-384 PEM-imported key must produce valid signatures"
    );
}

// ============================================================================
// Test 8: Cross-algorithm chain — Root uses P-384, Intermediate uses P-256
// ============================================================================

/// Build a chain where the root and intermediate use different classical
/// algorithms. Validates that `validate_chain` handles mixed-algorithm
/// hierarchies correctly — the verifier must pick the right verification
/// routine for each certificate based on its `signatureAlgorithm` OID.
#[test]
fn test_cross_algorithm_chain_p384_root_p256_intermediate() {
    // Root: P-384
    let root_key = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();
    let root_cert = build_self_signed_root(&root_key, "Cross-Algo Root CA");
    let root_der = cert_to_der(&root_cert);

    // Intermediate: P-256, signed by P-384 root
    let int_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let int_cert = build_intermediate(
        &int_key,
        &root_key,
        "Cross-Algo Issuing CA",
        "Cross-Algo Root CA",
    );
    let int_der = cert_to_der(&int_cert);

    // Leaf: P-256, signed by P-256 intermediate
    let leaf_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let leaf_cert = build_leaf(
        &leaf_key,
        &int_key,
        "crossalgo.example.com",
        "Cross-Algo Issuing CA",
    );
    let leaf_der = cert_to_der(&leaf_cert);

    // Parse all three
    let chain = vec![
        cert_from_der(&leaf_der),
        cert_from_der(&int_der),
        cert_from_der(&root_der),
    ];
    let trust_anchors = vec![root_der.clone()];

    let opts = ChainValidationOptions {
        check_signatures: true,
        check_validity: true,
        check_constraints: true,
        ..Default::default()
    };

    let result = validate_chain(&chain, &trust_anchors, &opts);
    assert!(
        result.valid,
        "Mixed P-384/P-256 chain must validate. Errors: {:?}",
        result.errors
    );
    assert!(
        result.trusted,
        "Root must be trusted. Warnings: {:?}",
        result.warnings
    );
}

// ============================================================================
// Test 9: Multiple PKCS#8 DER round-trips — key material is stable
// ============================================================================

/// Export the same key to PKCS#8 DER twice and confirm both exports are
/// identical. Then import from each export and verify all three keys
/// (original, import-1, import-2) produce identical public keys and
/// cross-verify each other's signatures. This guards against any
/// non-determinism in the PKCS#8 serialiser.
#[test]
fn test_pkcs8_der_double_export_stability() {
    let original = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let der_a = original.private_key_der().unwrap();
    let der_b = original.private_key_der().unwrap();

    // Two exports of the same key must be byte-identical
    assert_eq!(
        der_a.as_slice(),
        der_b.as_slice(),
        "PKCS#8 DER export must be deterministic"
    );

    // Both imports must produce the same public key
    let import_a = KeyPair::from_pkcs8_der(AlgorithmId::EcdsaP256, &der_a).unwrap();
    let import_b = KeyPair::from_pkcs8_der(AlgorithmId::EcdsaP256, &der_b).unwrap();

    assert_eq!(
        original.public_key_der().unwrap(),
        import_a.public_key_der().unwrap()
    );
    assert_eq!(
        import_a.public_key_der().unwrap(),
        import_b.public_key_der().unwrap()
    );

    // Sign with one, verify with another
    let message = b"stability test";
    let sig = original.sign(message).unwrap();
    assert!(import_a.verify(message, &sig).unwrap());
    assert!(import_b.verify(message, &sig).unwrap());
}

// ============================================================================
// Test 10: DER certificate round-trip — no bytes lost in encode/decode
// ============================================================================

/// Encode a certificate to DER, decode it, encode again, and compare. If
/// both DER outputs are byte-identical the serialiser is idempotent — a
/// necessary property for any correct ASN.1 implementation.
#[test]
fn test_cert_der_encode_decode_idempotent() {
    let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let cert = build_self_signed_root(&key, "Idempotent DER Test");

    let der1 = cert_to_der(&cert);
    let parsed = cert_from_der(&der1);
    let der2 = cert_to_der(&parsed);

    assert_eq!(
        der1, der2,
        "Certificate DER encode→decode→encode must be idempotent"
    );
    assert!(!der1.is_empty(), "Serialised certificate must not be empty");
}

// ============================================================================
// Test 11: SoftwareKeyStore import of externally-generated PKCS#8
// ============================================================================

/// Generate a key pair directly with `KeyPair::generate`, export to PKCS#8
/// DER, then import into a `SoftwareKeyStore` via `import_key`. Confirms the
/// import path works end-to-end and that the stored key can sign data that
/// verifies against the original public key.
#[test]
fn test_keystore_import_external_pkcs8_p256() {
    // Generate key externally (simulating an external key source)
    let external_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let external_pub_der = external_key.public_key_der().unwrap();
    let pkcs8_der = external_key.private_key_der().unwrap();

    // Import into an exportable store
    let store = SoftwareKeyStore::new_exportable();
    let key_id = store.import_key("imported-external", &pkcs8_der).unwrap();

    // Public key from store must match the original
    let stored_pub_der = store.public_key_der(&key_id).unwrap();
    assert_eq!(
        external_pub_der, stored_pub_der,
        "Imported key public key must match original"
    );

    // Sign via the store, verify with original key
    let message = b"external import test";
    let sig = store.sign(&key_id, message).unwrap();
    assert!(
        external_key.verify(message, &sig).unwrap(),
        "Store-signed message must verify with the original key"
    );
}

#[test]
fn test_keystore_import_external_pkcs8_p384() {
    let external_key = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();
    let external_pub_der = external_key.public_key_der().unwrap();
    let pkcs8_der = external_key.private_key_der().unwrap();

    let store = SoftwareKeyStore::new_exportable();
    let key_id = store.import_key("imported-p384", &pkcs8_der).unwrap();

    let stored_pub_der = store.public_key_der(&key_id).unwrap();
    assert_eq!(external_pub_der, stored_pub_der);

    let message = b"P-384 external import test";
    let sig = store.sign(&key_id, message).unwrap();
    assert!(
        external_key.verify(message, &sig).unwrap(),
        "P-384 store-signed message must verify with original key"
    );
}

// ============================================================================
// Test 12: Key-cert-sign pipeline — sign a cert, re-import issuer key,
//          re-sign, confirm both DERs are structurally valid certs
// ============================================================================

/// Simulate the full "export issuer key → migrate to new process → re-sign
/// subordinate certificates" workflow. Generates a root key, exports it, then
/// reconstitutes the key pair and uses the reconstituted key to issue an
/// intermediate certificate. Validates the result.
#[test]
fn test_reconstituted_key_signs_valid_cert() {
    let root_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let root_cert = build_self_signed_root(&root_key, "Reconstitution Root");
    let root_der = cert_to_der(&root_cert);

    // Export root key material and reconstitute it
    let pkcs8_der = root_key.private_key_der().unwrap();
    let reconstituted_root_key =
        KeyPair::from_pkcs8_der(AlgorithmId::EcdsaP256, &pkcs8_der).unwrap();

    // Issue intermediate using the *reconstituted* key
    let int_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let int_cert = build_intermediate(
        &int_key,
        &reconstituted_root_key,
        "Reconstitution Issuing CA",
        "Reconstitution Root",
    );
    let int_der = cert_to_der(&int_cert);

    // Chain must validate
    let chain = vec![cert_from_der(&int_der), cert_from_der(&root_der)];
    let trust_anchors = vec![root_der];

    let opts = ChainValidationOptions {
        check_signatures: true,
        check_validity: true,
        check_constraints: true,
        ..Default::default()
    };

    let result = validate_chain(&chain, &trust_anchors, &opts);
    assert!(
        result.valid,
        "Chain signed with reconstituted key must be valid. Errors: {:?}",
        result.errors
    );
}

// ============================================================================
// Test 13: Ed25519 PKCS#8 DER round-trip
// ============================================================================

/// Ed25519 is not FIPS-approved (not in FIPS_APPROVED_ALGORITHMS)
#[cfg(not(feature = "fips"))]
#[test]
fn test_pkcs8_der_roundtrip_ed25519() {
    let original = KeyPair::generate(AlgorithmId::Ed25519).unwrap();
    let pub_der_original = original.public_key_der().unwrap();

    let pkcs8_der = original.private_key_der().unwrap();
    assert!(
        !pkcs8_der.is_empty(),
        "Ed25519 PKCS#8 DER must not be empty"
    );

    let imported = KeyPair::from_pkcs8_der(AlgorithmId::Ed25519, &pkcs8_der).unwrap();
    assert_eq!(imported.algorithm_id(), AlgorithmId::Ed25519);

    let pub_der_imported = imported.public_key_der().unwrap();
    assert_eq!(
        pub_der_original, pub_der_imported,
        "Ed25519 public key must survive PKCS#8 round-trip"
    );

    let message = b"Ed25519 DER round-trip test";
    let sig = imported.sign(message).unwrap();
    assert!(
        original.verify(message, &sig).unwrap(),
        "Ed25519 signature from imported key must verify against original"
    );
}

// ============================================================================
// Test 14: Corrupt PKCS#8 DER is rejected cleanly
// ============================================================================

/// Ensures that importing garbage bytes as PKCS#8 produces a clear error
/// rather than a panic, silent failure, or undefined behaviour.
#[test]
fn test_corrupt_pkcs8_der_rejected() {
    let garbage = b"\x00\x01\x02\x03\xFF\xFE\xFD garbage data that is not a valid PKCS#8";
    let result = KeyPair::from_pkcs8_der(AlgorithmId::EcdsaP256, garbage);
    assert!(
        result.is_err(),
        "Corrupt PKCS#8 DER must be rejected with an error, not accepted"
    );
}

/// Passing an empty slice must also be rejected cleanly.
#[test]
fn test_empty_pkcs8_der_rejected() {
    let result = KeyPair::from_pkcs8_der(AlgorithmId::EcdsaP256, b"");
    assert!(
        result.is_err(),
        "Empty PKCS#8 DER must be rejected, not silently accepted"
    );
}

// ============================================================================
// Test 15: Signature non-malleability — wrong key must not verify
// ============================================================================

/// Sign with key A, attempt to verify with key B. Must return false (or a
/// verifiable error), not true. Guards against any regression in the verify
/// path that might accept arbitrary signatures.
#[test]
fn test_signature_rejects_wrong_key() {
    let key_a = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let key_b = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let message = b"wrong key verification test";
    let sig_a = key_a.sign(message).unwrap();

    // key_b must reject a signature produced by key_a
    let result = key_b.verify(message, &sig_a).unwrap();
    assert!(
        !result,
        "Signature from key A must NOT verify against key B"
    );
}

/// Sign with one key, import it, sign the same message with the *original*
/// key but attempt to verify with an unrelated second key. All negative cases.
#[test]
fn test_signature_non_malleability_after_import() {
    let signer = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let unrelated = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    let pkcs8_der = signer.private_key_der().unwrap();
    let reimported = KeyPair::from_pkcs8_der(AlgorithmId::EcdsaP256, &pkcs8_der).unwrap();

    let message = b"non-malleability test";

    // Original signer, verify with unrelated key — must fail
    let sig = signer.sign(message).unwrap();
    assert!(
        !unrelated.verify(message, &sig).unwrap(),
        "Unrelated key must not verify signer's signature"
    );

    // Reimported key, verify with unrelated — must also fail
    let sig2 = reimported.sign(message).unwrap();
    assert!(
        !unrelated.verify(message, &sig2).unwrap(),
        "Unrelated key must not verify reimported key's signature"
    );

    // Reimported key must verify its own signature
    assert!(
        reimported.verify(message, &sig2).unwrap(),
        "Reimported key must verify its own signature"
    );
}
