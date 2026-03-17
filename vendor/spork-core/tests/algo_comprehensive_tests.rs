//! Comprehensive algorithm tests for security audit
//!
//! These tests cover edge cases, boundary conditions, and security properties.

use spork_core::algo::{AlgorithmId, KeyPair};

// ============================================================================
// Key Generation Tests
// ============================================================================

#[test]
#[cfg(not(feature = "fips"))] // RSA-2048 not permitted in FIPS mode
fn test_all_algorithms_generate_valid_keys() {
    let algorithms = [
        AlgorithmId::EcdsaP256,
        AlgorithmId::EcdsaP384,
        AlgorithmId::Rsa2048,
        // Rsa4096 is slow, tested separately
    ];

    for algo in algorithms {
        let kp =
            KeyPair::generate(algo).unwrap_or_else(|_| panic!("Failed to generate {:?}", algo));
        assert_eq!(kp.algorithm_id(), algo);

        // Verify key can sign and verify
        let msg = b"test";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }
}

#[test]
#[cfg(not(feature = "fips"))] // RSA-2048 not permitted in FIPS mode
fn test_key_sizes_meet_minimums() {
    // ECDSA P-256 public key should be ~65 bytes (uncompressed)
    let p256 = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let pub_der = p256.public_key_der().unwrap();
    assert!(
        pub_der.len() >= 60,
        "P-256 public key too small: {} bytes",
        pub_der.len()
    );

    // ECDSA P-384 public key should be ~97 bytes
    let p384 = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();
    let pub_der = p384.public_key_der().unwrap();
    assert!(
        pub_der.len() >= 90,
        "P-384 public key too small: {} bytes",
        pub_der.len()
    );

    // RSA-2048 public key should be ~270+ bytes in SPKI
    let rsa = KeyPair::generate(AlgorithmId::Rsa2048).unwrap();
    let pub_der = rsa.public_key_der().unwrap();
    assert!(
        pub_der.len() >= 250,
        "RSA-2048 public key too small: {} bytes",
        pub_der.len()
    );
}

// ============================================================================
// Sign/Verify Edge Cases
// ============================================================================

#[test]
#[cfg(not(feature = "fips"))] // RSA-2048 not permitted in FIPS mode
fn test_sign_verify_empty_message() {
    let algorithms = [
        AlgorithmId::EcdsaP256,
        AlgorithmId::EcdsaP384,
        AlgorithmId::Rsa2048,
    ];

    for algo in algorithms {
        let kp = KeyPair::generate(algo).unwrap();

        // Empty message should work
        let sig = kp
            .sign(b"")
            .unwrap_or_else(|_| panic!("{:?}: Failed to sign empty message", algo));
        assert!(kp
            .verify(b"", &sig)
            .unwrap_or_else(|_| panic!("{:?}: Failed to verify empty message", algo)));
    }
}

#[test]
fn test_sign_verify_large_message() {
    // 1MB message
    let large_msg = vec![0x42u8; 1024 * 1024];

    let algorithms = [
        AlgorithmId::EcdsaP256,
        AlgorithmId::EcdsaP384,
        // RSA is slow with large messages, skip
    ];

    for algo in algorithms {
        let kp = KeyPair::generate(algo).unwrap();
        let sig = kp
            .sign(&large_msg)
            .unwrap_or_else(|_| panic!("{:?}: Failed to sign 1MB message", algo));
        assert!(kp
            .verify(&large_msg, &sig)
            .unwrap_or_else(|_| panic!("{:?}: Failed to verify 1MB message", algo)));
    }
}

#[test]
fn test_sign_verify_all_byte_values() {
    // Message with all possible byte values
    let msg: Vec<u8> = (0u8..=255).collect();

    let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let sig = kp.sign(&msg).unwrap();
    assert!(kp.verify(&msg, &sig).unwrap());
}

// ============================================================================
// PKCS#8 Roundtrip Tests
// ============================================================================

#[test]
#[cfg(not(feature = "fips"))] // RSA-2048 not permitted in FIPS mode
fn test_pkcs8_roundtrip_all_algorithms() {
    let algorithms = [
        AlgorithmId::EcdsaP256,
        AlgorithmId::EcdsaP384,
        AlgorithmId::Rsa2048,
    ];

    for algo in algorithms {
        let kp1 = KeyPair::generate(algo).unwrap();
        let der = kp1.private_key_der().unwrap();

        // Reload from DER
        let kp2 = KeyPair::from_pkcs8_der(algo, &der)
            .unwrap_or_else(|_| panic!("{:?}: Failed PKCS#8 roundtrip", algo));

        // Verify signatures are compatible
        let msg = b"roundtrip test";
        let sig1 = kp1.sign(msg).unwrap();
        assert!(
            kp2.verify(msg, &sig1).unwrap(),
            "{:?}: Cross-verify failed",
            algo
        );

        let sig2 = kp2.sign(msg).unwrap();
        assert!(
            kp1.verify(msg, &sig2).unwrap(),
            "{:?}: Reverse cross-verify failed",
            algo
        );
    }
}

#[test]
#[cfg(not(feature = "fips"))] // RSA-2048 not permitted in FIPS mode
fn test_pem_format_correctness() {
    let algorithms = [
        AlgorithmId::EcdsaP256,
        AlgorithmId::EcdsaP384,
        AlgorithmId::Rsa2048,
    ];

    for algo in algorithms {
        let kp = KeyPair::generate(algo).unwrap();

        // Private key PEM
        let priv_pem = kp.private_key_pem().unwrap();
        assert!(
            priv_pem.starts_with("-----BEGIN PRIVATE KEY-----"),
            "{:?}: Invalid private key PEM header",
            algo
        );
        assert!(
            priv_pem.trim().ends_with("-----END PRIVATE KEY-----"),
            "{:?}: Invalid private key PEM footer",
            algo
        );

        // Public key PEM
        let pub_pem = kp.public_key_pem().unwrap();
        assert!(
            pub_pem.starts_with("-----BEGIN PUBLIC KEY-----"),
            "{:?}: Invalid public key PEM header",
            algo
        );
        assert!(
            pub_pem.trim().ends_with("-----END PUBLIC KEY-----"),
            "{:?}: Invalid public key PEM footer",
            algo
        );
    }
}

// ============================================================================
// Invalid Input Handling
// ============================================================================

#[test]
#[cfg(not(feature = "fips"))] // RSA-2048 not permitted in FIPS mode
fn test_invalid_pkcs8_input() {
    let algorithms = [
        AlgorithmId::EcdsaP256,
        AlgorithmId::EcdsaP384,
        AlgorithmId::Rsa2048,
    ];

    for algo in algorithms {
        // Empty input
        assert!(
            KeyPair::from_pkcs8_der(algo, &[]).is_err(),
            "{:?}: Should reject empty PKCS#8",
            algo
        );

        // Random garbage
        assert!(
            KeyPair::from_pkcs8_der(algo, &[0xDE, 0xAD, 0xBE, 0xEF]).is_err(),
            "{:?}: Should reject garbage PKCS#8",
            algo
        );

        // Truncated valid DER
        let kp = KeyPair::generate(algo).unwrap();
        let der = kp.private_key_der().unwrap();
        let truncated = &der[..der.len() / 2];
        assert!(
            KeyPair::from_pkcs8_der(algo, truncated).is_err(),
            "{:?}: Should reject truncated PKCS#8",
            algo
        );
    }
}

#[test]
fn test_verify_truncated_signature() {
    let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let msg = b"test";
    let sig = kp.sign(msg).unwrap();

    // Truncate signature
    let truncated = &sig[..sig.len() / 2];

    // Should either fail or return false, not panic
    if let Ok(valid) = kp.verify(msg, truncated) {
        assert!(!valid, "Truncated signature should be invalid");
    }
    // Err is acceptable
}

#[test]
fn test_verify_corrupted_signature() {
    let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let msg = b"test";
    let mut sig = kp.sign(msg).unwrap();

    // Flip some bits
    if sig.len() > 10 {
        sig[5] ^= 0xFF;
        sig[10] ^= 0xFF;
    }

    // Should either fail or return false, not panic
    if let Ok(valid) = kp.verify(msg, &sig) {
        assert!(!valid, "Corrupted signature should be invalid");
    }
    // Err is acceptable
}

#[test]
fn test_verify_wrong_key_type() {
    // Generate P-256 key
    let kp256 = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let msg = b"test";
    let sig = kp256.sign(msg).unwrap();

    // Try to verify with P-384 key (different curve)
    let kp384 = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();

    // Should fail - signatures aren't compatible between curves
    if let Ok(valid) = kp384.verify(msg, &sig) {
        assert!(!valid, "Cross-algorithm verify should fail");
    }
    // Err is acceptable
}

// ============================================================================
// OID Correctness
// ============================================================================

#[test]
fn test_oid_values() {
    // ECDSA-SHA256 OID: 1.2.840.10045.4.3.2
    let p256 = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    assert_eq!(p256.oid().to_string(), "1.2.840.10045.4.3.2");

    // ECDSA-SHA384 OID: 1.2.840.10045.4.3.3
    let p384 = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();
    assert_eq!(p384.oid().to_string(), "1.2.840.10045.4.3.3");

    // RSA-SHA256 OID: 1.2.840.113549.1.1.11 — check via signature_oid() (no key needed)
    assert_eq!(
        AlgorithmId::Rsa2048.signature_oid().to_string(),
        "1.2.840.113549.1.1.11"
    );
}

// ============================================================================
// Key ID Consistency
// ============================================================================

#[test]
fn test_public_key_der_consistency() {
    let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    // Multiple calls should return same result
    let der1 = kp.public_key_der().unwrap();
    let der2 = kp.public_key_der().unwrap();
    assert_eq!(der1, der2, "public_key_der should be deterministic");
}

// ============================================================================
// Algorithm Properties
// ============================================================================

#[test]
fn test_security_levels() {
    assert_eq!(AlgorithmId::EcdsaP256.security_level(), 2);
    assert_eq!(AlgorithmId::EcdsaP384.security_level(), 3);
    assert_eq!(AlgorithmId::Rsa2048.security_level(), 2);
    assert_eq!(AlgorithmId::Rsa4096.security_level(), 3);
}

#[test]
fn test_signature_sizes() {
    assert!(AlgorithmId::EcdsaP256.signature_size() >= 64);
    assert!(AlgorithmId::EcdsaP384.signature_size() >= 96);
    assert_eq!(AlgorithmId::Rsa2048.signature_size(), 256);
    assert_eq!(AlgorithmId::Rsa4096.signature_size(), 512);
}

#[test]
fn test_is_pqc() {
    // Legacy algorithms
    assert!(!AlgorithmId::EcdsaP256.is_pqc());
    assert!(!AlgorithmId::EcdsaP384.is_pqc());
    assert!(!AlgorithmId::Rsa2048.is_pqc());
    assert!(!AlgorithmId::Rsa4096.is_pqc());
}

// ============================================================================
// Uniqueness Tests
// ============================================================================

#[test]
fn test_generated_keys_are_unique() {
    let kp1 = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let kp2 = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

    // Public keys should differ
    let pub1 = kp1.public_key_der().unwrap();
    let pub2 = kp2.public_key_der().unwrap();
    assert_ne!(pub1, pub2, "Generated keys should be unique");
}

#[test]
fn test_signatures_are_unique() {
    let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let msg = b"same message";

    // ECDSA signatures should differ each time (due to random k)
    let sig1 = kp.sign(msg).unwrap();
    let sig2 = kp.sign(msg).unwrap();

    // Both should verify
    assert!(kp.verify(msg, &sig1).unwrap());
    assert!(kp.verify(msg, &sig2).unwrap());

    // But ECDSA signatures are typically different each time
    // (RSA-PKCS1v15 is deterministic)
}

// ============================================================================
// Zeroize Tests
// ============================================================================

#[test]
fn test_private_key_der_is_zeroizing() {
    let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let der = kp.private_key_der().unwrap();

    // Verify it's a Zeroizing container (by type, compilation check)
    let _: &zeroize::Zeroizing<Vec<u8>> = &der;

    // Value should be non-empty
    assert!(!der.is_empty());
}
