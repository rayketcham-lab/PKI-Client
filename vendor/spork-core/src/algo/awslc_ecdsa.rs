//! ECDSA implementation using aws-lc-rs (FIPS 140-3 certified backend)
//!
//! This module provides ECDSA P-256 and P-384 signing/verification using
//! the AWS-LC cryptographic library, which has FIPS 140-3 Level 1 certification
//! (NIST Certificate #4816). Active only when `--features fips` is enabled.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    EcdsaKeyPair, KeyPair as AwsKeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING,
};
use zeroize::Zeroizing;

use super::oid;
use super::{AlgorithmId, SigningAlgorithm};
use crate::error::{Error, Result};

// ---- SPKI DER constants for EC public key encoding ----

// OID 1.2.840.10045.2.1 (id-ecPublicKey) DER-encoded
const EC_PUBLIC_KEY_OID: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

// OID 1.2.840.10045.3.1.7 (secp256r1/P-256) DER-encoded
const SECP256R1_OID: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

// OID 1.3.132.0.34 (secp384r1/P-384) DER-encoded
const SECP384R1_OID: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

/// Build an SPKI DER structure for an EC public key.
///
/// SubjectPublicKeyInfo ::= SEQUENCE {
///   algorithm AlgorithmIdentifier { id-ecPublicKey, namedCurve },
///   subjectPublicKey BIT STRING
/// }
fn build_ec_spki_der(raw_pk: &[u8], curve_oid: &[u8]) -> Result<Vec<u8>> {
    // AlgorithmIdentifier: SEQUENCE { ecPublicKey OID, curve OID }
    let mut alg_id_inner = Vec::new();
    alg_id_inner.extend_from_slice(EC_PUBLIC_KEY_OID);
    alg_id_inner.extend_from_slice(curve_oid);

    let mut alg_id = Vec::new();
    alg_id.push(0x30); // SEQUENCE
    alg_id.push(alg_id_inner.len() as u8);
    alg_id.extend_from_slice(&alg_id_inner);

    // BIT STRING: 0x00 padding byte + raw public key
    let mut bit_string = Vec::new();
    bit_string.push(0x03); // BIT STRING tag
    bit_string.push((raw_pk.len() + 1) as u8);
    bit_string.push(0x00); // unused bits = 0
    bit_string.extend_from_slice(raw_pk);

    // Outer SEQUENCE
    let inner_len = alg_id.len() + bit_string.len();
    let mut spki = Vec::new();
    spki.push(0x30); // SEQUENCE
    spki.push(inner_len as u8);
    spki.extend_from_slice(&alg_id);
    spki.extend_from_slice(&bit_string);

    Ok(spki)
}

/// Convert DER bytes to PEM with the given label.
fn der_to_pem(der: &[u8], label: &str) -> String {
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

// =============================================================================
// ECDSA P-256
// =============================================================================

/// ECDSA with P-256 curve (secp256r1) — aws-lc-rs FIPS backend
pub struct EcdsaP256 {
    key_pair: EcdsaKeyPair,
    pkcs8_der: Zeroizing<Vec<u8>>,
}

impl EcdsaP256 {
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|_| Error::KeyGeneration("ECDSA P-256 keygen failed".to_string()))?;
        let pkcs8_bytes = pkcs8_doc.as_ref().to_vec();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8_bytes)
            .map_err(|e| Error::InvalidKey(format!("ECDSA P-256 load: {}", e)))?;
        Ok(Self {
            key_pair,
            pkcs8_der: Zeroizing::new(pkcs8_bytes),
        })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der)
            .map_err(|e| Error::InvalidKey(format!("ECDSA P-256 PKCS#8 decode: {}", e)))?;
        Ok(Self {
            key_pair,
            pkcs8_der: Zeroizing::new(der.to_vec()),
        })
    }
}

impl SigningAlgorithm for EcdsaP256 {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::EcdsaP256
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let sig = self
            .key_pair
            .sign(&rng, message)
            .map_err(|_| Error::SigningError("ECDSA P-256 signing failed".to_string()))?;
        Ok(sig.as_ref().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let pub_key_bytes = self.key_pair.public_key().as_ref();
        let peer_pub = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pub_key_bytes);
        Ok(peer_pub.verify(message, signature).is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(self.pkcs8_der.clone())
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(der_to_pem(&self.pkcs8_der, "PRIVATE KEY")))
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        let raw_pk = self.key_pair.public_key().as_ref();
        build_ec_spki_der(raw_pk, SECP256R1_OID)
    }

    fn public_key_pem(&self) -> Result<String> {
        let der = self.public_key_der()?;
        Ok(der_to_pem(&der, "PUBLIC KEY"))
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::ECDSA_SHA256
    }
}

// =============================================================================
// ECDSA P-384
// =============================================================================

/// ECDSA with P-384 curve (secp384r1) — aws-lc-rs FIPS backend
pub struct EcdsaP384 {
    key_pair: EcdsaKeyPair,
    pkcs8_der: Zeroizing<Vec<u8>>,
}

impl EcdsaP384 {
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
            .map_err(|_| Error::KeyGeneration("ECDSA P-384 keygen failed".to_string()))?;
        let pkcs8_bytes = pkcs8_doc.as_ref().to_vec();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &pkcs8_bytes)
            .map_err(|e| Error::InvalidKey(format!("ECDSA P-384 load: {}", e)))?;
        Ok(Self {
            key_pair,
            pkcs8_der: Zeroizing::new(pkcs8_bytes),
        })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, der)
            .map_err(|e| Error::InvalidKey(format!("ECDSA P-384 PKCS#8 decode: {}", e)))?;
        Ok(Self {
            key_pair,
            pkcs8_der: Zeroizing::new(der.to_vec()),
        })
    }
}

impl SigningAlgorithm for EcdsaP384 {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::EcdsaP384
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let sig = self
            .key_pair
            .sign(&rng, message)
            .map_err(|_| Error::SigningError("ECDSA P-384 signing failed".to_string()))?;
        Ok(sig.as_ref().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let pub_key_bytes = self.key_pair.public_key().as_ref();
        let peer_pub = UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, pub_key_bytes);
        Ok(peer_pub.verify(message, signature).is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(self.pkcs8_der.clone())
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(der_to_pem(&self.pkcs8_der, "PRIVATE KEY")))
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        let raw_pk = self.key_pair.public_key().as_ref();
        build_ec_spki_der(raw_pk, SECP384R1_OID)
    }

    fn public_key_pem(&self) -> Result<String> {
        let der = self.public_key_der()?;
        Ok(der_to_pem(&der, "PUBLIC KEY"))
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::ECDSA_SHA384
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p256_sign_verify() {
        let kp = EcdsaP256::generate().unwrap();
        let msg = b"test message";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
        assert!(!kp.verify(b"wrong message", &sig).unwrap());
    }

    #[test]
    fn test_p384_sign_verify() {
        let kp = EcdsaP384::generate().unwrap();
        let msg = b"test message";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_p256_pkcs8_roundtrip() {
        let kp1 = EcdsaP256::generate().unwrap();
        let der = kp1.private_key_der().unwrap();
        let kp2 = EcdsaP256::from_pkcs8_der(&der).unwrap();

        let msg = b"roundtrip test";
        let sig = kp1.sign(msg).unwrap();
        assert!(kp2.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_p256_pem_format() {
        let kp = EcdsaP256::generate().unwrap();
        let pem = kp.private_key_pem().unwrap();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
        assert!(pem.contains("END PRIVATE KEY"));

        let pub_pem = kp.public_key_pem().unwrap();
        assert!(pub_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn test_p256_algorithm_id() {
        let kp = EcdsaP256::generate().unwrap();
        assert_eq!(kp.algorithm_id(), AlgorithmId::EcdsaP256);
    }

    #[test]
    fn test_p384_algorithm_id() {
        let kp = EcdsaP384::generate().unwrap();
        assert_eq!(kp.algorithm_id(), AlgorithmId::EcdsaP384);
    }

    #[test]
    fn test_p256_oid() {
        let kp = EcdsaP256::generate().unwrap();
        assert_eq!(kp.oid(), oid::ECDSA_SHA256);
    }

    #[test]
    fn test_p384_oid() {
        let kp = EcdsaP384::generate().unwrap();
        assert_eq!(kp.oid(), oid::ECDSA_SHA384);
    }

    #[test]
    fn test_p384_pkcs8_roundtrip() {
        let kp1 = EcdsaP384::generate().unwrap();
        let der = kp1.private_key_der().unwrap();
        let kp2 = EcdsaP384::from_pkcs8_der(&der).unwrap();

        let msg = b"roundtrip test p384";
        let sig = kp1.sign(msg).unwrap();
        assert!(kp2.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_p256_public_key_der_format() {
        let kp = EcdsaP256::generate().unwrap();
        let der = kp.public_key_der().unwrap();
        assert_eq!(der[0], 0x30); // SEQUENCE
        assert!(!der.is_empty());
    }

    #[test]
    fn test_p256_cross_key_verify_fails() {
        let kp1 = EcdsaP256::generate().unwrap();
        let kp2 = EcdsaP256::generate().unwrap();
        let msg = b"signed by kp1";
        let sig = kp1.sign(msg).unwrap();
        assert!(!kp2.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_p256_from_invalid_pkcs8() {
        let result = EcdsaP256::from_pkcs8_der(&[0x30, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_p384_from_invalid_pkcs8() {
        let result = EcdsaP384::from_pkcs8_der(&[0x30, 0x00]);
        assert!(result.is_err());
    }
}
