//! Ed25519 implementation using aws-lc-rs (FIPS 140-3 certified backend)
//!
//! Provides Ed25519 (RFC 8032/8410) signing/verification using the AWS-LC
//! cryptographic library. Active only when `--features fips` is enabled.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as AwsKeyPair, UnparsedPublicKey, ED25519};
use zeroize::Zeroizing;

use super::oid;
use super::{AlgorithmId, SigningAlgorithm};
use crate::error::{Error, Result};

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

/// Ed25519 signing key pair (RFC 8032) — aws-lc-rs FIPS backend
pub struct Ed25519 {
    key_pair: Ed25519KeyPair,
    pkcs8_der: Zeroizing<Vec<u8>>,
}

impl Ed25519 {
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| Error::KeyGeneration("Ed25519 keygen failed".to_string()))?;
        let pkcs8_bytes = pkcs8_doc.as_ref().to_vec();
        let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes)
            .map_err(|e| Error::InvalidKey(format!("Ed25519 load: {}", e)))?;
        Ok(Self {
            key_pair,
            pkcs8_der: Zeroizing::new(pkcs8_bytes),
        })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
            .map_err(|e| Error::InvalidKey(format!("Ed25519 PKCS#8 decode: {}", e)))?;
        Ok(Self {
            key_pair,
            pkcs8_der: Zeroizing::new(der.to_vec()),
        })
    }
}

impl SigningAlgorithm for Ed25519 {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::Ed25519
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sig = self.key_pair.sign(message);
        Ok(sig.as_ref().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let pub_key_bytes = self.key_pair.public_key().as_ref();
        let peer_pub = UnparsedPublicKey::new(&ED25519, pub_key_bytes);
        Ok(peer_pub.verify(message, signature).is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(self.pkcs8_der.clone())
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(der_to_pem(&self.pkcs8_der, "PRIVATE KEY")))
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        // Build SPKI DER manually per RFC 8410 §4:
        // SubjectPublicKeyInfo ::= SEQUENCE {
        //   algorithm AlgorithmIdentifier { id-Ed25519, absent },
        //   subjectPublicKey BIT STRING (32 bytes)
        // }
        let pk_bytes = self.key_pair.public_key().as_ref();

        // AlgorithmIdentifier: SEQUENCE { OID 1.3.101.112 } (no params)
        let oid_bytes = oid::ED25519.as_bytes();
        let mut alg_id = Vec::new();
        alg_id.push(0x06); // OID tag
        alg_id.push(oid_bytes.len() as u8);
        alg_id.extend_from_slice(oid_bytes);

        let mut alg_seq = Vec::new();
        alg_seq.push(0x30); // SEQUENCE
        alg_seq.push(alg_id.len() as u8);
        alg_seq.extend_from_slice(&alg_id);

        // BIT STRING: 0x00 padding byte + 32 bytes public key
        let mut bit_string = Vec::new();
        bit_string.push(0x03); // BIT STRING tag
        bit_string.push((pk_bytes.len() + 1) as u8); // length = 33
        bit_string.push(0x00); // unused bits = 0
        bit_string.extend_from_slice(pk_bytes);

        // Outer SEQUENCE
        let inner_len = alg_seq.len() + bit_string.len();
        let mut spki = Vec::new();
        spki.push(0x30); // SEQUENCE
        spki.push(inner_len as u8);
        spki.extend_from_slice(&alg_seq);
        spki.extend_from_slice(&bit_string);

        Ok(spki)
    }

    fn public_key_pem(&self) -> Result<String> {
        let der = self.public_key_der()?;
        Ok(der_to_pem(&der, "PUBLIC KEY"))
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::ED25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let kp = Ed25519::generate().unwrap();
        let msg = b"test message";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), 64, "Ed25519 signature should be 64 bytes");
        assert!(kp.verify(msg, &sig).unwrap());
        assert!(!kp.verify(b"wrong message", &sig).unwrap());
    }

    #[test]
    fn test_ed25519_pkcs8_roundtrip() {
        let kp1 = Ed25519::generate().unwrap();
        let der = kp1.private_key_der().unwrap();
        let kp2 = Ed25519::from_pkcs8_der(&der).unwrap();

        let msg = b"roundtrip test";
        let sig = kp1.sign(msg).unwrap();
        assert!(kp2.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_ed25519_pem_format() {
        let kp = Ed25519::generate().unwrap();
        let pem = kp.private_key_pem().unwrap();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
        assert!(pem.contains("END PRIVATE KEY"));

        let pub_pem = kp.public_key_pem().unwrap();
        assert!(pub_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn test_ed25519_algorithm_id() {
        let kp = Ed25519::generate().unwrap();
        assert_eq!(kp.algorithm_id(), AlgorithmId::Ed25519);
    }

    #[test]
    fn test_ed25519_oid() {
        let kp = Ed25519::generate().unwrap();
        assert_eq!(kp.oid(), oid::ED25519);
    }

    #[test]
    fn test_ed25519_public_key_der_format() {
        let kp = Ed25519::generate().unwrap();
        let der = kp.public_key_der().unwrap();
        assert_eq!(der[0], 0x30); // SEQUENCE
        assert!(!der.is_empty());
    }

    #[test]
    fn test_ed25519_verify_wrong_signature() {
        let kp = Ed25519::generate().unwrap();
        let result = kp.verify(b"hello", &[0xFF; 64]);
        assert!(!result.unwrap());
    }

    #[test]
    fn test_ed25519_cross_key_verify_fails() {
        let kp1 = Ed25519::generate().unwrap();
        let kp2 = Ed25519::generate().unwrap();
        let msg = b"signed by kp1";
        let sig = kp1.sign(msg).unwrap();
        assert!(!kp2.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_ed25519_from_invalid_pkcs8() {
        let result = Ed25519::from_pkcs8_der(&[0x30, 0x00]);
        assert!(result.is_err());
    }
}
