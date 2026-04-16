//! Ed25519 implementation (RFC 8032/8410)
//!
//! Ed25519 is an EdDSA signature scheme using Curve25519.
//! - Key type OID: 1.3.101.112 (id-Ed25519)
//! - Signature: 64 bytes (raw, not DER-wrapped)
//! - Public key: 32 bytes
//! - No parameters in AlgorithmIdentifier (RFC 8410 §3)

use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand_core::OsRng;
use zeroize::Zeroizing;

use super::oid;
use super::{AlgorithmId, SigningAlgorithm};
use crate::error::{Error, Result};

/// Ed25519 signing key pair (RFC 8032)
pub struct Ed25519 {
    signing_key: SigningKey,
}

impl Ed25519 {
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        Ok(Self { signing_key })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let signing_key = SigningKey::from_pkcs8_der(der)
            .map_err(|e| Error::InvalidKey(format!("Ed25519 PKCS#8 decode: {}", e)))?;
        Ok(Self { signing_key })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl SigningAlgorithm for Ed25519 {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::Ed25519
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sig: Ed25519Signature = self.signing_key.sign(message);
        // RFC 8032: Ed25519 signatures are 64 bytes, raw (not DER-wrapped)
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let sig = Ed25519Signature::from_slice(signature)
            .map_err(|e| Error::InvalidSignature(format!("Ed25519 sig decode: {}", e)))?;
        Ok(self.verifying_key().verify(message, &sig).is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        let der = self
            .signing_key
            .to_pkcs8_der()
            .map_err(|e| Error::Encoding(format!("PKCS#8 encode: {}", e)))?;
        Ok(Zeroizing::new(der.as_bytes().to_vec()))
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        let der = self
            .signing_key
            .to_pkcs8_der()
            .map_err(|e| Error::Encoding(format!("PKCS#8 PEM encode: {}", e)))?;
        let pem_str = der
            .to_pem("PRIVATE KEY", LineEnding::LF)
            .map_err(|e| Error::Encoding(format!("PEM encode: {}", e)))?;
        Ok(Zeroizing::new(pem_str.to_string()))
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        // Build SPKI DER manually per RFC 8410 §4:
        // SubjectPublicKeyInfo ::= SEQUENCE {
        //   algorithm AlgorithmIdentifier { id-Ed25519, absent },
        //   subjectPublicKey BIT STRING (32 bytes)
        // }
        let pk_bytes = self.verifying_key().to_bytes();

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
        bit_string.extend_from_slice(&pk_bytes);

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
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &der);
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        Ok(pem)
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
        // SPKI DER should start with SEQUENCE tag (0x30)
        assert_eq!(der[0], 0x30);
        assert!(!der.is_empty());
    }

    #[test]
    fn test_ed25519_verify_wrong_signature() {
        let kp = Ed25519::generate().unwrap();
        let result = kp.verify(b"hello", &[0xFF; 64]);
        // Should return Ok(false) since it's a valid-length but wrong signature
        assert!(!result.unwrap());
    }

    #[test]
    fn test_ed25519_verify_invalid_length() {
        let kp = Ed25519::generate().unwrap();
        let result = kp.verify(b"hello", &[0xFF; 10]);
        assert!(result.is_err());
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
