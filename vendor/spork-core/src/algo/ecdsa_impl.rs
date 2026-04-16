//! ECDSA implementation for P-256 and P-384 curves

use p256::ecdsa::{
    signature::Signer as _, signature::Verifier as _, Signature as P256Signature,
    SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{
    Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
};
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rand_core::OsRng;
use zeroize::Zeroizing;

use super::{AlgorithmId, SigningAlgorithm};
use crate::error::{Error, Result};

use super::oid;

/// ECDSA with P-256 curve (secp256r1)
pub struct EcdsaP256 {
    signing_key: P256SigningKey,
}

impl EcdsaP256 {
    pub fn generate() -> Result<Self> {
        let signing_key = P256SigningKey::random(&mut OsRng);
        Ok(Self { signing_key })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let signing_key = P256SigningKey::from_pkcs8_der(der)
            .map_err(|e| Error::InvalidKey(format!("ECDSA P-256 PKCS#8 decode: {}", e)))?;
        Ok(Self { signing_key })
    }

    pub fn verifying_key(&self) -> P256VerifyingKey {
        *self.signing_key.verifying_key()
    }
}

impl SigningAlgorithm for EcdsaP256 {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::EcdsaP256
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sig: P256Signature = self.signing_key.sign(message);
        Ok(sig.to_der().to_bytes().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let sig = P256Signature::from_der(signature)
            .map_err(|e| Error::InvalidSignature(format!("ECDSA P-256 sig decode: {}", e)))?;
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
        let pem = self
            .signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| Error::Encoding(format!("PKCS#8 PEM encode: {}", e)))?;
        Ok(pem)
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        let der = self
            .verifying_key()
            .to_public_key_der()
            .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;
        Ok(der.as_bytes().to_vec())
    }

    fn public_key_pem(&self) -> Result<String> {
        let pem = self
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Error::Encoding(format!("SPKI PEM encode: {}", e)))?;
        Ok(pem)
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::ECDSA_SHA256
    }
}

/// ECDSA with P-384 curve (secp384r1)
pub struct EcdsaP384 {
    signing_key: P384SigningKey,
}

impl EcdsaP384 {
    pub fn generate() -> Result<Self> {
        let signing_key = P384SigningKey::random(&mut OsRng);
        Ok(Self { signing_key })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let signing_key = P384SigningKey::from_pkcs8_der(der)
            .map_err(|e| Error::InvalidKey(format!("ECDSA P-384 PKCS#8 decode: {}", e)))?;
        Ok(Self { signing_key })
    }

    pub fn verifying_key(&self) -> P384VerifyingKey {
        *self.signing_key.verifying_key()
    }
}

impl SigningAlgorithm for EcdsaP384 {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::EcdsaP384
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sig: P384Signature = self.signing_key.sign(message);
        Ok(sig.to_der().to_bytes().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let sig = P384Signature::from_der(signature)
            .map_err(|e| Error::InvalidSignature(format!("ECDSA P-384 sig decode: {}", e)))?;
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
        let pem = self
            .signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| Error::Encoding(format!("PKCS#8 PEM encode: {}", e)))?;
        Ok(pem)
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        let der = self
            .verifying_key()
            .to_public_key_der()
            .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;
        Ok(der.as_bytes().to_vec())
    }

    fn public_key_pem(&self) -> Result<String> {
        let pem = self
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Error::Encoding(format!("SPKI PEM encode: {}", e)))?;
        Ok(pem)
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
    fn test_p384_pem_format() {
        let kp = EcdsaP384::generate().unwrap();
        let pem = kp.private_key_pem().unwrap();
        assert!(pem.contains("BEGIN PRIVATE KEY"));

        let pub_pem = kp.public_key_pem().unwrap();
        assert!(pub_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn test_p256_public_key_der_format() {
        let kp = EcdsaP256::generate().unwrap();
        let der = kp.public_key_der().unwrap();
        // SPKI DER should start with SEQUENCE tag (0x30)
        assert_eq!(der[0], 0x30);
        assert!(!der.is_empty());
    }

    #[test]
    fn test_p256_verify_wrong_signature() {
        let kp = EcdsaP256::generate().unwrap();
        // Totally invalid signature bytes
        let result = kp.verify(b"hello", &[0xFF; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_p256_cross_key_verify_fails() {
        let kp1 = EcdsaP256::generate().unwrap();
        let kp2 = EcdsaP256::generate().unwrap();
        let msg = b"signed by kp1";
        let sig = kp1.sign(msg).unwrap();
        // kp2 should fail to verify kp1's signature
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
