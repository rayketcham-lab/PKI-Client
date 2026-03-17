//! RSA implementation for 2048, 3072, and 4096 bit keys

use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::rngs::OsRng;
use rsa::{
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    pss::{
        Signature as PssSignature, SigningKey as PssSigningKey, VerifyingKey as PssVerifyingKey,
    },
    signature::{RandomizedSigner, SignatureEncoding, Signer, Verifier},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use sha2::{Sha256, Sha384};
use zeroize::Zeroizing;

use super::{AlgorithmId, SigningAlgorithm};
use crate::error::{Error, Result};

use super::oid;

/// RSA-2048 with SHA-256
pub struct Rsa2048 {
    private_key: RsaPrivateKey,
}

impl Rsa2048 {
    pub fn generate() -> Result<Self> {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
            .map_err(|e| Error::KeyGeneration(format!("RSA-2048: {}", e)))?;
        Ok(Self { private_key })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|e| Error::InvalidKey(format!("RSA PKCS#8 decode: {}", e)))?;
        // Validate key size
        if private_key.size() * 8 != 2048 {
            return Err(Error::InvalidKey(format!(
                "Expected 2048-bit key, got {}-bit",
                private_key.size() * 8
            )));
        }
        Ok(Self { private_key })
    }

    pub fn public_key(&self) -> RsaPublicKey {
        self.private_key.to_public_key()
    }
}

impl SigningAlgorithm for Rsa2048 {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::Rsa2048
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let sig = signing_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let verifying_key = VerifyingKey::<Sha256>::new(self.public_key());
        let sig = Signature::try_from(signature)
            .map_err(|e| Error::InvalidSignature(format!("RSA sig decode: {}", e)))?;
        Ok(verifying_key.verify(message, &sig).is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        let der = self
            .private_key
            .to_pkcs8_der()
            .map_err(|e| Error::Encoding(format!("PKCS#8 encode: {}", e)))?;
        Ok(Zeroizing::new(der.as_bytes().to_vec()))
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        let pem = self
            .private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| Error::Encoding(format!("PKCS#8 PEM encode: {}", e)))?;
        Ok(pem)
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        let der = self
            .public_key()
            .to_public_key_der()
            .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;
        Ok(der.as_bytes().to_vec())
    }

    fn public_key_pem(&self) -> Result<String> {
        let pem = self
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Error::Encoding(format!("SPKI PEM encode: {}", e)))?;
        Ok(pem)
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::RSA_SHA256
    }
}

/// RSA-3072 with SHA-384 (strength-matched: 128-bit key security + 192-bit hash)
pub struct Rsa3072 {
    private_key: RsaPrivateKey,
}

impl Rsa3072 {
    pub fn generate() -> Result<Self> {
        let private_key = RsaPrivateKey::new(&mut OsRng, 3072)
            .map_err(|e| Error::KeyGeneration(format!("RSA-3072: {}", e)))?;
        Ok(Self { private_key })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|e| Error::InvalidKey(format!("RSA PKCS#8 decode: {}", e)))?;
        // Validate key size
        if private_key.size() * 8 != 3072 {
            return Err(Error::InvalidKey(format!(
                "Expected 3072-bit key, got {}-bit",
                private_key.size() * 8
            )));
        }
        Ok(Self { private_key })
    }

    pub fn public_key(&self) -> RsaPublicKey {
        self.private_key.to_public_key()
    }
}

impl SigningAlgorithm for Rsa3072 {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::Rsa3072
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::<Sha384>::new(self.private_key.clone());
        let sig = signing_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let verifying_key = VerifyingKey::<Sha384>::new(self.public_key());
        let sig = Signature::try_from(signature)
            .map_err(|e| Error::InvalidSignature(format!("RSA sig decode: {}", e)))?;
        Ok(verifying_key.verify(message, &sig).is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        let der = self
            .private_key
            .to_pkcs8_der()
            .map_err(|e| Error::Encoding(format!("PKCS#8 encode: {}", e)))?;
        Ok(Zeroizing::new(der.as_bytes().to_vec()))
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        let pem = self
            .private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| Error::Encoding(format!("PKCS#8 PEM encode: {}", e)))?;
        Ok(pem)
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        let der = self
            .public_key()
            .to_public_key_der()
            .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;
        Ok(der.as_bytes().to_vec())
    }

    fn public_key_pem(&self) -> Result<String> {
        let pem = self
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Error::Encoding(format!("SPKI PEM encode: {}", e)))?;
        Ok(pem)
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::RSA_SHA384
    }
}

/// RSA-4096 with SHA-256
pub struct Rsa4096 {
    private_key: RsaPrivateKey,
}

impl Rsa4096 {
    pub fn generate() -> Result<Self> {
        let private_key = RsaPrivateKey::new(&mut OsRng, 4096)
            .map_err(|e| Error::KeyGeneration(format!("RSA-4096: {}", e)))?;
        Ok(Self { private_key })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|e| Error::InvalidKey(format!("RSA PKCS#8 decode: {}", e)))?;
        // Validate key size
        if private_key.size() * 8 != 4096 {
            return Err(Error::InvalidKey(format!(
                "Expected 4096-bit key, got {}-bit",
                private_key.size() * 8
            )));
        }
        Ok(Self { private_key })
    }

    pub fn public_key(&self) -> RsaPublicKey {
        self.private_key.to_public_key()
    }
}

impl SigningAlgorithm for Rsa4096 {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::Rsa4096
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let sig = signing_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let verifying_key = VerifyingKey::<Sha256>::new(self.public_key());
        let sig = Signature::try_from(signature)
            .map_err(|e| Error::InvalidSignature(format!("RSA sig decode: {}", e)))?;
        Ok(verifying_key.verify(message, &sig).is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        let der = self
            .private_key
            .to_pkcs8_der()
            .map_err(|e| Error::Encoding(format!("PKCS#8 encode: {}", e)))?;
        Ok(Zeroizing::new(der.as_bytes().to_vec()))
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        let pem = self
            .private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| Error::Encoding(format!("PKCS#8 PEM encode: {}", e)))?;
        Ok(pem)
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        let der = self
            .public_key()
            .to_public_key_der()
            .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;
        Ok(der.as_bytes().to_vec())
    }

    fn public_key_pem(&self) -> Result<String> {
        let pem = self
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Error::Encoding(format!("SPKI PEM encode: {}", e)))?;
        Ok(pem)
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::RSA_SHA256
    }
}

// =============================================================================
// RSA-PSS (RFC 4055) — RSASSA-PSS with SHA-256
// =============================================================================
// Same RSA keys, different signature scheme. PSS is required for FIPS compliance
// and is recommended over PKCS#1 v1.5 for new deployments.

/// RSA-3072 with PSS padding and SHA-256 (RFC 4055)
pub struct Rsa3072Pss {
    private_key: RsaPrivateKey,
}

impl Rsa3072Pss {
    pub fn generate() -> Result<Self> {
        let private_key = RsaPrivateKey::new(&mut OsRng, 3072)
            .map_err(|e| Error::KeyGeneration(format!("RSA-3072-PSS: {}", e)))?;
        Ok(Self { private_key })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|e| Error::InvalidKey(format!("RSA PKCS#8 decode: {}", e)))?;
        if private_key.size() * 8 != 3072 {
            return Err(Error::InvalidKey(format!(
                "Expected 3072-bit key, got {}-bit",
                private_key.size() * 8
            )));
        }
        Ok(Self { private_key })
    }

    pub fn public_key(&self) -> RsaPublicKey {
        self.private_key.to_public_key()
    }
}

impl SigningAlgorithm for Rsa3072Pss {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::Rsa3072Pss
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signing_key = PssSigningKey::<Sha256>::new(self.private_key.clone());
        let sig = signing_key.sign_with_rng(&mut OsRng, message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let verifying_key = PssVerifyingKey::<Sha256>::new(self.public_key());
        let sig = PssSignature::try_from(signature)
            .map_err(|e| Error::InvalidSignature(format!("RSA-PSS sig decode: {}", e)))?;
        Ok(verifying_key.verify(message, &sig).is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        let der = self
            .private_key
            .to_pkcs8_der()
            .map_err(|e| Error::Encoding(format!("PKCS#8 encode: {}", e)))?;
        Ok(Zeroizing::new(der.as_bytes().to_vec()))
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        let pem = self
            .private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| Error::Encoding(format!("PKCS#8 PEM encode: {}", e)))?;
        Ok(pem)
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        let der = self
            .public_key()
            .to_public_key_der()
            .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;
        Ok(der.as_bytes().to_vec())
    }

    fn public_key_pem(&self) -> Result<String> {
        let pem = self
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Error::Encoding(format!("SPKI PEM encode: {}", e)))?;
        Ok(pem)
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::RSASSA_PSS
    }
}

/// RSA-4096 with PSS padding and SHA-256 (RFC 4055)
pub struct Rsa4096Pss {
    private_key: RsaPrivateKey,
}

impl Rsa4096Pss {
    pub fn generate() -> Result<Self> {
        let private_key = RsaPrivateKey::new(&mut OsRng, 4096)
            .map_err(|e| Error::KeyGeneration(format!("RSA-4096-PSS: {}", e)))?;
        Ok(Self { private_key })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|e| Error::InvalidKey(format!("RSA PKCS#8 decode: {}", e)))?;
        if private_key.size() * 8 != 4096 {
            return Err(Error::InvalidKey(format!(
                "Expected 4096-bit key, got {}-bit",
                private_key.size() * 8
            )));
        }
        Ok(Self { private_key })
    }

    pub fn public_key(&self) -> RsaPublicKey {
        self.private_key.to_public_key()
    }
}

impl SigningAlgorithm for Rsa4096Pss {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::Rsa4096Pss
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signing_key = PssSigningKey::<Sha256>::new(self.private_key.clone());
        let sig = signing_key.sign_with_rng(&mut OsRng, message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let verifying_key = PssVerifyingKey::<Sha256>::new(self.public_key());
        let sig = PssSignature::try_from(signature)
            .map_err(|e| Error::InvalidSignature(format!("RSA-PSS sig decode: {}", e)))?;
        Ok(verifying_key.verify(message, &sig).is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        let der = self
            .private_key
            .to_pkcs8_der()
            .map_err(|e| Error::Encoding(format!("PKCS#8 encode: {}", e)))?;
        Ok(Zeroizing::new(der.as_bytes().to_vec()))
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        let pem = self
            .private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| Error::Encoding(format!("PKCS#8 PEM encode: {}", e)))?;
        Ok(pem)
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        let der = self
            .public_key()
            .to_public_key_der()
            .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;
        Ok(der.as_bytes().to_vec())
    }

    fn public_key_pem(&self) -> Result<String> {
        let pem = self
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Error::Encoding(format!("SPKI PEM encode: {}", e)))?;
        Ok(pem)
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::RSASSA_PSS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa2048_sign_verify() {
        let kp = Rsa2048::generate().unwrap();
        let msg = b"test message";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
        assert!(!kp.verify(b"wrong message", &sig).unwrap());
    }

    // RSA-3072 and RSA-4096 keygen is slow, skip in normal tests
    #[test]
    #[ignore]
    fn test_rsa3072_sign_verify() {
        let kp = Rsa3072::generate().unwrap();
        let msg = b"test message";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    #[ignore]
    fn test_rsa4096_sign_verify() {
        let kp = Rsa4096::generate().unwrap();
        let msg = b"test message";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_rsa2048_pkcs8_roundtrip() {
        let kp1 = Rsa2048::generate().unwrap();
        let der = kp1.private_key_der().unwrap();
        let kp2 = Rsa2048::from_pkcs8_der(&der).unwrap();

        let msg = b"roundtrip test";
        let sig = kp1.sign(msg).unwrap();
        assert!(kp2.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_rsa2048_algorithm_id() {
        let kp = Rsa2048::generate().unwrap();
        assert_eq!(kp.algorithm_id(), AlgorithmId::Rsa2048);
    }

    #[test]
    fn test_rsa2048_oid() {
        let kp = Rsa2048::generate().unwrap();
        assert_eq!(kp.oid(), oid::RSA_SHA256);
    }

    #[test]
    fn test_rsa2048_pem_format() {
        let kp = Rsa2048::generate().unwrap();
        let pem = kp.private_key_pem().unwrap();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
        assert!(pem.contains("END PRIVATE KEY"));

        let pub_pem = kp.public_key_pem().unwrap();
        assert!(pub_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn test_rsa2048_public_key_der_format() {
        let kp = Rsa2048::generate().unwrap();
        let der = kp.public_key_der().unwrap();
        // SPKI DER should start with SEQUENCE tag (0x30)
        assert_eq!(der[0], 0x30);
        assert!(der.len() > 256); // RSA-2048 public key > 256 bytes
    }

    #[test]
    fn test_rsa2048_verify_invalid_signature() {
        let kp = Rsa2048::generate().unwrap();
        // Short garbage — may decode but won't verify
        let result = kp.verify(b"hello", &[0xFF; 10]);
        if let Ok(valid) = result {
            assert!(!valid);
        }
        // Err is also acceptable — decode failure
    }

    #[test]
    fn test_rsa2048_from_invalid_pkcs8() {
        let result = Rsa2048::from_pkcs8_der(&[0x30, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_rsa2048_cross_key_verify_fails() {
        let kp1 = Rsa2048::generate().unwrap();
        let kp2 = Rsa2048::generate().unwrap();
        let msg = b"signed by kp1";
        let sig = kp1.sign(msg).unwrap();
        assert!(!kp2.verify(msg, &sig).unwrap());
    }

    // --- RSA-PSS tests (RFC 4055) ---

    #[test]
    fn test_rsa3072_pss_sign_verify() {
        let kp = Rsa3072Pss::generate().unwrap();
        let msg = b"PSS test message";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
        assert!(!kp.verify(b"wrong message", &sig).unwrap());
    }

    #[test]
    fn test_rsa3072_pss_algorithm_id() {
        let kp = Rsa3072Pss::generate().unwrap();
        assert_eq!(kp.algorithm_id(), AlgorithmId::Rsa3072Pss);
    }

    #[test]
    fn test_rsa3072_pss_oid() {
        let kp = Rsa3072Pss::generate().unwrap();
        assert_eq!(kp.oid(), oid::RSASSA_PSS);
    }

    #[test]
    fn test_rsa3072_pss_pkcs8_roundtrip() {
        let kp1 = Rsa3072Pss::generate().unwrap();
        let der = kp1.private_key_der().unwrap();
        let kp2 = Rsa3072Pss::from_pkcs8_der(&der).unwrap();

        let msg = b"PSS roundtrip";
        let sig = kp1.sign(msg).unwrap();
        assert!(kp2.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_rsa3072_pss_vs_pkcs1v15_different_signatures() {
        // PSS and PKCS#1 v1.5 produce different signatures from the same key
        let private_key = RsaPrivateKey::new(&mut OsRng, 3072).unwrap();
        let pss = Rsa3072Pss {
            private_key: private_key.clone(),
        };
        let v15 = Rsa3072 {
            private_key: private_key.clone(),
        };

        let msg = b"same key different scheme";
        let pss_sig = pss.sign(msg).unwrap();
        let v15_sig = v15.sign(msg).unwrap();

        // Both should verify with their own scheme
        assert!(pss.verify(msg, &pss_sig).unwrap());
        assert!(v15.verify(msg, &v15_sig).unwrap());

        // Cross-verification should fail (different padding)
        assert!(!pss.verify(msg, &v15_sig).unwrap_or(false));
        assert!(!v15.verify(msg, &pss_sig).unwrap_or(false));
    }

    #[test]
    #[ignore] // RSA-4096 keygen is slow
    fn test_rsa4096_pss_sign_verify() {
        let kp = Rsa4096Pss::generate().unwrap();
        let msg = b"PSS 4096 test";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_rsa3072_pss_pem_format() {
        let kp = Rsa3072Pss::generate().unwrap();
        let pem = kp.private_key_pem().unwrap();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
        let pub_pem = kp.public_key_pem().unwrap();
        assert!(pub_pem.contains("BEGIN PUBLIC KEY"));
    }
}
