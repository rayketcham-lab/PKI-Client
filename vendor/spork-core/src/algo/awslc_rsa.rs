//! RSA implementation using aws-lc-rs (FIPS 140-3 certified backend)
//!
//! Provides RSA 2048/3072/4096 with PKCS#1 v1.5 and PSS padding using
//! the AWS-LC cryptographic library. Active only when `--features fips` is enabled.

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaGenKeyPair, KeySize};
use aws_lc_rs::signature::{
    self, KeyPair as AwsKeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PSS_2048_8192_SHA256,
    RSA_PSS_SHA256,
};
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

/// Generate an RSA key pair of the given size and return (key_pair, pkcs8_der).
fn generate_rsa(size: KeySize, algo_name: &str) -> Result<(RsaGenKeyPair, Zeroizing<Vec<u8>>)> {
    let gen_kp = RsaGenKeyPair::generate(size)
        .map_err(|_| Error::KeyGeneration(format!("{} keygen failed", algo_name)))?;
    let pkcs8_doc = gen_kp
        .as_der()
        .map_err(|_| Error::Encoding(format!("{} PKCS#8 export failed", algo_name)))?;
    let pkcs8_bytes = Zeroizing::new(pkcs8_doc.as_ref().to_vec());
    Ok((gen_kp, pkcs8_bytes))
}

/// Load an RSA signing key pair from PKCS#8 DER.
fn load_rsa_signing(der: &[u8], algo_name: &str) -> Result<RsaGenKeyPair> {
    RsaGenKeyPair::from_pkcs8(der)
        .map_err(|e| Error::InvalidKey(format!("{} PKCS#8 decode: {}", algo_name, e)))
}

/// Get the SPKI DER for an RSA public key.
fn rsa_public_key_der(kp: &RsaGenKeyPair) -> Result<Vec<u8>> {
    let pub_key = kp.public_key();
    let der = pub_key
        .as_der()
        .map_err(|_| Error::Encoding("RSA public key SPKI export failed".to_string()))?;
    Ok(der.as_ref().to_vec())
}

/// Sign using RSA PKCS#1 v1.5.
fn rsa_pkcs1_sign(
    kp: &RsaGenKeyPair,
    padding: &'static dyn signature::RsaEncoding,
    message: &[u8],
    algo_name: &str,
) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut sig = vec![0u8; kp.public_modulus_len()];
    kp.sign(padding, &rng, message, &mut sig)
        .map_err(|_| Error::SigningError(format!("{} signing failed", algo_name)))?;
    Ok(sig)
}

// =============================================================================
// RSA-2048 with SHA-256 (PKCS#1 v1.5)
// =============================================================================

pub struct Rsa2048 {
    key_pair: RsaGenKeyPair,
    pkcs8_der: Zeroizing<Vec<u8>>,
}

impl Rsa2048 {
    pub fn generate() -> Result<Self> {
        let (key_pair, pkcs8_der) = generate_rsa(KeySize::Rsa2048, "RSA-2048")?;
        Ok(Self {
            key_pair,
            pkcs8_der,
        })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let key_pair = load_rsa_signing(der, "RSA-2048")?;
        Ok(Self {
            key_pair,
            pkcs8_der: Zeroizing::new(der.to_vec()),
        })
    }
}

impl SigningAlgorithm for Rsa2048 {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::Rsa2048
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        rsa_pkcs1_sign(&self.key_pair, &RSA_PKCS1_SHA256, message, "RSA-2048")
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let pub_der = rsa_public_key_der(&self.key_pair)?;
        let peer = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &pub_der);
        Ok(peer.verify(message, signature).is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(self.pkcs8_der.clone())
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(der_to_pem(&self.pkcs8_der, "PRIVATE KEY")))
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        rsa_public_key_der(&self.key_pair)
    }

    fn public_key_pem(&self) -> Result<String> {
        let der = self.public_key_der()?;
        Ok(der_to_pem(&der, "PUBLIC KEY"))
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::RSA_SHA256
    }
}

// =============================================================================
// RSA-3072 with SHA-384 (PKCS#1 v1.5)
// =============================================================================

pub struct Rsa3072 {
    key_pair: RsaGenKeyPair,
    pkcs8_der: Zeroizing<Vec<u8>>,
}

impl Rsa3072 {
    pub fn generate() -> Result<Self> {
        let (key_pair, pkcs8_der) = generate_rsa(KeySize::Rsa3072, "RSA-3072")?;
        Ok(Self {
            key_pair,
            pkcs8_der,
        })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let key_pair = load_rsa_signing(der, "RSA-3072")?;
        Ok(Self {
            key_pair,
            pkcs8_der: Zeroizing::new(der.to_vec()),
        })
    }
}

impl SigningAlgorithm for Rsa3072 {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::Rsa3072
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        rsa_pkcs1_sign(&self.key_pair, &RSA_PKCS1_SHA384, message, "RSA-3072")
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let pub_der = rsa_public_key_der(&self.key_pair)?;
        let peer = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, &pub_der);
        Ok(peer.verify(message, signature).is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(self.pkcs8_der.clone())
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(der_to_pem(&self.pkcs8_der, "PRIVATE KEY")))
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        rsa_public_key_der(&self.key_pair)
    }

    fn public_key_pem(&self) -> Result<String> {
        let der = self.public_key_der()?;
        Ok(der_to_pem(&der, "PUBLIC KEY"))
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::RSA_SHA384
    }
}

// =============================================================================
// RSA-4096 with SHA-256 (PKCS#1 v1.5)
// =============================================================================

pub struct Rsa4096 {
    key_pair: RsaGenKeyPair,
    pkcs8_der: Zeroizing<Vec<u8>>,
}

impl Rsa4096 {
    pub fn generate() -> Result<Self> {
        let (key_pair, pkcs8_der) = generate_rsa(KeySize::Rsa4096, "RSA-4096")?;
        Ok(Self {
            key_pair,
            pkcs8_der,
        })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let key_pair = load_rsa_signing(der, "RSA-4096")?;
        Ok(Self {
            key_pair,
            pkcs8_der: Zeroizing::new(der.to_vec()),
        })
    }
}

impl SigningAlgorithm for Rsa4096 {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::Rsa4096
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        rsa_pkcs1_sign(&self.key_pair, &RSA_PKCS1_SHA256, message, "RSA-4096")
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let pub_der = rsa_public_key_der(&self.key_pair)?;
        let peer = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &pub_der);
        Ok(peer.verify(message, signature).is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(self.pkcs8_der.clone())
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(der_to_pem(&self.pkcs8_der, "PRIVATE KEY")))
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        rsa_public_key_der(&self.key_pair)
    }

    fn public_key_pem(&self) -> Result<String> {
        let der = self.public_key_der()?;
        Ok(der_to_pem(&der, "PUBLIC KEY"))
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::RSA_SHA256
    }
}

// =============================================================================
// RSA-3072-PSS with SHA-256 (RFC 4055)
// =============================================================================

pub struct Rsa3072Pss {
    key_pair: RsaGenKeyPair,
    pkcs8_der: Zeroizing<Vec<u8>>,
}

impl Rsa3072Pss {
    pub fn generate() -> Result<Self> {
        let (key_pair, pkcs8_der) = generate_rsa(KeySize::Rsa3072, "RSA-3072-PSS")?;
        Ok(Self {
            key_pair,
            pkcs8_der,
        })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let key_pair = load_rsa_signing(der, "RSA-3072-PSS")?;
        Ok(Self {
            key_pair,
            pkcs8_der: Zeroizing::new(der.to_vec()),
        })
    }
}

impl SigningAlgorithm for Rsa3072Pss {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::Rsa3072Pss
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        rsa_pkcs1_sign(&self.key_pair, &RSA_PSS_SHA256, message, "RSA-3072-PSS")
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let pub_der = rsa_public_key_der(&self.key_pair)?;
        let peer = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, &pub_der);
        Ok(peer.verify(message, signature).is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(self.pkcs8_der.clone())
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(der_to_pem(&self.pkcs8_der, "PRIVATE KEY")))
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        rsa_public_key_der(&self.key_pair)
    }

    fn public_key_pem(&self) -> Result<String> {
        let der = self.public_key_der()?;
        Ok(der_to_pem(&der, "PUBLIC KEY"))
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::RSASSA_PSS
    }
}

// =============================================================================
// RSA-4096-PSS with SHA-256 (RFC 4055)
// =============================================================================

pub struct Rsa4096Pss {
    key_pair: RsaGenKeyPair,
    pkcs8_der: Zeroizing<Vec<u8>>,
}

impl Rsa4096Pss {
    pub fn generate() -> Result<Self> {
        let (key_pair, pkcs8_der) = generate_rsa(KeySize::Rsa4096, "RSA-4096-PSS")?;
        Ok(Self {
            key_pair,
            pkcs8_der,
        })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let key_pair = load_rsa_signing(der, "RSA-4096-PSS")?;
        Ok(Self {
            key_pair,
            pkcs8_der: Zeroizing::new(der.to_vec()),
        })
    }
}

impl SigningAlgorithm for Rsa4096Pss {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::Rsa4096Pss
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        rsa_pkcs1_sign(&self.key_pair, &RSA_PSS_SHA256, message, "RSA-4096-PSS")
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let pub_der = rsa_public_key_der(&self.key_pair)?;
        let peer = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, &pub_der);
        Ok(peer.verify(message, signature).is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(self.pkcs8_der.clone())
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(der_to_pem(&self.pkcs8_der, "PRIVATE KEY")))
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        rsa_public_key_der(&self.key_pair)
    }

    fn public_key_pem(&self) -> Result<String> {
        let der = self.public_key_der()?;
        Ok(der_to_pem(&der, "PUBLIC KEY"))
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
    fn test_rsa2048_pem_format() {
        let kp = Rsa2048::generate().unwrap();
        let pem = kp.private_key_pem().unwrap();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
        let pub_pem = kp.public_key_pem().unwrap();
        assert!(pub_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn test_rsa2048_public_key_der_format() {
        let kp = Rsa2048::generate().unwrap();
        let der = kp.public_key_der().unwrap();
        assert_eq!(der[0], 0x30); // SEQUENCE
        assert!(der.len() > 256);
    }

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
}
