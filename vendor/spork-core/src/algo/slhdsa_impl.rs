//! SLH-DSA (FIPS 205) implementation
//!
//! Stateless Hash-Based Digital Signature Algorithm
//! Supports SLH-DSA-SHA2-{128s,192s,256s} (small signature variants)

use core::convert::Infallible;
use slh_dsa::{
    signature::{
        rand_core::{TryCryptoRng, TryRng},
        Keypair,
    },
    Sha2_128s as Sha2_128sParam, Sha2_192s as Sha2_192sParam, Sha2_256s as Sha2_256sParam,
    Signature, SigningKey,
};
use zeroize::Zeroizing;

/// Try to extract raw key bytes from a PKCS#8 OneAsymmetricKey envelope.
/// PKCS#8: SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING { raw_key } }
/// If the input looks like PKCS#8 (starts with SEQUENCE tag 0x30), attempt extraction.
/// Returns None if the input isn't valid PKCS#8 — caller should use input as raw bytes.
fn try_extract_pkcs8_payload(der: &[u8]) -> Option<&[u8]> {
    // PKCS#8 starts with SEQUENCE (0x30), raw SLH-DSA keys don't
    if der.first()? != &0x30 {
        return None;
    }
    let pki = pkcs8::PrivateKeyInfo::try_from(der).ok()?;
    Some(pki.private_key)
}

use super::{AlgorithmId, SigningAlgorithm};
use crate::error::{Error, Result};

/// Wrapper around getrandom that implements the traits needed by slh-dsa
struct GetrandomRng;

impl TryRng for GetrandomRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Infallible> {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Infallible> {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Infallible> {
        getrandom::getrandom(dest).expect("getrandom failed");
        Ok(())
    }
}

impl TryCryptoRng for GetrandomRng {}

use super::oid;

/// SLH-DSA-SHA2-128s (NIST Level 1, small signatures)
pub struct SlhDsaSha2_128s {
    signing_key: SigningKey<Sha2_128sParam>,
}

impl SlhDsaSha2_128s {
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::<Sha2_128sParam>::new(&mut GetrandomRng);
        Ok(Self { signing_key })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let signing_key = SigningKey::<Sha2_128sParam>::try_from(bytes)
            .map_err(|e| Error::InvalidKey(format!("Invalid SLH-DSA-SHA2-128s key: {}", e)))?;
        Ok(Self { signing_key })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let raw = try_extract_pkcs8_payload(der).unwrap_or(der);
        Self::from_bytes(raw)
    }
}

impl SigningAlgorithm for SlhDsaSha2_128s {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::SlhDsaSha2_128s
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use slh_dsa::signature::Signer;
        let sig = self
            .signing_key
            .try_sign(message)
            .map_err(|e| Error::SigningError(format!("{}", e)))?;
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        use slh_dsa::signature::Verifier;
        let sig = Signature::<Sha2_128sParam>::try_from(signature)
            .map_err(|e| Error::InvalidSignature(format!("{}", e)))?;
        Ok(self
            .signing_key
            .verifying_key()
            .verify(message, &sig)
            .is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(self.signing_key.to_bytes().to_vec()))
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        let der = self.private_key_der()?;
        let b64 = base64_encode(&der);
        Ok(Zeroizing::new(format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            b64
        )))
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        Ok(self.signing_key.verifying_key().to_bytes().to_vec())
    }

    fn public_key_pem(&self) -> Result<String> {
        let der = self.public_key_der()?;
        let b64 = base64_encode(&der);
        Ok(format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            b64
        ))
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::SLH_DSA_SHA2_128S
    }
}

/// SLH-DSA-SHA2-192s (NIST Level 3, small signatures)
pub struct SlhDsaSha2_192s {
    signing_key: SigningKey<Sha2_192sParam>,
}

impl SlhDsaSha2_192s {
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::<Sha2_192sParam>::new(&mut GetrandomRng);
        Ok(Self { signing_key })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let signing_key = SigningKey::<Sha2_192sParam>::try_from(bytes)
            .map_err(|e| Error::InvalidKey(format!("Invalid SLH-DSA-SHA2-192s key: {}", e)))?;
        Ok(Self { signing_key })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let raw = try_extract_pkcs8_payload(der).unwrap_or(der);
        Self::from_bytes(raw)
    }
}

impl SigningAlgorithm for SlhDsaSha2_192s {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::SlhDsaSha2_192s
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use slh_dsa::signature::Signer;
        let sig = self
            .signing_key
            .try_sign(message)
            .map_err(|e| Error::SigningError(format!("{}", e)))?;
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        use slh_dsa::signature::Verifier;
        let sig = Signature::<Sha2_192sParam>::try_from(signature)
            .map_err(|e| Error::InvalidSignature(format!("{}", e)))?;
        Ok(self
            .signing_key
            .verifying_key()
            .verify(message, &sig)
            .is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(self.signing_key.to_bytes().to_vec()))
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        let der = self.private_key_der()?;
        let b64 = base64_encode(&der);
        Ok(Zeroizing::new(format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            b64
        )))
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        Ok(self.signing_key.verifying_key().to_bytes().to_vec())
    }

    fn public_key_pem(&self) -> Result<String> {
        let der = self.public_key_der()?;
        let b64 = base64_encode(&der);
        Ok(format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            b64
        ))
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::SLH_DSA_SHA2_192S
    }
}

/// SLH-DSA-SHA2-256s (NIST Level 5, small signatures)
pub struct SlhDsaSha2_256s {
    signing_key: SigningKey<Sha2_256sParam>,
}

impl SlhDsaSha2_256s {
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::<Sha2_256sParam>::new(&mut GetrandomRng);
        Ok(Self { signing_key })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let signing_key = SigningKey::<Sha2_256sParam>::try_from(bytes)
            .map_err(|e| Error::InvalidKey(format!("Invalid SLH-DSA-SHA2-256s key: {}", e)))?;
        Ok(Self { signing_key })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let raw = try_extract_pkcs8_payload(der).unwrap_or(der);
        Self::from_bytes(raw)
    }
}

impl SigningAlgorithm for SlhDsaSha2_256s {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::SlhDsaSha2_256s
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use slh_dsa::signature::Signer;
        let sig = self
            .signing_key
            .try_sign(message)
            .map_err(|e| Error::SigningError(format!("{}", e)))?;
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        use slh_dsa::signature::Verifier;
        let sig = Signature::<Sha2_256sParam>::try_from(signature)
            .map_err(|e| Error::InvalidSignature(format!("{}", e)))?;
        Ok(self
            .signing_key
            .verifying_key()
            .verify(message, &sig)
            .is_ok())
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(self.signing_key.to_bytes().to_vec()))
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        let der = self.private_key_der()?;
        let b64 = base64_encode(&der);
        Ok(Zeroizing::new(format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            b64
        )))
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        Ok(self.signing_key.verifying_key().to_bytes().to_vec())
    }

    fn public_key_pem(&self) -> Result<String> {
        let der = self.public_key_der()?;
        let b64 = base64_encode(&der);
        Ok(format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            b64
        ))
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        oid::SLH_DSA_SHA2_256S
    }
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut line_len = 0;

    for chunk in data.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0) as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        let combined = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[(combined >> 18) & 0x3F] as char);
        result.push(ALPHABET[(combined >> 12) & 0x3F] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[(combined >> 6) & 0x3F] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[combined & 0x3F] as char);
        } else {
            result.push('=');
        }

        line_len += 4;
        if line_len >= 64 {
            result.push('\n');
            line_len = 0;
        }
    }

    // Remove trailing newline if present (avoids blank line before END marker)
    if result.ends_with('\n') {
        result.pop();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slhdsa_128s_sign_verify() {
        let kp = SlhDsaSha2_128s::generate().unwrap();
        let msg = b"test message";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
        assert!(!kp.verify(b"wrong message", &sig).unwrap());
    }

    #[test]
    fn test_slhdsa_192s_sign_verify() {
        let kp = SlhDsaSha2_192s::generate().unwrap();
        let msg = b"test message";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_slhdsa_256s_sign_verify() {
        let kp = SlhDsaSha2_256s::generate().unwrap();
        let msg = b"test message";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }
}
