//! ML-DSA (FIPS 204) implementation
//!
//! Supports ML-DSA-44, ML-DSA-65, ML-DSA-87

#[allow(deprecated)]
use ml_dsa::ExpandedSigningKey;
use ml_dsa::{
    KeyGen, MlDsa44 as MlDsa44Param, MlDsa65 as MlDsa65Param, MlDsa87 as MlDsa87Param, Seed,
    Signature, SigningKey, VerifyingKey,
};
use zeroize::Zeroizing;

use super::{AlgorithmId, SigningAlgorithm};
use crate::error::{Error, Result};

use super::oid;

/// ML-DSA-44 (NIST Level 1)
pub struct MlDsa44 {
    seed: Zeroizing<[u8; 32]>,
    signing_key: SigningKey<MlDsa44Param>,
    verifying_key: VerifyingKey<MlDsa44Param>,
}

impl MlDsa44 {
    pub fn generate() -> Result<Self> {
        let mut seed_bytes = [0u8; 32];
        getrandom::getrandom(&mut seed_bytes).map_err(|e| Error::RandomError(format!("{}", e)))?;
        Self::from_seed(&seed_bytes)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let keypair = MlDsa44Param::from_seed(&Seed::from(*seed));
        let signing_key = keypair.signing_key().clone();
        let verifying_key = keypair.verifying_key().clone();
        Ok(Self {
            seed: Zeroizing::new(*seed),
            signing_key,
            verifying_key,
        })
    }

    #[allow(deprecated)]
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        // New format: 32-byte seed (compact, preferred)
        if der.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(der);
            return Self::from_seed(&seed);
        }
        // Legacy format: expanded signing key (backward compat)
        let encoded: ExpandedSigningKey<MlDsa44Param> = der.try_into().map_err(|_| {
            Error::InvalidKey("Invalid ML-DSA-44 key: expected 32-byte seed or expanded key".into())
        })?;
        let signing_key = SigningKey::<MlDsa44Param>::from_expanded(&encoded);
        let verifying_key = signing_key.verifying_key().clone();
        // Re-derive seed not possible from expanded key; store zeroed seed
        // (key will work for signing, but re-export will produce expanded format)
        Ok(Self {
            seed: Zeroizing::new([0u8; 32]),
            signing_key,
            verifying_key,
        })
    }
}

impl SigningAlgorithm for MlDsa44 {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::MlDsa44
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sig = self
            .signing_key
            .sign_deterministic(message, &[])
            .map_err(|e| Error::SigningError(format!("{:?}", e)))?;
        Ok(sig.encode().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let encoded: ml_dsa::EncodedSignature<MlDsa44Param> = signature
            .try_into()
            .map_err(|_| Error::InvalidSignature("Wrong signature length".into()))?;
        let sig = Signature::<MlDsa44Param>::decode(&encoded)
            .ok_or_else(|| Error::InvalidSignature("Invalid signature encoding".into()))?;
        Ok(self.verifying_key.verify_with_context(message, &[], &sig))
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        // Prefer seed format (32 bytes) if available
        if *self.seed != [0u8; 32] {
            return Ok(Zeroizing::new(self.seed.to_vec()));
        }
        // Fallback: legacy expanded format for keys loaded from old storage
        #[allow(deprecated)]
        Ok(Zeroizing::new(self.signing_key.to_expanded().to_vec()))
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
        Ok(self.verifying_key.encode().to_vec())
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
        oid::ML_DSA_44
    }
}

/// ML-DSA-65 (NIST Level 3)
pub struct MlDsa65 {
    seed: Zeroizing<[u8; 32]>,
    signing_key: SigningKey<MlDsa65Param>,
    verifying_key: VerifyingKey<MlDsa65Param>,
}

impl MlDsa65 {
    pub fn generate() -> Result<Self> {
        let mut seed_bytes = [0u8; 32];
        getrandom::getrandom(&mut seed_bytes).map_err(|e| Error::RandomError(format!("{}", e)))?;
        Self::from_seed(&seed_bytes)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let keypair = MlDsa65Param::from_seed(&Seed::from(*seed));
        let signing_key = keypair.signing_key().clone();
        let verifying_key = keypair.verifying_key().clone();
        Ok(Self {
            seed: Zeroizing::new(*seed),
            signing_key,
            verifying_key,
        })
    }

    #[allow(deprecated)]
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        if der.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(der);
            return Self::from_seed(&seed);
        }
        let encoded: ExpandedSigningKey<MlDsa65Param> = der.try_into().map_err(|_| {
            Error::InvalidKey("Invalid ML-DSA-65 key: expected 32-byte seed or expanded key".into())
        })?;
        let signing_key = SigningKey::<MlDsa65Param>::from_expanded(&encoded);
        let verifying_key = signing_key.verifying_key().clone();
        Ok(Self {
            seed: Zeroizing::new([0u8; 32]),
            signing_key,
            verifying_key,
        })
    }
}

impl SigningAlgorithm for MlDsa65 {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::MlDsa65
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sig = self
            .signing_key
            .sign_deterministic(message, &[])
            .map_err(|e| Error::SigningError(format!("{:?}", e)))?;
        Ok(sig.encode().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let encoded: ml_dsa::EncodedSignature<MlDsa65Param> = signature
            .try_into()
            .map_err(|_| Error::InvalidSignature("Wrong signature length".into()))?;
        let sig = Signature::<MlDsa65Param>::decode(&encoded)
            .ok_or_else(|| Error::InvalidSignature("Invalid signature encoding".into()))?;
        Ok(self.verifying_key.verify_with_context(message, &[], &sig))
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        if *self.seed != [0u8; 32] {
            return Ok(Zeroizing::new(self.seed.to_vec()));
        }
        #[allow(deprecated)]
        Ok(Zeroizing::new(self.signing_key.to_expanded().to_vec()))
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
        Ok(self.verifying_key.encode().to_vec())
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
        oid::ML_DSA_65
    }
}

/// ML-DSA-87 (NIST Level 5)
pub struct MlDsa87 {
    seed: Zeroizing<[u8; 32]>,
    signing_key: SigningKey<MlDsa87Param>,
    verifying_key: VerifyingKey<MlDsa87Param>,
}

impl MlDsa87 {
    pub fn generate() -> Result<Self> {
        let mut seed_bytes = [0u8; 32];
        getrandom::getrandom(&mut seed_bytes).map_err(|e| Error::RandomError(format!("{}", e)))?;
        Self::from_seed(&seed_bytes)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let keypair = MlDsa87Param::from_seed(&Seed::from(*seed));
        let signing_key = keypair.signing_key().clone();
        let verifying_key = keypair.verifying_key().clone();
        Ok(Self {
            seed: Zeroizing::new(*seed),
            signing_key,
            verifying_key,
        })
    }

    #[allow(deprecated)]
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        if der.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(der);
            return Self::from_seed(&seed);
        }
        let encoded: ExpandedSigningKey<MlDsa87Param> = der.try_into().map_err(|_| {
            Error::InvalidKey("Invalid ML-DSA-87 key: expected 32-byte seed or expanded key".into())
        })?;
        let signing_key = SigningKey::<MlDsa87Param>::from_expanded(&encoded);
        let verifying_key = signing_key.verifying_key().clone();
        Ok(Self {
            seed: Zeroizing::new([0u8; 32]),
            signing_key,
            verifying_key,
        })
    }
}

impl SigningAlgorithm for MlDsa87 {
    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::MlDsa87
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sig = self
            .signing_key
            .sign_deterministic(message, &[])
            .map_err(|e| Error::SigningError(format!("{:?}", e)))?;
        Ok(sig.encode().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let encoded: ml_dsa::EncodedSignature<MlDsa87Param> = signature
            .try_into()
            .map_err(|_| Error::InvalidSignature("Wrong signature length".into()))?;
        let sig = Signature::<MlDsa87Param>::decode(&encoded)
            .ok_or_else(|| Error::InvalidSignature("Invalid signature encoding".into()))?;
        Ok(self.verifying_key.verify_with_context(message, &[], &sig))
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        if *self.seed != [0u8; 32] {
            return Ok(Zeroizing::new(self.seed.to_vec()));
        }
        #[allow(deprecated)]
        Ok(Zeroizing::new(self.signing_key.to_expanded().to_vec()))
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
        Ok(self.verifying_key.encode().to_vec())
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
        oid::ML_DSA_87
    }
}

// Simple base64 encoding for PEM (no external dep needed)
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
    fn test_mldsa44_sign_verify() {
        let kp = MlDsa44::generate().unwrap();
        let msg = b"test message";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
        assert!(!kp.verify(b"wrong message", &sig).unwrap());
    }

    #[test]
    fn test_mldsa65_sign_verify() {
        let kp = MlDsa65::generate().unwrap();
        let msg = b"test message";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_mldsa87_sign_verify() {
        let kp = MlDsa87::generate().unwrap();
        let msg = b"test message";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_key_export() {
        let kp = MlDsa65::generate().unwrap();
        let der = kp.private_key_der().unwrap();
        assert!(!der.is_empty());
        let pem = kp.private_key_pem().unwrap();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_mldsa44_seed_round_trip() {
        let kp = MlDsa44::generate().unwrap();
        let der = kp.private_key_der().unwrap();
        // New keys export as 32-byte seed
        assert_eq!(der.len(), 32);
        // Round-trip: load from seed, verify same public key
        let kp2 = MlDsa44::from_pkcs8_der(&der).unwrap();
        assert_eq!(kp.public_key_der().unwrap(), kp2.public_key_der().unwrap());
        // Sign with original, verify with reloaded
        let sig = kp.sign(b"round trip test").unwrap();
        assert!(kp2.verify(b"round trip test", &sig).unwrap());
    }

    #[test]
    fn test_mldsa65_seed_round_trip() {
        let kp = MlDsa65::generate().unwrap();
        let der = kp.private_key_der().unwrap();
        assert_eq!(der.len(), 32);
        let kp2 = MlDsa65::from_pkcs8_der(&der).unwrap();
        assert_eq!(kp.public_key_der().unwrap(), kp2.public_key_der().unwrap());
        let sig = kp.sign(b"round trip test").unwrap();
        assert!(kp2.verify(b"round trip test", &sig).unwrap());
    }

    #[test]
    fn test_mldsa87_seed_round_trip() {
        let kp = MlDsa87::generate().unwrap();
        let der = kp.private_key_der().unwrap();
        assert_eq!(der.len(), 32);
        let kp2 = MlDsa87::from_pkcs8_der(&der).unwrap();
        assert_eq!(kp.public_key_der().unwrap(), kp2.public_key_der().unwrap());
        let sig = kp.sign(b"round trip test").unwrap();
        assert!(kp2.verify(b"round trip test", &sig).unwrap());
    }

    #[test]
    #[allow(deprecated)]
    fn test_mldsa44_legacy_expanded_key_compat() {
        // Simulate legacy: generate, export as expanded, reload
        let kp = MlDsa44::generate().unwrap();
        let expanded_bytes = kp.signing_key.to_expanded().to_vec();
        assert!(expanded_bytes.len() > 32); // Expanded key is much larger
                                            // Load from legacy expanded format
        let kp2 = MlDsa44::from_pkcs8_der(&expanded_bytes).unwrap();
        assert_eq!(kp.public_key_der().unwrap(), kp2.public_key_der().unwrap());
        let sig = kp.sign(b"legacy compat").unwrap();
        assert!(kp2.verify(b"legacy compat", &sig).unwrap());
    }

    #[test]
    fn test_mldsa_invalid_key_rejected() {
        // Not 32 bytes and not a valid expanded key
        let bad = vec![0u8; 64];
        assert!(MlDsa44::from_pkcs8_der(&bad).is_err());
        assert!(MlDsa65::from_pkcs8_der(&bad).is_err());
        assert!(MlDsa87::from_pkcs8_der(&bad).is_err());
    }
}
