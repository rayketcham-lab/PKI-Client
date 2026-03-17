//! Composite (Hybrid) Signature Implementation
//!
//! Implements composite signatures per draft-ietf-lamps-pq-composite-sigs.
//! Combines PQC algorithms (ML-DSA) with classical algorithms (ECDSA) for
//! hybrid post-quantum/classical security.

use crate::algo::{AlgorithmId, EcdsaP256, EcdsaP384, MlDsa44, MlDsa65, MlDsa87, SigningAlgorithm};
use crate::error::{Error, Result};
use zeroize::Zeroizing;

/// Composite key pair holding both PQC and classical keys
pub struct CompositeKeyPair {
    algorithm_id: AlgorithmId,
    pqc_key: Box<dyn SigningAlgorithm>,
    classical_key: Box<dyn SigningAlgorithm>,
}

impl CompositeKeyPair {
    /// Generate a new composite key pair
    pub fn generate(algorithm: AlgorithmId) -> Result<Self> {
        let (pqc_key, classical_key): (Box<dyn SigningAlgorithm>, Box<dyn SigningAlgorithm>) =
            match algorithm {
                AlgorithmId::MlDsa44EcdsaP256 => (
                    Box::new(MlDsa44::generate()?),
                    Box::new(EcdsaP256::generate()?),
                ),
                AlgorithmId::MlDsa65EcdsaP256 => (
                    Box::new(MlDsa65::generate()?),
                    Box::new(EcdsaP256::generate()?),
                ),
                AlgorithmId::MlDsa65EcdsaP384 => (
                    Box::new(MlDsa65::generate()?),
                    Box::new(EcdsaP384::generate()?),
                ),
                AlgorithmId::MlDsa87EcdsaP384 => (
                    Box::new(MlDsa87::generate()?),
                    Box::new(EcdsaP384::generate()?),
                ),
                _ => return Err(Error::UnsupportedAlgorithm(format!("{:?}", algorithm))),
            };

        Ok(Self {
            algorithm_id: algorithm,
            pqc_key,
            classical_key,
        })
    }

    /// Load a composite key pair from the custom DER format
    /// Format: [pqc_len:u32][pqc_der][classical_der]
    pub fn from_composite_der(algorithm: AlgorithmId, der: &[u8]) -> Result<Self> {
        if der.len() < 4 {
            return Err(Error::InvalidKey("Composite key DER too short".into()));
        }

        let pqc_len = u32::from_be_bytes([der[0], der[1], der[2], der[3]]) as usize;
        if der.len() < 4 + pqc_len {
            return Err(Error::InvalidKey("Composite key DER truncated".into()));
        }

        let pqc_der = &der[4..4 + pqc_len];
        let classical_der = &der[4 + pqc_len..];

        let (pqc_key, classical_key): (Box<dyn SigningAlgorithm>, Box<dyn SigningAlgorithm>) =
            match algorithm {
                AlgorithmId::MlDsa44EcdsaP256 => (
                    Box::new(MlDsa44::from_pkcs8_der(pqc_der)?),
                    Box::new(EcdsaP256::from_pkcs8_der(classical_der)?),
                ),
                AlgorithmId::MlDsa65EcdsaP256 => (
                    Box::new(MlDsa65::from_pkcs8_der(pqc_der)?),
                    Box::new(EcdsaP256::from_pkcs8_der(classical_der)?),
                ),
                AlgorithmId::MlDsa65EcdsaP384 => (
                    Box::new(MlDsa65::from_pkcs8_der(pqc_der)?),
                    Box::new(EcdsaP384::from_pkcs8_der(classical_der)?),
                ),
                AlgorithmId::MlDsa87EcdsaP384 => (
                    Box::new(MlDsa87::from_pkcs8_der(pqc_der)?),
                    Box::new(EcdsaP384::from_pkcs8_der(classical_der)?),
                ),
                _ => return Err(Error::UnsupportedAlgorithm(format!("{:?}", algorithm))),
            };

        Ok(Self {
            algorithm_id: algorithm,
            pqc_key,
            classical_key,
        })
    }

    /// Create composite signature from both keys
    /// Returns DER-encoded SEQUENCE { pqc_sig, classical_sig }
    fn create_composite_signature(&self, message: &[u8]) -> Result<Vec<u8>> {
        let pqc_sig = self.pqc_key.sign(message)?;
        let classical_sig = self.classical_key.sign(message)?;

        // Encode as SEQUENCE { BIT STRING pqc_sig, BIT STRING classical_sig }
        encode_composite_signature(&pqc_sig, &classical_sig)
    }

    /// Verify composite signature
    fn verify_composite_signature(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let (pqc_sig, classical_sig) = decode_composite_signature(signature)?;

        let pqc_ok = self.pqc_key.verify(message, &pqc_sig)?;
        let classical_ok = self.classical_key.verify(message, &classical_sig)?;

        // Both must verify for composite to be valid
        Ok(pqc_ok && classical_ok)
    }

    /// Create composite public key
    /// Returns DER-encoded SEQUENCE { pqc_pk, classical_pk }
    fn composite_public_key_der(&self) -> Result<Vec<u8>> {
        let pqc_pk = self.pqc_key.public_key_der()?;
        let classical_pk = self.classical_key.public_key_der()?;

        encode_composite_public_key(&pqc_pk, &classical_pk, self.algorithm_id)
    }

    /// Create composite private key
    /// Returns custom format: length-prefixed concatenation
    fn composite_private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        let pqc_sk = self.pqc_key.private_key_der()?;
        let classical_sk = self.classical_key.private_key_der()?;

        // Simple format: [pqc_len:u32][pqc_der][classical_der]
        let mut result = Vec::new();
        result.extend_from_slice(&(pqc_sk.len() as u32).to_be_bytes());
        result.extend_from_slice(&pqc_sk);
        result.extend_from_slice(&classical_sk);

        Ok(Zeroizing::new(result))
    }
}

impl SigningAlgorithm for CompositeKeyPair {
    fn algorithm_id(&self) -> AlgorithmId {
        self.algorithm_id
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.create_composite_signature(message)
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        self.verify_composite_signature(message, signature)
    }

    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.composite_private_key_der()
    }

    fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        let der = self.private_key_der()?;
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &*der);
        let pem = format!(
            "-----BEGIN COMPOSITE PRIVATE KEY-----\n{}\n-----END COMPOSITE PRIVATE KEY-----\n",
            b64
        );
        Ok(Zeroizing::new(pem))
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        self.composite_public_key_der()
    }

    fn public_key_pem(&self) -> Result<String> {
        let der = self.public_key_der()?;
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &der);
        Ok(format!(
            "-----BEGIN COMPOSITE PUBLIC KEY-----\n{}\n-----END COMPOSITE PUBLIC KEY-----\n",
            b64
        ))
    }

    fn oid(&self) -> const_oid::ObjectIdentifier {
        self.algorithm_id.signature_oid()
    }
}

/// Verify a composite signature given raw public key SPKI bytes, message, and signature.
/// Used by certificate chain verification where we don't have a CompositeKeyPair instance.
pub fn verify_composite_signature_standalone(
    algorithm: AlgorithmId,
    pk_spki_bytes: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool> {
    // Decode the composite signature: SEQUENCE { BIT STRING (pqc), BIT STRING (classical) }
    let (pqc_sig, classical_sig) = decode_composite_signature(signature)?;

    // Decode the composite public key from the SPKI's subjectPublicKey BIT STRING.
    // pk_spki_bytes is the BIT STRING content = CompositePublicKey SEQUENCE.
    // CompositePublicKey ::= SEQUENCE { pqc_raw_key_bytes, classical_spki_bytes }
    // Note: PQC component is raw encoded verifying key (not SPKI-wrapped).
    //       Classical component is a full SPKI (SEQUENCE { AlgId, BIT STRING }).
    let (pk_content, _) = decode_der_element(pk_spki_bytes)?;

    // The PQC key is raw bytes concatenated with classical SPKI bytes.
    // We know the PQC key size from the algorithm, so split accordingly.
    let pqc_key_len = match algorithm {
        AlgorithmId::MlDsa44EcdsaP256 => 1312, // ML-DSA-44 verifying key
        AlgorithmId::MlDsa65EcdsaP256 | AlgorithmId::MlDsa65EcdsaP384 => 1952, // ML-DSA-65
        AlgorithmId::MlDsa87EcdsaP384 => 2592, // ML-DSA-87
        _ => return Err(Error::UnsupportedAlgorithm(format!("{:?}", algorithm))),
    };

    if pk_content.len() < pqc_key_len {
        return Err(Error::InvalidCertificate(format!(
            "Composite public key too short: {} < {}",
            pk_content.len(),
            pqc_key_len
        )));
    }

    let pqc_pk = &pk_content[..pqc_key_len];
    let classical_spki_bytes = &pk_content[pqc_key_len..];

    // Extract SEC1 point from classical SPKI: SEQUENCE { AlgId, BIT STRING { point } }
    let (classical_spki_content, _) = decode_der_element_raw(classical_spki_bytes)?;
    let classical_pk = extract_raw_pk_from_spki_content(classical_spki_content)?;

    // Verify PQC component
    let pqc_ok = match algorithm {
        AlgorithmId::MlDsa44EcdsaP256 => {
            verify_mldsa_sig::<ml_dsa::MlDsa44>(pqc_pk, message, &pqc_sig)?
        }
        AlgorithmId::MlDsa65EcdsaP256 | AlgorithmId::MlDsa65EcdsaP384 => {
            verify_mldsa_sig::<ml_dsa::MlDsa65>(pqc_pk, message, &pqc_sig)?
        }
        AlgorithmId::MlDsa87EcdsaP384 => {
            verify_mldsa_sig::<ml_dsa::MlDsa87>(pqc_pk, message, &pqc_sig)?
        }
        _ => return Err(Error::UnsupportedAlgorithm(format!("{:?}", algorithm))),
    };

    // Verify classical component
    let classical_ok = match algorithm {
        AlgorithmId::MlDsa44EcdsaP256 | AlgorithmId::MlDsa65EcdsaP256 => {
            use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(&classical_pk).map_err(|e| {
                Error::InvalidCertificate(format!("Invalid P-256 public key: {}", e))
            })?;
            let sig = Signature::from_der(&classical_sig)
                .map_err(|e| Error::InvalidSignature(format!("Invalid P-256 signature: {}", e)))?;
            vk.verify(message, &sig).is_ok()
        }
        AlgorithmId::MlDsa65EcdsaP384 | AlgorithmId::MlDsa87EcdsaP384 => {
            use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(&classical_pk).map_err(|e| {
                Error::InvalidCertificate(format!("Invalid P-384 public key: {}", e))
            })?;
            let sig = Signature::from_der(&classical_sig)
                .map_err(|e| Error::InvalidSignature(format!("Invalid P-384 signature: {}", e)))?;
            vk.verify(message, &sig).is_ok()
        }
        _ => return Err(Error::UnsupportedAlgorithm(format!("{:?}", algorithm))),
    };

    Ok(pqc_ok && classical_ok)
}

/// Extract raw public key bytes from SPKI content (the inner bytes of a SEQUENCE).
/// SPKI content = AlgorithmIdentifier (SEQUENCE) || subjectPublicKey (BIT STRING)
fn extract_raw_pk_from_spki_content(spki_content: &[u8]) -> Result<Vec<u8>> {
    // Skip the AlgorithmIdentifier SEQUENCE
    let (_alg_id_content, rest) = decode_der_element_raw(spki_content)?;
    // Parse the BIT STRING containing the raw public key
    let (pk_bytes, _) = decode_bitstring(rest)?;
    Ok(pk_bytes)
}

/// Verify ML-DSA signature for a specific parameter set
fn verify_mldsa_sig<P>(pk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<bool>
where
    P: ml_dsa::MlDsaParams,
{
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Signature, VerifyingKey};
    let encoded_vk: EncodedVerifyingKey<P> = pk_bytes.try_into().map_err(|_| {
        Error::InvalidCertificate(format!(
            "Invalid ML-DSA public key length: {}",
            pk_bytes.len()
        ))
    })?;
    let vk = VerifyingKey::<P>::decode(&encoded_vk);
    let encoded_sig: EncodedSignature<P> = sig_bytes.try_into().map_err(|_| {
        Error::InvalidSignature(format!(
            "Invalid ML-DSA signature length: {}",
            sig_bytes.len()
        ))
    })?;
    let sig = Signature::<P>::decode(&encoded_sig)
        .ok_or_else(|| Error::InvalidSignature("Invalid ML-DSA signature encoding".into()))?;
    Ok(vk.verify_with_context(message, &[], &sig))
}

/// Decode a raw DER element, returning the content bytes and remaining data.
/// Handles both short and long form lengths.
fn decode_der_element_raw(data: &[u8]) -> Result<(&[u8], &[u8])> {
    if data.len() < 2 {
        return Err(Error::Decoding("DER element too short".into()));
    }
    let _tag = data[0];
    let (len, header_len) = if data[1] & 0x80 == 0 {
        (data[1] as usize, 2)
    } else {
        let num_bytes = (data[1] & 0x7F) as usize;
        if num_bytes > 4 || data.len() < 2 + num_bytes {
            return Err(Error::Decoding("Invalid DER length encoding".into()));
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | (data[2 + i] as usize);
        }
        (len, 2 + num_bytes)
    };
    if data.len() < header_len + len {
        return Err(Error::Decoding("DER element truncated".into()));
    }
    Ok((
        &data[header_len..header_len + len],
        &data[header_len + len..],
    ))
}

/// Encode composite signature as DER SEQUENCE
/// CompositeSignatureValue ::= SEQUENCE {
///     pqcSignature    BIT STRING,
///     classicalSignature BIT STRING
/// }
fn encode_composite_signature(pqc_sig: &[u8], classical_sig: &[u8]) -> Result<Vec<u8>> {
    // BIT STRING encoding: tag (0x03) + length + unused bits (0x00) + data
    let pqc_bitstring = encode_bitstring(pqc_sig);
    let classical_bitstring = encode_bitstring(classical_sig);

    // SEQUENCE encoding
    let inner_len = pqc_bitstring.len() + classical_bitstring.len();
    let mut result = Vec::with_capacity(inner_len + 10);

    // SEQUENCE tag
    result.push(0x30);
    encode_length(inner_len, &mut result);
    result.extend_from_slice(&pqc_bitstring);
    result.extend_from_slice(&classical_bitstring);

    Ok(result)
}

/// Decode composite signature from DER SEQUENCE
fn decode_composite_signature(signature: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if signature.is_empty() || signature[0] != 0x30 {
        return Err(Error::Decoding(
            "Invalid composite signature: not a SEQUENCE".into(),
        ));
    }

    let (content, _) = decode_der_element(signature)?;

    // Parse two BIT STRINGs from the sequence content
    let (pqc_sig, rest) = decode_bitstring(content)?;
    let (classical_sig, _) = decode_bitstring(rest)?;

    Ok((pqc_sig, classical_sig))
}

/// Encode composite public key as SPKI
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm   AlgorithmIdentifier,
///     subjectPublicKey BIT STRING containing CompositePublicKey
/// }
/// CompositePublicKey ::= SEQUENCE {
///     pqcPublicKey    SPKI,
///     classicalPublicKey SPKI
/// }
fn encode_composite_public_key(
    pqc_pk: &[u8],
    classical_pk: &[u8],
    algorithm: AlgorithmId,
) -> Result<Vec<u8>> {
    // Build inner CompositePublicKey SEQUENCE
    let inner_len = pqc_pk.len() + classical_pk.len();
    let mut composite_pk = Vec::with_capacity(inner_len + 10);
    composite_pk.push(0x30); // SEQUENCE
    encode_length(inner_len, &mut composite_pk);
    composite_pk.extend_from_slice(pqc_pk);
    composite_pk.extend_from_slice(classical_pk);

    // Build AlgorithmIdentifier
    let oid = algorithm.signature_oid();
    let oid_bytes = oid.as_bytes();
    let mut alg_id = vec![
        0x30,                        // SEQUENCE
        (oid_bytes.len() + 2) as u8, // OID tag + length + OID
        0x06,                        // OBJECT IDENTIFIER
        oid_bytes.len() as u8,
    ];
    alg_id.extend_from_slice(oid_bytes);

    // Build SubjectPublicKeyInfo
    let pk_bitstring = encode_bitstring(&composite_pk);
    let spki_inner_len = alg_id.len() + pk_bitstring.len();
    let mut spki = Vec::with_capacity(spki_inner_len + 10);
    spki.push(0x30); // SEQUENCE
    encode_length(spki_inner_len, &mut spki);
    spki.extend_from_slice(&alg_id);
    spki.extend_from_slice(&pk_bitstring);

    Ok(spki)
}

/// Encode a BIT STRING
fn encode_bitstring(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len() + 10);
    result.push(0x03); // BIT STRING tag
    encode_length(data.len() + 1, &mut result); // +1 for unused bits byte
    result.push(0x00); // unused bits
    result.extend_from_slice(data);
    result
}

/// Decode a BIT STRING, returning (content, remaining)
fn decode_bitstring(data: &[u8]) -> Result<(Vec<u8>, &[u8])> {
    if data.is_empty() || data[0] != 0x03 {
        return Err(Error::Decoding("Expected BIT STRING".into()));
    }

    let (content, rest) = decode_der_element(data)?;
    if content.is_empty() {
        return Err(Error::Decoding("Empty BIT STRING".into()));
    }

    // First byte is unused bits count
    let _unused_bits = content[0];
    Ok((content[1..].to_vec(), rest))
}

/// Decode a DER element, returning (content, remaining)
fn decode_der_element(data: &[u8]) -> Result<(&[u8], &[u8])> {
    if data.len() < 2 {
        return Err(Error::Decoding("DER element too short".into()));
    }

    let _tag = data[0];
    let (length, header_len) = decode_length(&data[1..])?;

    let total_len = 1 + header_len + length;
    if data.len() < total_len {
        return Err(Error::Decoding("DER element truncated".into()));
    }

    let content = &data[1 + header_len..1 + header_len + length];
    let rest = &data[total_len..];

    Ok((content, rest))
}

/// Encode DER length
fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 65536 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// Decode DER length, returning (length, bytes_consumed)
fn decode_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(Error::Decoding("Missing length byte".into()));
    }

    let first = data[0];
    if first < 128 {
        Ok((first as usize, 1))
    } else {
        let num_octets = (first & 0x7f) as usize;
        if data.len() < 1 + num_octets {
            return Err(Error::Decoding("Truncated length".into()));
        }
        let mut length = 0usize;
        for i in 0..num_octets {
            length = (length << 8) | (data[1 + i] as usize);
        }
        Ok((length, 1 + num_octets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_composite_generate_and_sign() {
        let kp = CompositeKeyPair::generate(AlgorithmId::MlDsa65EcdsaP256).unwrap();
        assert_eq!(kp.algorithm_id(), AlgorithmId::MlDsa65EcdsaP256);

        let message = b"test message for composite signature";
        let signature = kp.sign(message).unwrap();

        // Signature should be a SEQUENCE
        assert_eq!(signature[0], 0x30);

        // Verify should succeed
        assert!(kp.verify(message, &signature).unwrap());

        // Wrong message should fail
        assert!(!kp.verify(b"wrong message", &signature).unwrap());
    }

    #[test]
    fn test_all_composite_variants() {
        let variants = [
            AlgorithmId::MlDsa44EcdsaP256,
            AlgorithmId::MlDsa65EcdsaP256,
            AlgorithmId::MlDsa65EcdsaP384,
            AlgorithmId::MlDsa87EcdsaP384,
        ];

        for algo in variants {
            let kp = CompositeKeyPair::generate(algo).unwrap();
            assert_eq!(kp.algorithm_id(), algo);

            let msg = b"test";
            let sig = kp.sign(msg).unwrap();
            assert!(kp.verify(msg, &sig).unwrap());
        }
    }

    #[test]
    fn test_composite_public_key() {
        let kp = CompositeKeyPair::generate(AlgorithmId::MlDsa65EcdsaP256).unwrap();
        let pk_der = kp.public_key_der().unwrap();

        // Should be a valid SPKI (starts with SEQUENCE)
        assert_eq!(pk_der[0], 0x30);
        assert!(pk_der.len() > 100); // Should be substantial size
    }
}
