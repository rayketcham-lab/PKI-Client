//! RSAES-OAEP encryption/decryption (RFC 8017 §7.1)
//!
//! Implements RSAES-OAEP (Optimal Asymmetric Encryption Padding) per
//! PKCS#1 v2.2 (RFC 8017). Used for key transport in CMS EnvelopedData
//! and key archival operations.
//!
//! Supported configurations:
//! - OAEP with SHA-256 and MGF1-SHA-256 (recommended)
//! - OAEP with SHA-384 and MGF1-SHA-384
//! - OAEP with SHA-512 and MGF1-SHA-512
//! - OAEP with SHA-1 and MGF1-SHA-1 (legacy compatibility only)
//!
//! # Example
//!
//! ```rust,ignore
//! use spork_core::algo::rsa_oaep::{oaep_encrypt, oaep_decrypt, OaepHash};
//!
//! let kp = KeyPair::generate(AlgorithmId::Rsa2048).unwrap();
//! let pub_der = kp.public_key_der().unwrap();
//! let priv_der = kp.private_key_der().unwrap();
//!
//! let plaintext = b"session key material";
//! let ciphertext = oaep_encrypt(&pub_der, plaintext, OaepHash::Sha256, None).unwrap();
//! let recovered = oaep_decrypt(&priv_der, &ciphertext, OaepHash::Sha256, None).unwrap();
//! assert_eq!(plaintext.as_slice(), recovered.as_slice());
//! ```

use pkcs8::{DecodePrivateKey, DecodePublicKey};
use rand_core::OsRng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Hash algorithm for OAEP padding (RFC 8017 §7.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OaepHash {
    /// SHA-1 (legacy — use only for interoperability with existing systems)
    Sha1,
    /// SHA-256 (recommended default)
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

/// RSAES-OAEP encrypt (RFC 8017 §7.1.1).
///
/// Encrypts `plaintext` using the RSA public key encoded as SPKI DER.
/// The plaintext must be shorter than `k - 2*hLen - 2` bytes where `k`
/// is the RSA modulus size in bytes and `hLen` is the hash output length.
///
/// # Arguments
///
/// * `public_key_der` — SPKI-encoded RSA public key (DER bytes)
/// * `plaintext` — Data to encrypt (typically a symmetric key, 16-64 bytes)
/// * `hash` — Hash algorithm for OAEP padding
/// * `label` — Optional label (most protocols use empty label)
pub fn oaep_encrypt(
    public_key_der: &[u8],
    plaintext: &[u8],
    hash: OaepHash,
    label: Option<&str>,
) -> Result<Vec<u8>> {
    let pub_key = RsaPublicKey::from_public_key_der(public_key_der)
        .map_err(|e| Error::InvalidKey(format!("RSA OAEP: invalid SPKI public key: {}", e)))?;

    let label_str = label.unwrap_or("");

    match hash {
        OaepHash::Sha1 => {
            let padding = Oaep::new_with_label::<sha1::Sha1, _>(label_str);
            pub_key
                .encrypt(&mut OsRng, padding, plaintext)
                .map_err(|e| Error::SigningError(format!("RSA OAEP encrypt (SHA-1): {}", e)))
        }
        OaepHash::Sha256 => {
            let padding = Oaep::new_with_label::<sha2::Sha256, _>(label_str);
            pub_key
                .encrypt(&mut OsRng, padding, plaintext)
                .map_err(|e| Error::SigningError(format!("RSA OAEP encrypt (SHA-256): {}", e)))
        }
        OaepHash::Sha384 => {
            let padding = Oaep::new_with_label::<sha2::Sha384, _>(label_str);
            pub_key
                .encrypt(&mut OsRng, padding, plaintext)
                .map_err(|e| Error::SigningError(format!("RSA OAEP encrypt (SHA-384): {}", e)))
        }
        OaepHash::Sha512 => {
            let padding = Oaep::new_with_label::<sha2::Sha512, _>(label_str);
            pub_key
                .encrypt(&mut OsRng, padding, plaintext)
                .map_err(|e| Error::SigningError(format!("RSA OAEP encrypt (SHA-512): {}", e)))
        }
    }
}

/// RSAES-OAEP decrypt (RFC 8017 §7.1.2).
///
/// Decrypts `ciphertext` using the RSA private key encoded as PKCS#8 DER.
/// Returns the original plaintext as a `Zeroizing<Vec<u8>>` to prevent
/// key material from lingering in memory.
///
/// # Arguments
///
/// * `private_key_der` — PKCS#8-encoded RSA private key (DER bytes)
/// * `ciphertext` — Data to decrypt (must be exactly `k` bytes)
/// * `hash` — Hash algorithm for OAEP padding (must match encryption)
/// * `label` — Optional label (must match encryption)
pub fn oaep_decrypt(
    private_key_der: &[u8],
    ciphertext: &[u8],
    hash: OaepHash,
    label: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    let priv_key = RsaPrivateKey::from_pkcs8_der(private_key_der)
        .map_err(|e| Error::InvalidKey(format!("RSA OAEP: invalid PKCS#8 private key: {}", e)))?;

    let label_str = label.unwrap_or("");

    let plaintext = match hash {
        OaepHash::Sha1 => {
            let padding = Oaep::new_with_label::<sha1::Sha1, _>(label_str);
            priv_key
                .decrypt(padding, ciphertext)
                .map_err(|e| Error::SigningError(format!("RSA OAEP decrypt (SHA-1): {}", e)))
        }
        OaepHash::Sha256 => {
            let padding = Oaep::new_with_label::<sha2::Sha256, _>(label_str);
            priv_key
                .decrypt(padding, ciphertext)
                .map_err(|e| Error::SigningError(format!("RSA OAEP decrypt (SHA-256): {}", e)))
        }
        OaepHash::Sha384 => {
            let padding = Oaep::new_with_label::<sha2::Sha384, _>(label_str);
            priv_key
                .decrypt(padding, ciphertext)
                .map_err(|e| Error::SigningError(format!("RSA OAEP decrypt (SHA-384): {}", e)))
        }
        OaepHash::Sha512 => {
            let padding = Oaep::new_with_label::<sha2::Sha512, _>(label_str);
            priv_key
                .decrypt(padding, ciphertext)
                .map_err(|e| Error::SigningError(format!("RSA OAEP decrypt (SHA-512): {}", e)))
        }
    }?;

    Ok(Zeroizing::new(plaintext))
}

/// Maximum plaintext length for OAEP encryption with a given key size and hash.
///
/// Per RFC 8017 §7.1.1: `mLen <= k - 2*hLen - 2`
pub fn max_oaep_plaintext_len(key_bits: usize, hash: OaepHash) -> usize {
    let k = key_bits / 8; // modulus size in bytes
    let h_len = match hash {
        OaepHash::Sha1 => 20,
        OaepHash::Sha256 => 32,
        OaepHash::Sha384 => 48,
        OaepHash::Sha512 => 64,
    };
    if k < 2 * h_len + 2 {
        0
    } else {
        k - 2 * h_len - 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algo::{AlgorithmId, KeyPair};

    fn generate_rsa_keys(algo: AlgorithmId) -> (Vec<u8>, Vec<u8>) {
        let kp = KeyPair::generate(algo).unwrap();
        let pub_der = kp.public_key_der().unwrap();
        let priv_der = kp.private_key_der().unwrap();
        (pub_der, priv_der.to_vec())
    }

    #[test]
    fn test_oaep_sha256_roundtrip() {
        let (pub_der, priv_der) = generate_rsa_keys(AlgorithmId::Rsa2048);
        let plaintext = b"AES-256 session key material!!";
        let ciphertext = oaep_encrypt(&pub_der, plaintext, OaepHash::Sha256, None).unwrap();
        assert_eq!(ciphertext.len(), 256); // 2048-bit key → 256-byte ciphertext
        let recovered = oaep_decrypt(&priv_der, &ciphertext, OaepHash::Sha256, None).unwrap();
        assert_eq!(plaintext.as_slice(), recovered.as_slice());
    }

    #[test]
    fn test_oaep_sha384_roundtrip() {
        let (pub_der, priv_der) = generate_rsa_keys(AlgorithmId::Rsa2048);
        let plaintext = b"key transport payload";
        let ciphertext = oaep_encrypt(&pub_der, plaintext, OaepHash::Sha384, None).unwrap();
        let recovered = oaep_decrypt(&priv_der, &ciphertext, OaepHash::Sha384, None).unwrap();
        assert_eq!(plaintext.as_slice(), recovered.as_slice());
    }

    #[test]
    fn test_oaep_sha512_roundtrip() {
        let (pub_der, priv_der) = generate_rsa_keys(AlgorithmId::Rsa2048);
        let plaintext = b"short key";
        let ciphertext = oaep_encrypt(&pub_der, plaintext, OaepHash::Sha512, None).unwrap();
        let recovered = oaep_decrypt(&priv_der, &ciphertext, OaepHash::Sha512, None).unwrap();
        assert_eq!(plaintext.as_slice(), recovered.as_slice());
    }

    #[test]
    fn test_oaep_sha1_roundtrip_legacy() {
        let (pub_der, priv_der) = generate_rsa_keys(AlgorithmId::Rsa2048);
        let plaintext = b"legacy interop";
        let ciphertext = oaep_encrypt(&pub_der, plaintext, OaepHash::Sha1, None).unwrap();
        let recovered = oaep_decrypt(&priv_der, &ciphertext, OaepHash::Sha1, None).unwrap();
        assert_eq!(plaintext.as_slice(), recovered.as_slice());
    }

    #[test]
    fn test_oaep_with_label() {
        let (pub_der, priv_der) = generate_rsa_keys(AlgorithmId::Rsa2048);
        let plaintext = b"labeled encryption";
        let label = "CMS-EnvelopedData";
        let ciphertext = oaep_encrypt(&pub_der, plaintext, OaepHash::Sha256, Some(label)).unwrap();
        let recovered =
            oaep_decrypt(&priv_der, &ciphertext, OaepHash::Sha256, Some(label)).unwrap();
        assert_eq!(plaintext.as_slice(), recovered.as_slice());
    }

    #[test]
    fn test_oaep_wrong_label_fails() {
        let (pub_der, priv_der) = generate_rsa_keys(AlgorithmId::Rsa2048);
        let plaintext = b"test data";
        let ciphertext =
            oaep_encrypt(&pub_der, plaintext, OaepHash::Sha256, Some("label-A")).unwrap();
        let result = oaep_decrypt(&priv_der, &ciphertext, OaepHash::Sha256, Some("label-B"));
        assert!(result.is_err(), "Decryption with wrong label should fail");
    }

    #[test]
    fn test_oaep_wrong_hash_fails() {
        let (pub_der, priv_der) = generate_rsa_keys(AlgorithmId::Rsa2048);
        let plaintext = b"test data";
        let ciphertext = oaep_encrypt(&pub_der, plaintext, OaepHash::Sha256, None).unwrap();
        let result = oaep_decrypt(&priv_der, &ciphertext, OaepHash::Sha384, None);
        assert!(
            result.is_err(),
            "Decryption with mismatched hash should fail"
        );
    }

    #[test]
    fn test_oaep_wrong_key_fails() {
        let (pub_der, _) = generate_rsa_keys(AlgorithmId::Rsa2048);
        let (_, other_priv) = generate_rsa_keys(AlgorithmId::Rsa2048);
        let plaintext = b"test data";
        let ciphertext = oaep_encrypt(&pub_der, plaintext, OaepHash::Sha256, None).unwrap();
        let result = oaep_decrypt(&other_priv, &ciphertext, OaepHash::Sha256, None);
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_oaep_empty_plaintext() {
        let (pub_der, priv_der) = generate_rsa_keys(AlgorithmId::Rsa2048);
        let plaintext = b"";
        let ciphertext = oaep_encrypt(&pub_der, plaintext, OaepHash::Sha256, None).unwrap();
        let recovered = oaep_decrypt(&priv_der, &ciphertext, OaepHash::Sha256, None).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_oaep_max_plaintext_length() {
        // RSA-2048 with SHA-256: max = 256 - 2*32 - 2 = 190 bytes
        assert_eq!(max_oaep_plaintext_len(2048, OaepHash::Sha256), 190);

        // RSA-2048 with SHA-1: max = 256 - 2*20 - 2 = 214 bytes
        assert_eq!(max_oaep_plaintext_len(2048, OaepHash::Sha1), 214);

        // RSA-2048 with SHA-384: max = 256 - 2*48 - 2 = 158 bytes
        assert_eq!(max_oaep_plaintext_len(2048, OaepHash::Sha384), 158);

        // RSA-2048 with SHA-512: max = 256 - 2*64 - 2 = 126 bytes
        assert_eq!(max_oaep_plaintext_len(2048, OaepHash::Sha512), 126);

        // RSA-4096 with SHA-256: max = 512 - 2*32 - 2 = 446 bytes
        assert_eq!(max_oaep_plaintext_len(4096, OaepHash::Sha256), 446);
    }

    #[test]
    fn test_oaep_plaintext_too_large() {
        let (pub_der, _) = generate_rsa_keys(AlgorithmId::Rsa2048);
        // Max for RSA-2048/SHA-256 is 190 bytes, try 200
        let too_large = vec![0xAA; 200];
        let result = oaep_encrypt(&pub_der, &too_large, OaepHash::Sha256, None);
        assert!(
            result.is_err(),
            "Plaintext exceeding max length should fail"
        );
    }

    #[test]
    fn test_oaep_invalid_public_key() {
        let result = oaep_encrypt(
            &[0x30, 0x03, 0x01, 0x01, 0x00],
            b"test",
            OaepHash::Sha256,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_oaep_invalid_private_key() {
        let result = oaep_decrypt(
            &[0x30, 0x03, 0x01, 0x01, 0x00],
            b"test",
            OaepHash::Sha256,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_oaep_ciphertext_is_randomized() {
        let (pub_der, _) = generate_rsa_keys(AlgorithmId::Rsa2048);
        let plaintext = b"same plaintext";
        let ct1 = oaep_encrypt(&pub_der, plaintext, OaepHash::Sha256, None).unwrap();
        let ct2 = oaep_encrypt(&pub_der, plaintext, OaepHash::Sha256, None).unwrap();
        assert_ne!(
            ct1, ct2,
            "OAEP encryption must be randomized (different ciphertext each time)"
        );
    }

    #[test]
    fn test_oaep_zeroizing_output() {
        let (pub_der, priv_der) = generate_rsa_keys(AlgorithmId::Rsa2048);
        let plaintext = b"sensitive key material";
        let ciphertext = oaep_encrypt(&pub_der, plaintext, OaepHash::Sha256, None).unwrap();
        let recovered = oaep_decrypt(&priv_der, &ciphertext, OaepHash::Sha256, None).unwrap();
        // Verify it's a Zeroizing wrapper
        assert_eq!(recovered.as_slice(), plaintext.as_slice());
        // When `recovered` drops, memory is zeroed (can't test at runtime, but type enforces it)
    }
}
