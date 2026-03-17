//! FIPS-aware digest helpers
//!
//! Thin wrappers over SHA-2 and SHA-3 hash functions that select the correct
//! backend at compile time:
//! - Default: RustCrypto `sha2` / `sha3` crates
//! - `--features fips`: aws-lc-rs (FIPS 140-3 certified, NIST Certificate #4816)
//!
//! SHA-3 (FIPS 202 / RFC 8702) is always provided via the `sha3` crate regardless
//! of the `fips` feature — aws-lc-rs doesn't expose SHA-3 in its public API yet.
//!
//! These helpers are used throughout spork-core to ensure all hashing operations
//! use the FIPS-certified module when the `fips` feature is enabled.

// ---- One-shot digests ----

/// Compute SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    #[cfg(not(feature = "fips"))]
    {
        use sha2::Digest;
        sha2::Sha256::digest(data).to_vec()
    }
    #[cfg(feature = "fips")]
    {
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
            .as_ref()
            .to_vec()
    }
}

/// Compute SHA-384 digest of `data`.
pub fn sha384(data: &[u8]) -> Vec<u8> {
    #[cfg(not(feature = "fips"))]
    {
        use sha2::Digest;
        sha2::Sha384::digest(data).to_vec()
    }
    #[cfg(feature = "fips")]
    {
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, data)
            .as_ref()
            .to_vec()
    }
}

/// Compute SHA-512 digest of `data`.
pub fn sha512(data: &[u8]) -> Vec<u8> {
    #[cfg(not(feature = "fips"))]
    {
        use sha2::Digest;
        sha2::Sha512::digest(data).to_vec()
    }
    #[cfg(feature = "fips")]
    {
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512, data)
            .as_ref()
            .to_vec()
    }
}

// ---- SHA-3 one-shot digests (FIPS 202 / RFC 8702) ----

/// Compute SHA3-256 digest of `data`.
pub fn sha3_256(data: &[u8]) -> Vec<u8> {
    use sha3::Digest;
    sha3::Sha3_256::digest(data).to_vec()
}

/// Compute SHA3-384 digest of `data`.
pub fn sha3_384(data: &[u8]) -> Vec<u8> {
    use sha3::Digest;
    sha3::Sha3_384::digest(data).to_vec()
}

/// Compute SHA3-512 digest of `data`.
pub fn sha3_512(data: &[u8]) -> Vec<u8> {
    use sha3::Digest;
    sha3::Sha3_512::digest(data).to_vec()
}

// ---- Streaming SHA-256 hasher ----

/// Incremental SHA-256 hasher for multi-part data.
#[cfg(not(feature = "fips"))]
pub struct Sha256Hasher(sha2::Sha256);

/// Incremental SHA-256 hasher for multi-part data.
#[cfg(feature = "fips")]
pub struct Sha256Hasher(aws_lc_rs::digest::Context);

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Hasher {
    /// Create a new SHA-256 hasher.
    pub fn new() -> Self {
        #[cfg(not(feature = "fips"))]
        {
            use sha2::Digest;
            Self(sha2::Sha256::new())
        }
        #[cfg(feature = "fips")]
        {
            Self(aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256))
        }
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        #[cfg(not(feature = "fips"))]
        {
            use sha2::Digest;
            self.0.update(data);
        }
        #[cfg(feature = "fips")]
        {
            self.0.update(data);
        }
    }

    /// Finalize and return the digest as a byte vector.
    pub fn finalize(self) -> Vec<u8> {
        #[cfg(not(feature = "fips"))]
        {
            use sha2::Digest;
            self.0.finalize().to_vec()
        }
        #[cfg(feature = "fips")]
        {
            self.0.finish().as_ref().to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_answer() {
        // SHA-256("abc") — NIST test vector
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(sha256(b"abc"), expected);
    }

    #[test]
    fn test_sha256_empty() {
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(sha256(b""), expected);
    }

    #[test]
    fn test_sha384_known_answer() {
        let result = sha384(b"abc");
        assert_eq!(result.len(), 48);
        assert_eq!(result[0], 0xcb);
    }

    #[test]
    fn test_sha512_known_answer() {
        let result = sha512(b"abc");
        assert_eq!(result.len(), 64);
        assert_eq!(result[0], 0xdd);
    }

    #[test]
    fn test_sha256_hasher_streaming() {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"ab");
        hasher.update(b"c");
        let streamed = hasher.finalize();
        let one_shot = sha256(b"abc");
        assert_eq!(streamed, one_shot);
    }

    #[test]
    fn test_sha256_hasher_empty() {
        let hasher = Sha256Hasher::new();
        let result = hasher.finalize();
        assert_eq!(result, sha256(b""));
    }

    // ---- SHA-3 tests (FIPS 202) ----

    #[test]
    fn test_sha3_256_known_answer() {
        // SHA3-256("abc") — NIST test vector
        let result = sha3_256(b"abc");
        assert_eq!(result.len(), 32);
        assert_eq!(result[0], 0x3a);
        assert_eq!(result[1], 0x98);
    }

    #[test]
    fn test_sha3_256_empty() {
        let result = sha3_256(b"");
        assert_eq!(result.len(), 32);
        // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662...
        assert_eq!(result[0], 0xa7);
    }

    #[test]
    fn test_sha3_384_known_answer() {
        let result = sha3_384(b"abc");
        assert_eq!(result.len(), 48);
        // SHA3-384("abc") starts with 0xec
        assert_eq!(result[0], 0xec);
    }

    #[test]
    fn test_sha3_512_known_answer() {
        let result = sha3_512(b"abc");
        assert_eq!(result.len(), 64);
        // SHA3-512("abc") starts with 0xb7
        assert_eq!(result[0], 0xb7);
    }

    #[test]
    fn test_sha3_256_differs_from_sha256() {
        let sha2_result = sha256(b"test");
        let sha3_result = sha3_256(b"test");
        assert_eq!(sha2_result.len(), sha3_result.len());
        assert_ne!(
            sha2_result, sha3_result,
            "SHA-256 and SHA3-256 must produce different digests"
        );
    }
}
