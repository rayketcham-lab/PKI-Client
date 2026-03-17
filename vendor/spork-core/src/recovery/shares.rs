//! Recovery share encoding using unambiguous characters
//!
//! Character set (24 chars, no ambiguous pairs):
//! A C D E F G H J K M N P Q R T W X Y 3 4 6 7 9
//!
//! Excluded (ambiguous): 0 O 1 I L 2 Z 5 S 8 B U V

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::rngs::OsRng;
use sharks::{Share, Sharks};
use std::collections::HashSet;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Unambiguous character set (24 characters)
pub const SHARE_ALPHABET: &[u8] = b"ACDEFGHJKMNPQRTWXY346789";

/// Recovery share threshold configuration
pub const TOTAL_SHARES: u8 = 3;
pub const LEVEL1_THRESHOLD: u8 = 2;
pub const LEVEL2_THRESHOLD: u8 = 3;

/// Single recovery share (printed on paper, given to custodian)
/// Format: SHARE-N-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX
///
/// Uses 64 base-24 characters (8 groups of 8) to encode up to 36 bytes of share data,
/// which is sufficient for the 33-byte shares produced by the `sharks` crate.
#[derive(Clone, ZeroizeOnDrop)]
#[allow(unused_assignments)] // False positive from ZeroizeOnDrop derive
pub struct RecoveryShare {
    #[zeroize(skip)]
    pub number: u8,
    #[zeroize(skip)]
    pub custodian: String,
    data: Vec<u8>,
}

impl RecoveryShare {
    /// Create new share
    pub fn new(number: u8, custodian: String, data: Vec<u8>) -> Self {
        Self {
            number,
            custodian,
            data,
        }
    }

    /// Format for display/printing: SHARE-1-XXXXXXXX-XXXXXXXX-...-XXXXXXXX
    pub fn to_display_string(&self) -> String {
        let encoded = encode_base24(&self.data);
        let groups: Vec<&str> = encoded
            .as_bytes()
            .chunks(8)
            .map(|chunk| std::str::from_utf8(chunk).expect("base24 is ASCII"))
            .collect();
        format!("SHARE-{}-{}", self.number, groups.join("-"))
    }

    /// Parse from display string (case-insensitive)
    pub fn from_display_string(s: &str) -> Result<Self, ShareError> {
        let s = s.trim().to_uppercase();

        if !s.starts_with("SHARE-") {
            return Err(ShareError::InvalidFormat("Must start with SHARE-".into()));
        }

        let parts: Vec<&str> = s.split('-').collect();
        // Minimum: SHARE-N-GROUP1 (3 parts), typical: SHARE-N-G1-G2-...-G8 (10 parts)
        if parts.len() < 3 {
            return Err(ShareError::InvalidFormat(
                "Expected format SHARE-N-XXXXXXXX-XXXXXXXX-...".into(),
            ));
        }

        let number: u8 = parts[1]
            .parse()
            .map_err(|_| ShareError::InvalidFormat("Invalid share number".into()))?;

        if !(1..=3).contains(&number) {
            return Err(ShareError::InvalidFormat(
                "Share number must be 1, 2, or 3".into(),
            ));
        }

        // Concatenate all data groups (everything after SHARE-N-)
        let data_str: String = parts[2..].concat();

        // Validate characters
        for c in data_str.chars() {
            if !SHARE_ALPHABET.contains(&(c as u8)) {
                return Err(ShareError::InvalidCharacter(c));
            }
        }

        let data = decode_base24(&data_str)?;

        Ok(Self {
            number,
            custodian: String::new(),
            data,
        })
    }

    /// Get raw bytes for Shamir reconstruction
    pub fn to_shark_share(&self) -> Result<Share, ShareError> {
        Share::try_from(self.data.as_slice()).map_err(|_| ShareError::InvalidShareData)
    }

    /// Get share number
    pub fn get_number(&self) -> u8 {
        self.number
    }

    /// Get custodian name
    pub fn get_custodian(&self) -> &str {
        &self.custodian
    }
}

impl std::fmt::Debug for RecoveryShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryShare")
            .field("number", &self.number)
            .field("custodian", &self.custodian)
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// Collection of all 3 shares (created during ceremony)
pub struct RecoveryShares {
    pub shares: [RecoveryShare; 3],
    pub secret_hash: String,
}

impl RecoveryShares {
    /// Generate new recovery shares with custodian names
    pub fn generate(
        custodian1: &str,
        custodian2: &str,
        custodian3: &str,
    ) -> Result<Self, ShareError> {
        // Generate random 32-byte secret
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).map_err(|_| ShareError::RandomGenerationFailed)?;

        // Create Shamir shares (2-of-3 minimum for reconstruction)
        // We use threshold=2 for Shamir, but enforce 3/3 at app level for Level 2
        let sharks = Sharks(2);
        let dealer = sharks.dealer(&secret);
        let shark_shares: Vec<Share> = dealer.take(3).collect();

        // Convert to our format
        let shares = [
            RecoveryShare::new(1, custodian1.to_string(), Vec::from(&shark_shares[0])),
            RecoveryShare::new(2, custodian2.to_string(), Vec::from(&shark_shares[1])),
            RecoveryShare::new(3, custodian3.to_string(), Vec::from(&shark_shares[2])),
        ];

        // Hash secret for verification (store only the hash)
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let secret_hash = argon2
            .hash_password(&secret, &salt)
            .map_err(|_| ShareError::HashingFailed)?
            .to_string();

        // Zeroize secret
        secret.zeroize();

        Ok(Self {
            shares,
            secret_hash,
        })
    }

    /// Verify shares and return true if valid
    pub fn verify_shares(shares: &[RecoveryShare], stored_hash: &str) -> Result<bool, ShareError> {
        if shares.len() < 2 {
            return Err(ShareError::InsufficientShares);
        }

        // Check for duplicate share numbers
        let mut seen = HashSet::new();
        for share in shares {
            if !seen.insert(share.number) {
                return Err(ShareError::DuplicateShares);
            }
        }

        // Reconstruct secret
        let sharks = Sharks(2);
        let shark_shares: Result<Vec<Share>, _> =
            shares.iter().map(|s| s.to_shark_share()).collect();
        let shark_shares = shark_shares?;

        let mut secret = sharks
            .recover(&shark_shares)
            .map_err(|_| ShareError::ReconstructionFailed)?;

        // Verify against stored hash
        let parsed_hash =
            PasswordHash::new(stored_hash).map_err(|_| ShareError::InvalidStoredHash)?;

        let result = Argon2::default()
            .verify_password(&secret, &parsed_hash)
            .is_ok();

        // Zeroize
        secret.zeroize();

        Ok(result)
    }
}

/// Number of base-24 characters needed to encode a shark share (33 bytes).
/// ceil(33 * 8 / log2(24)) = ceil(264 / 4.585) = 58, rounded up to 64 for clean 8-char groups.
const ENCODED_SHARE_LEN: usize = 64;

/// Encode bytes to base-24 using unambiguous alphabet.
///
/// Encodes ALL bytes of the input (up to 36 bytes / 288 bits) into a fixed-length
/// base-24 string of `ENCODED_SHARE_LEN` characters. The encoding uses big-integer
/// arithmetic to preserve every bit.
fn encode_base24(data: &[u8]) -> String {
    // Convert data to a big-endian big integer using a Vec<u8> as arbitrary-precision storage.
    // We repeatedly divide by 24 to extract base-24 digits.
    let mut num = data.to_vec();

    let mut result = Vec::with_capacity(ENCODED_SHARE_LEN);
    for _ in 0..ENCODED_SHARE_LEN {
        // Divide num by 24, collecting remainder
        let mut remainder = 0u16;
        for byte in num.iter_mut() {
            let value = (remainder << 8) | (*byte as u16);
            *byte = (value / 24) as u8;
            remainder = value % 24;
        }
        result.push(SHARE_ALPHABET[remainder as usize] as char);
    }

    // Reverse to get most-significant digit first
    result.into_iter().rev().collect()
}

/// Decode base-24 string to bytes (reconstructs the original share data).
///
/// Accepts any string length (supports both legacy 16-char and new 64-char formats).
fn decode_base24(s: &str) -> Result<Vec<u8>, ShareError> {
    // Multiply-and-add in base-256 to reconstruct the big integer
    let mut num: Vec<u8> = vec![0];

    for c in s.chars() {
        let index = SHARE_ALPHABET
            .iter()
            .position(|&x| x == c as u8)
            .ok_or(ShareError::InvalidCharacter(c))? as u16;

        // Multiply num by 24 and add index
        let mut carry = index;
        for byte in num.iter_mut().rev() {
            let value = (*byte as u16) * 24 + carry;
            *byte = (value & 0xFF) as u8;
            carry = value >> 8;
        }
        while carry > 0 {
            num.insert(0, (carry & 0xFF) as u8);
            carry >>= 8;
        }
    }

    // Strip leading zeros but preserve at least one byte
    while num.len() > 1 && num[0] == 0 {
        num.remove(0);
    }

    Ok(num)
}

/// Errors during share operations
#[derive(Debug, Clone)]
pub enum ShareError {
    /// Invalid share format
    InvalidFormat(String),
    /// Invalid character in share
    InvalidCharacter(char),
    /// Invalid share data
    InvalidShareData,
    /// Invalid stored hash
    InvalidStoredHash,
    /// Duplicate share numbers provided
    DuplicateShares,
    /// Insufficient shares provided
    InsufficientShares,
    /// Failed to reconstruct secret
    ReconstructionFailed,
    /// Failed to hash secret
    HashingFailed,
    /// Failed to generate random bytes
    RandomGenerationFailed,
}

impl std::fmt::Display for ShareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShareError::InvalidFormat(msg) => write!(f, "Invalid share format: {}", msg),
            ShareError::InvalidCharacter(c) => write!(f, "Invalid character '{}' in share", c),
            ShareError::InvalidShareData => write!(f, "Invalid share data"),
            ShareError::InvalidStoredHash => write!(f, "Invalid stored hash"),
            ShareError::DuplicateShares => write!(f, "Duplicate share numbers provided"),
            ShareError::InsufficientShares => write!(f, "Insufficient shares provided"),
            ShareError::ReconstructionFailed => write!(f, "Failed to reconstruct secret"),
            ShareError::HashingFailed => write!(f, "Failed to hash secret"),
            ShareError::RandomGenerationFailed => write!(f, "Failed to generate random bytes"),
        }
    }
}

impl std::error::Error for ShareError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_roundtrip() {
        let shares = RecoveryShares::generate("Alice", "Bob", "Charlie").unwrap();

        for share in &shares.shares {
            let display = share.to_display_string();
            assert!(display.starts_with("SHARE-"));

            let parsed = RecoveryShare::from_display_string(&display).unwrap();
            assert_eq!(parsed.number, share.number);
        }
    }

    #[test]
    fn test_no_ambiguous_chars() {
        // Exclude visually confusable pairs - we include 8 but exclude B
        // 0/O, 1/I/L, 2/Z, 5/S, B (confusable with 8), U/V
        let ambiguous = b"0O1IL2Z5SBUV";
        for c in ambiguous {
            assert!(
                !SHARE_ALPHABET.contains(c),
                "Contains ambiguous char: {}",
                *c as char
            );
        }
    }

    #[test]
    fn test_alphabet_size() {
        assert_eq!(SHARE_ALPHABET.len(), 24);
    }

    #[test]
    fn test_2_of_3_recovery() {
        let shares = RecoveryShares::generate("A", "B", "C").unwrap();

        // Any 2 shares should work
        let result = RecoveryShares::verify_shares(
            &[shares.shares[0].clone(), shares.shares[1].clone()],
            &shares.secret_hash,
        )
        .unwrap();
        assert!(result);

        let result = RecoveryShares::verify_shares(
            &[shares.shares[1].clone(), shares.shares[2].clone()],
            &shares.secret_hash,
        )
        .unwrap();
        assert!(result);

        let result = RecoveryShares::verify_shares(
            &[shares.shares[0].clone(), shares.shares[2].clone()],
            &shares.secret_hash,
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_3_of_3_recovery() {
        let shares = RecoveryShares::generate("A", "B", "C").unwrap();

        let result = RecoveryShares::verify_shares(
            &[
                shares.shares[0].clone(),
                shares.shares[1].clone(),
                shares.shares[2].clone(),
            ],
            &shares.secret_hash,
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_wrong_shares_fail() {
        let shares1 = RecoveryShares::generate("A", "B", "C").unwrap();
        let shares2 = RecoveryShares::generate("X", "Y", "Z").unwrap();

        // Mix shares from different sets - should fail reconstruction or verification
        let result = RecoveryShares::verify_shares(
            &[shares1.shares[0].clone(), shares2.shares[1].clone()],
            &shares1.secret_hash,
        );

        // Should fail reconstruction or verification
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_duplicate_shares_rejected() {
        let shares = RecoveryShares::generate("A", "B", "C").unwrap();

        let result = RecoveryShares::verify_shares(
            &[shares.shares[0].clone(), shares.shares[0].clone()],
            &shares.secret_hash,
        );

        assert!(matches!(result, Err(ShareError::DuplicateShares)));
    }

    #[test]
    fn test_case_insensitive_parsing() {
        let shares = RecoveryShares::generate("A", "B", "C").unwrap();
        let display = shares.shares[0].to_display_string();

        // Lowercase should work
        let lower = display.to_lowercase();
        let parsed = RecoveryShare::from_display_string(&lower);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_share_format() {
        let shares = RecoveryShares::generate("A", "B", "C").unwrap();
        let display = shares.shares[0].to_display_string();

        // Check format: SHARE-N-XXXXXXXX-XXXXXXXX-...-XXXXXXXX (8 groups of 8)
        let parts: Vec<&str> = display.split('-').collect();
        assert_eq!(
            parts.len(),
            10,
            "Expected SHARE-N + 8 groups, got: {}",
            display
        );
        assert_eq!(parts[0], "SHARE");
        assert_eq!(parts[1], "1");
        for group in &parts[2..] {
            assert_eq!(
                group.len(),
                8,
                "Each group should be 8 chars, got: {}",
                group
            );
        }
    }

    #[test]
    fn test_share_data_fully_preserved() {
        // Verify that the full 33 bytes of share data survive encode/decode
        let shares = RecoveryShares::generate("A", "B", "C").unwrap();

        for share in &shares.shares {
            let display = share.to_display_string();
            let parsed = RecoveryShare::from_display_string(&display).unwrap();
            // The decoded data must match the original
            assert_eq!(
                parsed.data, share.data,
                "Share data must survive roundtrip (share {}): display={}",
                share.number, display
            );
        }
    }

    // ===== Recovery threshold enforcement =====

    /// Providing exactly 1 share to verify_shares must fail with InsufficientShares.
    /// The Shamir threshold is 2; reconstruction with fewer shares is cryptographically
    /// impossible and the API must reject it before attempting.
    #[test]
    fn test_one_share_below_threshold_returns_insufficient() {
        let shares = RecoveryShares::generate("A", "B", "C").unwrap();

        let result =
            RecoveryShares::verify_shares(&[shares.shares[0].clone()], &shares.secret_hash);

        assert!(
            matches!(result, Err(ShareError::InsufficientShares)),
            "Expected InsufficientShares when only 1 share is provided, got: {:?}",
            result
        );
    }

    /// Providing zero shares must fail with InsufficientShares (not a panic or wrong error).
    #[test]
    fn test_zero_shares_returns_insufficient() {
        let shares = RecoveryShares::generate("A", "B", "C").unwrap();

        let result = RecoveryShares::verify_shares(&[], &shares.secret_hash);

        assert!(
            matches!(result, Err(ShareError::InsufficientShares)),
            "Expected InsufficientShares when no shares are provided, got: {:?}",
            result
        );
    }
}
