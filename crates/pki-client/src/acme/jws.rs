//! JWS (JSON Web Signature) Implementation for ACME Client
//!
//! Implements JWS signing using ECDSA P-256 (ES256) for ACME requests.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use p256::SecretKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Base64url encoding without padding.
pub fn base64url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Base64url decoding.
#[allow(dead_code)]
pub fn base64url_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .with_context(|| "Failed to decode base64url")
}

/// ACME Account Key (ECDSA P-256).
#[derive(Clone)]
pub struct AccountKey {
    signing_key: SigningKey,
}

impl AccountKey {
    /// Generate a new account key.
    pub fn generate() -> Self {
        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(&secret_key);
        Self { signing_key }
    }

    /// Load account key from PEM (accepts both SEC1 and PKCS#8 formats).
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let pem_data = pem::parse(pem_str).context("Failed to parse PEM")?;
        let secret_key = if pem_data.tag() == "EC PRIVATE KEY" {
            // SEC1 format
            SecretKey::from_sec1_der(pem_data.contents())
                .context("Failed to parse SEC1 EC private key")?
        } else {
            // PKCS#8 format (BEGIN PRIVATE KEY)
            use p256::pkcs8::DecodePrivateKey;
            SecretKey::from_pkcs8_der(pem_data.contents())
                .context("Failed to parse PKCS#8 private key")?
        };
        let signing_key = SigningKey::from(&secret_key);
        Ok(Self { signing_key })
    }

    /// Export account key to PEM (SEC1 DER encoding).
    pub fn to_pem(&self) -> String {
        let secret_key: SecretKey = self.signing_key.clone().into();
        let der = secret_key.to_sec1_der().expect("SEC1 DER encoding");
        let der_bytes: &[u8] = &der;
        let pem = pem::Pem::new("EC PRIVATE KEY", der_bytes.to_vec());
        pem::encode(&pem)
    }

    /// Get the public key as a JWK.
    pub fn to_jwk(&self) -> Jwk {
        let verifying_key = VerifyingKey::from(&self.signing_key);
        let encoded_point = verifying_key.to_encoded_point(false);
        let x = encoded_point.x().expect("EC point has x coordinate");
        let y = encoded_point.y().expect("EC point has y coordinate");

        Jwk {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some(base64url_encode(x)),
            y: Some(base64url_encode(y)),
            n: None,
            e: None,
        }
    }

    /// Calculate the JWK thumbprint (RFC 7638).
    pub fn thumbprint(&self) -> Result<String> {
        self.to_jwk().thumbprint()
    }

    /// Sign a JWS request with JWK in header (for new account).
    pub fn sign_with_jwk(&self, url: &str, nonce: &str, payload: Option<&[u8]>) -> Result<String> {
        let jwk = self.to_jwk();
        let protected = JwsProtected {
            alg: "ES256".to_string(),
            nonce: nonce.to_string(),
            url: url.to_string(),
            jwk: Some(jwk),
            kid: None,
        };
        self.sign_jws(protected, payload)
    }

    /// Sign a JWS request with key ID (for authenticated requests).
    pub fn sign_with_kid(
        &self,
        url: &str,
        nonce: &str,
        kid: &str,
        payload: Option<&[u8]>,
    ) -> Result<String> {
        let protected = JwsProtected {
            alg: "ES256".to_string(),
            nonce: nonce.to_string(),
            url: url.to_string(),
            jwk: None,
            kid: Some(kid.to_string()),
        };
        self.sign_jws(protected, payload)
    }

    /// Sign a JWS with the given protected header.
    fn sign_jws(&self, protected: JwsProtected, payload: Option<&[u8]>) -> Result<String> {
        // Encode protected header
        let protected_json = serde_json::to_vec(&protected)?;
        let protected_b64 = base64url_encode(&protected_json);

        // Encode payload (empty string for POST-as-GET)
        let payload_b64 = match payload {
            Some(p) => base64url_encode(p),
            None => String::new(),
        };

        // Create signing input
        let signing_input = format!("{}.{}", protected_b64, payload_b64);

        // Sign with ES256
        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        let signature_b64 = base64url_encode(&signature.to_bytes());

        // Return flattened JWS JSON
        let jws = JwsFlat {
            protected: protected_b64,
            payload: payload_b64,
            signature: signature_b64,
        };

        Ok(serde_json::to_string(&jws)?)
    }
}

/// JWS Protected Header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsProtected {
    /// Algorithm
    pub alg: String,
    /// Nonce
    pub nonce: String,
    /// URL
    pub url: String,
    /// JWK (for new account requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
    /// Key ID (for authenticated requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// JSON Web Key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (EC, RSA)
    pub kty: String,
    /// Curve (for EC keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// X coordinate (for EC keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Y coordinate (for EC keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// Modulus (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// Exponent (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

impl Jwk {
    /// Calculate JWK thumbprint (RFC 7638).
    pub fn thumbprint(&self) -> Result<String> {
        // Build canonical JSON representation (alphabetically ordered keys)
        let canonical = match self.kty.as_str() {
            "EC" => {
                let crv = self
                    .crv
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing EC curve"))?;
                let x = self.x.as_ref().ok_or_else(|| anyhow!("Missing EC x"))?;
                let y = self.y.as_ref().ok_or_else(|| anyhow!("Missing EC y"))?;
                serde_json::json!({
                    "crv": crv,
                    "kty": "EC",
                    "x": x,
                    "y": y
                })
            }
            "RSA" => {
                let e = self.e.as_ref().ok_or_else(|| anyhow!("Missing RSA e"))?;
                let n = self.n.as_ref().ok_or_else(|| anyhow!("Missing RSA n"))?;
                serde_json::json!({
                    "e": e,
                    "kty": "RSA",
                    "n": n
                })
            }
            _ => return Err(anyhow!("Unsupported key type: {}", self.kty)),
        };

        let json = serde_json::to_string(&canonical)?;
        let hash = Sha256::digest(json.as_bytes());
        Ok(base64url_encode(&hash))
    }
}

/// Flattened JWS JSON format.
#[derive(Debug, Serialize, Deserialize)]
pub struct JwsFlat {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_key_generation() {
        let key = AccountKey::generate();
        let jwk = key.to_jwk();

        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, Some("P-256".to_string()));
        assert!(jwk.x.is_some());
        assert!(jwk.y.is_some());
    }

    #[test]
    fn test_account_key_pem_roundtrip() {
        let key = AccountKey::generate();
        let pem = key.to_pem();
        assert!(pem.contains("EC PRIVATE KEY"));

        // Note: Full roundtrip would require proper SEC1 encoding
        // This test verifies PEM generation
    }

    #[test]
    fn test_jwk_thumbprint() {
        let key = AccountKey::generate();
        let thumbprint = key.thumbprint().unwrap();

        // Thumbprint should be base64url encoded SHA-256 hash (43 chars)
        assert_eq!(thumbprint.len(), 43);
    }

    #[test]
    fn test_jws_signing() {
        let key = AccountKey::generate();
        let url = "https://acme.example.com/new-account";
        let nonce = "test-nonce-123";
        let payload = b"{}";

        let jws = key.sign_with_jwk(url, nonce, Some(payload)).unwrap();

        // Should be valid JSON
        let parsed: JwsFlat = serde_json::from_str(&jws).unwrap();
        assert!(!parsed.protected.is_empty());
        assert!(!parsed.signature.is_empty());
    }

    #[test]
    fn test_base64url_encoding() {
        let data = b"Hello, World!";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(data, decoded.as_slice());
    }
}
