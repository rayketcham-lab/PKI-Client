//! EST Types and Constants

use serde::{Deserialize, Serialize};

/// EST operation types (RFC 7030 Section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstOperation {
    /// Get CA certificates
    CaCerts,
    /// Simple enrollment
    SimpleEnroll,
    /// Re-enrollment
    SimpleReEnroll,
    /// Server-side key generation
    ServerKeyGen,
    /// Get CSR attributes
    CsrAttrs,
}

impl EstOperation {
    /// Get the path suffix for this operation.
    pub fn path(&self) -> &'static str {
        match self {
            EstOperation::CaCerts => "cacerts",
            EstOperation::SimpleEnroll => "simpleenroll",
            EstOperation::SimpleReEnroll => "simplereenroll",
            EstOperation::ServerKeyGen => "serverkeygen",
            EstOperation::CsrAttrs => "csrattrs",
        }
    }

    /// Get the HTTP method for this operation.
    #[allow(dead_code)] // RFC 7030 protocol completeness
    pub fn method(&self) -> &'static str {
        match self {
            EstOperation::CaCerts | EstOperation::CsrAttrs => "GET",
            _ => "POST",
        }
    }

    /// Whether this operation requires authentication.
    #[allow(dead_code)] // RFC 7030 protocol completeness
    pub fn requires_auth(&self) -> bool {
        !matches!(self, EstOperation::CaCerts)
    }
}

impl std::fmt::Display for EstOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path())
    }
}

/// Server key generation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerKeyGenResponse {
    /// The generated private key (PEM encoded).
    pub private_key: String,
    /// The issued certificate (PEM encoded).
    pub certificate: String,
}

/// EST content types (RFC 7030 Section 4).
pub mod content_type {
    /// PKCS#7 certs-only (for CA certificates)
    pub const PKCS7_CERTS: &str = "application/pkcs7-mime; smime-type=certs-only";

    /// PKCS#10 CSR
    pub const PKCS10: &str = "application/pkcs10";

    /// PKCS#7 with certificate
    pub const PKCS7_ENROLL: &str = "application/pkcs7-mime";

    /// CSR attributes
    pub const CSR_ATTRS: &str = "application/csrattrs";

    /// PKCS#8 private key
    #[allow(dead_code)] // RFC 7030 protocol completeness
    pub const PKCS8: &str = "application/pkcs8";
}
