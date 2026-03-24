//! SCEP Types and Constants

use serde::{Deserialize, Serialize};

/// SCEP operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScepOperation {
    /// Get CA capabilities
    GetCACaps,
    /// Get CA certificate(s)
    GetCACert,
    /// Get next CA certificate (for rollover)
    GetNextCACert,
    /// PKI operation (enrollment, query)
    PKIOperation,
}

impl ScepOperation {
    /// Get the operation parameter value.
    pub fn param(&self) -> &'static str {
        match self {
            ScepOperation::GetCACaps => "GetCACaps",
            ScepOperation::GetCACert => "GetCACert",
            ScepOperation::GetNextCACert => "GetNextCACert",
            ScepOperation::PKIOperation => "PKIOperation",
        }
    }
}

impl std::fmt::Display for ScepOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.param())
    }
}

/// SCEP message types (per RFC 8894).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)] // RFC 8894 protocol completeness
pub enum MessageType {
    /// Certificate request
    PKCSReq = 19,
    /// Certificate response
    CertRep = 3,
    /// Get certificate (initial/polling)
    GetCertInitial = 20,
    /// Get existing certificate
    GetCert = 21,
    /// Get CRL
    GetCRL = 22,
}

#[allow(dead_code)] // RFC 8894 protocol completeness
impl MessageType {
    /// Parse from integer.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            19 => Some(Self::PKCSReq),
            3 => Some(Self::CertRep),
            20 => Some(Self::GetCertInitial),
            21 => Some(Self::GetCert),
            22 => Some(Self::GetCRL),
            _ => None,
        }
    }

    /// Get the numeric value.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// SCEP PKI status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[allow(dead_code)] // RFC 8894 protocol completeness
pub enum PkiStatus {
    /// Operation succeeded
    Success = 0,
    /// Operation failed
    Failure = 2,
    /// Request is pending
    Pending = 3,
}

#[allow(dead_code)] // RFC 8894 protocol completeness
impl PkiStatus {
    /// Parse from integer.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Success),
            2 => Some(Self::Failure),
            3 => Some(Self::Pending),
            _ => None,
        }
    }
}

impl std::fmt::Display for PkiStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PkiStatus::Success => write!(f, "SUCCESS"),
            PkiStatus::Failure => write!(f, "FAILURE"),
            PkiStatus::Pending => write!(f, "PENDING"),
        }
    }
}

/// SCEP failure info (names per RFC 8894).
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[allow(dead_code)] // RFC 8894 protocol completeness
pub enum FailInfo {
    /// Unrecognized or unsupported algorithm
    BadAlg = 0,
    /// Integrity check failed
    BadMessageCheck = 1,
    /// Transaction not permitted or supported
    BadRequest = 2,
    /// Timestamp not accepted
    BadTime = 3,
    /// No certificate could be identified
    BadCertId = 4,
}

#[allow(dead_code)] // RFC 8894 protocol completeness
impl FailInfo {
    /// Get the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            FailInfo::BadAlg => "badAlg",
            FailInfo::BadMessageCheck => "badMessageCheck",
            FailInfo::BadRequest => "badRequest",
            FailInfo::BadTime => "badTime",
            FailInfo::BadCertId => "badCertId",
        }
    }

    /// Parse from integer.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::BadAlg),
            1 => Some(Self::BadMessageCheck),
            2 => Some(Self::BadRequest),
            3 => Some(Self::BadTime),
            4 => Some(Self::BadCertId),
            _ => None,
        }
    }
}

impl std::fmt::Display for FailInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// SCEP CA capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaCapabilities {
    /// List of supported capabilities
    pub capabilities: Vec<String>,
}

impl CaCapabilities {
    /// Parse capabilities from response body.
    pub fn from_response(body: &str) -> Self {
        let capabilities = body
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Self { capabilities }
    }

    /// Check if POST PKIOperation is supported.
    pub fn supports_post(&self) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.eq_ignore_ascii_case("POSTPKIOperation"))
    }

    /// Check if SHA-256 is supported.
    pub fn supports_sha256(&self) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.eq_ignore_ascii_case("SHA-256"))
    }

    /// Check if AES encryption is supported.
    pub fn supports_aes(&self) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.eq_ignore_ascii_case("AES"))
    }

    /// Check if renewal is supported.
    pub fn supports_renewal(&self) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.eq_ignore_ascii_case("Renewal"))
    }
}

/// SCEP enrollment response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // RFC 8894 protocol completeness
pub struct EnrollmentResponse {
    /// Transaction ID
    pub transaction_id: String,
    /// PKI status
    pub status: PkiStatus,
    /// Failure info (if status is Failure)
    pub fail_info: Option<FailInfo>,
    /// Issued certificate (PEM, if status is Success)
    pub certificate: Option<String>,
    /// Private key PEM (generated during enrollment)
    /// Never serialized — use enrollment_to_json() for safe JSON output.
    #[serde(skip_serializing)]
    pub private_key_pem: Option<String>,
}

/// Configuration for SCEP enrollment.
#[derive(Debug, Clone)]
pub struct EnrollConfig {
    /// Subject Common Name (CN)
    pub subject_cn: String,
    /// Challenge password (optional)
    pub challenge: Option<String>,
    /// Subject Alternative Names (DNS names)
    pub san_names: Vec<String>,
    /// Key type for enrollment
    pub key_type: crate::scep::envelope::ScepKeyType,
    /// Seconds between polling attempts (for PENDING responses)
    pub poll_interval_secs: u64,
    /// Maximum number of polling attempts
    pub max_polls: u32,
}
