//! Certificate Storage
//!
//! Encrypted storage for CA state, certificates, and revocation data.
//! Designed for PostgreSQL with field-level encryption.

mod memory;
mod schema;

pub use memory::MemoryStore;
pub use schema::{CaStateRecord, CertificateRecord, RevocationRecord};

use crate::error::{Error, Result};

/// Storage backend trait
pub trait CertificateStore: Send + Sync {
    /// Store a certificate
    fn store_certificate(&self, record: CertificateRecord) -> Result<()>;

    /// Get certificate by serial number
    fn get_certificate(&self, serial: &str) -> Result<Option<CertificateRecord>>;

    /// Get certificate by subject CN
    fn get_certificate_by_cn(&self, cn: &str) -> Result<Vec<CertificateRecord>>;

    /// List all certificates
    fn list_certificates(&self) -> Result<Vec<CertificateRecord>>;

    /// Revoke a certificate
    fn revoke_certificate(&self, serial: &str, reason: RevocationReason) -> Result<()>;

    /// Get revocation status
    fn get_revocation(&self, serial: &str) -> Result<Option<RevocationRecord>>;

    /// List all revocations
    fn list_revocations(&self) -> Result<Vec<RevocationRecord>>;

    /// Store CA state
    fn store_ca_state(&self, state: CaStateRecord) -> Result<()>;

    /// Get CA state
    fn get_ca_state(&self, ca_id: &str) -> Result<Option<CaStateRecord>>;
}

/// Revocation reasons (RFC 5280 Section 5.3.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    // 7 is unused
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl TryFrom<u8> for RevocationReason {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Unspecified),
            1 => Ok(Self::KeyCompromise),
            2 => Ok(Self::CaCompromise),
            3 => Ok(Self::AffiliationChanged),
            4 => Ok(Self::Superseded),
            5 => Ok(Self::CessationOfOperation),
            6 => Ok(Self::CertificateHold),
            8 => Ok(Self::RemoveFromCrl),
            9 => Ok(Self::PrivilegeWithdrawn),
            10 => Ok(Self::AaCompromise),
            _ => Err(Error::InvalidCertificate(format!(
                "Unknown revocation reason: {}",
                value
            ))),
        }
    }
}
