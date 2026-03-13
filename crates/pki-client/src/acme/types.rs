//! ACME Protocol Types (RFC 8555)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// ACME Directory - entry point for ACME operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Directory {
    /// URL to get a new nonce
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    /// URL to create a new account
    #[serde(rename = "newAccount")]
    pub new_account: String,
    /// URL to create a new order
    #[serde(rename = "newOrder")]
    pub new_order: String,
    /// URL for new authorization (optional)
    #[serde(rename = "newAuthz", skip_serializing_if = "Option::is_none")]
    pub new_authz: Option<String>,
    /// URL to revoke a certificate
    #[serde(rename = "revokeCert", skip_serializing_if = "Option::is_none")]
    pub revoke_cert: Option<String>,
    /// URL for key change
    #[serde(rename = "keyChange", skip_serializing_if = "Option::is_none")]
    pub key_change: Option<String>,
    /// Directory metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<DirectoryMeta>,
}

/// Directory metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryMeta {
    /// Terms of service URL
    #[serde(rename = "termsOfService", skip_serializing_if = "Option::is_none")]
    pub terms_of_service: Option<String>,
    /// Website URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// CAA identities
    #[serde(rename = "caaIdentities", skip_serializing_if = "Option::is_none")]
    pub caa_identities: Option<Vec<String>>,
    /// Whether external account binding is required
    #[serde(
        rename = "externalAccountRequired",
        skip_serializing_if = "Option::is_none"
    )]
    pub external_account_required: Option<bool>,
}

/// ACME Account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Account status
    pub status: AccountStatus,
    /// Contact URLs (mailto:, tel:, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contact: Vec<String>,
    /// Whether terms of service were agreed to
    #[serde(
        rename = "termsOfServiceAgreed",
        skip_serializing_if = "Option::is_none"
    )]
    pub terms_of_service_agreed: Option<bool>,
    /// Orders URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orders: Option<String>,
}

/// Account status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    /// Account is valid
    Valid,
    /// Account is deactivated
    Deactivated,
    /// Account is revoked
    Revoked,
}

/// Request to create a new account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAccountRequest {
    /// Contact URLs
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contact: Vec<String>,
    /// Agree to terms of service
    #[serde(
        rename = "termsOfServiceAgreed",
        skip_serializing_if = "Option::is_none"
    )]
    pub terms_of_service_agreed: Option<bool>,
    /// Only return existing account
    #[serde(rename = "onlyReturnExisting", skip_serializing_if = "Option::is_none")]
    pub only_return_existing: Option<bool>,
}

/// ACME Order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    /// Order status
    pub status: OrderStatus,
    /// Expiration timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    /// Identifiers (domains/IPs)
    pub identifiers: Vec<Identifier>,
    /// Authorization URLs
    pub authorizations: Vec<String>,
    /// Finalize URL
    pub finalize: String,
    /// Certificate URL (after issuance)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// Not before
    #[serde(rename = "notBefore", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    /// Not after
    #[serde(rename = "notAfter", skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<Utc>>,
}

/// Order status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    /// Order is pending authorization
    Pending,
    /// All authorizations are valid, ready to finalize
    Ready,
    /// Finalization is in progress
    Processing,
    /// Certificate has been issued
    Valid,
    /// Order has failed
    Invalid,
}

/// Request to create a new order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOrderRequest {
    /// Identifiers to include
    pub identifiers: Vec<Identifier>,
    /// Not before (optional)
    #[serde(rename = "notBefore", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    /// Not after (optional)
    #[serde(rename = "notAfter", skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<Utc>>,
}

/// ACME Identifier (domain name or IP address).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identifier {
    /// Identifier type (dns or ip)
    #[serde(rename = "type")]
    pub id_type: String,
    /// Identifier value
    pub value: String,
}

impl Identifier {
    /// Create a DNS identifier.
    pub fn dns(domain: impl Into<String>) -> Self {
        Self {
            id_type: "dns".to_string(),
            value: domain.into(),
        }
    }

    /// Create an IP identifier.
    #[allow(dead_code)]
    pub fn ip(addr: impl Into<String>) -> Self {
        Self {
            id_type: "ip".to_string(),
            value: addr.into(),
        }
    }
}

/// ACME Authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    /// Authorization status
    pub status: AuthorizationStatus,
    /// Expiration timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    /// The identifier being authorized
    pub identifier: Identifier,
    /// Available challenges
    pub challenges: Vec<Challenge>,
    /// Whether this is a wildcard authorization
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wildcard: Option<bool>,
}

/// Authorization status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationStatus {
    /// Authorization is pending
    Pending,
    /// Authorization is valid
    Valid,
    /// Authorization is invalid
    Invalid,
    /// Authorization was deactivated
    Deactivated,
    /// Authorization expired
    Expired,
    /// Authorization was revoked
    Revoked,
}

/// ACME Challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Challenge type
    #[serde(rename = "type")]
    pub challenge_type: ChallengeType,
    /// Challenge URL
    pub url: String,
    /// Challenge token
    pub token: String,
    /// Challenge status
    pub status: ChallengeStatus,
    /// Validation timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validated: Option<DateTime<Utc>>,
    /// Error if validation failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AcmeProblem>,
}

/// Challenge type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeType {
    /// HTTP-01 challenge
    #[serde(rename = "http-01")]
    Http01,
    /// DNS-01 challenge
    #[serde(rename = "dns-01")]
    Dns01,
    /// TLS-ALPN-01 challenge
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

impl std::fmt::Display for ChallengeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChallengeType::Http01 => write!(f, "http-01"),
            ChallengeType::Dns01 => write!(f, "dns-01"),
            ChallengeType::TlsAlpn01 => write!(f, "tls-alpn-01"),
        }
    }
}

/// Challenge status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    /// Challenge is pending
    Pending,
    /// Challenge is processing
    Processing,
    /// Challenge is valid
    Valid,
    /// Challenge is invalid
    Invalid,
}

/// ACME Problem (RFC 7807).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeProblem {
    /// Problem type URI
    #[serde(rename = "type")]
    pub problem_type: String,
    /// Problem detail
    pub detail: String,
    /// HTTP status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

impl std::fmt::Display for AcmeProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.problem_type, self.detail)
    }
}

/// Finalization request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeRequest {
    /// CSR in base64url encoding
    pub csr: String,
}

/// Revocation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRequest {
    /// Certificate in base64url encoding
    pub certificate: String,
    /// Revocation reason (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<u8>,
}
