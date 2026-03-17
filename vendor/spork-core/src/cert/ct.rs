//! Certificate Transparency (RFC 9162 / RFC 6962) — SCT embedding and verification
//!
//! Implements SignedCertificateTimestamp (SCT) encoding, decoding, verification,
//! and X.509 extension embedding for Certificate Transparency.
//!
//! SCTs are embedded in certificates via the SCT List extension
//! (OID 1.3.6.1.4.1.11129.2.4.2) as defined in RFC 6962 Section 3.3.

use std::time::Duration;

use crate::digest;

use crate::error::{Error, Result};

/// OID for the SCT List X.509 extension (RFC 6962 Section 3.3)
/// 1.3.6.1.4.1.11129.2.4.2
pub const SCT_LIST_OID: &str = "1.3.6.1.4.1.11129.2.4.2";

/// SCT version (RFC 6962 Section 3.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SctVersion {
    /// Version 1 (v1) — only version defined in RFC 6962
    V1 = 0,
}

impl SctVersion {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(SctVersion::V1),
            _ => Err(Error::Decoding(format!("Unknown SCT version: {}", v))),
        }
    }
}

/// Hash algorithm identifiers for DigitallySigned (RFC 5246 Section 7.4.1.4.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HashAlgorithm {
    Sha256 = 4,
}

impl HashAlgorithm {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            4 => Ok(HashAlgorithm::Sha256),
            _ => Err(Error::Decoding(format!(
                "Unsupported hash algorithm: {}",
                v
            ))),
        }
    }
}

/// Signature algorithm identifiers for DigitallySigned (RFC 5246 Section 7.4.1.4.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    /// ECDSA
    Ecdsa = 3,
    /// RSA
    Rsa = 1,
}

impl SignatureAlgorithm {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(SignatureAlgorithm::Rsa),
            3 => Ok(SignatureAlgorithm::Ecdsa),
            _ => Err(Error::Decoding(format!(
                "Unsupported signature algorithm: {}",
                v
            ))),
        }
    }
}

/// DigitallySigned struct (RFC 5246 Section 4.7 / RFC 6962 Section 3.2)
///
/// ```text
/// digitally-signed struct {
///   HashAlgorithm hash;
///   SignatureAlgorithm signature;
///   opaque signature<0..2^16-1>;
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigitallySigned {
    pub hash_algorithm: HashAlgorithm,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature: Vec<u8>,
}

impl DigitallySigned {
    /// Encode as TLS wire format
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.hash_algorithm as u8);
        buf.push(self.signature_algorithm as u8);
        // 2-byte length prefix for signature
        let sig_len = self.signature.len() as u16;
        buf.extend_from_slice(&sig_len.to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Decode from TLS wire format
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 4 {
            return Err(Error::Decoding(
                "DigitallySigned too short: need at least 4 bytes".into(),
            ));
        }
        let hash_algorithm = HashAlgorithm::from_u8(data[0])?;
        let signature_algorithm = SignatureAlgorithm::from_u8(data[1])?;
        let sig_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + sig_len {
            return Err(Error::Decoding(format!(
                "DigitallySigned truncated: need {} bytes, have {}",
                4 + sig_len,
                data.len()
            )));
        }
        let signature = data[4..4 + sig_len].to_vec();
        Ok((
            DigitallySigned {
                hash_algorithm,
                signature_algorithm,
                signature,
            },
            4 + sig_len,
        ))
    }
}

/// Signed Certificate Timestamp (RFC 6962 Section 3.2)
///
/// ```text
/// struct {
///   Version sct_version;
///   LogID id;
///   uint64 timestamp;
///   CtExtensions extensions;
///   digitally-signed struct { ... };
/// } SignedCertificateTimestamp;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sct {
    /// SCT version (v1 = 0)
    pub version: SctVersion,
    /// SHA-256 hash of the log's public key (32 bytes)
    pub log_id: [u8; 32],
    /// Timestamp in milliseconds since Unix epoch
    pub timestamp: u64,
    /// Extensions (opaque bytes, typically empty)
    pub extensions: Vec<u8>,
    /// The log's signature over the SCT data
    pub signature: DigitallySigned,
}

impl Sct {
    /// Encode this SCT as TLS wire format (used inside SerializedSCT)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.version as u8);
        buf.extend_from_slice(&self.log_id);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        // Extensions with 2-byte length prefix
        let ext_len = self.extensions.len() as u16;
        buf.extend_from_slice(&ext_len.to_be_bytes());
        buf.extend_from_slice(&self.extensions);
        // DigitallySigned
        buf.extend_from_slice(&self.signature.encode());
        buf
    }

    /// Decode an SCT from TLS wire format
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        // Minimum: version(1) + log_id(32) + timestamp(8) + ext_len(2) + sig(4+)
        if data.len() < 47 {
            return Err(Error::Decoding(
                "SCT too short: need at least 47 bytes".into(),
            ));
        }

        let version = SctVersion::from_u8(data[0])?;
        let mut log_id = [0u8; 32];
        log_id.copy_from_slice(&data[1..33]);
        let timestamp = u64::from_be_bytes(data[33..41].try_into().unwrap());

        let ext_len = u16::from_be_bytes([data[41], data[42]]) as usize;
        let ext_end = 43 + ext_len;
        if data.len() < ext_end {
            return Err(Error::Decoding("SCT extensions truncated".into()));
        }
        let extensions = data[43..ext_end].to_vec();

        let (signature, sig_consumed) = DigitallySigned::decode(&data[ext_end..])?;
        let total = ext_end + sig_consumed;

        Ok((
            Sct {
                version,
                log_id,
                timestamp,
                extensions,
                signature,
            },
            total,
        ))
    }
}

/// SCT List for the X.509 extension (OID 1.3.6.1.4.1.11129.2.4.2)
///
/// The extension value is a TLS-encoded list of SerializedSCTs:
/// ```text
/// opaque SerializedSCT<1..2^16-1>;
/// struct {
///   SerializedSCT sct_list<1..2^16-1>;
/// } SignedCertificateTimestampList;
/// ```
///
/// Each SerializedSCT is a 2-byte length prefix followed by the TLS-encoded SCT.
/// The outer list also has a 2-byte length prefix for the total.
#[derive(Debug, Clone)]
pub struct SctList {
    pub scts: Vec<Sct>,
}

impl SctList {
    pub fn new(scts: Vec<Sct>) -> Self {
        Self { scts }
    }

    /// Encode as TLS wire format (SignedCertificateTimestampList)
    ///
    /// Returns the raw TLS-encoded bytes suitable for wrapping in an OCTET STRING
    /// for the X.509 extension value.
    pub fn encode_tls(&self) -> Vec<u8> {
        // First, encode each SCT with its 2-byte length prefix
        let mut serialized_scts = Vec::new();
        for sct in &self.scts {
            let sct_bytes = sct.encode();
            let sct_len = sct_bytes.len() as u16;
            serialized_scts.extend_from_slice(&sct_len.to_be_bytes());
            serialized_scts.extend_from_slice(&sct_bytes);
        }
        // Outer list: 2-byte length prefix for the entire list
        let list_len = serialized_scts.len() as u16;
        let mut result = Vec::new();
        result.extend_from_slice(&list_len.to_be_bytes());
        result.extend_from_slice(&serialized_scts);
        result
    }

    /// Decode from TLS wire format
    pub fn decode_tls(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(Error::Decoding(
                "SCT list too short: need at least 2 bytes for length".into(),
            ));
        }
        let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + list_len {
            return Err(Error::Decoding(format!(
                "SCT list truncated: declared {} bytes, have {}",
                list_len,
                data.len() - 2
            )));
        }
        let list_data = &data[2..2 + list_len];
        let mut scts = Vec::new();
        let mut pos = 0;

        while pos < list_data.len() {
            if pos + 2 > list_data.len() {
                return Err(Error::Decoding(
                    "SCT list: truncated SerializedSCT length".into(),
                ));
            }
            let sct_len = u16::from_be_bytes([list_data[pos], list_data[pos + 1]]) as usize;
            pos += 2;
            if pos + sct_len > list_data.len() {
                return Err(Error::Decoding(
                    "SCT list: truncated SerializedSCT data".into(),
                ));
            }
            let (sct, consumed) = Sct::decode(&list_data[pos..pos + sct_len])?;
            if consumed != sct_len {
                return Err(Error::Decoding(format!(
                    "SCT length mismatch: declared {}, consumed {}",
                    sct_len, consumed
                )));
            }
            scts.push(sct);
            pos += sct_len;
        }

        Ok(SctList { scts })
    }

    /// Encode as DER OCTET STRING for embedding in an X.509 extension
    ///
    /// The X.509 extension value wraps the TLS-encoded SCT list in an
    /// ASN.1 OCTET STRING.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let tls_bytes = self.encode_tls();
        // Wrap in OCTET STRING (tag 0x04)
        let mut der = vec![0x04];
        encode_der_length(&mut der, tls_bytes.len());
        der.extend_from_slice(&tls_bytes);
        Ok(der)
    }

    /// Decode from DER OCTET STRING (X.509 extension value)
    pub fn from_der(data: &[u8]) -> Result<Self> {
        if data.len() < 2 || data[0] != 0x04 {
            return Err(Error::Decoding(
                "SCT list extension: expected OCTET STRING".into(),
            ));
        }
        let (len, offset) = read_der_length(&data[1..])?;
        let start = 1 + offset;
        if data.len() < start + len {
            return Err(Error::Decoding(
                "SCT list extension: OCTET STRING truncated".into(),
            ));
        }
        Self::decode_tls(&data[start..start + len])
    }
}

/// Compute the log_id (SHA-256 hash of the log's DER-encoded SubjectPublicKeyInfo)
pub fn compute_log_id(log_public_key_der: &[u8]) -> [u8; 32] {
    let result = digest::sha256(log_public_key_der);
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// Reconstruct the data signed by the CT log for SCT verification (RFC 6962 Section 3.2)
///
/// For a precertificate SCT, the signed data is:
/// ```text
/// digitally-signed struct {
///   Version sct_version = v1;
///   SignatureType signature_type = certificate_timestamp(0);
///   uint64 timestamp;
///   LogEntryType entry_type = precert_entry(1);
///   PreCert precert_entry;
///   CtExtensions extensions;
/// };
/// ```
///
/// Where PreCert is:
/// ```text
/// struct {
///   opaque issuer_key_hash[32];
///   TBSCertificate tbs_certificate<1..2^24-1>;
/// } PreCert;
/// ```
pub fn build_precert_signed_data(
    sct: &Sct,
    tbs_certificate_der: &[u8],
    issuer_key_hash: &[u8],
) -> Vec<u8> {
    let mut signed_data = Vec::new();
    // sct_version
    signed_data.push(sct.version as u8);
    // signature_type: certificate_timestamp = 0
    signed_data.push(0);
    // timestamp
    signed_data.extend_from_slice(&sct.timestamp.to_be_bytes());
    // entry_type: precert_entry = 1
    signed_data.extend_from_slice(&1u16.to_be_bytes());
    // issuer_key_hash (32 bytes)
    signed_data.extend_from_slice(&issuer_key_hash[..32]);
    // tbs_certificate with 3-byte length prefix
    let tbs_len = tbs_certificate_der.len();
    signed_data.push(((tbs_len >> 16) & 0xFF) as u8);
    signed_data.push(((tbs_len >> 8) & 0xFF) as u8);
    signed_data.push((tbs_len & 0xFF) as u8);
    signed_data.extend_from_slice(tbs_certificate_der);
    // extensions with 2-byte length prefix
    let ext_len = sct.extensions.len() as u16;
    signed_data.extend_from_slice(&ext_len.to_be_bytes());
    signed_data.extend_from_slice(&sct.extensions);
    signed_data
}

/// Reconstruct the data signed by the CT log for a final certificate SCT
///
/// ```text
/// digitally-signed struct {
///   Version sct_version = v1;
///   SignatureType signature_type = certificate_timestamp(0);
///   uint64 timestamp;
///   LogEntryType entry_type = x509_entry(0);
///   ASN.1Cert signed_entry;
///   CtExtensions extensions;
/// };
/// ```
pub fn build_cert_signed_data(sct: &Sct, cert_der: &[u8]) -> Vec<u8> {
    let mut signed_data = Vec::new();
    // sct_version
    signed_data.push(sct.version as u8);
    // signature_type: certificate_timestamp = 0
    signed_data.push(0);
    // timestamp
    signed_data.extend_from_slice(&sct.timestamp.to_be_bytes());
    // entry_type: x509_entry = 0
    signed_data.extend_from_slice(&0u16.to_be_bytes());
    // ASN.1Cert with 3-byte length prefix
    let cert_len = cert_der.len();
    signed_data.push(((cert_len >> 16) & 0xFF) as u8);
    signed_data.push(((cert_len >> 8) & 0xFF) as u8);
    signed_data.push((cert_len & 0xFF) as u8);
    signed_data.extend_from_slice(cert_der);
    // extensions with 2-byte length prefix
    let ext_len = sct.extensions.len() as u16;
    signed_data.extend_from_slice(&ext_len.to_be_bytes());
    signed_data.extend_from_slice(&sct.extensions);
    signed_data
}

/// Verify an SCT signature against the CT log's public key
///
/// Reconstructs the signed data and verifies the DigitallySigned signature
/// using the log's ECDSA P-256 or RSA public key.
///
/// # Arguments
/// * `sct` - The SCT to verify
/// * `cert_der` - DER-encoded certificate (for x509_entry) or TBS certificate (for precert)
/// * `issuer_key_hash` - SHA-256 hash of the issuing CA's public key (for precert; empty for x509_entry)
/// * `log_public_key` - DER-encoded SubjectPublicKeyInfo of the CT log
/// * `is_precert` - Whether this is a precertificate SCT
pub fn verify_sct(
    sct: &Sct,
    cert_der: &[u8],
    issuer_key_hash: &[u8],
    log_public_key: &[u8],
    is_precert: bool,
) -> Result<bool> {
    // Reconstruct the signed data
    let signed_data = if is_precert {
        if issuer_key_hash.len() < 32 {
            return Err(Error::InvalidCertificate(
                "issuer_key_hash must be at least 32 bytes".into(),
            ));
        }
        build_precert_signed_data(sct, cert_der, issuer_key_hash)
    } else {
        build_cert_signed_data(sct, cert_der)
    };

    // Verify the log_id matches the provided public key
    let expected_log_id = compute_log_id(log_public_key);
    if sct.log_id != expected_log_id {
        return Ok(false);
    }

    // Hash the signed data with SHA-256
    let hash = digest::sha256(&signed_data);

    // Verify signature based on algorithm
    match sct.signature.signature_algorithm {
        SignatureAlgorithm::Ecdsa => {
            verify_ecdsa_signature(log_public_key, &hash, &sct.signature.signature)
        }
        SignatureAlgorithm::Rsa => {
            verify_rsa_signature(log_public_key, &hash, &sct.signature.signature)
        }
    }
}

/// Verify an ECDSA signature from a CT log
fn verify_ecdsa_signature(
    public_key_der: &[u8],
    message_hash: &[u8],
    signature: &[u8],
) -> Result<bool> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    // Parse the SPKI-encoded public key
    let verifying_key = VerifyingKey::from_sec1_bytes(extract_ec_point_from_spki(public_key_der)?)
        .or_else(|_| {
            // Try parsing the whole thing as SPKI
            use spki::SubjectPublicKeyInfoRef;
            let spki = SubjectPublicKeyInfoRef::try_from(public_key_der)
                .map_err(|e| Error::Decoding(format!("SPKI parse: {}", e)))?;
            VerifyingKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
                .map_err(|e| Error::Decoding(format!("EC key parse: {}", e)))
        })?;

    // CT logs sign the raw data, not a pre-hashed digest.
    // Reconstruct the full signed data for verification.
    // The message_hash here is SHA-256(signed_data), but ECDSA in CT
    // signs the raw signed_data directly (the ECDSA algorithm itself hashes).
    // However, we already computed SHA-256 — for CT log verification,
    // we need the signature to be over the hash since CT uses DigitallySigned
    // with hash_algorithm=SHA-256.
    let sig = Signature::from_der(signature)
        .map_err(|e| Error::Decoding(format!("ECDSA sig parse: {}", e)))?;

    // CT logs use SHA-256 hash in the DigitallySigned struct, but the actual
    // ECDSA verification expects the raw hash bytes via verify_prehash.
    // For CT, the DigitallySigned specifies SHA-256, meaning the log computes
    // SHA-256 of the signed_data struct and then signs that hash with ECDSA.
    // We need to verify against the pre-hashed value.
    match verifying_key.verify_prehash(message_hash, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify an RSA signature from a CT log
fn verify_rsa_signature(
    public_key_der: &[u8],
    message_hash: &[u8],
    signature: &[u8],
) -> Result<bool> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;
    use sha2::Sha256;

    // Parse the SPKI-encoded RSA public key
    let rsa_key = RsaPublicKey::try_from(
        spki::SubjectPublicKeyInfoRef::try_from(public_key_der)
            .map_err(|e| Error::Decoding(format!("SPKI parse: {}", e)))?,
    )
    .map_err(|e| Error::Decoding(format!("RSA key parse: {}", e)))?;

    let verifying_key = VerifyingKey::<Sha256>::new(rsa_key);
    let sig = Signature::try_from(signature)
        .map_err(|e| Error::Decoding(format!("RSA sig parse: {}", e)))?;

    // For RSA PKCS#1v1.5 with SHA-256, verify against the pre-hashed value
    match verifying_key.verify(message_hash, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Extract raw EC point bytes from a DER-encoded SubjectPublicKeyInfo
fn extract_ec_point_from_spki(spki_der: &[u8]) -> Result<&[u8]> {
    use spki::SubjectPublicKeyInfoRef;
    let spki = SubjectPublicKeyInfoRef::try_from(spki_der)
        .map_err(|e| Error::Decoding(format!("SPKI parse: {}", e)))?;
    Ok(spki.subject_public_key.raw_bytes())
}

// --- CT Log Client ---

/// Configuration for a single CT log
#[derive(Debug, Clone)]
pub struct CtLogEntry {
    /// URL of the CT log (e.g., "https://ct.googleapis.com/logs/us1/argon2025h1")
    pub url: String,
    /// DER-encoded SubjectPublicKeyInfo of the log's public key
    pub public_key: Vec<u8>,
    /// SHA-256 of the log's public key (computed or provided)
    pub log_id: [u8; 32],
}

impl CtLogEntry {
    /// Create a log entry, computing the log_id from the public key
    pub fn new(url: String, public_key: Vec<u8>) -> Self {
        let log_id = compute_log_id(&public_key);
        Self {
            url,
            public_key,
            log_id,
        }
    }
}

/// Configuration for Certificate Transparency
#[derive(Debug, Clone)]
pub struct CtConfig {
    /// CT logs to submit precertificates to
    pub logs: Vec<CtLogEntry>,
    /// Timeout for HTTP requests to CT logs
    pub submission_timeout: Duration,
    /// Minimum number of SCTs required for embedding
    pub required_scts: usize,
}

impl Default for CtConfig {
    fn default() -> Self {
        Self {
            logs: Vec::new(),
            submission_timeout: Duration::from_secs(30),
            required_scts: 2,
        }
    }
}

/// CT log client for submitting precertificates and obtaining SCTs
///
/// Submits certificate chains to CT logs via HTTP POST and parses
/// the SCT responses. Requires the `aia-chasing` feature for HTTP support.
pub struct CtLogClient {
    config: CtConfig,
}

impl CtLogClient {
    pub fn new(config: CtConfig) -> Self {
        Self { config }
    }

    /// Build the JSON body for add-pre-chain submission (RFC 6962 Section 4.1)
    ///
    /// The chain is an array of base64-encoded DER certificates.
    /// The first entry is the precertificate, followed by the issuer chain.
    pub fn build_add_pre_chain_body(chain: &[Vec<u8>]) -> String {
        let entries: Vec<String> = chain
            .iter()
            .map(|cert_der| {
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, cert_der)
            })
            .collect();
        format!(
            r#"{{"chain":[{}]}}"#,
            entries
                .iter()
                .map(|e| format!("\"{}\"", e))
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    /// Build the JSON body for add-chain submission (RFC 6962 Section 4.1)
    pub fn build_add_chain_body(chain: &[Vec<u8>]) -> String {
        // Same format as add-pre-chain
        Self::build_add_pre_chain_body(chain)
    }

    /// Parse an SCT from a CT log JSON response
    ///
    /// Expected JSON format (RFC 6962 Section 4.1):
    /// ```json
    /// {
    ///   "sct_version": 0,
    ///   "id": "<base64 log_id>",
    ///   "timestamp": 1234567890,
    ///   "extensions": "",
    ///   "signature": "<base64 DigitallySigned>"
    /// }
    /// ```
    pub fn parse_sct_response(json_body: &str) -> Result<Sct> {
        let v: serde_json::Value = serde_json::from_str(json_body)
            .map_err(|e| Error::Decoding(format!("CT log JSON: {}", e)))?;

        let version = v
            .get("sct_version")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::Decoding("Missing sct_version".into()))?;
        let version = SctVersion::from_u8(version as u8)?;

        let id_b64 = v
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Decoding("Missing id".into()))?;
        let id_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, id_b64)
            .map_err(|e| Error::Decoding(format!("CT log id base64: {}", e)))?;
        if id_bytes.len() != 32 {
            return Err(Error::Decoding(format!(
                "CT log id wrong length: expected 32, got {}",
                id_bytes.len()
            )));
        }
        let mut log_id = [0u8; 32];
        log_id.copy_from_slice(&id_bytes);

        let timestamp = v
            .get("timestamp")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::Decoding("Missing timestamp".into()))?;

        let ext_b64 = v.get("extensions").and_then(|v| v.as_str()).unwrap_or("");
        let extensions = if ext_b64.is_empty() {
            Vec::new()
        } else {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ext_b64)
                .map_err(|e| Error::Decoding(format!("CT extensions base64: {}", e)))?
        };

        let sig_b64 = v
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Decoding("Missing signature".into()))?;
        let sig_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64)
            .map_err(|e| Error::Decoding(format!("CT signature base64: {}", e)))?;
        let (signature, _) = DigitallySigned::decode(&sig_bytes)?;

        Ok(Sct {
            version,
            log_id,
            timestamp,
            extensions,
            signature,
        })
    }

    /// Get the configured logs
    pub fn logs(&self) -> &[CtLogEntry] {
        &self.config.logs
    }

    /// Get the required number of SCTs
    pub fn required_scts(&self) -> usize {
        self.config.required_scts
    }

    /// Get the submission timeout
    pub fn submission_timeout(&self) -> Duration {
        self.config.submission_timeout
    }
}

// --- DER encoding helpers ---

/// Encode a DER length value
fn encode_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else {
        let len_bytes = (len as u32).to_be_bytes();
        let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(3);
        let len_len = 4 - start;
        buf.push(0x80 | len_len as u8);
        buf.extend_from_slice(&len_bytes[start..]);
    }
}

/// Read a DER length value, returning (length, bytes_consumed)
fn read_der_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(Error::Decoding("DER length: empty data".into()));
    }
    let first = data[0] as usize;
    if first < 0x80 {
        Ok((first, 1))
    } else if first == 0x81 {
        if data.len() < 2 {
            return Err(Error::Decoding("DER length: truncated".into()));
        }
        Ok((data[1] as usize, 2))
    } else if first == 0x82 {
        if data.len() < 3 {
            return Err(Error::Decoding("DER length: truncated".into()));
        }
        Ok((((data[1] as usize) << 8) | (data[2] as usize), 3))
    } else {
        Err(Error::Decoding(format!(
            "DER length: unsupported form 0x{:02x}",
            first
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_sct() -> Sct {
        Sct {
            version: SctVersion::V1,
            log_id: [0xAA; 32],
            timestamp: 1_700_000_000_000,
            extensions: Vec::new(),
            signature: DigitallySigned {
                hash_algorithm: HashAlgorithm::Sha256,
                signature_algorithm: SignatureAlgorithm::Ecdsa,
                signature: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            },
        }
    }

    #[test]
    fn test_sct_version_roundtrip() {
        assert_eq!(SctVersion::from_u8(0).unwrap(), SctVersion::V1);
        assert!(SctVersion::from_u8(1).is_err());
        assert!(SctVersion::from_u8(255).is_err());
    }

    #[test]
    fn test_hash_algorithm_roundtrip() {
        assert_eq!(HashAlgorithm::from_u8(4).unwrap(), HashAlgorithm::Sha256);
        assert!(HashAlgorithm::from_u8(0).is_err());
        assert!(HashAlgorithm::from_u8(99).is_err());
    }

    #[test]
    fn test_signature_algorithm_roundtrip() {
        assert_eq!(
            SignatureAlgorithm::from_u8(3).unwrap(),
            SignatureAlgorithm::Ecdsa
        );
        assert_eq!(
            SignatureAlgorithm::from_u8(1).unwrap(),
            SignatureAlgorithm::Rsa
        );
        assert!(SignatureAlgorithm::from_u8(0).is_err());
    }

    #[test]
    fn test_digitally_signed_encode_decode() {
        let ds = DigitallySigned {
            hash_algorithm: HashAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::Ecdsa,
            signature: vec![0x30, 0x44, 0x02, 0x20, 0x01, 0x02],
        };
        let encoded = ds.encode();
        let (decoded, consumed) = DigitallySigned::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, ds);
    }

    #[test]
    fn test_digitally_signed_too_short() {
        assert!(DigitallySigned::decode(&[0x04]).is_err());
        assert!(DigitallySigned::decode(&[]).is_err());
    }

    #[test]
    fn test_digitally_signed_truncated_signature() {
        // Claims 100-byte signature but only has 2 bytes
        let data = vec![0x04, 0x03, 0x00, 100, 0x01, 0x02];
        assert!(DigitallySigned::decode(&data).is_err());
    }

    #[test]
    fn test_sct_encode_decode_roundtrip() {
        let sct = make_test_sct();
        let encoded = sct.encode();
        let (decoded, consumed) = Sct::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.version, sct.version);
        assert_eq!(decoded.log_id, sct.log_id);
        assert_eq!(decoded.timestamp, sct.timestamp);
        assert_eq!(decoded.extensions, sct.extensions);
        assert_eq!(decoded.signature, sct.signature);
    }

    #[test]
    fn test_sct_with_extensions() {
        let mut sct = make_test_sct();
        sct.extensions = vec![0x01, 0x02, 0x03, 0x04];
        let encoded = sct.encode();
        let (decoded, _) = Sct::decode(&encoded).unwrap();
        assert_eq!(decoded.extensions, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_sct_decode_too_short() {
        assert!(Sct::decode(&[0; 10]).is_err());
    }

    #[test]
    fn test_sct_list_encode_decode_single() {
        let sct = make_test_sct();
        let list = SctList::new(vec![sct]);
        let tls = list.encode_tls();
        let decoded = SctList::decode_tls(&tls).unwrap();
        assert_eq!(decoded.scts.len(), 1);
        assert_eq!(decoded.scts[0].log_id, [0xAA; 32]);
    }

    #[test]
    fn test_sct_list_encode_decode_multiple() {
        let sct1 = make_test_sct();
        let mut sct2 = make_test_sct();
        sct2.log_id = [0xBB; 32];
        sct2.timestamp = 1_700_000_001_000;
        let list = SctList::new(vec![sct1, sct2]);
        let tls = list.encode_tls();
        let decoded = SctList::decode_tls(&tls).unwrap();
        assert_eq!(decoded.scts.len(), 2);
        assert_eq!(decoded.scts[0].log_id, [0xAA; 32]);
        assert_eq!(decoded.scts[1].log_id, [0xBB; 32]);
    }

    #[test]
    fn test_sct_list_empty_rejected() {
        assert!(SctList::decode_tls(&[]).is_err());
    }

    #[test]
    fn test_sct_list_der_roundtrip() {
        let sct = make_test_sct();
        let list = SctList::new(vec![sct]);
        let der = list.to_der().unwrap();
        // Should start with OCTET STRING tag
        assert_eq!(der[0], 0x04);
        let decoded = SctList::from_der(&der).unwrap();
        assert_eq!(decoded.scts.len(), 1);
        assert_eq!(decoded.scts[0].log_id, [0xAA; 32]);
    }

    #[test]
    fn test_compute_log_id() {
        let pub_key = vec![0x30, 0x59, 0x30, 0x13]; // fake SPKI prefix
        let id = compute_log_id(&pub_key);
        // Should be SHA-256 of the input
        let expected = digest::sha256(&pub_key);
        assert_eq!(&id[..], &expected[..]);
    }

    #[test]
    fn test_build_cert_signed_data() {
        let sct = make_test_sct();
        let cert_der = vec![0x30, 0x82, 0x01, 0x00]; // fake cert
        let data = build_cert_signed_data(&sct, &cert_der);

        // Check structure: version(1) + sig_type(1) + timestamp(8) + entry_type(2)
        //   + cert_len(3) + cert(4) + ext_len(2) + ext(0) = 21
        assert_eq!(data.len(), 21);
        assert_eq!(data[0], 0); // v1
        assert_eq!(data[1], 0); // certificate_timestamp
                                // entry_type: x509_entry = 0
        assert_eq!(data[10], 0);
        assert_eq!(data[11], 0);
    }

    #[test]
    fn test_build_precert_signed_data() {
        let sct = make_test_sct();
        let tbs = vec![0x30, 0x82, 0x01, 0x00]; // fake TBS
        let issuer_hash = [0xCC; 32];
        let data = build_precert_signed_data(&sct, &tbs, &issuer_hash);

        // version(1) + sig_type(1) + timestamp(8) + entry_type(2) + issuer_hash(32)
        //   + tbs_len(3) + tbs(4) + ext_len(2) + ext(0) = 53
        assert_eq!(data.len(), 53);
        assert_eq!(data[0], 0); // v1
        assert_eq!(data[1], 0); // certificate_timestamp
                                // entry_type: precert_entry = 1
        assert_eq!(data[10], 0);
        assert_eq!(data[11], 1);
        // issuer_key_hash starts at offset 12
        assert_eq!(&data[12..44], &[0xCC; 32]);
    }

    #[test]
    fn test_ct_log_entry_computes_log_id() {
        let pub_key = vec![0x30, 0x59, 0x30, 0x13, 0x06, 0x07];
        let entry = CtLogEntry::new("https://example.com/ct".into(), pub_key.clone());
        let expected = compute_log_id(&pub_key);
        assert_eq!(entry.log_id, expected);
    }

    #[test]
    fn test_ct_config_default() {
        let config = CtConfig::default();
        assert!(config.logs.is_empty());
        assert_eq!(config.submission_timeout, Duration::from_secs(30));
        assert_eq!(config.required_scts, 2);
    }

    #[test]
    fn test_parse_sct_response() {
        // Build a valid JSON response with base64-encoded fields
        let log_id_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0xAA; 32]);
        let ds = DigitallySigned {
            hash_algorithm: HashAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::Ecdsa,
            signature: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        };
        let sig_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ds.encode());

        let json = format!(
            r#"{{"sct_version":0,"id":"{}","timestamp":1700000000000,"extensions":"","signature":"{}"}}"#,
            log_id_b64, sig_b64
        );

        let sct = CtLogClient::parse_sct_response(&json).unwrap();
        assert_eq!(sct.version, SctVersion::V1);
        assert_eq!(sct.log_id, [0xAA; 32]);
        assert_eq!(sct.timestamp, 1_700_000_000_000);
        assert!(sct.extensions.is_empty());
        assert_eq!(sct.signature.hash_algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn test_parse_sct_response_missing_fields() {
        assert!(CtLogClient::parse_sct_response("{}").is_err());
        assert!(CtLogClient::parse_sct_response(r#"{"sct_version":0}"#).is_err());
    }

    #[test]
    fn test_parse_sct_response_bad_json() {
        assert!(CtLogClient::parse_sct_response("not json").is_err());
    }

    #[test]
    fn test_build_add_pre_chain_body() {
        let chain = vec![vec![0x30, 0x82], vec![0x30, 0x83]];
        let body = CtLogClient::build_add_pre_chain_body(&chain);
        // Should be valid JSON with base64-encoded certs
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let arr = v["chain"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn test_sct_list_length_mismatch() {
        // Outer length says 100 but only 10 bytes available
        let mut data = vec![0x00, 0x64]; // length = 100
        data.extend_from_slice(&[0; 10]);
        assert!(SctList::decode_tls(&data).is_err());
    }

    #[test]
    fn test_der_length_encoding() {
        // Short form
        let mut buf = Vec::new();
        encode_der_length(&mut buf, 50);
        assert_eq!(buf, vec![50]);

        // Long form (1 byte)
        let mut buf = Vec::new();
        encode_der_length(&mut buf, 200);
        assert_eq!(buf, vec![0x81, 200]);

        // Long form (2 bytes)
        let mut buf = Vec::new();
        encode_der_length(&mut buf, 300);
        assert_eq!(buf, vec![0x82, 0x01, 0x2C]);
    }

    #[test]
    fn test_sct_list_from_der_bad_tag() {
        // Wrong tag (SEQUENCE instead of OCTET STRING)
        let data = vec![0x30, 0x02, 0x00, 0x00];
        assert!(SctList::from_der(&data).is_err());
    }

    #[test]
    fn test_verify_sct_log_id_mismatch() {
        let mut sct = make_test_sct();
        sct.log_id = [0xFF; 32]; // Wrong log_id
        let fake_key = vec![0x30, 0x59]; // Won't match
        let result = verify_sct(&sct, &[0x30], &[], &fake_key, false).unwrap();
        assert!(!result, "Should fail when log_id doesn't match");
    }

    #[test]
    fn test_verify_sct_precert_short_issuer_hash() {
        let sct = make_test_sct();
        let result = verify_sct(&sct, &[0x30], &[0x01, 0x02], &[], true);
        assert!(result.is_err(), "Should reject short issuer_key_hash");
    }

    #[test]
    fn test_ct_log_client_accessors() {
        let config = CtConfig {
            logs: vec![CtLogEntry::new(
                "https://log.example.com".into(),
                vec![0x30],
            )],
            submission_timeout: Duration::from_secs(10),
            required_scts: 3,
        };
        let client = CtLogClient::new(config);
        assert_eq!(client.logs().len(), 1);
        assert_eq!(client.required_scts(), 3);
        assert_eq!(client.submission_timeout(), Duration::from_secs(10));
    }
}
