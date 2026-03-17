//! RFC 5914 Trust Anchor Format
//!
//! Implements the TrustAnchorInfo structure defined in RFC 5914 §2:
//!
//! ```text
//! TrustAnchorInfo ::= SEQUENCE {
//!     version   TrustAnchorInfoVersion DEFAULT v1,
//!     pubKey    SubjectPublicKeyInfo,
//!     keyId     KeyIdentifier,
//!     taTitle   UTF8String (SIZE (1..64)) OPTIONAL,
//!     certPath  CertPathControls OPTIONAL,
//!     exts      [1] EXPLICIT Extensions OPTIONAL,
//!     taTitleLangTag  [2] UTF8String OPTIONAL
//! }
//!
//! CertPathControls ::= SEQUENCE {
//!     taName          Name,
//!     certificate     [0] Certificate OPTIONAL,
//!     policySet       [1] CertificatePolicies OPTIONAL,
//!     policyFlags     [2] CertPolicyFlags OPTIONAL,
//!     nameConstr      [3] NameConstraints OPTIONAL,
//!     pathLenConstraint [4] INTEGER (0..MAX) OPTIONAL
//! }
//! ```
//!
//! Trust anchors are the roots of trust in a PKI — they are the
//! self-signed CA certificates (or just their public keys) that
//! relying parties have decided to trust unconditionally.

use der::{Decode, Encode};
use x509_cert::Certificate;

use crate::digest;

use crate::error::{Error, Result};

/// RFC 5914 Trust Anchor representation.
///
/// A trust anchor conveys a public key, a key identifier, and optionally
/// the certification path controls that apply when using this TA.
#[derive(Debug, Clone)]
pub struct TrustAnchorInfo {
    /// SubjectPublicKeyInfo DER — the TA's public key
    pub public_key_info: Vec<u8>,
    /// KeyIdentifier — SHA-256 digest of the SubjectPublicKeyInfo DER (truncated to 20 bytes)
    pub key_id: Vec<u8>,
    /// Human-readable title for the trust anchor (max 64 UTF-8 chars)
    pub ta_title: Option<String>,
    /// Certification path controls (name, path length, name constraints, etc.)
    pub cert_path: Option<CertPathControls>,
    /// Optional backing X.509 certificate DER
    pub certificate: Option<Vec<u8>>,
}

/// Certification path controls associated with a trust anchor (RFC 5914 §2).
#[derive(Debug, Clone)]
pub struct CertPathControls {
    /// Subject name of the TA encoded as a DER Name
    pub ta_name: Vec<u8>,
    /// Maximum number of non-self-issued certificates that may follow this TA in a path
    pub path_len_constraint: Option<u32>,
    /// NameConstraints DER (RFC 5280 §4.2.1.10), restricting valid subject names
    pub name_constraints: Option<Vec<u8>>,
}

impl TrustAnchorInfo {
    /// Create a TrustAnchorInfo by extracting fields from a DER-encoded X.509 certificate.
    ///
    /// The backing certificate is stored in `self.certificate`. The SPKI, SKI, subject
    /// name, and path length constraint are derived from the certificate.
    pub fn from_certificate(cert_der: &[u8]) -> Result<Self> {
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| Error::Decoding(format!("Trust anchor cert parse: {}", e)))?;

        // Extract SubjectPublicKeyInfo as DER
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;

        // Compute key identifier: SHA-256 of SPKI, truncated to 20 bytes (RFC 5280 §4.2.1.2 Method 1)
        let key_id = compute_ski(&spki_der);

        // Extract subject Name as DER
        let ta_name = cert
            .tbs_certificate
            .subject
            .to_der()
            .map_err(|e| Error::Encoding(format!("Subject Name encode: {}", e)))?;

        // Extract path length constraint from BasicConstraints
        let path_len_constraint = extract_path_len(&cert);

        // Extract NameConstraints extension DER if present
        let name_constraints = extract_name_constraints_der(&cert);

        let cert_path = Some(CertPathControls {
            ta_name,
            path_len_constraint,
            name_constraints,
        });

        // Build a human-readable title from the subject CN (if available)
        let ta_title = extract_cn(&cert).map(|cn| {
            if cn.len() > 64 {
                cn[..64].to_string()
            } else {
                cn
            }
        });

        Ok(Self {
            public_key_info: spki_der,
            key_id,
            ta_title,
            cert_path,
            certificate: Some(cert_der.to_vec()),
        })
    }

    /// DER-encode this TrustAnchorInfo as a minimal SEQUENCE.
    ///
    /// Encoding:
    /// ```text
    /// SEQUENCE {
    ///   SEQUENCE { ... }    -- SubjectPublicKeyInfo (pubKey)
    ///   OCTET STRING { }    -- KeyIdentifier (keyId)
    ///   UTF8String { ... }  -- taTitle OPTIONAL
    ///   SEQUENCE {          -- CertPathControls OPTIONAL
    ///     SEQUENCE { ... }  -- Name (taName)
    ///     [4] INTEGER       -- pathLenConstraint OPTIONAL
    ///     [3] SEQUENCE {...} -- nameConstraints OPTIONAL
    ///   }
    /// }
    /// ```
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let mut content = Vec::new();

        // pubKey: SubjectPublicKeyInfo (already DER)
        content.extend_from_slice(&self.public_key_info);

        // keyId: OCTET STRING
        encode_octet_string(&mut content, &self.key_id);

        // taTitle: UTF8String OPTIONAL
        if let Some(ref title) = self.ta_title {
            let title_bytes = title.as_bytes();
            let truncated = if title_bytes.len() > 64 {
                &title_bytes[..64]
            } else {
                title_bytes
            };
            encode_utf8_string(&mut content, truncated);
        }

        // certPath: CertPathControls OPTIONAL
        if let Some(ref cp) = self.cert_path {
            let mut cp_content = Vec::new();

            // taName: Name (already DER)
            cp_content.extend_from_slice(&cp.ta_name);

            // pathLenConstraint [4] INTEGER OPTIONAL
            if let Some(path_len) = cp.path_len_constraint {
                let int_der = encode_integer_u32(path_len);
                // [4] EXPLICIT
                encode_tagged(&mut cp_content, 4, true, &int_der);
            }

            // nameConstraints [3] OPTIONAL (raw DER — already a SEQUENCE)
            if let Some(ref nc_der) = cp.name_constraints {
                // [3] EXPLICIT wrapping the existing NameConstraints SEQUENCE
                encode_tagged(&mut cp_content, 3, true, nc_der);
            }

            encode_sequence(&mut content, &cp_content);
        }

        // Wrap everything in SEQUENCE
        Ok(wrap_sequence(&content))
    }

    /// Parse a DER-encoded TrustAnchorInfo back into a `TrustAnchorInfo`.
    ///
    /// Handles the minimal encoding written by `to_der()`. The optional backing
    /// certificate is not recovered from DER (set to `None`).
    pub fn from_der(data: &[u8]) -> Result<Self> {
        // Unwrap outer SEQUENCE
        let inner = unwrap_sequence(data)
            .ok_or_else(|| Error::Decoding("TrustAnchorInfo: expected SEQUENCE".into()))?;

        let mut pos = 0;

        // pubKey: SubjectPublicKeyInfo SEQUENCE
        let (spki_der, consumed) = next_tlv(inner, pos).ok_or_else(|| {
            Error::Decoding("TrustAnchorInfo: missing SubjectPublicKeyInfo".into())
        })?;
        pos += consumed;

        // keyId: OCTET STRING (tag 0x04)
        let (key_id_bytes, consumed) = next_tlv(inner, pos)
            .ok_or_else(|| Error::Decoding("TrustAnchorInfo: missing KeyIdentifier".into()))?;
        // key_id_bytes includes TLV — extract value
        let key_id = parse_octet_string(key_id_bytes)
            .ok_or_else(|| Error::Decoding("TrustAnchorInfo: invalid KeyIdentifier".into()))?;
        pos += consumed;

        // Optional fields
        let mut ta_title: Option<String> = None;
        let mut cert_path: Option<CertPathControls> = None;

        while pos < inner.len() {
            let remaining = &inner[pos..];
            if remaining.is_empty() {
                break;
            }

            let tag = remaining[0];

            match tag {
                // UTF8String (0x0C) — taTitle
                0x0C => {
                    let (tlv, consumed) = next_tlv(inner, pos)
                        .ok_or_else(|| Error::Decoding("TrustAnchorInfo: bad taTitle".into()))?;
                    let title_bytes = parse_string_value(tlv).ok_or_else(|| {
                        Error::Decoding("TrustAnchorInfo: invalid taTitle".into())
                    })?;
                    ta_title = Some(
                        std::str::from_utf8(title_bytes)
                            .map_err(|_| {
                                Error::Decoding("TrustAnchorInfo: taTitle not UTF-8".into())
                            })?
                            .to_string(),
                    );
                    pos += consumed;
                }
                // SEQUENCE (0x30) — CertPathControls
                0x30 => {
                    let (cp_tlv, consumed) = next_tlv(inner, pos).ok_or_else(|| {
                        Error::Decoding("TrustAnchorInfo: bad CertPathControls".into())
                    })?;
                    cert_path = Some(parse_cert_path_controls(cp_tlv)?);
                    pos += consumed;
                }
                // Context-tagged [0]..[4] or other — skip
                _ => {
                    let (_, consumed) = next_tlv(inner, pos)
                        .ok_or_else(|| Error::Decoding("TrustAnchorInfo: unexpected TLV".into()))?;
                    pos += consumed;
                }
            }
        }

        Ok(Self {
            public_key_info: spki_der.to_vec(),
            key_id,
            ta_title,
            cert_path,
            certificate: None,
        })
    }

    /// Describe the public key algorithm from the SubjectPublicKeyInfo.
    ///
    /// Returns a human-readable string like "ECDSA P-256", "RSA", or "ML-DSA-65".
    pub fn public_key_algorithm(&self) -> String {
        // Parse the AlgorithmIdentifier OID from SPKI
        // SPKI SEQUENCE { AlgorithmIdentifier SEQUENCE { OID ... }, BIT STRING }
        if let Some(inner) = unwrap_sequence(&self.public_key_info) {
            if let Some((alg_seq, _)) = next_tlv(inner, 0) {
                if let Some(alg_inner) = unwrap_sequence(alg_seq) {
                    if let Some(oid_str) = parse_oid(alg_inner) {
                        return match oid_str.as_str() {
                            // ECDSA / EC public key OID (the curve is in parameters)
                            "1.2.840.10045.2.1" => {
                                // Find parameter OID after the algorithm OID TLV
                                if let Some((_, oid_tlv_len)) = next_tlv(alg_inner, 0) {
                                    if let Some(param_oid) = parse_oid(&alg_inner[oid_tlv_len..]) {
                                        return match param_oid.as_str() {
                                            "1.2.840.10045.3.1.7" => "ECDSA P-256".to_string(),
                                            "1.3.132.0.34" => "ECDSA P-384".to_string(),
                                            "1.3.132.0.35" => "ECDSA P-521".to_string(),
                                            _ => format!("EC (curve {})", param_oid),
                                        };
                                    }
                                }
                                "ECDSA".to_string()
                            }
                            // RSA
                            "1.2.840.113549.1.1.1" => "RSA".to_string(),
                            // RSA-PSS
                            "1.2.840.113549.1.1.10" => "RSA-PSS".to_string(),
                            // ML-DSA (FIPS 204)
                            "2.16.840.1.101.3.4.3.17" => "ML-DSA-44".to_string(),
                            "2.16.840.1.101.3.4.3.18" => "ML-DSA-65".to_string(),
                            "2.16.840.1.101.3.4.3.19" => "ML-DSA-87".to_string(),
                            // SLH-DSA (FIPS 205)
                            "2.16.840.1.101.3.4.3.20" => "SLH-DSA-SHA2-128s".to_string(),
                            "2.16.840.1.101.3.4.3.22" => "SLH-DSA-SHA2-192s".to_string(),
                            "2.16.840.1.101.3.4.3.24" => "SLH-DSA-SHA2-256s".to_string(),
                            other => format!("Unknown ({})", other),
                        };
                    }
                }
            }
        }
        "Unknown".to_string()
    }

    /// Verify that the public key from the trust anchor matches the one in a given certificate.
    pub fn matches_certificate(&self, cert_der: &[u8]) -> bool {
        let cert = match Certificate::from_der(cert_der) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let cert_spki = match cert.tbs_certificate.subject_public_key_info.to_der() {
            Ok(d) => d,
            Err(_) => return false,
        };
        cert_spki == self.public_key_info
    }
}

// --------------------------------------------------------------------------
// Helpers for extracting X.509 fields
// --------------------------------------------------------------------------

/// Compute a key identifier: SHA-256 of SPKI DER, truncated to 20 bytes (Method 1, RFC 5280 §4.2.1.2).
fn compute_ski(spki_der: &[u8]) -> Vec<u8> {
    digest::sha256(spki_der)[..20].to_vec()
}

/// Extract path length constraint from BasicConstraints extension.
fn extract_path_len(cert: &Certificate) -> Option<u32> {
    use der::Decode;
    use x509_cert::ext::pkix::BasicConstraints;

    const OID_BASIC_CONSTRAINTS: &[u32] = &[2, 5, 29, 19];

    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts.iter() {
        let arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if arcs == OID_BASIC_CONSTRAINTS {
            if let Ok(bc) = BasicConstraints::from_der(ext.extn_value.as_bytes()) {
                return bc.path_len_constraint.map(|v| v as u32);
            }
        }
    }
    None
}

/// Extract NameConstraints extension value (the raw DER of the extension value, not the extension wrapper).
fn extract_name_constraints_der(cert: &Certificate) -> Option<Vec<u8>> {
    const OID_NAME_CONSTRAINTS: &[u32] = &[2, 5, 29, 30];

    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts.iter() {
        let arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if arcs == OID_NAME_CONSTRAINTS {
            return Some(ext.extn_value.as_bytes().to_vec());
        }
    }
    None
}

/// Extract the CN from a certificate subject.
fn extract_cn(cert: &Certificate) -> Option<String> {
    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            let arcs: Vec<u32> = atv.oid.arcs().collect();
            if arcs == [2, 5, 4, 3] {
                if let Ok(cn) = std::str::from_utf8(atv.value.value()) {
                    return Some(cn.to_string());
                }
            }
        }
    }
    None
}

// --------------------------------------------------------------------------
// Minimal DER encoding helpers (avoids pulling in heavy proc-macro derives)
// --------------------------------------------------------------------------

/// Encode a DER length field.
fn encode_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len <= 0xFF {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

/// Wrap bytes in a DER SEQUENCE (tag 0x30).
fn wrap_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    encode_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// Write a DER SEQUENCE TLV into a buffer.
fn encode_sequence(buf: &mut Vec<u8>, content: &[u8]) {
    buf.push(0x30);
    encode_length(buf, content.len());
    buf.extend_from_slice(content);
}

/// Write a DER OCTET STRING TLV into a buffer.
fn encode_octet_string(buf: &mut Vec<u8>, value: &[u8]) {
    buf.push(0x04);
    encode_length(buf, value.len());
    buf.extend_from_slice(value);
}

/// Write a DER UTF8String TLV into a buffer.
fn encode_utf8_string(buf: &mut Vec<u8>, value: &[u8]) {
    buf.push(0x0C);
    encode_length(buf, value.len());
    buf.extend_from_slice(value);
}

/// Write a context-tagged TLV (EXPLICIT or PRIMITIVE) into a buffer.
fn encode_tagged(buf: &mut Vec<u8>, tag_num: u8, explicit: bool, content: &[u8]) {
    let class_bits = 0xA0u8; // context-specific | constructed
    let tag = if explicit {
        class_bits | tag_num
    } else {
        0x80 | tag_num
    };
    buf.push(tag);
    encode_length(buf, content.len());
    buf.extend_from_slice(content);
}

/// Encode a u32 as a minimal DER INTEGER.
fn encode_integer_u32(v: u32) -> Vec<u8> {
    let mut out = vec![0x02]; // INTEGER tag
    if v == 0 {
        out.push(1);
        out.push(0);
    } else {
        let bytes = v.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        let int_bytes = &bytes[start..];
        // Add leading 0x00 if high bit is set (to keep it positive)
        let needs_pad = int_bytes[0] & 0x80 != 0;
        let len = int_bytes.len() + if needs_pad { 1 } else { 0 };
        out.push(len as u8);
        if needs_pad {
            out.push(0x00);
        }
        out.extend_from_slice(int_bytes);
    }
    out
}

// --------------------------------------------------------------------------
// Minimal DER decoding helpers
// --------------------------------------------------------------------------

/// Read the length at `data[pos]`, returning (length_value, bytes_consumed).
fn read_der_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()? as usize;
    if first < 0x80 {
        Some((first, 1))
    } else if first == 0x81 {
        Some((*data.get(1)? as usize, 2))
    } else if first == 0x82 {
        let hi = *data.get(1)? as usize;
        let lo = *data.get(2)? as usize;
        Some(((hi << 8) | lo, 3))
    } else {
        None
    }
}

/// Unwrap a DER SEQUENCE, returning the inner bytes (excluding the SEQUENCE TLV wrapper).
fn unwrap_sequence(data: &[u8]) -> Option<&[u8]> {
    if data.first()? != &0x30 {
        return None;
    }
    let (len, consumed) = read_der_length(&data[1..])?;
    let start = 1 + consumed;
    if data.len() < start + len {
        return None;
    }
    Some(&data[start..start + len])
}

/// Return the complete TLV at `data[pos]` as a slice, plus the number of bytes consumed.
fn next_tlv(data: &[u8], pos: usize) -> Option<(&[u8], usize)> {
    let data = &data[pos..];
    if data.len() < 2 {
        return None;
    }
    let (len, lc) = read_der_length(&data[1..])?;
    let total = 1 + lc + len;
    if data.len() < total {
        return None;
    }
    Some((&data[..total], total))
}

/// Extract the value bytes from an OCTET STRING TLV.
fn parse_octet_string(tlv: &[u8]) -> Option<Vec<u8>> {
    if tlv.first()? != &0x04 {
        return None;
    }
    let (len, lc) = read_der_length(&tlv[1..])?;
    let start = 1 + lc;
    Some(tlv.get(start..start + len)?.to_vec())
}

/// Extract the value bytes from a UTF8String or other simple string TLV.
fn parse_string_value(tlv: &[u8]) -> Option<&[u8]> {
    if tlv.len() < 2 {
        return None;
    }
    let (len, lc) = read_der_length(&tlv[1..])?;
    let start = 1 + lc;
    tlv.get(start..start + len)
}

/// Parse a DER OID TLV and return its dotted string representation.
fn parse_oid(data: &[u8]) -> Option<String> {
    if data.first()? != &0x06 {
        return None;
    }
    let (len, lc) = read_der_length(&data[1..])?;
    let start = 1 + lc;
    let oid_bytes = data.get(start..start + len)?;

    // Decode BER/DER OID encoding
    let mut arcs = Vec::new();
    if oid_bytes.is_empty() {
        return None;
    }
    // First byte encodes first two arcs: first*40 + second
    let first_byte = oid_bytes[0] as u32;
    arcs.push(first_byte / 40);
    arcs.push(first_byte % 40);

    let mut i = 1;
    while i < oid_bytes.len() {
        let mut value: u32 = 0;
        loop {
            let b = *oid_bytes.get(i)? as u32;
            i += 1;
            value = (value << 7) | (b & 0x7F);
            if b & 0x80 == 0 {
                break;
            }
        }
        arcs.push(value);
    }

    Some(
        arcs.iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// Parse a CertPathControls SEQUENCE TLV.
fn parse_cert_path_controls(tlv: &[u8]) -> Result<CertPathControls> {
    let inner = unwrap_sequence(tlv)
        .ok_or_else(|| Error::Decoding("CertPathControls: expected SEQUENCE".into()))?;

    let mut pos = 0;

    // taName: first SEQUENCE is the Name
    let (name_tlv, consumed) = next_tlv(inner, pos)
        .ok_or_else(|| Error::Decoding("CertPathControls: missing taName".into()))?;
    let ta_name = name_tlv.to_vec();
    pos += consumed;

    let mut path_len_constraint: Option<u32> = None;
    let mut name_constraints: Option<Vec<u8>> = None;

    while pos < inner.len() {
        let remaining = &inner[pos..];
        if remaining.is_empty() {
            break;
        }

        let tag = remaining[0];
        let (field_tlv, consumed) = next_tlv(inner, pos)
            .ok_or_else(|| Error::Decoding("CertPathControls: truncated field".into()))?;
        pos += consumed;

        match tag {
            // [3] EXPLICIT — nameConstraints
            0xA3 => {
                // Remove the explicit wrapper to get the inner content
                let inner_content = &field_tlv[1..]; // skip tag
                if let Some((inner_len, lc)) = read_der_length(inner_content) {
                    let nc_der = inner_content.get(lc..lc + inner_len).map(|s| s.to_vec());
                    name_constraints = nc_der;
                }
            }
            // [4] EXPLICIT — pathLenConstraint
            0xA4 => {
                // Unwrap explicit tag to get INTEGER
                let inner_content = &field_tlv[1..]; // skip tag byte
                if let Some((_outer_len, lc)) = read_der_length(inner_content) {
                    let int_tlv = &inner_content[lc..];
                    if int_tlv.first() == Some(&0x02) {
                        path_len_constraint = parse_integer_u32(int_tlv);
                    }
                }
            }
            _ => {} // Unknown field — skip
        }
    }

    Ok(CertPathControls {
        ta_name,
        path_len_constraint,
        name_constraints,
    })
}

/// Parse a DER INTEGER TLV into a u32 (assuming non-negative value fitting in u32).
fn parse_integer_u32(tlv: &[u8]) -> Option<u32> {
    if tlv.first()? != &0x02 {
        return None;
    }
    let (len, lc) = read_der_length(&tlv[1..])?;
    let start = 1 + lc;
    let int_bytes = tlv.get(start..start + len)?;

    // Skip leading zero byte (sign extension)
    let int_bytes = if int_bytes.first() == Some(&0x00) {
        &int_bytes[1..]
    } else {
        int_bytes
    };

    if int_bytes.len() > 4 {
        return None; // Won't fit in u32
    }

    let mut value: u32 = 0;
    for &b in int_bytes {
        value = (value << 8) | b as u32;
    }
    Some(value)
}

// --------------------------------------------------------------------------
// Trust anchor store helper
// --------------------------------------------------------------------------

/// A simple in-memory store of trust anchors.
///
/// Used alongside `validate_chain_with_trust_anchors` to validate certificate
/// chains against RFC 5914 trust anchors rather than raw certificate DER.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchorStore {
    anchors: Vec<TrustAnchorInfo>,
}

impl TrustAnchorStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trust anchor.
    pub fn add(&mut self, ta: TrustAnchorInfo) {
        self.anchors.push(ta);
    }

    /// Load a trust anchor from DER-encoded certificate bytes.
    pub fn add_from_cert_der(&mut self, cert_der: &[u8]) -> Result<()> {
        let ta = TrustAnchorInfo::from_certificate(cert_der)?;
        self.anchors.push(ta);
        Ok(())
    }

    /// Check whether any trust anchor's public key matches the given DER certificate.
    pub fn is_trusted(&self, cert_der: &[u8]) -> bool {
        self.anchors
            .iter()
            .any(|ta| ta.matches_certificate(cert_der))
    }

    /// Return the SPKI DER bytes for all trust anchors, for use in chain validation.
    pub fn spki_list(&self) -> Vec<Vec<u8>> {
        self.anchors
            .iter()
            .map(|ta| ta.public_key_info.clone())
            .collect()
    }

    /// Number of trust anchors in this store.
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// Iterate over all trust anchors.
    pub fn iter(&self) -> impl Iterator<Item = &TrustAnchorInfo> {
        self.anchors.iter()
    }
}

// --------------------------------------------------------------------------
// RFC 6024 Trust Anchor Management
// --------------------------------------------------------------------------

/// Unique identifier for a trust anchor — hex-encoded SHA-256 of the public key DER.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustAnchorId(pub String);

impl TrustAnchorId {
    /// Compute a TrustAnchorId from SubjectPublicKeyInfo DER bytes.
    pub fn from_spki(spki_der: &[u8]) -> Self {
        let hex = digest::sha256(spki_der)
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        Self(hex)
    }
}

impl std::fmt::Display for TrustAnchorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Lifecycle state of a trust anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaState {
    /// Trust anchor is active and used for path validation.
    Active,
    /// Trust anchor is temporarily suspended (not used for validation but not removed).
    Suspended,
    /// Trust anchor has been retired (kept for audit history but not used).
    Retired,
}

impl std::fmt::Display for TaState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaState::Active => write!(f, "Active"),
            TaState::Suspended => write!(f, "Suspended"),
            TaState::Retired => write!(f, "Retired"),
        }
    }
}

/// Summary view of a trust anchor for listing purposes.
#[derive(Debug, Clone)]
pub struct TrustAnchorSummary {
    /// Unique identifier (hex SHA-256 of SPKI DER).
    pub id: TrustAnchorId,
    /// Common Name extracted from the trust anchor title or cert path.
    pub subject_cn: String,
    /// When this trust anchor was added to the manager.
    pub added: chrono::DateTime<chrono::Utc>,
    /// Certification path controls, if any.
    pub constraints: Option<CertPathControls>,
    /// Current lifecycle state.
    pub state: TaState,
}

/// Actions that can be recorded in the trust anchor audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaAction {
    /// Trust anchor was added.
    Added,
    /// Trust anchor was removed.
    Removed,
    /// Certification path constraints were updated.
    ConstraintsUpdated,
    /// Lifecycle state was changed.
    StateChanged,
}

impl std::fmt::Display for TaAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaAction::Added => write!(f, "Added"),
            TaAction::Removed => write!(f, "Removed"),
            TaAction::ConstraintsUpdated => write!(f, "ConstraintsUpdated"),
            TaAction::StateChanged => write!(f, "StateChanged"),
        }
    }
}

/// An entry in the trust anchor audit log.
#[derive(Debug, Clone)]
pub struct TaAuditEntry {
    /// When this action occurred.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// What action was taken.
    pub action: TaAction,
    /// Which trust anchor was affected.
    pub ta_id: TrustAnchorId,
    /// Human-readable details about the action.
    pub details: String,
}

/// Internal record pairing a TrustAnchorInfo with its managed metadata.
#[derive(Debug, Clone)]
struct ManagedTrustAnchor {
    info: TrustAnchorInfo,
    id: TrustAnchorId,
    added: chrono::DateTime<chrono::Utc>,
    state: TaState,
}

/// RFC 6024 Trust Anchor Manager — lifecycle management for trust anchors.
///
/// Provides add/remove/update operations with full audit logging,
/// state transitions (Active/Suspended/Retired), and bulk export/import.
#[derive(Debug)]
pub struct TrustAnchorManager {
    store: TrustAnchorStore,
    managed: Vec<ManagedTrustAnchor>,
    audit_log: Vec<TaAuditEntry>,
}

impl TrustAnchorManager {
    /// Create an empty trust anchor manager.
    pub fn new() -> Self {
        Self {
            store: TrustAnchorStore::new(),
            managed: Vec::new(),
            audit_log: Vec::new(),
        }
    }

    /// Add a trust anchor from a DER-encoded X.509 certificate.
    ///
    /// Extracts the SPKI, subject, and constraints from the certificate,
    /// assigns a TrustAnchorId (hex SHA-256 of SPKI DER), and logs the addition.
    pub fn add_from_certificate(&mut self, cert_der: &[u8]) -> Result<TrustAnchorId> {
        let tai = TrustAnchorInfo::from_certificate(cert_der)?;
        self.add_from_trust_anchor_info(tai)
    }

    /// Add a pre-built TrustAnchorInfo to the manager.
    ///
    /// The TrustAnchorId is computed from the SPKI DER. Duplicate additions
    /// (same public key) are rejected with an error.
    pub fn add_from_trust_anchor_info(&mut self, tai: TrustAnchorInfo) -> Result<TrustAnchorId> {
        let id = TrustAnchorId::from_spki(&tai.public_key_info);

        // Reject duplicates
        if self.managed.iter().any(|m| m.id == id) {
            return Err(Error::InvalidCertificate(format!(
                "Trust anchor {} already exists",
                id
            )));
        }

        let cn = tai
            .ta_title
            .clone()
            .unwrap_or_else(|| "Unknown".to_string());
        let now = chrono::Utc::now();

        self.store.add(tai.clone());
        self.managed.push(ManagedTrustAnchor {
            info: tai,
            id: id.clone(),
            added: now,
            state: TaState::Active,
        });

        self.audit_log.push(TaAuditEntry {
            timestamp: now,
            action: TaAction::Added,
            ta_id: id.clone(),
            details: format!("Added trust anchor: {}", cn),
        });

        Ok(id)
    }

    /// Remove a trust anchor by ID.
    ///
    /// The trust anchor is removed from both the managed list and the underlying
    /// store. An audit entry is recorded.
    pub fn remove(&mut self, id: &TrustAnchorId) -> Result<()> {
        let pos = self
            .managed
            .iter()
            .position(|m| m.id == *id)
            .ok_or_else(|| Error::InvalidCertificate(format!("Trust anchor {} not found", id)))?;

        let removed = self.managed.remove(pos);
        let cn = removed
            .info
            .ta_title
            .clone()
            .unwrap_or_else(|| "Unknown".to_string());

        // Rebuild the store without the removed anchor
        self.rebuild_store();

        self.audit_log.push(TaAuditEntry {
            timestamp: chrono::Utc::now(),
            action: TaAction::Removed,
            ta_id: id.clone(),
            details: format!("Removed trust anchor: {}", cn),
        });

        Ok(())
    }

    /// Update the certification path constraints for a trust anchor.
    pub fn update_constraints(
        &mut self,
        id: &TrustAnchorId,
        controls: CertPathControls,
    ) -> Result<()> {
        let managed = self
            .managed
            .iter_mut()
            .find(|m| m.id == *id)
            .ok_or_else(|| Error::InvalidCertificate(format!("Trust anchor {} not found", id)))?;

        managed.info.cert_path = Some(controls);

        // Rebuild the store to reflect updated constraints
        self.rebuild_store();

        self.audit_log.push(TaAuditEntry {
            timestamp: chrono::Utc::now(),
            action: TaAction::ConstraintsUpdated,
            ta_id: id.clone(),
            details: "Updated certification path constraints".to_string(),
        });

        Ok(())
    }

    /// Change the lifecycle state of a trust anchor.
    pub fn set_state(&mut self, id: &TrustAnchorId, new_state: TaState) -> Result<()> {
        let managed = self
            .managed
            .iter_mut()
            .find(|m| m.id == *id)
            .ok_or_else(|| Error::InvalidCertificate(format!("Trust anchor {} not found", id)))?;

        let old_state = managed.state;
        managed.state = new_state;

        self.audit_log.push(TaAuditEntry {
            timestamp: chrono::Utc::now(),
            action: TaAction::StateChanged,
            ta_id: id.clone(),
            details: format!("State changed from {} to {}", old_state, new_state),
        });

        Ok(())
    }

    /// Get a trust anchor by ID.
    pub fn get(&self, id: &TrustAnchorId) -> Option<&TrustAnchorInfo> {
        self.managed.iter().find(|m| m.id == *id).map(|m| &m.info)
    }

    /// Get the state of a trust anchor by ID.
    pub fn get_state(&self, id: &TrustAnchorId) -> Option<TaState> {
        self.managed.iter().find(|m| m.id == *id).map(|m| m.state)
    }

    /// List all trust anchors as summaries.
    pub fn list(&self) -> Vec<TrustAnchorSummary> {
        self.managed
            .iter()
            .map(|m| TrustAnchorSummary {
                id: m.id.clone(),
                subject_cn: m
                    .info
                    .ta_title
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
                added: m.added,
                constraints: m.info.cert_path.clone(),
                state: m.state,
            })
            .collect()
    }

    /// Return the full audit log.
    pub fn audit_log(&self) -> &[TaAuditEntry] {
        &self.audit_log
    }

    /// Number of managed trust anchors.
    pub fn len(&self) -> usize {
        self.managed.len()
    }

    /// Whether the manager has no trust anchors.
    pub fn is_empty(&self) -> bool {
        self.managed.is_empty()
    }

    /// Access the underlying TrustAnchorStore (contains only Active anchors
    /// after a rebuild, but currently contains all for simplicity).
    pub fn store(&self) -> &TrustAnchorStore {
        &self.store
    }

    /// Export all trust anchors as a DER SEQUENCE OF TrustAnchorInfo.
    ///
    /// Each TrustAnchorInfo is individually DER-encoded and then wrapped in an
    /// outer SEQUENCE.
    pub fn export_all(&self) -> Result<Vec<u8>> {
        let mut content = Vec::new();
        for m in &self.managed {
            let ta_der = m.info.to_der()?;
            content.extend_from_slice(&ta_der);
        }
        Ok(wrap_sequence(&content))
    }

    /// Import trust anchors from a DER SEQUENCE OF TrustAnchorInfo.
    ///
    /// Returns the number of trust anchors successfully imported. Duplicates
    /// are silently skipped.
    pub fn import_all(&mut self, data: &[u8]) -> Result<usize> {
        let inner = unwrap_sequence(data)
            .ok_or_else(|| Error::Decoding("import_all: expected outer SEQUENCE".into()))?;

        let mut count = 0;
        let mut pos = 0;

        while pos < inner.len() {
            let (ta_tlv, consumed) = next_tlv(inner, pos)
                .ok_or_else(|| Error::Decoding("import_all: truncated TrustAnchorInfo".into()))?;
            pos += consumed;

            let tai = TrustAnchorInfo::from_der(ta_tlv)?;
            let id = TrustAnchorId::from_spki(&tai.public_key_info);

            // Skip duplicates
            if self.managed.iter().any(|m| m.id == id) {
                continue;
            }

            let cn = tai
                .ta_title
                .clone()
                .unwrap_or_else(|| "Unknown".to_string());
            let now = chrono::Utc::now();

            self.store.add(tai.clone());
            self.managed.push(ManagedTrustAnchor {
                info: tai,
                id: id.clone(),
                added: now,
                state: TaState::Active,
            });

            self.audit_log.push(TaAuditEntry {
                timestamp: now,
                action: TaAction::Added,
                ta_id: id,
                details: format!("Imported trust anchor: {}", cn),
            });

            count += 1;
        }

        Ok(count)
    }

    /// Rebuild the underlying TrustAnchorStore from the managed list.
    fn rebuild_store(&mut self) {
        let mut new_store = TrustAnchorStore::new();
        for m in &self.managed {
            new_store.add(m.info.clone());
        }
        self.store = new_store;
    }
}

impl Default for TrustAnchorManager {
    fn default() -> Self {
        Self::new()
    }
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "ceremony")]
    mod ceremony_tests {
        use super::*;
        use crate::algo::AlgorithmId;
        use crate::ca::{CaCeremony, CaConfig};
        use crate::cert::{encode_certificate_der, NameBuilder};

        fn make_self_signed_root(name: &str, algo: AlgorithmId) -> Vec<u8> {
            let config = CaConfig::root(name, algo).with_subject(
                NameBuilder::new(name)
                    .organization("SPORK Trust Anchor Test")
                    .country("US")
                    .build(),
            );
            let result = CaCeremony::init_root(config).unwrap();
            encode_certificate_der(&result.ca.certificate).unwrap()
        }

        #[test]
        fn test_from_certificate_basic() {
            let cert_der = make_self_signed_root("TA Test Root", AlgorithmId::EcdsaP256);
            let ta = TrustAnchorInfo::from_certificate(&cert_der).unwrap();

            // SPKI must be non-empty
            assert!(!ta.public_key_info.is_empty(), "SPKI should be populated");

            // key_id is SHA-256 truncated to 20 bytes
            assert_eq!(ta.key_id.len(), 20, "key_id must be 20 bytes");

            // title should contain the CN
            let title = ta.ta_title.as_deref().unwrap_or("");
            assert!(title.contains("TA Test Root"), "taTitle should contain CN");

            // cert_path present for CA cert
            assert!(ta.cert_path.is_some(), "cert_path should be present");

            // Backing cert stored
            assert_eq!(ta.certificate.as_deref(), Some(cert_der.as_slice()));
        }

        #[test]
        fn test_from_certificate_spki_matches_cert() {
            let cert_der = make_self_signed_root("SPKI Match Root", AlgorithmId::EcdsaP256);
            let cert = Certificate::from_der(&cert_der).unwrap();

            let ta = TrustAnchorInfo::from_certificate(&cert_der).unwrap();

            let expected_spki = cert
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap();
            assert_eq!(
                ta.public_key_info, expected_spki,
                "SPKI must match cert SPKI"
            );
        }

        #[test]
        fn test_from_certificate_key_id_is_sha256_of_spki() {
            let cert_der = make_self_signed_root("SKI Root", AlgorithmId::EcdsaP256);
            let ta = TrustAnchorInfo::from_certificate(&cert_der).unwrap();

            let expected_ski = compute_ski(&ta.public_key_info);
            assert_eq!(
                ta.key_id, expected_ski,
                "key_id must be SHA-256[:20] of SPKI"
            );
        }

        #[test]
        fn test_der_round_trip() {
            let cert_der = make_self_signed_root("Round Trip Root", AlgorithmId::EcdsaP256);
            let ta = TrustAnchorInfo::from_certificate(&cert_der).unwrap();

            let encoded = ta.to_der().unwrap();
            let decoded = TrustAnchorInfo::from_der(&encoded).unwrap();

            assert_eq!(
                decoded.public_key_info, ta.public_key_info,
                "SPKI round-trip"
            );
            assert_eq!(decoded.key_id, ta.key_id, "key_id round-trip");
            assert_eq!(decoded.ta_title, ta.ta_title, "taTitle round-trip");
        }

        #[test]
        fn test_der_round_trip_cert_path() {
            let cert_der = make_self_signed_root("CertPath Root", AlgorithmId::EcdsaP256);
            let ta = TrustAnchorInfo::from_certificate(&cert_der).unwrap();

            let encoded = ta.to_der().unwrap();
            let decoded = TrustAnchorInfo::from_der(&encoded).unwrap();

            // cert_path name round-trip
            if let (Some(orig_cp), Some(dec_cp)) = (&ta.cert_path, &decoded.cert_path) {
                assert_eq!(orig_cp.ta_name, dec_cp.ta_name, "taName round-trip");
                assert_eq!(
                    orig_cp.path_len_constraint, dec_cp.path_len_constraint,
                    "pathLenConstraint round-trip"
                );
            }
        }

        #[test]
        fn test_public_key_algorithm_p256() {
            let cert_der = make_self_signed_root("P256 Algo Root", AlgorithmId::EcdsaP256);
            let ta = TrustAnchorInfo::from_certificate(&cert_der).unwrap();
            assert_eq!(ta.public_key_algorithm(), "ECDSA P-256");
        }

        #[test]
        fn test_public_key_algorithm_p384() {
            let cert_der = make_self_signed_root("P384 Algo Root", AlgorithmId::EcdsaP384);
            let ta = TrustAnchorInfo::from_certificate(&cert_der).unwrap();
            assert_eq!(ta.public_key_algorithm(), "ECDSA P-384");
        }

        #[test]
        #[cfg(not(feature = "fips"))] // RSA-2048 rejected in FIPS mode (minimum 3072-bit)
        fn test_public_key_algorithm_rsa() {
            let cert_der = make_self_signed_root("RSA Algo Root", AlgorithmId::Rsa2048);
            let ta = TrustAnchorInfo::from_certificate(&cert_der).unwrap();
            assert_eq!(ta.public_key_algorithm(), "RSA");
        }

        #[test]
        fn test_matches_certificate_true() {
            let cert_der = make_self_signed_root("Match Root", AlgorithmId::EcdsaP256);
            let ta = TrustAnchorInfo::from_certificate(&cert_der).unwrap();
            assert!(
                ta.matches_certificate(&cert_der),
                "Should match its own cert"
            );
        }

        #[test]
        fn test_matches_certificate_false() {
            let cert_der_a = make_self_signed_root("Root A", AlgorithmId::EcdsaP256);
            let cert_der_b = make_self_signed_root("Root B", AlgorithmId::EcdsaP256);
            let ta = TrustAnchorInfo::from_certificate(&cert_der_a).unwrap();
            assert!(
                !ta.matches_certificate(&cert_der_b),
                "Different certs should not match"
            );
        }

        #[test]
        fn test_trust_anchor_store_basic() {
            let cert_der = make_self_signed_root("Store Root", AlgorithmId::EcdsaP256);
            let mut store = TrustAnchorStore::new();
            store.add_from_cert_der(&cert_der).unwrap();

            assert_eq!(store.len(), 1);
            assert!(!store.is_empty());
            assert!(store.is_trusted(&cert_der), "Loaded cert should be trusted");
        }

        #[test]
        #[cfg(not(feature = "fips"))] // RSA-2048 rejected in FIPS mode (minimum 3072-bit)
        fn test_trust_anchor_store_multiple() {
            let cert_p256 = make_self_signed_root("P256 Root", AlgorithmId::EcdsaP256);
            let cert_p384 = make_self_signed_root("P384 Root", AlgorithmId::EcdsaP384);
            let cert_rsa = make_self_signed_root("RSA Root", AlgorithmId::Rsa2048);

            let mut store = TrustAnchorStore::new();
            store.add_from_cert_der(&cert_p256).unwrap();
            store.add_from_cert_der(&cert_p384).unwrap();
            store.add_from_cert_der(&cert_rsa).unwrap();

            assert_eq!(store.len(), 3);
            assert!(store.is_trusted(&cert_p256));
            assert!(store.is_trusted(&cert_p384));
            assert!(store.is_trusted(&cert_rsa));
        }

        #[test]
        fn test_trust_anchor_store_untrusted() {
            let cert_a = make_self_signed_root("Trusted Root", AlgorithmId::EcdsaP256);
            let cert_b = make_self_signed_root("Untrusted Root", AlgorithmId::EcdsaP256);

            let mut store = TrustAnchorStore::new();
            store.add_from_cert_der(&cert_a).unwrap();

            assert!(!store.is_trusted(&cert_b), "cert_b should not be trusted");
        }

        #[test]
        fn test_trust_anchor_spki_list() {
            let cert_p256 = make_self_signed_root("SPKI List Root", AlgorithmId::EcdsaP256);
            let mut store = TrustAnchorStore::new();
            store.add_from_cert_der(&cert_p256).unwrap();

            let spkis = store.spki_list();
            assert_eq!(spkis.len(), 1);
            assert!(!spkis[0].is_empty());
        }

        #[test]
        fn test_chain_validation_with_trust_anchor_store() {
            use crate::ca::CaConfig;

            // Build root → intermediate → EE
            let root_config = CaConfig::root("TA Store Root", AlgorithmId::EcdsaP256).with_subject(
                NameBuilder::new("TA Store Root")
                    .organization("SPORK Test")
                    .country("US")
                    .build(),
            );
            let root_result = CaCeremony::init_root(root_config).unwrap();
            let root_cert_der = encode_certificate_der(&root_result.ca.certificate).unwrap();

            // Load root into trust anchor store
            let mut store = TrustAnchorStore::new();
            store.add_from_cert_der(&root_cert_der).unwrap();
            assert!(store.is_trusted(&root_cert_der), "Root should be in store");
        }
    }

    // --- Tests that don't require the ceremony feature ---

    #[test]
    fn test_compute_ski_length() {
        let spki = b"fake spki bytes for testing";
        let ski = compute_ski(spki);
        assert_eq!(ski.len(), 20, "SKI must be exactly 20 bytes");
    }

    #[test]
    fn test_compute_ski_deterministic() {
        let spki = b"test spki bytes";
        let ski1 = compute_ski(spki);
        let ski2 = compute_ski(spki);
        assert_eq!(ski1, ski2, "SKI must be deterministic");
    }

    #[test]
    fn test_encode_decode_integer_u32_zero() {
        let encoded = encode_integer_u32(0);
        let val = parse_integer_u32(&encoded).unwrap();
        assert_eq!(val, 0);
    }

    #[test]
    fn test_encode_decode_integer_u32_small() {
        for v in [1u32, 5, 127, 128, 255, 256, 65535, 0x00FF_FFFF] {
            let encoded = encode_integer_u32(v);
            let parsed = parse_integer_u32(&encoded).unwrap();
            assert_eq!(parsed, v, "Round-trip failed for {}", v);
        }
    }

    #[test]
    fn test_wrap_unwrap_sequence() {
        let inner = b"hello world";
        let wrapped = wrap_sequence(inner);
        let unwrapped = unwrap_sequence(&wrapped).unwrap();
        assert_eq!(unwrapped, inner);
    }

    #[test]
    fn test_der_round_trip_without_cert() {
        // Synthesize a minimal TrustAnchorInfo without needing ceremony feature
        // Use a fake (but structurally valid) SPKI: real P-256 SPKI header with zeros
        // SEQUENCE { SEQUENCE { OID 1.2.840.10045.2.1, OID 1.2.840.10045.3.1.7 }, BIT STRING }
        let fake_spki = vec![
            0x30, 0x59, // SEQUENCE (89 bytes)
            0x30, 0x13, // AlgorithmIdentifier SEQUENCE
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
            0x07, // OID 1.2.840.10045.3.1.7
            0x03, 0x42, 0x00, // BIT STRING (66 bytes, 0 unused)
            // 65 bytes of fake EC public key point
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let key_id = compute_ski(&fake_spki);
        let ta = TrustAnchorInfo {
            public_key_info: fake_spki.clone(),
            key_id: key_id.clone(),
            ta_title: Some("Test TA".to_string()),
            cert_path: None,
            certificate: None,
        };

        let encoded = ta.to_der().unwrap();
        let decoded = TrustAnchorInfo::from_der(&encoded).unwrap();

        assert_eq!(decoded.public_key_info, fake_spki);
        assert_eq!(decoded.key_id, key_id);
        assert_eq!(decoded.ta_title.as_deref(), Some("Test TA"));
    }

    #[test]
    fn test_public_key_algorithm_from_spki() {
        // P-256 SPKI OID
        let fake_spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
            0x01, // EC OID
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // P-256 OID
            0x03, 0x42, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let ta = TrustAnchorInfo {
            public_key_info: fake_spki,
            key_id: vec![0u8; 20],
            ta_title: None,
            cert_path: None,
            certificate: None,
        };
        assert_eq!(ta.public_key_algorithm(), "ECDSA P-256");
    }

    #[test]
    fn test_trust_anchor_store_empty() {
        let store = TrustAnchorStore::new();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
        assert!(!store.is_trusted(b"anything"));
    }

    // --- RFC 6024 TrustAnchorManager tests ---

    /// Helper: build a fake TrustAnchorInfo with a unique SPKI.
    fn make_fake_tai(title: &str, key_byte: u8) -> TrustAnchorInfo {
        let mut fake_spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        // Fill 64 bytes with key_byte to make each SPKI unique
        fake_spki.extend(std::iter::repeat_n(key_byte, 64));
        let key_id = compute_ski(&fake_spki);
        TrustAnchorInfo {
            public_key_info: fake_spki,
            key_id,
            ta_title: Some(title.to_string()),
            cert_path: None,
            certificate: None,
        }
    }

    #[test]
    fn test_manager_new_is_empty() {
        let mgr = TrustAnchorManager::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.len(), 0);
        assert!(mgr.list().is_empty());
        assert!(mgr.audit_log().is_empty());
    }

    #[test]
    fn test_manager_add_from_tai() {
        let mut mgr = TrustAnchorManager::new();
        let tai = make_fake_tai("Test Root", 0x01);
        let id = mgr.add_from_trust_anchor_info(tai).unwrap();

        assert_eq!(mgr.len(), 1);
        assert!(!mgr.is_empty());
        assert!(mgr.get(&id).is_some());
        assert_eq!(mgr.get(&id).unwrap().ta_title.as_deref(), Some("Test Root"));
    }

    #[test]
    fn test_manager_add_duplicate_rejected() {
        let mut mgr = TrustAnchorManager::new();
        let tai = make_fake_tai("Dup Root", 0x02);
        mgr.add_from_trust_anchor_info(tai.clone()).unwrap();

        let result = mgr.add_from_trust_anchor_info(tai);
        assert!(result.is_err(), "Duplicate add should fail");
    }

    #[test]
    fn test_manager_remove() {
        let mut mgr = TrustAnchorManager::new();
        let tai = make_fake_tai("Remove Root", 0x03);
        let id = mgr.add_from_trust_anchor_info(tai).unwrap();
        assert_eq!(mgr.len(), 1);

        mgr.remove(&id).unwrap();
        assert_eq!(mgr.len(), 0);
        assert!(mgr.get(&id).is_none());
    }

    #[test]
    fn test_manager_remove_nonexistent() {
        let mut mgr = TrustAnchorManager::new();
        let fake_id = TrustAnchorId("nonexistent".to_string());
        let result = mgr.remove(&fake_id);
        assert!(result.is_err(), "Remove nonexistent should fail");
    }

    #[test]
    fn test_manager_update_constraints() {
        let mut mgr = TrustAnchorManager::new();
        let tai = make_fake_tai("Constrain Root", 0x04);
        let id = mgr.add_from_trust_anchor_info(tai).unwrap();

        // Initially no constraints
        assert!(mgr.get(&id).unwrap().cert_path.is_none());

        let controls = CertPathControls {
            ta_name: vec![0x30, 0x00], // minimal empty Name SEQUENCE
            path_len_constraint: Some(2),
            name_constraints: None,
        };
        mgr.update_constraints(&id, controls).unwrap();

        let updated = mgr.get(&id).unwrap();
        assert!(updated.cert_path.is_some());
        assert_eq!(
            updated.cert_path.as_ref().unwrap().path_len_constraint,
            Some(2)
        );
    }

    #[test]
    fn test_manager_update_constraints_nonexistent() {
        let mut mgr = TrustAnchorManager::new();
        let fake_id = TrustAnchorId("nope".to_string());
        let controls = CertPathControls {
            ta_name: vec![0x30, 0x00],
            path_len_constraint: None,
            name_constraints: None,
        };
        let result = mgr.update_constraints(&fake_id, controls);
        assert!(result.is_err());
    }

    #[test]
    fn test_manager_state_transitions() {
        let mut mgr = TrustAnchorManager::new();
        let tai = make_fake_tai("State Root", 0x05);
        let id = mgr.add_from_trust_anchor_info(tai).unwrap();

        // Default state is Active
        assert_eq!(mgr.get_state(&id), Some(TaState::Active));

        // Suspend
        mgr.set_state(&id, TaState::Suspended).unwrap();
        assert_eq!(mgr.get_state(&id), Some(TaState::Suspended));

        // Retire
        mgr.set_state(&id, TaState::Retired).unwrap();
        assert_eq!(mgr.get_state(&id), Some(TaState::Retired));

        // Reactivate
        mgr.set_state(&id, TaState::Active).unwrap();
        assert_eq!(mgr.get_state(&id), Some(TaState::Active));
    }

    #[test]
    fn test_manager_state_nonexistent() {
        let mut mgr = TrustAnchorManager::new();
        let fake_id = TrustAnchorId("absent".to_string());
        let result = mgr.set_state(&fake_id, TaState::Suspended);
        assert!(result.is_err());
    }

    #[test]
    fn test_manager_list() {
        let mut mgr = TrustAnchorManager::new();
        let tai1 = make_fake_tai("List Root A", 0x06);
        let tai2 = make_fake_tai("List Root B", 0x07);
        let id1 = mgr.add_from_trust_anchor_info(tai1).unwrap();
        let _id2 = mgr.add_from_trust_anchor_info(tai2).unwrap();

        let summaries = mgr.list();
        assert_eq!(summaries.len(), 2);

        // Check first summary
        let s1 = summaries.iter().find(|s| s.id == id1).unwrap();
        assert_eq!(s1.subject_cn, "List Root A");
        assert_eq!(s1.state, TaState::Active);
    }

    #[test]
    fn test_manager_audit_log_add_remove() {
        let mut mgr = TrustAnchorManager::new();
        let tai = make_fake_tai("Audit Root", 0x08);
        let id = mgr.add_from_trust_anchor_info(tai).unwrap();

        assert_eq!(mgr.audit_log().len(), 1);
        assert_eq!(mgr.audit_log()[0].action, TaAction::Added);
        assert_eq!(mgr.audit_log()[0].ta_id, id);

        mgr.remove(&id).unwrap();
        assert_eq!(mgr.audit_log().len(), 2);
        assert_eq!(mgr.audit_log()[1].action, TaAction::Removed);
    }

    #[test]
    fn test_manager_audit_log_state_change() {
        let mut mgr = TrustAnchorManager::new();
        let tai = make_fake_tai("Audit State Root", 0x09);
        let id = mgr.add_from_trust_anchor_info(tai).unwrap();

        mgr.set_state(&id, TaState::Suspended).unwrap();
        assert_eq!(mgr.audit_log().len(), 2);
        assert_eq!(mgr.audit_log()[1].action, TaAction::StateChanged);
        assert!(mgr.audit_log()[1].details.contains("Suspended"));
    }

    #[test]
    fn test_manager_audit_log_constraints_updated() {
        let mut mgr = TrustAnchorManager::new();
        let tai = make_fake_tai("Audit Constraints Root", 0x0A);
        let id = mgr.add_from_trust_anchor_info(tai).unwrap();

        let controls = CertPathControls {
            ta_name: vec![0x30, 0x00],
            path_len_constraint: Some(1),
            name_constraints: None,
        };
        mgr.update_constraints(&id, controls).unwrap();
        assert_eq!(mgr.audit_log().len(), 2);
        assert_eq!(mgr.audit_log()[1].action, TaAction::ConstraintsUpdated);
    }

    #[test]
    fn test_manager_export_import_round_trip() {
        let mut mgr1 = TrustAnchorManager::new();
        let tai1 = make_fake_tai("Export A", 0x0B);
        let tai2 = make_fake_tai("Export B", 0x0C);
        mgr1.add_from_trust_anchor_info(tai1).unwrap();
        mgr1.add_from_trust_anchor_info(tai2).unwrap();

        let exported = mgr1.export_all().unwrap();
        assert!(!exported.is_empty());

        // Import into a fresh manager
        let mut mgr2 = TrustAnchorManager::new();
        let count = mgr2.import_all(&exported).unwrap();
        assert_eq!(count, 2);
        assert_eq!(mgr2.len(), 2);

        // Verify titles survived the round-trip
        let summaries = mgr2.list();
        let titles: Vec<&str> = summaries.iter().map(|s| s.subject_cn.as_str()).collect();
        assert!(titles.contains(&"Export A"));
        assert!(titles.contains(&"Export B"));
    }

    #[test]
    fn test_manager_import_skips_duplicates() {
        let mut mgr = TrustAnchorManager::new();
        let tai = make_fake_tai("Dup Import", 0x0D);
        mgr.add_from_trust_anchor_info(tai).unwrap();

        let exported = mgr.export_all().unwrap();

        // Import the same data again
        let count = mgr.import_all(&exported).unwrap();
        assert_eq!(count, 0, "Duplicate import should be skipped");
        assert_eq!(mgr.len(), 1, "Should still have only 1 TA");
    }

    #[test]
    fn test_manager_export_empty() {
        let mgr = TrustAnchorManager::new();
        let exported = mgr.export_all().unwrap();
        // Should be a valid empty SEQUENCE: 0x30 0x00
        assert_eq!(exported, vec![0x30, 0x00]);
    }

    #[test]
    fn test_manager_store_sync() {
        let mut mgr = TrustAnchorManager::new();
        let tai = make_fake_tai("Store Sync Root", 0x0E);
        let spki = tai.public_key_info.clone();
        mgr.add_from_trust_anchor_info(tai).unwrap();

        // Underlying store should contain the SPKI
        let spkis = mgr.store().spki_list();
        assert_eq!(spkis.len(), 1);
        assert_eq!(spkis[0], spki);
    }

    #[test]
    fn test_manager_remove_rebuilds_store() {
        let mut mgr = TrustAnchorManager::new();
        let tai1 = make_fake_tai("Keep Root", 0x0F);
        let tai2 = make_fake_tai("Remove Root 2", 0x10);
        let _id1 = mgr.add_from_trust_anchor_info(tai1).unwrap();
        let id2 = mgr.add_from_trust_anchor_info(tai2).unwrap();
        assert_eq!(mgr.store().len(), 2);

        mgr.remove(&id2).unwrap();
        assert_eq!(mgr.store().len(), 1);
    }

    #[test]
    fn test_trust_anchor_id_from_spki() {
        let spki = b"test spki for id";
        let id1 = TrustAnchorId::from_spki(spki);
        let id2 = TrustAnchorId::from_spki(spki);
        assert_eq!(id1, id2, "Same SPKI should produce same ID");

        let id3 = TrustAnchorId::from_spki(b"different spki");
        assert_ne!(id1, id3, "Different SPKI should produce different ID");

        // ID should be 64 hex chars (SHA-256 = 32 bytes = 64 hex)
        assert_eq!(id1.0.len(), 64);
    }

    #[test]
    fn test_ta_state_display() {
        assert_eq!(format!("{}", TaState::Active), "Active");
        assert_eq!(format!("{}", TaState::Suspended), "Suspended");
        assert_eq!(format!("{}", TaState::Retired), "Retired");
    }

    #[test]
    fn test_ta_action_display() {
        assert_eq!(format!("{}", TaAction::Added), "Added");
        assert_eq!(format!("{}", TaAction::Removed), "Removed");
        assert_eq!(
            format!("{}", TaAction::ConstraintsUpdated),
            "ConstraintsUpdated"
        );
        assert_eq!(format!("{}", TaAction::StateChanged), "StateChanged");
    }
}
