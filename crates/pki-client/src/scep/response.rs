//! SCEP CertRep Response Parser (RFC 8894 §3.4)
//!
//! Parses the CMS SignedData response from the SCEP server and extracts:
//! - pkiStatus (SUCCESS / PENDING / FAILURE)
//! - failInfo (if FAILURE)
//! - recipientNonce
//! - Issued certificate (if SUCCESS)

use anyhow::{anyhow, Context, Result};

use super::types::{FailInfo, PkiStatus};

/// Parsed SCEP CertRep response.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields read during enrollment polling
pub struct ParsedCertRep {
    /// PKI status from authenticatedAttributes
    pub status: PkiStatus,
    /// Fail info (present if status == Failure)
    pub fail_info: Option<FailInfo>,
    /// Recipient nonce (echo of sender nonce)
    pub recipient_nonce: Option<Vec<u8>>,
    /// Transaction ID from response
    pub transaction_id: Option<String>,
    /// DER-encoded issued certificates (present if status == Success)
    pub certificates: Vec<Vec<u8>>,
}

/// Parse a SCEP CertRep response (CMS SignedData DER bytes).
///
/// Extracts authenticated attributes and certificates from the signed response.
/// Note: We do not verify the CA's signature on the response — callers should
/// validate the issued certificate against the CA certificate after enrollment.
pub fn parse_cert_rep(der: &[u8]) -> Result<ParsedCertRep> {
    // Strip ContentInfo wrapper to get SignedData
    let signed_data = extract_content_info_content(der)
        .context("Failed to extract SignedData from ContentInfo")?;

    // Parse SignedData fields
    let sd_content =
        parse_sequence_content(signed_data).context("Failed to parse SignedData SEQUENCE")?;

    let mut pos = 0;

    // version CMSVersion
    let (_, version_len) = parse_tlv_at(sd_content, pos)?;
    pos += version_len;

    // digestAlgorithms SET
    let (_, da_len) = parse_tlv_at(sd_content, pos)?;
    pos += da_len;

    // encapContentInfo SEQUENCE
    let (_, eci_len) = parse_tlv_at(sd_content, pos)?;
    pos += eci_len;

    // certificates [0] OPTIONAL
    let mut cert_ders = Vec::new();
    if pos < sd_content.len() && sd_content[pos] == 0xa0 {
        let (certs_content, certs_len) = parse_tlv_at(sd_content, pos)?;
        extract_certificates(certs_content, &mut cert_ders);
        pos += certs_len;
    }

    // crls [1] OPTIONAL — skip if present
    if pos < sd_content.len() && sd_content[pos] == 0xa1 {
        let (_, crls_len) = parse_tlv_at(sd_content, pos)?;
        pos += crls_len;
    }

    // signerInfos SET
    if pos >= sd_content.len() || sd_content[pos] != 0x31 {
        return Err(anyhow!("No signerInfos found in CertRep SignedData"));
    }

    let (signer_infos_content, _) = parse_tlv_at(sd_content, pos)?;
    let attrs = extract_authenticated_attrs_from_signer_infos(signer_infos_content);
    let status = parse_pki_status(&attrs)?;
    let fail_info = parse_fail_info(&attrs);
    let recipient_nonce = parse_recipient_nonce(&attrs);
    let transaction_id = parse_transaction_id(&attrs);

    Ok(ParsedCertRep {
        status,
        fail_info,
        recipient_nonce,
        transaction_id,
        certificates: cert_ders,
    })
}

// ── Attribute extraction ──────────────────────────────────────────────────────

/// Collected SCEP attributes from SignerInfo authenticated attributes.
struct ScepAttrs {
    pki_status: Option<String>,
    fail_info: Option<u8>,
    recipient_nonce: Option<Vec<u8>>,
    transaction_id: Option<String>,
}

/// Extract authenticated attributes from SignerInfos SET content.
fn extract_authenticated_attrs_from_signer_infos(signer_infos: &[u8]) -> ScepAttrs {
    let mut attrs = ScepAttrs {
        pki_status: None,
        fail_info: None,
        recipient_nonce: None,
        transaction_id: None,
    };

    // Iterate over SignerInfo SEQUENCEs in the SET
    let mut pos = 0;
    while pos < signer_infos.len() {
        let Ok((si_content, si_len)) = parse_tlv_at(signer_infos, pos) else {
            break;
        };
        pos += si_len;

        // Parse SignerInfo to find authenticatedAttributes [0]
        parse_signer_info_for_attrs(si_content, &mut attrs);
    }

    attrs
}

/// Walk a SignerInfo SEQUENCE to find \[0\] authenticatedAttributes.
fn parse_signer_info_for_attrs(si: &[u8], attrs: &mut ScepAttrs) {
    let mut pos = 0;

    // version
    if let Ok((_, len)) = parse_tlv_at(si, pos) {
        pos += len;
    } else {
        return;
    }
    // sid (IssuerAndSerialNumber or [0] SubjectKeyIdentifier)
    if let Ok((_, len)) = parse_tlv_at(si, pos) {
        pos += len;
    } else {
        return;
    }
    // digestAlgorithm
    if let Ok((_, len)) = parse_tlv_at(si, pos) {
        pos += len;
    } else {
        return;
    }

    // authenticatedAttributes [0] IMPLICIT — optional
    if pos < si.len() && si[pos] == 0xa0 {
        let Ok((aa_content, _)) = parse_tlv_at(si, pos) else {
            return;
        };
        parse_attributes(aa_content, attrs);
    }
}

/// Parse a SET OF Attribute entries for SCEP OIDs.
fn parse_attributes(attrs_der: &[u8], out: &mut ScepAttrs) {
    use super::envelope::{
        OID_SCEP_FAIL_INFO, OID_SCEP_PKI_STATUS, OID_SCEP_RECIPIENT_NONCE, OID_SCEP_TRANSACTION_ID,
    };

    let mut pos = 0;
    while pos < attrs_der.len() {
        let Ok((attr_content, attr_len)) = parse_tlv_at(attrs_der, pos) else {
            break;
        };
        pos += attr_len;

        // Attribute ::= SEQUENCE { attrType OID, attrValues SET }
        // attr_content is the content of the SEQUENCE
        let Some((oid_bytes, rest)) = extract_oid_from_attr(attr_content) else {
            continue;
        };

        // Match OID against SCEP attribute OIDs
        if oid_bytes == OID_SCEP_PKI_STATUS {
            if let Some(val) = extract_printable_string_value(rest) {
                out.pki_status = Some(val);
            }
        } else if oid_bytes == OID_SCEP_FAIL_INFO {
            if let Some(val) = extract_printable_string_value(rest) {
                out.fail_info = val.parse::<u8>().ok();
            }
        } else if oid_bytes == OID_SCEP_RECIPIENT_NONCE {
            out.recipient_nonce = extract_octet_string_value(rest);
        } else if oid_bytes == OID_SCEP_TRANSACTION_ID {
            if let Some(val) = extract_printable_string_value(rest) {
                out.transaction_id = Some(val);
            }
        }
    }
}

/// Extract OID bytes from an Attribute SEQUENCE content.
/// Returns `(oid_value_bytes, remaining_bytes_after_oid)`.
fn extract_oid_from_attr(attr_content: &[u8]) -> Option<(&[u8], &[u8])> {
    if attr_content.is_empty() || attr_content[0] != 0x06 {
        return None;
    }
    let Ok((oid_val, consumed)) = parse_tlv_at(attr_content, 0) else {
        return None;
    };
    Some((oid_val, &attr_content[consumed..]))
}

/// Extract a PrintableString value from the attrValues SET.
fn extract_printable_string_value(rest: &[u8]) -> Option<String> {
    // rest begins with SET { PrintableString | IA5String | UTF8String }
    let Ok((set_content, _)) = parse_tlv_at(rest, 0) else {
        return None;
    };
    // First value in SET
    if set_content.is_empty() {
        return None;
    }
    let tag = set_content[0];
    // 0x13=PrintableString, 0x16=IA5String, 0x0c=UTF8String
    if matches!(tag, 0x13 | 0x16 | 0x0c) {
        let Ok((val, _)) = parse_tlv_at(set_content, 0) else {
            return None;
        };
        std::str::from_utf8(val).ok().map(|s| s.to_string())
    } else {
        None
    }
}

/// Extract an OCTET STRING value from the attrValues SET.
fn extract_octet_string_value(rest: &[u8]) -> Option<Vec<u8>> {
    let Ok((set_content, _)) = parse_tlv_at(rest, 0) else {
        return None;
    };
    if set_content.is_empty() || set_content[0] != 0x04 {
        return None;
    }
    let Ok((val, _)) = parse_tlv_at(set_content, 0) else {
        return None;
    };
    Some(val.to_vec())
}

// ── Certificate extraction ────────────────────────────────────────────────────

/// Extract individual X.509 certificate DER blobs from the SignedData certificates field.
fn extract_certificates(certs_content: &[u8], out: &mut Vec<Vec<u8>>) {
    let mut pos = 0;
    while pos < certs_content.len() {
        let Ok((_, consumed)) = parse_tlv_at(certs_content, pos) else {
            break;
        };
        // Reconstruct full DER (tag + length + value)
        let full_der = &certs_content[pos..pos + consumed];
        if !full_der.is_empty() {
            out.push(full_der.to_vec());
        }
        pos += consumed;
    }
}

// ── SCEP attribute parsers ────────────────────────────────────────────────────

fn parse_pki_status(attrs: &ScepAttrs) -> Result<PkiStatus> {
    let s = attrs
        .pki_status
        .as_deref()
        .ok_or_else(|| anyhow!("pkiStatus attribute missing from CertRep"))?;

    let val: u8 = s
        .parse()
        .with_context(|| format!("Invalid pkiStatus value: {}", s))?;

    PkiStatus::from_u8(val).ok_or_else(|| anyhow!("Unknown pkiStatus value: {}", val))
}

fn parse_fail_info(attrs: &ScepAttrs) -> Option<FailInfo> {
    attrs.fail_info.and_then(FailInfo::from_u8)
}

fn parse_recipient_nonce(attrs: &ScepAttrs) -> Option<Vec<u8>> {
    attrs.recipient_nonce.clone()
}

fn parse_transaction_id(attrs: &ScepAttrs) -> Option<String> {
    attrs.transaction_id.clone()
}

// ── DER parsing helpers ───────────────────────────────────────────────────────

/// Parse ContentInfo and extract the content (stripping id-signedData OID and \[0\] wrapper).
fn extract_content_info_content(der: &[u8]) -> Result<&[u8]> {
    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
    let ci_content = parse_sequence_content(der).context("ContentInfo is not a SEQUENCE")?;

    let mut pos = 0;

    // Skip contentType OID
    let (_, oid_len) = parse_tlv_at(ci_content, pos)?;
    pos += oid_len;

    // content [0] EXPLICIT
    if pos >= ci_content.len() || ci_content[pos] != 0xa0 {
        return Err(anyhow!(
            "ContentInfo: expected [0] EXPLICIT, got 0x{:02x}",
            ci_content.get(pos).copied().unwrap_or(0)
        ));
    }
    let (content, _) = parse_tlv_at(ci_content, pos)?;
    Ok(content)
}

/// Get the content bytes of a SEQUENCE TLV (i.e. strip the outer tag+length).
fn parse_sequence_content(der: &[u8]) -> Result<&[u8]> {
    if der.is_empty() || der[0] != 0x30 {
        return Err(anyhow!(
            "Expected SEQUENCE, got 0x{:02x}",
            der.first().copied().unwrap_or(0)
        ));
    }
    let (content, _) = parse_tlv_at(der, 0)?;
    Ok(content)
}

/// Parse TLV at offset within `data`.
/// Returns `(value_slice, total_bytes_consumed)`.
fn parse_tlv_at(data: &[u8], offset: usize) -> Result<(&[u8], usize)> {
    if offset >= data.len() {
        return Err(anyhow!(
            "DER offset {} out of bounds (len {})",
            offset,
            data.len()
        ));
    }
    let data = &data[offset..];
    if data.len() < 2 {
        return Err(anyhow!("DER TLV too short"));
    }
    let (len, header_len) = parse_der_length(&data[1..])
        .with_context(|| format!("Failed to parse DER length at offset {}", offset))?;
    let total = 1 + header_len + len;
    if data.len() < total {
        return Err(anyhow!(
            "DER TLV truncated: need {} bytes, have {}",
            total,
            data.len()
        ));
    }
    Ok((&data[1 + header_len..total], total))
}

/// Parse DER length field. Returns `(length_value, bytes_consumed)`.
fn parse_der_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(anyhow!("Empty DER length field"));
    }
    if data[0] < 0x80 {
        return Ok((data[0] as usize, 1));
    }
    let num_bytes = (data[0] & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 {
        return Err(anyhow!(
            "DER length: unsupported long form ({} bytes)",
            num_bytes
        ));
    }
    if data.len() < 1 + num_bytes {
        return Err(anyhow!("DER length: truncated"));
    }
    let mut len = 0usize;
    for i in 0..num_bytes {
        len = (len << 8) | data[1 + i] as usize;
    }
    Ok((len, 1 + num_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_der_length_short_form() {
        let data = &[0x42u8];
        let (len, consumed) = parse_der_length(data).unwrap();
        assert_eq!(len, 0x42);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_parse_der_length_long_form() {
        let data = &[0x82u8, 0x01, 0x00];
        let (len, consumed) = parse_der_length(data).unwrap();
        assert_eq!(len, 256);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_parse_tlv_sequence() {
        // SEQUENCE(length=5) containing INTEGER(1) + NULL
        let seq = vec![0x30, 0x05, 0x02, 0x01, 0x01, 0x05, 0x00];
        let (content, total) = parse_tlv_at(&seq, 0).unwrap();
        assert_eq!(total, 7);
        assert_eq!(content, &[0x02, 0x01, 0x01, 0x05, 0x00]);
    }
}
