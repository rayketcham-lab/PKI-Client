//! PKCS#8 (RFC 5958) helpers for PQC keys.
//!
//! PQC signers emit raw seeds/key bytes, but downstream consumers expect
//! self-describing PKCS#8 PrivateKeyInfo blobs so the algorithm is derivable
//! from the OID. These helpers wrap raw bytes and extract payloads.

use const_oid::ObjectIdentifier;

/// Minimal DER length encoder (matches composite_impl's conventions).
fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 65536 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// Wrap raw key bytes in a PKCS#8 PrivateKeyInfo (RFC 5958 §2):
///
/// ```text
/// PrivateKeyInfo ::= SEQUENCE {
///   version         INTEGER (0),
///   algorithm       AlgorithmIdentifier { OID },
///   privateKey      OCTET STRING { raw_key_bytes }
/// }
/// ```
///
/// `parameters` is omitted (ML-DSA/SLH-DSA AlgorithmIdentifiers have no params).
pub(crate) fn wrap_in_pkcs8(raw_key: &[u8], oid: &ObjectIdentifier) -> Vec<u8> {
    let oid_bytes = oid.as_bytes();

    let mut alg_id = Vec::with_capacity(oid_bytes.len() + 6);
    alg_id.push(0x30);
    encode_length(oid_bytes.len() + 2, &mut alg_id);
    alg_id.push(0x06);
    encode_length(oid_bytes.len(), &mut alg_id);
    alg_id.extend_from_slice(oid_bytes);

    let mut priv_key = Vec::with_capacity(raw_key.len() + 6);
    priv_key.push(0x04);
    encode_length(raw_key.len(), &mut priv_key);
    priv_key.extend_from_slice(raw_key);

    let version: [u8; 3] = [0x02, 0x01, 0x00];
    let inner_len = version.len() + alg_id.len() + priv_key.len();

    let mut out = Vec::with_capacity(inner_len + 6);
    out.push(0x30);
    encode_length(inner_len, &mut out);
    out.extend_from_slice(&version);
    out.extend_from_slice(&alg_id);
    out.extend_from_slice(&priv_key);
    out
}

/// Try to extract raw key bytes from a PKCS#8 OneAsymmetricKey envelope.
/// Returns `None` if the input isn't a parsable PKCS#8 — callers should
/// treat the original input as raw bytes in that case.
pub(crate) fn try_extract_pkcs8_payload(der: &[u8]) -> Option<&[u8]> {
    if der.first()? != &0x30 {
        return None;
    }
    let pki = pkcs8::PrivateKeyInfo::try_from(der).ok()?;
    Some(pki.private_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_32_byte_seed() {
        let oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
        let seed = [0x42u8; 32];
        let wrapped = wrap_in_pkcs8(&seed, &oid);
        assert_eq!(wrapped[0], 0x30, "outer SEQUENCE");
        let payload = try_extract_pkcs8_payload(&wrapped).expect("extractable");
        assert_eq!(payload, &seed);
    }

    #[test]
    fn extract_rejects_non_pkcs8() {
        let raw_seed = [0u8; 32];
        assert!(try_extract_pkcs8_payload(&raw_seed).is_none());
    }

    #[test]
    fn roundtrip_long_seed() {
        // SLH-DSA-256s uses 128-byte seeds; exercise the 2-byte length path.
        let oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.24");
        let seed = vec![0xAB; 128];
        let wrapped = wrap_in_pkcs8(&seed, &oid);
        let payload = try_extract_pkcs8_payload(&wrapped).expect("extractable");
        assert_eq!(payload, seed.as_slice());
    }
}
