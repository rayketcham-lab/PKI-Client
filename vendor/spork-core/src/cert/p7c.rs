//! Certs-only CMS (.p7c) generator (RFC 5652 / RFC 5280)
//!
//! A "degenerate" SignedData structure containing certificates and no signerInfos.
//! Used with the SubjectInformationAccess `id-ad-caRepository` access method
//! to publish all certificates issued under a CA (required for FPKI compliance).
//!
//! ASN.1 structure:
//! ```text
//! ContentInfo ::= SEQUENCE {
//!     contentType   id-signedData (1.2.840.113549.1.7.2),
//!     content   [0] EXPLICIT SignedData
//! }
//! SignedData ::= SEQUENCE {
//!     version          CMSVersion (INTEGER),   -- always 1
//!     digestAlgorithms DigestAlgorithmIdentifiers,  -- empty SET
//!     encapContentInfo EncapsulatedContentInfo,  -- id-data, no content
//!     certificates [0] IMPLICIT CertificateSet OPTIONAL,  -- the certs
//!     signerInfos      SignerInfos  -- empty SET
//! }
//! ```

use crate::error::{Error, Result};

// OID: id-signedData (1.2.840.113549.1.7.2)
// DER encoding: 06 09 2a 86 48 86 f7 0d 01 07 02
const ID_SIGNED_DATA_OID_DER: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
];

// OID: id-data (1.2.840.113549.1.7.1)
// DER encoding: 06 09 2a 86 48 86 f7 0d 01 07 01
const ID_DATA_OID_DER: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
];

/// Generate a certs-only CMS file (PKCS#7 degenerate SignedData).
///
/// The resulting DER bytes can be written to a `.p7c` file and published
/// at the URL referenced by the SIA `id-ad-caRepository` access method.
///
/// # Arguments
///
/// * `cert_ders` - DER-encoded X.509 certificates to include. May be empty,
///   but at least one certificate is required for a useful .p7c file.
///
/// # Returns
///
/// DER-encoded ContentInfo wrapping a degenerate SignedData.
pub fn build_p7c(cert_ders: &[Vec<u8>]) -> Result<Vec<u8>> {
    if cert_ders.is_empty() {
        return Err(Error::InvalidCertificate(
            "p7c must contain at least one certificate".into(),
        ));
    }

    // Each cert DER must be non-empty
    for (i, der) in cert_ders.iter().enumerate() {
        if der.is_empty() {
            return Err(Error::InvalidCertificate(format!(
                "Certificate {} has empty DER encoding",
                i
            )));
        }
    }

    let signed_data_der = build_signed_data(cert_ders)?;

    // ContentInfo ::= SEQUENCE {
    //   contentType   OBJECT IDENTIFIER,
    //   content   [0] EXPLICIT ANY }
    //
    // content [0] EXPLICIT = wrap signed_data_der in context [0] CONSTRUCTED EXPLICIT
    let mut content_explicit = vec![0xA0]; // [0] CONSTRUCTED
    encode_length(&mut content_explicit, signed_data_der.len());
    content_explicit.extend_from_slice(&signed_data_der);

    let inner_len = ID_SIGNED_DATA_OID_DER.len() + content_explicit.len();
    let mut result = vec![0x30]; // SEQUENCE tag
    encode_length(&mut result, inner_len);
    result.extend_from_slice(ID_SIGNED_DATA_OID_DER);
    result.extend_from_slice(&content_explicit);

    Ok(result)
}

/// Build the inner SignedData SEQUENCE.
fn build_signed_data(cert_ders: &[Vec<u8>]) -> Result<Vec<u8>> {
    // version: CMSVersion ::= INTEGER
    // RFC 5652 Section 5.1: version is 1 when no attribute certificates are present.
    // INTEGER 1 = 02 01 01
    let version_der: &[u8] = &[0x02, 0x01, 0x01];

    // digestAlgorithms: DigestAlgorithmIdentifiers ::= SET OF AlgorithmIdentifier
    // Empty SET = 31 00
    let digest_algorithms_der: &[u8] = &[0x31, 0x00];

    // encapContentInfo: EncapsulatedContentInfo ::= SEQUENCE {
    //   eContentType OBJECT IDENTIFIER (id-data),
    //   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
    // No eContent for degenerate case — just the OID wrapped in SEQUENCE.
    let encap_content_info_len = ID_DATA_OID_DER.len();
    let mut encap_content_info = vec![0x30]; // SEQUENCE
    encode_length(&mut encap_content_info, encap_content_info_len);
    encap_content_info.extend_from_slice(ID_DATA_OID_DER);

    // certificates: [0] IMPLICIT CertificateSet
    // CertificateSet ::= SET OF CertificateChoices
    // CertificateChoices ::= CHOICE { certificate Certificate, ... }
    // We only use Certificate (plain X.509 DER), so each entry is one cert DER.
    let mut cert_set_inner = Vec::new();
    for der in cert_ders {
        cert_set_inner.extend_from_slice(der);
    }

    // Wrap in [0] IMPLICIT (replaces the outer SET tag)
    let mut certificates = vec![0xA0]; // [0] CONSTRUCTED IMPLICIT (replaces SET)
    encode_length(&mut certificates, cert_set_inner.len());
    certificates.extend_from_slice(&cert_set_inner);

    // signerInfos: SignerInfos ::= SET OF SignerInfo
    // Empty SET = 31 00
    let signer_infos_der: &[u8] = &[0x31, 0x00];

    // Assemble SignedData body
    let body_len = version_der.len()
        + digest_algorithms_der.len()
        + encap_content_info.len()
        + certificates.len()
        + signer_infos_der.len();

    let mut signed_data = vec![0x30]; // SEQUENCE
    encode_length(&mut signed_data, body_len);
    signed_data.extend_from_slice(version_der);
    signed_data.extend_from_slice(digest_algorithms_der);
    signed_data.extend_from_slice(&encap_content_info);
    signed_data.extend_from_slice(&certificates);
    signed_data.extend_from_slice(signer_infos_der);

    Ok(signed_data)
}

/// Encode a DER length field.
fn encode_length(buf: &mut Vec<u8>, len: usize) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algo::{AlgorithmId, KeyPair};
    use crate::cert::{builder::CertificateBuilder, extensions::BasicConstraints, NameBuilder};

    /// Build a simple self-signed certificate DER for testing.
    fn make_test_cert_der(cn: &str) -> Vec<u8> {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new(cn).build();
        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .basic_constraints(BasicConstraints::ca())
        .build_and_sign(&kp)
        .unwrap();

        use der::Encode;
        cert.to_der().unwrap()
    }

    #[test]
    fn test_p7c_empty_input_rejected() {
        let result = build_p7c(&[]);
        assert!(result.is_err(), "Empty cert list should be rejected");
    }

    #[test]
    fn test_p7c_empty_cert_der_rejected() {
        let result = build_p7c(&[vec![]]);
        assert!(result.is_err(), "Empty cert DER should be rejected");
    }

    #[test]
    fn test_p7c_single_cert_structure() {
        let cert_der = make_test_cert_der("Test CA");
        let p7c = build_p7c(std::slice::from_ref(&cert_der)).unwrap();

        // Outer structure: SEQUENCE tag
        assert_eq!(p7c[0], 0x30, "ContentInfo must start with SEQUENCE tag");
        // Must be non-trivially large
        assert!(p7c.len() > 30);

        // The certificate DER should be embedded in the output
        assert!(
            p7c.windows(cert_der.len()).any(|w| w == cert_der),
            "Certificate DER should appear verbatim inside p7c"
        );
    }

    #[test]
    fn test_p7c_contains_signed_data_oid() {
        let cert_der = make_test_cert_der("OID Test CA");
        let p7c = build_p7c(&[cert_der]).unwrap();

        // id-signedData OID bytes (without the 0x06 tag and length)
        let signed_data_oid_value: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
        assert!(
            p7c.windows(signed_data_oid_value.len())
                .any(|w| w == signed_data_oid_value),
            "p7c must contain id-signedData OID"
        );
    }

    #[test]
    fn test_p7c_contains_id_data_oid() {
        let cert_der = make_test_cert_der("Data OID CA");
        let p7c = build_p7c(&[cert_der]).unwrap();

        // id-data OID value bytes
        let id_data_oid_value: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
        assert!(
            p7c.windows(id_data_oid_value.len())
                .any(|w| w == id_data_oid_value),
            "p7c must contain id-data OID in encapContentInfo"
        );
    }

    #[test]
    fn test_p7c_multiple_certs() {
        let cert1 = make_test_cert_der("CA One");
        let cert2 = make_test_cert_der("CA Two");
        let cert3 = make_test_cert_der("CA Three");

        let p7c = build_p7c(&[cert1.clone(), cert2.clone(), cert3.clone()]).unwrap();

        assert_eq!(p7c[0], 0x30, "Must start with SEQUENCE");

        // All three certs must be present
        assert!(
            p7c.windows(cert1.len()).any(|w| w == cert1),
            "Cert 1 must be in p7c"
        );
        assert!(
            p7c.windows(cert2.len()).any(|w| w == cert2),
            "Cert 2 must be in p7c"
        );
        assert!(
            p7c.windows(cert3.len()).any(|w| w == cert3),
            "Cert 3 must be in p7c"
        );
    }

    #[test]
    fn test_p7c_version_is_one() {
        let cert_der = make_test_cert_der("Version Test CA");
        let p7c = build_p7c(&[cert_der]).unwrap();

        // VERSION INTEGER 1 = 02 01 01
        let version_bytes: &[u8] = &[0x02, 0x01, 0x01];
        assert!(
            p7c.windows(3).any(|w| w == version_bytes),
            "SignedData version must be 1 (DER: 02 01 01)"
        );
    }

    #[test]
    fn test_p7c_empty_signer_infos() {
        let cert_der = make_test_cert_der("No Signers CA");
        let p7c = build_p7c(&[cert_der]).unwrap();

        // Empty SET = 31 00
        let empty_set: &[u8] = &[0x31, 0x00];
        // Should appear at least once (empty signerInfos)
        assert!(
            p7c.windows(2).any(|w| w == empty_set),
            "p7c must contain empty SET (signerInfos)"
        );
    }

    #[test]
    fn test_p7c_der_starts_with_sequence() {
        let cert_der = make_test_cert_der("Sequence Tag CA");
        let p7c = build_p7c(&[cert_der]).unwrap();
        assert_eq!(
            p7c[0], 0x30,
            "ContentInfo outer tag must be SEQUENCE (0x30)"
        );
    }

    #[test]
    fn test_p7c_explicit_zero_tag_present() {
        // [0] EXPLICIT wrapping the SignedData: tag byte 0xA0
        let cert_der = make_test_cert_der("Explicit Tag CA");
        let p7c = build_p7c(&[cert_der]).unwrap();
        assert!(
            p7c.contains(&0xA0),
            "ContentInfo must contain [0] EXPLICIT tag (0xA0) wrapping SignedData"
        );
    }
}
