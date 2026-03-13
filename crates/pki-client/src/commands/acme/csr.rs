//! CSR (Certificate Signing Request) generation using custom ASN.1 DER builder.

use anyhow::{anyhow, Context, Result};

/// Generate a minimal CSR in DER format for the given domains.
///
/// Uses pki-core's CSR generation if available, otherwise builds a
/// basic PKCS#10 request using p256 directly.
pub(super) fn generate_csr_der(key_pem: &str, domains: &[String]) -> Result<Vec<u8>> {
    // For now we use a simplified CSR that the ACME server can accept.
    // The CSR contains the primary domain as CN and all domains as SANs.
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::SecretKey;

    let pem_data = pem::parse(key_pem).context("Failed to parse domain key PEM")?;
    let secret_key = if pem_data.tag() == "EC PRIVATE KEY" {
        SecretKey::from_sec1_der(pem_data.contents())
            .context("Failed to parse SEC1 EC private key for CSR")?
    } else {
        use p256::pkcs8::DecodePrivateKey;
        SecretKey::from_pkcs8_der(pem_data.contents())
            .context("Failed to parse PKCS#8 private key for CSR")?
    };
    let signing_key = SigningKey::from(&secret_key);

    // Build a minimal PKCS#10 CSR in DER
    // This is a simplified implementation that creates a valid CSR structure
    let primary_domain = domains
        .first()
        .ok_or_else(|| anyhow!("No domains provided"))?;

    // Build Subject: CN=primary_domain
    let cn_oid = &[0x55, 0x04, 0x03u8]; // 2.5.4.3 (CN)
    let cn_value = asn1_utf8string(primary_domain.as_bytes());
    let cn_attr = asn1_sequence(&[&asn1_oid(cn_oid), &cn_value]);
    let cn_set = asn1_set(&[&cn_attr]);
    let subject = asn1_sequence(&[&cn_set]);

    // Build SubjectPublicKeyInfo from the signing key
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let encoded_point = verifying_key.to_encoded_point(false);
    let pub_key_bytes = encoded_point.as_bytes();

    // Algorithm: ecPublicKey with P-256
    let ec_pub_key_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01u8]; // 1.2.840.10045.2.1
    let p256_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07u8]; // 1.2.840.10045.3.1.7
    let algorithm = asn1_sequence(&[&asn1_oid(ec_pub_key_oid), &asn1_oid(p256_oid)]);
    let pub_key_bitstring = asn1_bitstring(pub_key_bytes);
    let spki = asn1_sequence(&[&algorithm, &pub_key_bitstring]);

    // Build SAN extension in attributes
    let san_extension_oid = &[0x55, 0x1D, 0x11u8]; // 2.5.29.17 (SAN)
    let mut san_entries = Vec::new();
    for domain in domains {
        // context tag [2] for dNSName
        let mut entry = vec![0x82];
        let domain_bytes = domain.as_bytes();
        asn1_encode_length(domain_bytes.len(), &mut entry);
        entry.extend_from_slice(domain_bytes);
        san_entries.push(entry);
    }
    let san_refs: Vec<&[u8]> = san_entries.iter().map(|e| e.as_slice()).collect();
    let san_sequence = asn1_sequence(&san_refs);
    let san_extension = asn1_sequence(&[
        &asn1_oid(san_extension_oid),
        &asn1_octet_string(&san_sequence),
    ]);
    let extensions = asn1_sequence(&[&san_extension]);

    // Extension request OID: 1.2.840.113549.1.9.14
    let ext_req_oid = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0Eu8];
    let ext_req_set = asn1_set(&[&extensions]);
    let ext_req_attr = asn1_sequence(&[&asn1_oid(ext_req_oid), &ext_req_set]);
    // Attributes: context tag [0] CONSTRUCTED
    let mut attributes = vec![0xA0];
    let attr_content = ext_req_attr;
    asn1_encode_length(attr_content.len(), &mut attributes);
    attributes.extend_from_slice(&attr_content);

    // CertificationRequestInfo: version, subject, spki, attributes
    let version = &[0x02, 0x01, 0x00]; // INTEGER 0
    let cert_req_info = asn1_sequence(&[version, &subject, &spki, &attributes]);

    // Sign the CertificationRequestInfo
    let signature: Signature = signing_key.sign(&cert_req_info);
    let sig_der_bytes = signature.to_der();

    // Signature algorithm: ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
    let ecdsa_sha256_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02u8];
    let sig_algorithm = asn1_sequence(&[&asn1_oid(ecdsa_sha256_oid)]);
    let sig_bitstring = asn1_bitstring(sig_der_bytes.as_bytes());

    // CertificationRequest: info, algorithm, signature
    let csr = asn1_sequence(&[&cert_req_info, &sig_algorithm, &sig_bitstring]);

    Ok(csr)
}

// ASN.1 DER encoding helpers

fn asn1_encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
}

fn asn1_tag_length_value(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    asn1_encode_length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

fn asn1_sequence(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for item in items {
        content.extend_from_slice(item);
    }
    asn1_tag_length_value(0x30, &content)
}

fn asn1_set(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for item in items {
        content.extend_from_slice(item);
    }
    asn1_tag_length_value(0x31, &content)
}

fn asn1_oid(oid_bytes: &[u8]) -> Vec<u8> {
    asn1_tag_length_value(0x06, oid_bytes)
}

fn asn1_utf8string(s: &[u8]) -> Vec<u8> {
    asn1_tag_length_value(0x0C, s)
}

fn asn1_bitstring(data: &[u8]) -> Vec<u8> {
    let mut content = vec![0x00]; // no unused bits
    content.extend_from_slice(data);
    asn1_tag_length_value(0x03, &content)
}

fn asn1_octet_string(data: &[u8]) -> Vec<u8> {
    asn1_tag_length_value(0x04, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::acme::helpers::generate_domain_key;

    // ── asn1_encode_length tests ──────────────────────────────────────

    #[test]
    fn test_asn1_encode_length_short_form_zero() {
        let mut out = Vec::new();
        asn1_encode_length(0, &mut out);
        assert_eq!(out, vec![0x00]);
    }

    #[test]
    fn test_asn1_encode_length_short_form_max() {
        let mut out = Vec::new();
        asn1_encode_length(0x7F, &mut out);
        assert_eq!(out, vec![0x7F]);
    }

    #[test]
    fn test_asn1_encode_length_long_form_one_byte() {
        let mut out = Vec::new();
        asn1_encode_length(0x80, &mut out);
        assert_eq!(out, vec![0x81, 0x80]);

        let mut out = Vec::new();
        asn1_encode_length(0xFF, &mut out);
        assert_eq!(out, vec![0x81, 0xFF]);
    }

    #[test]
    fn test_asn1_encode_length_long_form_two_bytes() {
        let mut out = Vec::new();
        asn1_encode_length(0x100, &mut out);
        assert_eq!(out, vec![0x82, 0x01, 0x00]);

        let mut out = Vec::new();
        asn1_encode_length(0xFFFF, &mut out);
        assert_eq!(out, vec![0x82, 0xFF, 0xFF]);
    }

    #[test]
    fn test_asn1_encode_length_boundary_127_128() {
        let mut short = Vec::new();
        asn1_encode_length(127, &mut short);
        assert_eq!(short.len(), 1);
        assert_eq!(short[0], 127);

        let mut long = Vec::new();
        asn1_encode_length(128, &mut long);
        assert_eq!(long.len(), 2);
        assert_eq!(long[0], 0x81);
        assert_eq!(long[1], 128);
    }

    // ── asn1_tag_length_value tests ───────────────────────────────────

    #[test]
    fn test_asn1_tag_length_value_empty_content() {
        let result = asn1_tag_length_value(0x30, &[]);
        assert_eq!(result, vec![0x30, 0x00]);
    }

    #[test]
    fn test_asn1_tag_length_value_with_content() {
        let result = asn1_tag_length_value(0x04, &[0x01, 0x02, 0x03]);
        assert_eq!(result, vec![0x04, 0x03, 0x01, 0x02, 0x03]);
    }

    // ── asn1 type builder tests ───────────────────────────────────────

    #[test]
    fn test_asn1_sequence_combines_items() {
        let a = vec![0x02, 0x01, 0x00];
        let b = vec![0x02, 0x01, 0x01];
        let result = asn1_sequence(&[&a, &b]);
        assert_eq!(result[0], 0x30);
        assert_eq!(result[1], 6);
        assert_eq!(&result[2..5], &a[..]);
        assert_eq!(&result[5..8], &b[..]);
    }

    #[test]
    fn test_asn1_set_tag() {
        let item = vec![0x02, 0x01, 0x00];
        let result = asn1_set(&[&item]);
        assert_eq!(result[0], 0x31);
        assert_eq!(result[1], 3);
        assert_eq!(&result[2..], &item[..]);
    }

    #[test]
    fn test_asn1_oid() {
        let oid_bytes = &[0x55, 0x04, 0x03];
        let result = asn1_oid(oid_bytes);
        assert_eq!(result, vec![0x06, 0x03, 0x55, 0x04, 0x03]);
    }

    #[test]
    fn test_asn1_utf8string() {
        let result = asn1_utf8string(b"hello");
        assert_eq!(result, vec![0x0C, 0x05, b'h', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn test_asn1_bitstring_prepends_unused_bits() {
        let result = asn1_bitstring(&[0xFF, 0x00]);
        assert_eq!(result, vec![0x03, 0x03, 0x00, 0xFF, 0x00]);
    }

    #[test]
    fn test_asn1_octet_string() {
        let result = asn1_octet_string(&[0xDE, 0xAD]);
        assert_eq!(result, vec![0x04, 0x02, 0xDE, 0xAD]);
    }

    // ── generate_domain_key tests ─────────────────────────────────────

    #[test]
    fn test_generate_domain_key_produces_valid_pem() {
        let pem_str = generate_domain_key().expect("key generation failed");
        assert!(pem_str.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pem_str.contains("-----END PRIVATE KEY-----"));

        let parsed = pem::parse(&pem_str).expect("PEM parse failed");
        assert_eq!(parsed.tag(), "PRIVATE KEY");
        assert!(parsed.contents().len() > 30, "DER content too short");
    }

    // ── generate_csr_der tests ────────────────────────────────────────

    #[test]
    fn test_generate_csr_der_single_domain() {
        let key_pem = generate_domain_key().expect("key gen");
        let domains = vec!["example.com".to_string()];
        let csr = generate_csr_der(&key_pem, &domains).expect("CSR gen failed");

        assert_eq!(csr[0], 0x30, "CSR must start with SEQUENCE tag");
        assert!(csr.len() > 200, "CSR too short: {} bytes", csr.len());
    }

    #[test]
    fn test_generate_csr_der_multiple_domains() {
        let key_pem = generate_domain_key().expect("key gen");
        let domains = vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "mail.example.com".to_string(),
        ];
        let csr = generate_csr_der(&key_pem, &domains).expect("CSR gen failed");

        assert_eq!(csr[0], 0x30);
        assert!(
            csr.len() > 250,
            "Multi-SAN CSR too short: {} bytes",
            csr.len()
        );

        for domain in &domains {
            let domain_bytes = domain.as_bytes();
            let found = csr.windows(domain_bytes.len()).any(|w| w == domain_bytes);
            assert!(found, "Domain '{}' not found in CSR DER", domain);
        }
    }

    #[test]
    fn test_generate_csr_der_empty_domains_fails() {
        let key_pem = generate_domain_key().expect("key gen");
        let domains: Vec<String> = vec![];
        let result = generate_csr_der(&key_pem, &domains);
        assert!(result.is_err(), "CSR with empty domain list should fail");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("No domains"),
            "Error should mention missing domains, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_generate_csr_der_contains_cn() {
        let key_pem = generate_domain_key().expect("key gen");
        let domain = "test.example.com";
        let domains = vec![domain.to_string()];
        let csr = generate_csr_der(&key_pem, &domains).expect("CSR gen failed");

        let cn_oid = [0x06, 0x03, 0x55, 0x04, 0x03];
        let has_cn_oid = csr.windows(cn_oid.len()).any(|w| w == cn_oid);
        assert!(has_cn_oid, "CSR should contain CN OID (2.5.4.3)");

        let domain_bytes = domain.as_bytes();
        let has_domain = csr.windows(domain_bytes.len()).any(|w| w == domain_bytes);
        assert!(has_domain, "CSR should contain the domain name");
    }

    #[test]
    fn test_generate_csr_der_contains_san_extension() {
        let key_pem = generate_domain_key().expect("key gen");
        let domains = vec!["a.example.com".to_string(), "b.example.com".to_string()];
        let csr = generate_csr_der(&key_pem, &domains).expect("CSR gen failed");

        let san_oid = [0x06, 0x03, 0x55, 0x1D, 0x11];
        let has_san_oid = csr.windows(san_oid.len()).any(|w| w == san_oid);
        assert!(
            has_san_oid,
            "CSR should contain SAN extension OID (2.5.29.17)"
        );

        let dns_tag_count = csr.windows(2).filter(|w| w[0] == 0x82).count();
        assert!(
            dns_tag_count >= 2,
            "CSR should contain at least 2 dNSName entries, found {}",
            dns_tag_count
        );
    }

    #[test]
    fn test_generate_csr_der_contains_ecdsa_sig_algorithm() {
        let key_pem = generate_domain_key().expect("key gen");
        let domains = vec!["sig.example.com".to_string()];
        let csr = generate_csr_der(&key_pem, &domains).expect("CSR gen failed");

        let ecdsa_sha256_oid = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
        let has_sig_alg = csr
            .windows(ecdsa_sha256_oid.len())
            .any(|w| w == ecdsa_sha256_oid);
        assert!(
            has_sig_alg,
            "CSR should contain ecdsa-with-SHA256 signature algorithm OID"
        );
    }

    #[test]
    fn test_generate_csr_der_contains_spki() {
        let key_pem = generate_domain_key().expect("key gen");
        let domains = vec!["spki.example.com".to_string()];
        let csr = generate_csr_der(&key_pem, &domains).expect("CSR gen failed");

        let ec_pub_oid = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
        let has_ec_pub = csr.windows(ec_pub_oid.len()).any(|w| w == ec_pub_oid);
        assert!(has_ec_pub, "CSR should contain ecPublicKey OID");

        let p256_oid = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        let has_p256 = csr.windows(p256_oid.len()).any(|w| w == p256_oid);
        assert!(has_p256, "CSR should contain P-256 curve OID");
    }

    #[test]
    fn test_generate_csr_der_version_zero() {
        let key_pem = generate_domain_key().expect("key gen");
        let domains = vec!["ver.example.com".to_string()];
        let csr = generate_csr_der(&key_pem, &domains).expect("CSR gen failed");

        let version_bytes = [0x02, 0x01, 0x00];
        let has_version = csr.windows(version_bytes.len()).any(|w| w == version_bytes);
        assert!(has_version, "CSR should contain version INTEGER 0");
    }

    #[test]
    fn test_generate_csr_der_long_domain_name() {
        let key_pem = generate_domain_key().expect("key gen");
        let long_label = "a".repeat(63);
        let long_domain = format!("{}.example.com", long_label);
        let domains = vec![long_domain.clone()];
        let csr = generate_csr_der(&key_pem, &domains).expect("CSR gen failed");

        assert_eq!(csr[0], 0x30);
        let domain_bytes = long_domain.as_bytes();
        let found = csr.windows(domain_bytes.len()).any(|w| w == domain_bytes);
        assert!(found, "Long domain name not found in CSR DER");
    }

    #[test]
    fn test_generate_csr_der_invalid_key_fails() {
        let bad_pem =
            "-----BEGIN EC PRIVATE KEY-----\nYmFkZGF0YQ==\n-----END EC PRIVATE KEY-----\n";
        let domains = vec!["example.com".to_string()];
        let result = generate_csr_der(bad_pem, &domains);
        assert!(result.is_err(), "CSR with invalid key should fail");
    }

    #[test]
    fn test_generate_csr_der_deterministic_structure() {
        let key_pem = generate_domain_key().expect("key gen");
        let domains = vec!["det.example.com".to_string()];
        let csr1 = generate_csr_der(&key_pem, &domains).expect("CSR gen 1");
        let csr2 = generate_csr_der(&key_pem, &domains).expect("CSR gen 2");

        assert_eq!(csr1[0], csr2[0]);
        // ECDSA DER signatures can vary by 1-2 bytes
        let size_diff = (csr1.len() as i64 - csr2.len() as i64).unsigned_abs();
        assert!(
            size_diff <= 2,
            "CSR sizes differ by {} bytes (got {} vs {})",
            size_diff,
            csr1.len(),
            csr2.len()
        );
    }
}
