//! Comprehensive Certificate Decode Tests
//!
//! Tests every certificate type, key algorithm, extension combination, and
//! issuance pattern the PKI client supports. Generates fixtures on-the-fly
//! using spork-core, then feeds them through the decode pipeline to verify
//! the output captures EVERYTHING.
//!
//! This is the "OpenSSL on crack" test suite — if it exists in the cert,
//! we parse it, display it, and verify it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use const_oid::ObjectIdentifier;
use der::Encode;

use spork_core::algo::{AlgorithmId, KeyPair};
use spork_core::cert::{
    encode_certificate_pem,
    extensions::{
        AuthorityInfoAccess, BasicConstraints, CertificatePolicies, CrlDistributionPoints,
        ExtendedKeyUsage, KeyUsage, KeyUsageFlags, SubjectAltName, TlsFeature,
    },
    CertificateBuilder, NameBuilder, Validity,
};

use pki_client_output::{CertFormatter, Certificate};

// ============================================================================
// Test Helpers
// ============================================================================

/// Build a self-signed root CA with the given algorithm.
fn build_root_ca(algo: AlgorithmId, cn: &str) -> (KeyPair, Vec<u8>, String) {
    let key = KeyPair::generate(algo).expect("keygen");
    let dn = NameBuilder::new(cn)
        .organization("Test PKI")
        .country("US")
        .build();

    let cert = CertificateBuilder::new(dn, key.public_key_der().unwrap(), key.algorithm_id())
        .validity(Validity::years_from_now(10))
        .basic_constraints(BasicConstraints::ca())
        .key_usage(KeyUsage::new(KeyUsageFlags::new(
            KeyUsageFlags::KEY_CERT_SIGN | KeyUsageFlags::CRL_SIGN,
        )))
        .include_authority_key_identifier(false)
        .build_and_sign(&key)
        .expect("build root CA");

    let der = cert.to_der().expect("encode DER");
    let pem = encode_certificate_pem(&cert).expect("encode PEM");
    (key, der, pem)
}

/// Build an intermediate CA signed by the given parent.
fn build_intermediate_ca(
    algo: AlgorithmId,
    cn: &str,
    parent_key: &KeyPair,
    parent_dn: &str,
) -> (KeyPair, Vec<u8>, String) {
    let key = KeyPair::generate(algo).expect("keygen");
    let dn = NameBuilder::new(cn)
        .organization("Test PKI")
        .country("US")
        .build();
    let issuer_dn = NameBuilder::new(parent_dn)
        .organization("Test PKI")
        .country("US")
        .build();

    let cert = CertificateBuilder::new(dn, key.public_key_der().unwrap(), key.algorithm_id())
        .validity(Validity::years_from_now(5))
        .issuer(issuer_dn)
        .basic_constraints(BasicConstraints::ca_with_path_len(0))
        .key_usage(KeyUsage::new(KeyUsageFlags::new(
            KeyUsageFlags::KEY_CERT_SIGN | KeyUsageFlags::CRL_SIGN,
        )))
        .crl_distribution_points(CrlDistributionPoints::with_url(
            "http://crl.test-pki.example/intermediate.crl",
        ))
        .authority_info_access(
            AuthorityInfoAccess::new()
                .ocsp("http://ocsp.test-pki.example/")
                .ca_issuer("http://ca.test-pki.example/root.cer"),
        )
        .build_and_sign(parent_key)
        .expect("build intermediate CA");

    let der = cert.to_der().expect("encode DER");
    let pem = encode_certificate_pem(&cert).expect("encode PEM");
    (key, der, pem)
}

/// Build an end-entity certificate with configurable options.
struct EeCertBuilder<'a> {
    algo: AlgorithmId,
    cn: String,
    issuer_key: &'a KeyPair,
    issuer_cn: String,
    san_dns: Vec<String>,
    san_ips: Vec<IpAddr>,
    san_emails: Vec<String>,
    san_uris: Vec<String>,
    eku_oids: Vec<ObjectIdentifier>,
    policy_oids: Vec<ObjectIdentifier>,
    ocsp_must_staple: bool,
    cdp_urls: Vec<String>,
    ocsp_urls: Vec<String>,
    ca_issuer_urls: Vec<String>,
}

impl<'a> EeCertBuilder<'a> {
    fn new(algo: AlgorithmId, cn: &str, issuer_key: &'a KeyPair, issuer_cn: &str) -> Self {
        Self {
            algo,
            cn: cn.to_string(),
            issuer_key,
            issuer_cn: issuer_cn.to_string(),
            san_dns: if cn.contains('.') && !cn.contains(' ') && !cn.contains('@') {
                vec![cn.to_string()]
            } else {
                Vec::new()
            },
            san_ips: Vec::new(),
            san_emails: Vec::new(),
            san_uris: Vec::new(),
            eku_oids: Vec::new(),
            policy_oids: Vec::new(),
            ocsp_must_staple: false,
            cdp_urls: Vec::new(),
            ocsp_urls: Vec::new(),
            ca_issuer_urls: Vec::new(),
        }
    }

    fn san_dns(mut self, dns: &str) -> Self {
        self.san_dns.push(dns.to_string());
        self
    }

    fn san_ip(mut self, ip: IpAddr) -> Self {
        self.san_ips.push(ip);
        self
    }

    fn san_email(mut self, email: &str) -> Self {
        self.san_emails.push(email.to_string());
        self
    }

    fn san_uri(mut self, uri: &str) -> Self {
        self.san_uris.push(uri.to_string());
        self
    }

    fn eku(mut self, oid: ObjectIdentifier) -> Self {
        self.eku_oids.push(oid);
        self
    }

    fn policy(mut self, oid: ObjectIdentifier) -> Self {
        self.policy_oids.push(oid);
        self
    }

    fn must_staple(mut self) -> Self {
        self.ocsp_must_staple = true;
        self
    }

    fn cdp(mut self, url: &str) -> Self {
        self.cdp_urls.push(url.to_string());
        self
    }

    fn ocsp(mut self, url: &str) -> Self {
        self.ocsp_urls.push(url.to_string());
        self
    }

    fn ca_issuer(mut self, url: &str) -> Self {
        self.ca_issuer_urls.push(url.to_string());
        self
    }

    fn build(self) -> (Vec<u8>, String) {
        let key = KeyPair::generate(self.algo).expect("keygen");
        let dn = NameBuilder::new(&self.cn)
            .organization("Test PKI")
            .country("US")
            .build();
        let issuer_dn = NameBuilder::new(&self.issuer_cn)
            .organization("Test PKI")
            .country("US")
            .build();

        let mut san = SubjectAltName::new();
        for dns in &self.san_dns {
            san = san.dns(dns);
        }
        for ip in &self.san_ips {
            san = san.ip(*ip);
        }
        for email in &self.san_emails {
            san = san.email(email);
        }
        for uri in &self.san_uris {
            san = san.uri(uri);
        }

        let mut builder =
            CertificateBuilder::new(dn, key.public_key_der().unwrap(), key.algorithm_id())
                .validity(Validity::years_from_now(1))
                .issuer(issuer_dn)
                .basic_constraints(BasicConstraints::end_entity())
                .key_usage(KeyUsage::new(KeyUsageFlags::new(
                    KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_ENCIPHERMENT,
                )))
                .subject_alt_name(san);

        if !self.eku_oids.is_empty() {
            builder = builder.extended_key_usage(ExtendedKeyUsage::new(self.eku_oids));
        }

        if !self.policy_oids.is_empty() {
            builder = builder.certificate_policies(CertificatePolicies::new(self.policy_oids));
        }

        if self.ocsp_must_staple {
            builder = builder.tls_feature(TlsFeature::must_staple());
        }

        if !self.cdp_urls.is_empty() {
            let mut cdp = CrlDistributionPoints::new();
            for url in &self.cdp_urls {
                cdp = cdp.url(url);
            }
            builder = builder.crl_distribution_points(cdp);
        }

        if !self.ocsp_urls.is_empty() || !self.ca_issuer_urls.is_empty() {
            let mut aia = AuthorityInfoAccess::new();
            for url in &self.ocsp_urls {
                aia = aia.ocsp(url);
            }
            for url in &self.ca_issuer_urls {
                aia = aia.ca_issuer(url);
            }
            builder = builder.authority_info_access(aia);
        }

        let cert = builder
            .build_and_sign(self.issuer_key)
            .expect("build EE cert");

        let der = cert.to_der().expect("encode DER");
        let pem_str = encode_certificate_pem(&cert).expect("encode PEM");
        (der, pem_str)
    }
}

/// Parse and verify the certificate can be decoded with all fields present.
fn decode_and_verify(der: &[u8], pem: &str) -> Certificate {
    // Test DER decode
    let cert_from_der = Certificate::from_der(der).expect("DER decode failed");
    // Test PEM decode
    let cert_from_pem = Certificate::from_pem(pem).expect("PEM decode failed");

    // Core fields must match between DER and PEM decode paths
    assert_eq!(cert_from_der.serial, cert_from_pem.serial);
    assert_eq!(cert_from_der.subject, cert_from_pem.subject);
    assert_eq!(cert_from_der.issuer, cert_from_pem.issuer);
    assert_eq!(
        cert_from_der.fingerprint_sha256,
        cert_from_pem.fingerprint_sha256
    );

    cert_from_der
}

/// Verify text output contains expected content.
fn verify_text_output(cert: &Certificate, expected_fragments: &[&str]) {
    let text = CertFormatter::format(cert, false);
    for frag in expected_fragments {
        assert!(
            text.contains(frag),
            "Text output missing '{}'. Full output:\n{}",
            frag,
            text
        );
    }
}

// Well-known EKU OIDs
const EKU_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
const EKU_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
const EKU_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
const EKU_EMAIL_PROTECTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");
const EKU_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
const EKU_OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");

// Well-known policy OIDs
const POLICY_DV: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.140.1.2.1");
const POLICY_OV: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.140.1.2.2");
const POLICY_EV: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.140.1.1");
const POLICY_ANY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32.0");

// ============================================================================
// KEY ALGORITHM TESTS — Every supported algorithm
// ============================================================================

#[test]
fn test_decode_ecdsa_p256_root_ca() {
    let (_, der, pem) = build_root_ca(AlgorithmId::EcdsaP256, "ECDSA P-256 Root CA");
    let cert = decode_and_verify(&der, &pem);

    assert_eq!(cert.version, 3);
    assert!(cert.is_ca);
    assert!(cert.is_self_signed());
    assert_eq!(cert.key_algorithm_name, "EC");
    assert_eq!(cert.ec_curve, Some("P-256".to_string()));
    assert_eq!(cert.key_size, 256);
    assert!(
        cert.signature_algorithm_name.contains("ecdsa")
            || cert.signature_algorithm_name.contains("SHA256")
    );
    assert!(cert.key_usage.contains(&"Certificate Sign".to_string()));
    assert!(cert.key_usage.contains(&"CRL Sign".to_string()));
    assert!(!cert.fingerprint_sha256.is_empty());
    assert!(!cert.fingerprint_sha1.is_empty());
    assert!(!cert.spki_sha256_b64.is_empty());

    verify_text_output(&cert, &["ECDSA", "P-256", "Certificate Sign"]);
}

#[test]
fn test_decode_ecdsa_p384_root_ca() {
    let (_, der, pem) = build_root_ca(AlgorithmId::EcdsaP384, "ECDSA P-384 Root CA");
    let cert = decode_and_verify(&der, &pem);

    assert_eq!(cert.key_algorithm_name, "EC");
    assert_eq!(cert.ec_curve, Some("P-384".to_string()));
    assert_eq!(cert.key_size, 384);
    assert!(cert.is_ca);
}

#[test]
fn test_decode_rsa_2048_root_ca() {
    let (_, der, pem) = build_root_ca(AlgorithmId::Rsa2048, "RSA 2048 Root CA");
    let cert = decode_and_verify(&der, &pem);

    assert_eq!(cert.key_algorithm_name, "RSA");
    assert!(cert.key_size >= 2048);
    assert!(cert.ec_curve.is_none());
    assert!(cert.rsa_modulus.is_some());
    assert!(cert.rsa_exponent.is_some());
    assert!(
        cert.signature_algorithm_name.contains("RSA")
            || cert.signature_algorithm_name.contains("sha256")
    );
}

#[test]
fn test_decode_rsa_3072_root_ca() {
    let (_, der, pem) = build_root_ca(AlgorithmId::Rsa3072, "RSA 3072 Root CA");
    let cert = decode_and_verify(&der, &pem);

    assert_eq!(cert.key_algorithm_name, "RSA");
    assert!(cert.key_size >= 3072);
}

#[test]
fn test_decode_rsa_4096_root_ca() {
    let (_, der, pem) = build_root_ca(AlgorithmId::Rsa4096, "RSA 4096 Root CA");
    let cert = decode_and_verify(&der, &pem);

    assert_eq!(cert.key_algorithm_name, "RSA");
    assert!(cert.key_size >= 4096);
}

#[test]
fn test_decode_ed25519_root_ca() {
    let (_, der, pem) = build_root_ca(AlgorithmId::Ed25519, "Ed25519 Root CA");
    let cert = decode_and_verify(&der, &pem);

    assert_eq!(cert.key_algorithm_name, "Ed25519");
    assert_eq!(cert.key_size, 256);
    assert!(cert.signature_algorithm_name.contains("Ed25519"));
}

// ============================================================================
// INTERMEDIATE CA TESTS — Chain building
// ============================================================================

#[test]
fn test_decode_intermediate_ca_ecdsa() {
    let (root_key, _, _) = build_root_ca(AlgorithmId::EcdsaP384, "Root CA");
    let (_, der, pem) = build_intermediate_ca(
        AlgorithmId::EcdsaP256,
        "Intermediate CA",
        &root_key,
        "Root CA",
    );
    let cert = decode_and_verify(&der, &pem);

    assert!(cert.is_ca);
    assert!(!cert.is_self_signed());
    assert_eq!(cert.path_length, 0);
    assert!(cert.subject.contains("Intermediate CA"));
    assert!(cert.issuer.contains("Root CA"));
    assert!(!cert.crl_distribution_points.is_empty());
    assert!(!cert.ocsp_urls.is_empty());
    assert!(!cert.ca_issuer_urls.is_empty());
    assert!(cert.authority_key_id.is_some());
}

#[test]
fn test_decode_cross_algo_chain_rsa_to_ec() {
    let (root_key, _, _) = build_root_ca(AlgorithmId::Rsa4096, "RSA Root");
    let (_, der, pem) = build_intermediate_ca(
        AlgorithmId::EcdsaP384,
        "EC Intermediate",
        &root_key,
        "RSA Root",
    );
    let cert = decode_and_verify(&der, &pem);

    // Cert key is EC but signed by RSA
    assert_eq!(cert.key_algorithm_name, "EC");
    assert!(
        cert.signature_algorithm_name.contains("RSA")
            || cert.signature_algorithm_name.contains("sha256")
            || cert.signature_algorithm_name.contains("sha384")
    );
}

#[test]
fn test_decode_cross_algo_chain_ec_to_ed25519() {
    let (root_key, _, _) = build_root_ca(AlgorithmId::EcdsaP384, "EC Root");
    let (_, der, pem) = build_intermediate_ca(
        AlgorithmId::Ed25519,
        "Ed25519 Intermediate",
        &root_key,
        "EC Root",
    );
    let cert = decode_and_verify(&der, &pem);

    assert_eq!(cert.key_algorithm_name, "Ed25519");
    assert!(
        cert.signature_algorithm_name.contains("ecdsa")
            || cert.signature_algorithm_name.contains("SHA")
    );
}

// ============================================================================
// END-ENTITY CERTIFICATE TESTS — Every purpose type
// ============================================================================

#[test]
fn test_decode_tls_server_cert() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP384, "TLS CA");
    let (der, pem) =
        EeCertBuilder::new(AlgorithmId::EcdsaP256, "www.example.com", &ca_key, "TLS CA")
            .san_dns("example.com")
            .san_dns("*.example.com")
            .eku(EKU_SERVER_AUTH)
            .eku(EKU_CLIENT_AUTH)
            .policy(POLICY_DV)
            .cdp("http://crl.example.com/tls.crl")
            .ocsp("http://ocsp.example.com/")
            .ca_issuer("http://ca.example.com/issuer.cer")
            .build();

    let cert = decode_and_verify(&der, &pem);

    // SAN verification
    assert!(cert.san.len() >= 3); // www.example.com, example.com, *.example.com
    let san_strs: Vec<String> = cert.san.iter().map(|s| s.to_string()).collect();
    assert!(san_strs.iter().any(|s| s.contains("www.example.com")));
    assert!(san_strs.iter().any(|s| s.contains("*.example.com")));

    // EKU verification
    assert!(!cert.extended_key_usage.is_empty());

    // Policy verification
    assert!(!cert.certificate_policies.is_empty());

    // CDP verification
    assert!(cert
        .crl_distribution_points
        .iter()
        .any(|u| u.contains("crl.example.com")));

    // AIA verification
    assert!(cert
        .ocsp_urls
        .iter()
        .any(|u| u.contains("ocsp.example.com")));
    assert!(cert.ca_issuer_urls.iter().any(|u| u.contains("issuer.cer")));

    // Not a CA
    assert!(!cert.is_ca);
    assert!(!cert.is_self_signed());

    // Key Usage
    assert!(cert.key_usage.contains(&"Digital Signature".to_string()));
    assert!(cert.key_usage.contains(&"Key Encipherment".to_string()));

    // Fingerprints
    assert!(!cert.fingerprint_sha256.is_empty());
    assert!(!cert.fingerprint_sha1.is_empty());

    verify_text_output(&cert, &["www.example.com", "Digital Signature"]);
}

#[test]
fn test_decode_tls_server_cert_with_must_staple() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP384, "OCSP CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "staple.example.com",
        &ca_key,
        "OCSP CA",
    )
    .eku(EKU_SERVER_AUTH)
    .must_staple()
    .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(cert.ocsp_must_staple, "OCSP Must-Staple not detected");
}

#[test]
fn test_decode_client_auth_cert() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP384, "Client CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "user@example.com",
        &ca_key,
        "Client CA",
    )
    .eku(EKU_CLIENT_AUTH)
    .san_email("user@example.com")
    .build();

    let cert = decode_and_verify(&der, &pem);
    let san_strs: Vec<String> = cert.san.iter().map(|s| s.to_string()).collect();
    assert!(san_strs.iter().any(|s| s.contains("user@example.com")));
}

#[test]
fn test_decode_code_signing_cert() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP384, "CodeSign CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "Code Signer",
        &ca_key,
        "CodeSign CA",
    )
    .eku(EKU_CODE_SIGNING)
    .eku(EKU_TIME_STAMPING)
    .policy(ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56266.1.1.10"))
    .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(!cert.extended_key_usage.is_empty());
    assert!(!cert.certificate_policies.is_empty());
}

#[test]
fn test_decode_email_smime_cert() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP384, "Email CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "secure@example.com",
        &ca_key,
        "Email CA",
    )
    .eku(EKU_EMAIL_PROTECTION)
    .san_email("secure@example.com")
    .san_email("alias@example.com")
    .build();

    let cert = decode_and_verify(&der, &pem);
    let san_strs: Vec<String> = cert.san.iter().map(|s| s.to_string()).collect();
    assert!(san_strs.iter().any(|s| s.contains("secure@example.com")));
    assert!(san_strs.iter().any(|s| s.contains("alias@example.com")));
}

#[test]
fn test_decode_ocsp_responder_cert() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP384, "OCSP Issuer CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "OCSP Responder",
        &ca_key,
        "OCSP Issuer CA",
    )
    .eku(EKU_OCSP_SIGNING)
    .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(!cert.extended_key_usage.is_empty());
}

#[test]
fn test_decode_timestamping_cert() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP384, "TSA CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "Time Stamp Authority",
        &ca_key,
        "TSA CA",
    )
    .eku(EKU_TIME_STAMPING)
    .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(!cert.extended_key_usage.is_empty());
}

// ============================================================================
// SAN VARIETY TESTS — Every SAN type combination
// ============================================================================

#[test]
fn test_decode_san_dns_only() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "SAN CA");
    let (der, pem) =
        EeCertBuilder::new(AlgorithmId::EcdsaP256, "dns.example.com", &ca_key, "SAN CA")
            .san_dns("www.dns.example.com")
            .san_dns("api.dns.example.com")
            .san_dns("mail.dns.example.com")
            .eku(EKU_SERVER_AUTH)
            .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(cert.san.len() >= 4);
    for san in &cert.san {
        assert!(san.to_string().starts_with("DNS:"));
    }
}

#[test]
fn test_decode_san_ipv4() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "IP CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "ip-cert.example.com",
        &ca_key,
        "IP CA",
    )
    .san_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    .san_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
    .eku(EKU_SERVER_AUTH)
    .build();

    let cert = decode_and_verify(&der, &pem);
    let san_strs: Vec<String> = cert.san.iter().map(|s| s.to_string()).collect();
    assert!(san_strs.iter().any(|s| s.contains("10.0.0.1")));
    assert!(san_strs.iter().any(|s| s.contains("192.168.1.100")));
}

#[test]
fn test_decode_san_ipv6() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "IPv6 CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "ipv6.example.com",
        &ca_key,
        "IPv6 CA",
    )
    .san_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
    .san_ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
    .eku(EKU_SERVER_AUTH)
    .build();

    let cert = decode_and_verify(&der, &pem);
    let san_strs: Vec<String> = cert.san.iter().map(|s| s.to_string()).collect();
    assert!(san_strs.iter().any(|s| s.starts_with("IP:")));
}

#[test]
fn test_decode_san_uri() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "URI CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "uri-cert.example.com",
        &ca_key,
        "URI CA",
    )
    .san_uri("https://service.example.com/api")
    .san_uri("spiffe://example.com/workload")
    .eku(EKU_SERVER_AUTH)
    .build();

    let cert = decode_and_verify(&der, &pem);
    let san_strs: Vec<String> = cert.san.iter().map(|s| s.to_string()).collect();
    assert!(san_strs.iter().any(|s| s.contains("service.example.com")));
    assert!(san_strs.iter().any(|s| s.contains("spiffe://")));
}

#[test]
fn test_decode_san_mixed_all_types() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "Mixed SAN CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "mixed.example.com",
        &ca_key,
        "Mixed SAN CA",
    )
    .san_dns("www.mixed.example.com")
    .san_ip(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)))
    .san_ip(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)))
    .san_email("admin@mixed.example.com")
    .san_uri("https://mixed.example.com/endpoint")
    .eku(EKU_SERVER_AUTH)
    .eku(EKU_CLIENT_AUTH)
    .build();

    let cert = decode_and_verify(&der, &pem);
    let san_strs: Vec<String> = cert.san.iter().map(|s| s.to_string()).collect();

    // Verify at least one of each type present
    assert!(san_strs.iter().any(|s| s.starts_with("DNS:")));
    assert!(san_strs.iter().any(|s| s.starts_with("IP:")));
    assert!(san_strs.iter().any(|s| s.starts_with("email:")));
    assert!(san_strs.iter().any(|s| s.starts_with("URI:")));
}

// ============================================================================
// WILDCARD & EDGE CASE SAN TESTS
// ============================================================================

#[test]
fn test_decode_wildcard_cert() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "Wild CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "*.wildcard.example.com",
        &ca_key,
        "Wild CA",
    )
    .san_dns("wildcard.example.com")
    .eku(EKU_SERVER_AUTH)
    .build();

    let cert = decode_and_verify(&der, &pem);
    let san_strs: Vec<String> = cert.san.iter().map(|s| s.to_string()).collect();
    assert!(san_strs.iter().any(|s| s.contains("*.wildcard")));
}

#[test]
fn test_decode_many_sans_cert() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "Many SAN CA");
    let mut builder = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "many.example.com",
        &ca_key,
        "Many SAN CA",
    )
    .eku(EKU_SERVER_AUTH);

    // Add 50 SANs
    for i in 0..50 {
        builder = builder.san_dns(&format!("host-{}.example.com", i));
    }

    let (der, pem) = builder.build();
    let cert = decode_and_verify(&der, &pem);
    assert!(cert.san.len() >= 50);
}

// ============================================================================
// CERTIFICATE POLICY TESTS
// ============================================================================

#[test]
fn test_decode_dv_policy() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "DV Policy CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "dv.example.com",
        &ca_key,
        "DV Policy CA",
    )
    .eku(EKU_SERVER_AUTH)
    .policy(POLICY_DV)
    .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(cert
        .certificate_policies
        .contains(&"2.23.140.1.2.1".to_string()));
}

#[test]
fn test_decode_ov_policy() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "OV Policy CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "ov.example.com",
        &ca_key,
        "OV Policy CA",
    )
    .eku(EKU_SERVER_AUTH)
    .policy(POLICY_OV)
    .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(cert
        .certificate_policies
        .contains(&"2.23.140.1.2.2".to_string()));
}

#[test]
fn test_decode_ev_policy() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "EV Policy CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "ev.example.com",
        &ca_key,
        "EV Policy CA",
    )
    .eku(EKU_SERVER_AUTH)
    .policy(POLICY_EV)
    .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(cert
        .certificate_policies
        .contains(&"2.23.140.1.1".to_string()));
}

#[test]
fn test_decode_multiple_policies() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "MultiPolicy CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "multi-policy.example.com",
        &ca_key,
        "MultiPolicy CA",
    )
    .eku(EKU_SERVER_AUTH)
    .policy(POLICY_DV)
    .policy(POLICY_ANY)
    .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(cert.certificate_policies.len() >= 2);
}

// ============================================================================
// AIA & CDP TESTS — Every distribution mechanism
// ============================================================================

#[test]
fn test_decode_multiple_ocsp_urls() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "Multi OCSP CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "multi-ocsp.example.com",
        &ca_key,
        "Multi OCSP CA",
    )
    .eku(EKU_SERVER_AUTH)
    .ocsp("http://ocsp1.example.com/")
    .ocsp("http://ocsp2.example.com/")
    .ca_issuer("http://ca.example.com/issuer1.cer")
    .ca_issuer("http://ca.example.com/issuer2.cer")
    .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(cert.ocsp_urls.len() >= 2);
    assert!(cert.ca_issuer_urls.len() >= 2);
}

#[test]
fn test_decode_multiple_cdp_urls() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "Multi CDP CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "multi-cdp.example.com",
        &ca_key,
        "Multi CDP CA",
    )
    .eku(EKU_SERVER_AUTH)
    .cdp("http://crl1.example.com/ca.crl")
    .cdp("http://crl2.example.com/ca.crl")
    .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(cert.crl_distribution_points.len() >= 2);
}

// ============================================================================
// KEY IDENTIFIER TESTS
// ============================================================================

#[test]
fn test_decode_subject_key_identifier() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "SKI CA");
    let (der, pem) =
        EeCertBuilder::new(AlgorithmId::EcdsaP256, "ski.example.com", &ca_key, "SKI CA")
            .eku(EKU_SERVER_AUTH)
            .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(cert.subject_key_id.is_some(), "SKI should be present");
    assert!(cert.authority_key_id.is_some(), "AKI should be present");
    // SKI should be a hex string
    let ski = cert.subject_key_id.unwrap();
    assert!(!ski.is_empty());
    assert!(ski.chars().all(|c| c.is_ascii_hexdigit()));
}

// ============================================================================
// CERTIFICATE LIFETIME & VALIDITY TESTS
// ============================================================================

#[test]
fn test_decode_validity_not_expired() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "Validity CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "valid.example.com",
        &ca_key,
        "Validity CA",
    )
    .eku(EKU_SERVER_AUTH)
    .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(!cert.is_expired());
    assert!(cert.days_until_expiry() > 0);
    assert!(cert.days_until_expiry() <= 366);
    let pct = cert.lifetime_used_percent();
    assert!((0.0..=100.0).contains(&pct));
}

// ============================================================================
// PEM BUNDLE TESTS — Multi-cert parsing
// ============================================================================

#[test]
fn test_decode_pem_bundle_chain() {
    let (ca_key, _, ca_pem) = build_root_ca(AlgorithmId::EcdsaP384, "Bundle Root");
    let (int_key, _, int_pem) = build_intermediate_ca(
        AlgorithmId::EcdsaP256,
        "Bundle Intermediate",
        &ca_key,
        "Bundle Root",
    );
    let (_, ee_pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "bundle.example.com",
        &int_key,
        "Bundle Intermediate",
    )
    .eku(EKU_SERVER_AUTH)
    .build();

    // Create PEM bundle: EE + Intermediate + Root
    let bundle = format!("{}\n{}\n{}", ee_pem, int_pem, ca_pem);

    let certs = Certificate::all_from_pem(&bundle).expect("bundle parse failed");
    assert_eq!(certs.len(), 3);

    // First cert should be the EE
    assert!(!certs[0].is_ca);
    assert!(certs[0].subject.contains("bundle.example.com"));

    // Second should be intermediate
    assert!(certs[1].is_ca);
    assert!(certs[1].subject.contains("Bundle Intermediate"));

    // Third should be root
    assert!(certs[2].is_ca);
    assert!(certs[2].is_self_signed());
}

// ============================================================================
// FORMATTER OUTPUT TESTS — Text, JSON, Compact
// ============================================================================

#[test]
fn test_format_text_output_completeness() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP384, "Fmt CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "format-test.example.com",
        &ca_key,
        "Fmt CA",
    )
    .san_dns("alt.format-test.example.com")
    .san_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)))
    .eku(EKU_SERVER_AUTH)
    .eku(EKU_CLIENT_AUTH)
    .policy(POLICY_DV)
    .cdp("http://crl.fmt.example.com/ca.crl")
    .ocsp("http://ocsp.fmt.example.com/")
    .ca_issuer("http://ca.fmt.example.com/issuer.cer")
    .must_staple()
    .build();

    let cert = decode_and_verify(&der, &pem);
    let text = CertFormatter::format(&cert, false);

    // Verify ALL major sections are present in output
    let required_sections = [
        // Identity
        "format-test.example.com",
        // Subject/Issuer info
        "Fmt CA",
        // Key info
        "EC",
        "P-256",
        // Key Usage
        "Digital Signature",
        // SANs
        "alt.format-test.example.com",
        "10.0.0.42",
        // Fingerprints
        "SHA-256",
    ];

    for section in &required_sections {
        assert!(
            text.contains(section),
            "Text output missing section: '{}'\nFull output:\n{}",
            section,
            text
        );
    }
}

#[test]
fn test_format_json_output_structure() {
    let (_, der, _) = build_root_ca(AlgorithmId::EcdsaP256, "JSON CA");
    let cert = Certificate::from_der(&der).unwrap();

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&cert).expect("JSON serialization failed");

    // Verify key JSON fields
    assert!(json.contains("\"version\""));
    assert!(json.contains("\"serial\""));
    assert!(json.contains("\"subject\""));
    assert!(json.contains("\"issuer\""));
    assert!(json.contains("\"not_before\""));
    assert!(json.contains("\"not_after\""));
    assert!(json.contains("\"signature_algorithm\""));
    assert!(json.contains("\"key_algorithm\""));
    assert!(json.contains("\"fingerprint_sha256\""));
    assert!(json.contains("\"fingerprint_sha1\""));

    // Verify it round-trips
    let deserialized: Certificate =
        serde_json::from_str(&json).expect("JSON deserialization failed");
    assert_eq!(cert.serial, deserialized.serial);
    assert_eq!(cert.subject, deserialized.subject);
}

// ============================================================================
// MULTI-ALGORITHM EE CERT DECODE — Every key algo as EE
// ============================================================================

fn test_ee_with_algo(algo: AlgorithmId, expected_key_name: &str) {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP384, "Algo Matrix CA");
    let (der, pem) = EeCertBuilder::new(algo, "algo-test.example.com", &ca_key, "Algo Matrix CA")
        .eku(EKU_SERVER_AUTH)
        .build();

    let cert = decode_and_verify(&der, &pem);
    assert_eq!(
        cert.key_algorithm_name, expected_key_name,
        "Expected key algo '{}', got '{}'",
        expected_key_name, cert.key_algorithm_name
    );
    assert!(!cert.is_ca);
}

#[test]
fn test_ee_ecdsa_p256() {
    test_ee_with_algo(AlgorithmId::EcdsaP256, "EC");
}

#[test]
fn test_ee_ecdsa_p384() {
    test_ee_with_algo(AlgorithmId::EcdsaP384, "EC");
}

#[test]
fn test_ee_rsa_2048() {
    test_ee_with_algo(AlgorithmId::Rsa2048, "RSA");
}

#[test]
fn test_ee_rsa_3072() {
    test_ee_with_algo(AlgorithmId::Rsa3072, "RSA");
}

#[test]
fn test_ee_rsa_4096() {
    test_ee_with_algo(AlgorithmId::Rsa4096, "RSA");
}

#[test]
fn test_ee_ed25519() {
    test_ee_with_algo(AlgorithmId::Ed25519, "Ed25519");
}

// ============================================================================
// FULL CHAIN DEPTH TESTS — Root -> Intermediate -> EE
// ============================================================================

#[test]
fn test_full_three_tier_chain_decode() {
    // Root CA (ECDSA P-384)
    let (root_key, root_der, _) = build_root_ca(AlgorithmId::EcdsaP384, "Three-Tier Root CA");
    let root_cert = Certificate::from_der(&root_der).unwrap();

    // Intermediate CA (ECDSA P-256)
    let (int_key, int_der, _) = build_intermediate_ca(
        AlgorithmId::EcdsaP256,
        "Three-Tier Intermediate CA",
        &root_key,
        "Three-Tier Root CA",
    );
    let int_cert = Certificate::from_der(&int_der).unwrap();

    // End-entity (RSA 2048)
    let (ee_der, _) = EeCertBuilder::new(
        AlgorithmId::Rsa2048,
        "three-tier.example.com",
        &int_key,
        "Three-Tier Intermediate CA",
    )
    .eku(EKU_SERVER_AUTH)
    .san_dns("www.three-tier.example.com")
    .policy(POLICY_OV)
    .cdp("http://crl.example.com/intermediate.crl")
    .ocsp("http://ocsp.example.com/")
    .build();
    let ee_cert = Certificate::from_der(&ee_der).unwrap();

    // Verify chain relationships
    assert!(root_cert.is_self_signed());
    assert!(root_cert.is_ca);

    assert!(!int_cert.is_self_signed());
    assert!(int_cert.is_ca);
    assert!(int_cert.issuer.contains("Three-Tier Root CA"));

    assert!(!ee_cert.is_self_signed());
    assert!(!ee_cert.is_ca);
    assert!(ee_cert.issuer.contains("Three-Tier Intermediate CA"));

    // Verify AKI and SKI are present in chain members
    assert!(
        int_cert.authority_key_id.is_some(),
        "Intermediate should have AKI"
    );
    assert!(ee_cert.authority_key_id.is_some(), "EE should have AKI");
    assert!(root_cert.subject_key_id.is_some(), "Root should have SKI");
    assert!(
        int_cert.subject_key_id.is_some(),
        "Intermediate should have SKI"
    );

    // Verify key algorithm variety in chain
    assert_eq!(root_cert.key_algorithm_name, "EC");
    assert_eq!(int_cert.key_algorithm_name, "EC");
    assert_eq!(ee_cert.key_algorithm_name, "RSA");
}

// ============================================================================
// EXHAUSTIVE EKU COMBINATION TESTS
// ============================================================================

#[test]
fn test_decode_dual_purpose_server_client() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "Dual CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "dual.example.com",
        &ca_key,
        "Dual CA",
    )
    .eku(EKU_SERVER_AUTH)
    .eku(EKU_CLIENT_AUTH)
    .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(cert.extended_key_usage.len() >= 2);
}

#[test]
fn test_decode_kitchen_sink_eku() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "Kitchen CA");
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "kitchen-sink.example.com",
        &ca_key,
        "Kitchen CA",
    )
    .eku(EKU_SERVER_AUTH)
    .eku(EKU_CLIENT_AUTH)
    .eku(EKU_CODE_SIGNING)
    .eku(EKU_EMAIL_PROTECTION)
    .eku(EKU_TIME_STAMPING)
    .eku(EKU_OCSP_SIGNING)
    .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(
        cert.extended_key_usage.len() >= 6,
        "Expected >=6 EKUs, got {}: {:?}",
        cert.extended_key_usage.len(),
        cert.extended_key_usage
    );
}

// ============================================================================
// RSA-PSS TESTS
// ============================================================================

#[test]
fn test_decode_rsa_pss_3072() {
    let (_, der, pem) = build_root_ca(AlgorithmId::Rsa3072Pss, "RSA-PSS 3072 Root CA");
    let cert = decode_and_verify(&der, &pem);

    assert_eq!(cert.key_algorithm_name, "RSA");
    assert!(cert.key_size >= 3072);
    assert!(cert.is_ca);
}

#[test]
fn test_decode_rsa_pss_4096() {
    let (_, der, pem) = build_root_ca(AlgorithmId::Rsa4096Pss, "RSA-PSS 4096 Root CA");
    let cert = decode_and_verify(&der, &pem);

    assert_eq!(cert.key_algorithm_name, "RSA");
    assert!(cert.key_size >= 4096);
}

// ============================================================================
// FINGERPRINT & SPKI PIN TESTS
// ============================================================================

#[test]
fn test_fingerprints_are_consistent() {
    let (_, der, pem) = build_root_ca(AlgorithmId::EcdsaP256, "Fingerprint CA");
    let cert1 = Certificate::from_der(&der).unwrap();
    let cert2 = Certificate::from_pem(&pem).unwrap();

    // Fingerprints from DER and PEM paths must match
    assert_eq!(cert1.fingerprint_sha256, cert2.fingerprint_sha256);
    assert_eq!(cert1.fingerprint_sha1, cert2.fingerprint_sha1);
    assert_eq!(cert1.spki_sha256_b64, cert2.spki_sha256_b64);

    // SHA-256 should be 64 hex chars
    assert_eq!(cert1.fingerprint_sha256.len(), 64);
    // SHA-1 should be 40 hex chars
    assert_eq!(cert1.fingerprint_sha1.len(), 40);
    // SPKI pin should be base64
    assert!(!cert1.spki_sha256_b64.is_empty());
}

#[test]
fn test_unique_fingerprints_per_cert() {
    let (_, der1, _) = build_root_ca(AlgorithmId::EcdsaP256, "FP Test CA 1");
    let (_, der2, _) = build_root_ca(AlgorithmId::EcdsaP256, "FP Test CA 2");

    let cert1 = Certificate::from_der(&der1).unwrap();
    let cert2 = Certificate::from_der(&der2).unwrap();

    assert_ne!(cert1.fingerprint_sha256, cert2.fingerprint_sha256);
    assert_ne!(cert1.fingerprint_sha1, cert2.fingerprint_sha1);
    assert_ne!(cert1.serial, cert2.serial);
}

// ============================================================================
// STRESS TEST — Decode many certs in sequence
// ============================================================================

#[test]
fn test_decode_many_certs_sequentially() {
    let algos = [
        AlgorithmId::EcdsaP256,
        AlgorithmId::EcdsaP384,
        AlgorithmId::Ed25519,
        AlgorithmId::Rsa2048,
    ];

    for (i, algo) in algos.iter().enumerate() {
        let cn = format!("stress-test-{}.example.com", i);
        let (_, der, pem) = build_root_ca(*algo, &cn);
        let cert = decode_and_verify(&der, &pem);
        assert!(cert.subject.contains(&cn));

        // Verify formatter doesn't panic
        let _text = CertFormatter::format(&cert, false);
        let _colored = CertFormatter::format(&cert, true);
        let _json = serde_json::to_string(&cert).unwrap();
    }
}

// ============================================================================
// CERTIFICATE COMMON NAME PARSING EDGE CASES
// ============================================================================

#[test]
fn test_decode_cn_with_special_chars() {
    let (ca_key, _, _) = build_root_ca(AlgorithmId::EcdsaP256, "Special CA");
    // Use valid DNS characters only (underscores are rejected by strict validators)
    let (der, pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "test-host-v2.prod.example.com",
        &ca_key,
        "Special CA",
    )
    .eku(EKU_SERVER_AUTH)
    .build();

    let cert = decode_and_verify(&der, &pem);
    assert!(cert.common_name().is_some());
    assert!(cert
        .common_name()
        .unwrap()
        .contains("test-host-v2.prod.example.com"));
}

// ============================================================================
// DER RAW BYTES TESTS
// ============================================================================

#[test]
fn test_raw_der_bytes_preserved() {
    let (_, der, _) = build_root_ca(AlgorithmId::EcdsaP256, "DER Test CA");
    let cert = Certificate::from_der(&der).unwrap();

    assert_eq!(cert.raw_der(), der.as_slice());
    assert!(cert.raw_der().len() > 100); // Cert should be substantial
    assert_eq!(cert.raw_der()[0], 0x30); // Must start with SEQUENCE tag
}

// ============================================================================
// FORENSIC OUTPUT TESTS — "OpenSSL on crack" mode
// ============================================================================

#[test]
fn test_forensic_output_root_ca() {
    let (_, der, _) = build_root_ca(AlgorithmId::EcdsaP384, "Forensic Test Root CA");
    let cert = Certificate::from_der(&der).unwrap();

    let output = CertFormatter::format_forensic(&cert, false);

    // Verify all major forensic sections are present
    assert!(output.contains("Forensic Certificate Analysis"));
    assert!(output.contains("IDENTITY"));
    assert!(output.contains("VERSION & SERIAL"));
    assert!(output.contains("VALIDITY & LIFETIME"));
    assert!(output.contains("SIGNATURE ALGORITHM"));
    assert!(output.contains("SUBJECT PUBLIC KEY"));
    assert!(output.contains("X.509v3 EXTENSIONS"));
    assert!(output.contains("FINGERPRINTS & PINNING"));
    assert!(output.contains("DER ENCODING"));

    // Verify identity details
    assert!(output.contains("Forensic Test Root CA"));
    assert!(output.contains("Self-Signed:          Yes"));
    assert!(output.contains("CA:                 TRUE"));

    // Verify key info
    assert!(output.contains("384 bits"));

    // Verify DER size is reported
    assert!(output.contains("bytes"));
}

#[test]
fn test_forensic_output_end_entity() {
    let (ca_key, _ca_der, ca_cn) = build_root_ca(AlgorithmId::EcdsaP256, "Forensic CA");
    let (ee, _pem) = EeCertBuilder::new(
        AlgorithmId::EcdsaP256,
        "forensic-test.example.com",
        &ca_key,
        &ca_cn,
    )
    .san_dns("*.example.com")
    .eku(EKU_SERVER_AUTH)
    .eku(EKU_CLIENT_AUTH)
    .ocsp("http://ocsp.example.com")
    .cdp("http://crl.example.com/ca.crl")
    .build();
    let cert = Certificate::from_der(&ee).unwrap();

    let output = CertFormatter::format_forensic(&cert, false);

    // Verify SANs with counts
    assert!(output.contains("Subject Alternative Name"));
    assert!(output.contains("2 entries"));
    assert!(output.contains("forensic-test.example.com"));
    assert!(output.contains("*.example.com"));

    // Verify EKUs present
    assert!(output.contains("TLS Web Server Authentication"));
    assert!(output.contains("TLS Web Client Authentication"));

    // Verify wildcard detected
    assert!(output.contains("Wildcard:             Yes"));

    // Verify self-signed = No
    assert!(output.contains("Self-Signed:          No"));

    // Verify revocation info
    assert!(output.contains("OCSP"));
    assert!(output.contains("ocsp.example.com"));
    assert!(output.contains("crl.example.com"));
}

#[test]
fn test_forensic_output_colored_vs_plain() {
    let (_, der, _) = build_root_ca(AlgorithmId::EcdsaP256, "Color Test CA");
    let cert = Certificate::from_der(&der).unwrap();

    let colored_output = CertFormatter::format_forensic(&cert, true);
    let plain_output = CertFormatter::format_forensic(&cert, false);

    // Plain output should NOT contain ANSI codes
    assert!(!plain_output.contains("\x1b["));

    // Both should contain the same content sections
    assert!(colored_output.contains("Forensic Certificate Analysis"));
    assert!(plain_output.contains("Forensic Certificate Analysis"));

    // Colored output should be longer (ANSI escape sequences add bytes)
    // unless colored is suppressed by environment
    assert!(colored_output.len() >= plain_output.len());
}

#[test]
fn test_forensic_output_via_formatter_trait() {
    use pki_client_output::{Formatter, OutputFormat};

    let (_, der, _) = build_root_ca(AlgorithmId::EcdsaP256, "Trait Test CA");
    let cert = Certificate::from_der(&der).unwrap();

    // Test via Formatter trait
    let output = cert.format(OutputFormat::Forensic, false);
    assert!(output.contains("Forensic Certificate Analysis"));
    assert!(output.contains("Trait Test CA"));
}

#[test]
fn test_forensic_output_security_assessment() {
    let (ca_key, _ca_der, ca_cn) = build_root_ca(AlgorithmId::EcdsaP256, "Assessment CA");

    // Build an EE cert with no OCSP, no CRL, no SANs — should flag issues
    let ee_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
    let ee_dn = NameBuilder::new("Bare Cert").build();
    let issuer_dn = NameBuilder::new(&ca_cn)
        .organization("Test PKI")
        .country("US")
        .build();
    let ee_cert = CertificateBuilder::new(
        ee_dn,
        ee_key.public_key_der().unwrap(),
        ee_key.algorithm_id(),
    )
    .validity(Validity::years_from_now(1))
    .issuer(issuer_dn)
    .basic_constraints(BasicConstraints::end_entity())
    .key_usage(KeyUsage::new(KeyUsageFlags::new(
        KeyUsageFlags::DIGITAL_SIGNATURE,
    )))
    .build_and_sign(&ca_key)
    .unwrap();
    let ee_der = ee_cert.to_der().unwrap();

    let cert = Certificate::from_der(&ee_der).unwrap();
    let output = CertFormatter::format_forensic(&cert, false);

    // Should flag missing SANs, OCSP, CRL
    assert!(output.contains("SECURITY ASSESSMENT"));
    // Should note missing revocation
    assert!(output.contains("revocation") || output.contains("OCSP") || output.contains("CRL"));
}
