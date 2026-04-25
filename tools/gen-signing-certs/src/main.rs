//! Generate PKI Signing Service code-signing certificates as PFX files.
//!
//! Creates a test ECDSA P-384 root CA, then issues 21 end-entity certificates
//! (3 types × 7 algorithms) with code-signing + timestamping extensions.
//!
//! Output: /tmp/pki-sign/certs/{type}_{algo}.pfx

#![forbid(unsafe_code)]

use std::path::Path;

use const_oid::ObjectIdentifier;

use spork_core::algo::{AlgorithmId, KeyPair};
use spork_core::cert::{
    extensions::{
        BasicConstraints, CertificatePolicies, ExtendedKeyUsage, KeyUsage, KeyUsageFlags,
    },
    CertificateBuilder, NameBuilder, Validity,
};

use der::Encode;
use p12_keystore::{Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, PrivateKeyChain};

/// PFX password — read from SPORK_PFX_PASSWORD env var, default "changeit" for test use.
fn pfx_password() -> String {
    std::env::var("SPORK_PFX_PASSWORD").unwrap_or_else(|_| "changeit".to_string())
}

/// Certificate types (all get identical extensions; the distinction is LDAP access control).
const TYPES: &[&str] = &["desktop", "server", "multipurpose"];

/// Algorithm matrix: (suffix, AlgorithmId, display name for CN)
const ALGOS: &[(&str, AlgorithmId, &str)] = &[
    ("ed25519", AlgorithmId::Ed25519, "Ed25519"),
    ("mldsa44", AlgorithmId::MlDsa44, "ML-DSA-44"),
    ("mldsa65", AlgorithmId::MlDsa65, "ML-DSA-65"),
    ("mldsa87", AlgorithmId::MlDsa87, "ML-DSA-87"),
    (
        "slhdsa128s",
        AlgorithmId::SlhDsaSha2_128s,
        "SLH-DSA-SHA2-128s",
    ),
    (
        "slhdsa192s",
        AlgorithmId::SlhDsaSha2_192s,
        "SLH-DSA-SHA2-192s",
    ),
    (
        "slhdsa256s",
        AlgorithmId::SlhDsaSha2_256s,
        "SLH-DSA-SHA2-256s",
    ),
];

/// EKU OIDs
const EKU_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
const EKU_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// Policy OIDs (Ogjos PEN 56266)
const CP_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56266.1.1.10");
const CP_TIMESTAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56266.1.1.12");

fn main() -> anyhow::Result<()> {
    let output_dir = Path::new("/tmp/pki-sign/certs");
    std::fs::create_dir_all(output_dir)?;

    let password = pfx_password();
    println!("Output:   {}", output_dir.display());
    println!("Password: (from SPORK_PFX_PASSWORD or default)");
    println!();

    // ── Step 1: Create self-signed root CA (ECDSA P-384) ──
    println!("Creating test root CA (ECDSA P-384)...");
    let ca_key = KeyPair::generate(AlgorithmId::EcdsaP384)?;
    let ca_dn = NameBuilder::new("PKI Signing Service Test Root CA")
        .domain("rayketcham.com")
        .organizational_unit("signingservice")
        .organization("test")
        .build();

    let ca_cert = CertificateBuilder::new(
        ca_dn.clone(),
        ca_key.public_key_der()?,
        ca_key.algorithm_id(),
    )
    .validity(Validity::years_from_now(10))
    .basic_constraints(BasicConstraints::ca())
    .key_usage(KeyUsage::new(KeyUsageFlags::new(
        KeyUsageFlags::KEY_CERT_SIGN | KeyUsageFlags::CRL_SIGN,
    )))
    .include_authority_key_identifier(false)
    .build_and_sign(&ca_key)?;

    let ca_cert_der = ca_cert.to_der()?;

    // Write CA cert for reference
    let ca_pem = spork_core::cert::encode_certificate_pem(&ca_cert)?;
    std::fs::write(output_dir.join("ca.pem"), &ca_pem)?;
    println!("  Wrote ca.pem");

    // ── Step 2: Issue end-entity certificates ──
    let mut count = 0u32;
    for (algo_suffix, algo_id, algo_display) in ALGOS {
        for cert_type in TYPES {
            let type_display = match *cert_type {
                "desktop" => "Desktop",
                "server" => "Server",
                "multipurpose" => "Multipurpose",
                _ => cert_type,
            };

            let cn = format!("{} Code Signing ({})", type_display, algo_display);
            let filename = format!("{}_{}.pfx", cert_type, algo_suffix);

            print!("  {}... ", filename);

            // Generate EE key pair
            let ee_key = KeyPair::generate(*algo_id)?;

            // Build EE DN
            let ee_dn = NameBuilder::new(&cn)
                .domain("rayketcham.com")
                .organizational_unit("signingservice")
                .organization("test")
                .build();

            // Build certificate
            let ee_cert =
                CertificateBuilder::new(ee_dn, ee_key.public_key_der()?, ee_key.algorithm_id())
                    .validity(Validity::years_from_now(2))
                    .issuer(ca_dn.clone())
                    .basic_constraints(BasicConstraints::end_entity())
                    .key_usage(KeyUsage::new(KeyUsageFlags::new(
                        KeyUsageFlags::DIGITAL_SIGNATURE,
                    )))
                    .extended_key_usage(ExtendedKeyUsage::new(vec![
                        EKU_CODE_SIGNING,
                        EKU_TIME_STAMPING,
                    ]))
                    .certificate_policies(CertificatePolicies::new(vec![
                        CP_CODE_SIGNING,
                        CP_TIMESTAMPING,
                    ]))
                    .build_and_sign(&ca_key)?;

            let ee_cert_der = ee_cert.to_der()?;
            let ee_key_der = ee_key.private_key_der()?;

            // Build PFX
            let pfx_data = build_pfx(&ee_cert_der, &ee_key_der, &ca_cert_der, &password, &cn)?;

            let pfx_path = output_dir.join(&filename);
            // Atomic 0600 write — a PFX carries the private key, so avoid any
            // window where the file exists at the default umask (TOCTOU). Mirrors
            // write_sensitive_file in crates/pki-client/src/util.rs.
            write_pfx_secure(&pfx_path, &pfx_data)?;

            println!("OK  ({})", cn);
            count += 1;
        }
    }

    println!();
    println!("Done: {} PFX files in {}", count, output_dir.display());
    Ok(())
}

/// Write PFX bytes with 0600 permissions set atomically at creation time.
///
/// `fs::write` followed by `set_permissions` leaves a race window where the
/// file exists world-readable. PFX contains a private key — close the window.
fn write_pfx_secure(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

/// Build a PKCS#12/PFX container from cert + key + CA cert.
fn build_pfx(
    cert_der: &[u8],
    key_der: &[u8],
    ca_cert_der: &[u8],
    password: &str,
    friendly_name: &str,
) -> anyhow::Result<Vec<u8>> {
    use sha2::{Digest, Sha256};

    let entity_cert = Certificate::from_der(cert_der)
        .map_err(|e| anyhow::anyhow!("Failed to parse entity cert: {}", e))?;
    let ca_cert = Certificate::from_der(ca_cert_der)
        .map_err(|e| anyhow::anyhow!("Failed to parse CA cert: {}", e))?;

    // Local key ID from cert hash
    let local_key_id = {
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        hasher.finalize().to_vec()
    };

    let key_chain = PrivateKeyChain::new(key_der, local_key_id, vec![entity_cert, ca_cert]);

    let mut keystore = KeyStore::new();
    keystore.add_entry(friendly_name, KeyStoreEntry::PrivateKeyChain(key_chain));

    let pfx_data = keystore
        .writer(password)
        .encryption_algorithm(EncryptionAlgorithm::PbeWithHmacSha256AndAes256)
        .write()
        .map_err(|e| anyhow::anyhow!("Failed to write PKCS#12: {}", e))?;

    Ok(pfx_data)
}
