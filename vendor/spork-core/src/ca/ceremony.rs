//! CA Initialization Ceremony
//!
//! Secure generation of CA keys and self-signed certificates

use der::Encode;
use zeroize::Zeroizing;

use crate::digest;

use crate::algo::{AlgorithmId, KeyPair};
use crate::cert::extensions::{
    AuthorityInfoAccess, BasicConstraints, CertificatePolicies, CrlDistributionPoints,
    ExtendedKeyUsage, KeyUsage, KeyUsageFlags, SporkIssuanceInfo,
};
use crate::cert::{
    encode_certificate_der, encode_certificate_pem, CertificateBuilder, DistinguishedName,
    NameBuilder, SerialNumber, Validity,
};
use crate::error::{Error, Result};

use super::CertificateAuthority;

/// CA Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CaType {
    /// Root CA (self-signed)
    Root,
    /// Intermediate CA (signed by parent)
    Intermediate,
}

/// CA Configuration
#[derive(Debug, Clone)]
pub struct CaConfig {
    /// CA type
    pub ca_type: CaType,
    /// Algorithm for CA key
    pub algorithm: AlgorithmId,
    /// Subject distinguished name
    pub subject: DistinguishedName,
    /// Validity period
    pub validity: Validity,
    /// Path length constraint (None = unlimited)
    pub path_length: Option<u8>,
    /// CRL Distribution Point URLs
    pub cdp_urls: Vec<String>,
    /// OCSP responder URLs (Authority Information Access)
    pub aia_ocsp_urls: Vec<String>,
    /// CA Issuer URLs (Authority Information Access)
    pub aia_ca_issuer_urls: Vec<String>,
    /// Certificate policies (defaults to evaluation policy if None)
    pub certificate_policies: Option<CertificatePolicies>,
    /// Extended key usage (None = no EKU extension)
    pub extended_key_usage: Option<ExtendedKeyUsage>,
}

impl CaConfig {
    /// Create root CA config with defaults
    pub fn root(common_name: impl Into<String>, algorithm: AlgorithmId) -> Self {
        Self {
            ca_type: CaType::Root,
            algorithm,
            subject: NameBuilder::new(common_name).build(),
            validity: Validity::ca_default(),
            path_length: None,
            cdp_urls: Vec::new(),
            aia_ocsp_urls: Vec::new(),
            aia_ca_issuer_urls: Vec::new(),
            certificate_policies: None,
            extended_key_usage: None,
        }
    }

    /// Create intermediate CA config
    pub fn intermediate(common_name: impl Into<String>, algorithm: AlgorithmId) -> Self {
        Self {
            ca_type: CaType::Intermediate,
            algorithm,
            subject: NameBuilder::new(common_name).build(),
            validity: Validity::days_from_now(365 * 10), // 10 years
            path_length: Some(0), // Can only sign end-entity certs by default
            cdp_urls: Vec::new(),
            aia_ocsp_urls: Vec::new(),
            aia_ca_issuer_urls: Vec::new(),
            certificate_policies: None,
            extended_key_usage: None,
        }
    }

    /// Set full subject DN
    pub fn with_subject(mut self, subject: DistinguishedName) -> Self {
        self.subject = subject;
        self
    }

    /// Set validity period
    pub fn with_validity(mut self, validity: Validity) -> Self {
        self.validity = validity;
        self
    }

    /// Set path length constraint
    pub fn with_path_length(mut self, path_length: Option<u8>) -> Self {
        self.path_length = path_length;
        self
    }

    /// Set CRL Distribution Point URLs
    pub fn with_cdp_urls(mut self, urls: Vec<String>) -> Self {
        self.cdp_urls = urls;
        self
    }

    /// Set Authority Information Access URLs
    pub fn with_aia(mut self, ocsp_urls: Vec<String>, ca_issuer_urls: Vec<String>) -> Self {
        self.aia_ocsp_urls = ocsp_urls;
        self.aia_ca_issuer_urls = ca_issuer_urls;
        self
    }

    /// Set certificate policies (overrides default evaluation policy)
    pub fn with_certificate_policies(mut self, policies: CertificatePolicies) -> Self {
        self.certificate_policies = Some(policies);
        self
    }

    /// Set extended key usage
    pub fn with_extended_key_usage(mut self, eku: ExtendedKeyUsage) -> Self {
        self.extended_key_usage = Some(eku);
        self
    }
}

/// Result of CA initialization
#[derive(Debug)]
pub struct InitializedCa {
    /// The initialized CA
    pub ca: CertificateAuthority,
    /// CA certificate in PEM format
    pub certificate_pem: String,
    /// CA certificate in DER format
    pub certificate_der: Vec<u8>,
    /// Private key in PEM format (for secure storage)
    pub private_key_pem: Zeroizing<String>,
}

/// Result of generating a subordinate CA CSR for offline signing
#[derive(Debug)]
pub struct SubordinateCsr {
    /// CSR in PEM format (to transfer to offline root)
    pub csr_pem: String,
    /// CSR in DER format
    pub csr_der: Vec<u8>,
    /// Private key in PEM format (keep secret on subordinate machine)
    pub private_key_pem: Zeroizing<String>,
    /// Private key in DER format
    pub private_key_der: Zeroizing<Vec<u8>>,
    /// Algorithm used for key generation
    pub algorithm: AlgorithmId,
    /// Subject DN requested
    pub subject: DistinguishedName,
}

/// CA Initialization Ceremony
pub struct CaCeremony;

impl CaCeremony {
    /// Initialize a new Root CA
    ///
    /// This generates a new key pair and self-signed certificate.
    pub fn init_root(config: CaConfig) -> Result<InitializedCa> {
        if config.ca_type != CaType::Root {
            return Err(Error::PolicyViolation(
                "Use init_root only for Root CAs".into(),
            ));
        }

        // Generate key pair
        let key_pair = KeyPair::generate(config.algorithm)?;

        // Build self-signed certificate
        let public_key_der = key_pair.public_key_der()?;

        let basic_constraints = match config.path_length {
            Some(len) => BasicConstraints::ca_with_path_len(len),
            None => BasicConstraints::ca(),
        };

        // Compute subject key ID for SPORK extension (self-signed, so CA ID is derived from own key)
        let ski = digest::sha256(&public_key_der);
        let ca_id = hex::encode(&ski[..8]);

        let mut builder =
            CertificateBuilder::new(config.subject.clone(), public_key_der, config.algorithm)
                .serial(SerialNumber::sequential(1))
                .validity(config.validity)
                .basic_constraints(basic_constraints)
                .key_usage(KeyUsage::new(KeyUsageFlags::ca_default()))
                .spork_issuance_info(SporkIssuanceInfo::new(ca_id))
                .certificate_policies(
                    config
                        .certificate_policies
                        .unwrap_or_else(CertificatePolicies::evaluation),
                );

        if !config.cdp_urls.is_empty() {
            let mut cdp = CrlDistributionPoints::new();
            for url in &config.cdp_urls {
                cdp = cdp.url(url);
            }
            builder = builder.crl_distribution_points(cdp);
        }

        if !config.aia_ocsp_urls.is_empty() || !config.aia_ca_issuer_urls.is_empty() {
            let mut aia = AuthorityInfoAccess::new();
            for url in &config.aia_ocsp_urls {
                aia = aia.ocsp(url);
            }
            for url in &config.aia_ca_issuer_urls {
                aia = aia.ca_issuer(url);
            }
            builder = builder.authority_info_access(aia);
        }

        if let Some(eku) = config.extended_key_usage {
            builder = builder.extended_key_usage(eku);
        }

        let certificate = builder.build_and_sign(&key_pair)?;

        let certificate_der = encode_certificate_der(&certificate)?;
        let certificate_pem = encode_certificate_pem(&certificate)?;
        let private_key_der = key_pair.private_key_der()?;
        let private_key_pem = key_pair.private_key_pem()?;

        let ca = CertificateAuthority::load(
            CaType::Root,
            certificate_der.clone(),
            private_key_der.to_vec(),
            config.algorithm,
            1, // Serial 1 used for CA cert
        )?;

        Ok(InitializedCa {
            ca,
            certificate_pem,
            certificate_der,
            private_key_pem,
        })
    }

    /// Initialize an Intermediate CA
    ///
    /// This generates a new key pair and CSR to be signed by a parent CA,
    /// or if parent_ca is provided, directly signs with the parent.
    pub fn init_intermediate(
        config: CaConfig,
        parent_ca: &mut CertificateAuthority,
    ) -> Result<InitializedCa> {
        if config.ca_type != CaType::Intermediate {
            return Err(Error::PolicyViolation(
                "Use init_intermediate only for Intermediate CAs".into(),
            ));
        }

        // Generate key pair for intermediate
        let key_pair = KeyPair::generate(config.algorithm)?;
        let public_key_der = key_pair.public_key_der()?;

        let basic_constraints = match config.path_length {
            Some(len) => BasicConstraints::ca_with_path_len(len),
            None => BasicConstraints::ca(),
        };

        // CA ID for SPORK extension is derived from parent's subject_key_id
        let ca_id = hex::encode(&parent_ca.subject_key_id[..8.min(parent_ca.subject_key_id.len())]);

        // Build certificate signed by parent
        let mut builder =
            CertificateBuilder::new(config.subject.clone(), public_key_der, config.algorithm)
                .serial(parent_ca.next_serial())
                .validity(config.validity)
                .issuer(parent_ca_subject_to_dn(parent_ca.subject())?)
                .basic_constraints(basic_constraints)
                .key_usage(KeyUsage::new(KeyUsageFlags::ca_default()))
                .authority_key_identifier(parent_ca.subject_key_id.clone())
                .spork_issuance_info(SporkIssuanceInfo::new(ca_id))
                .certificate_policies(
                    config
                        .certificate_policies
                        .unwrap_or_else(CertificatePolicies::evaluation),
                );

        if !config.cdp_urls.is_empty() {
            let mut cdp = CrlDistributionPoints::new();
            for url in &config.cdp_urls {
                cdp = cdp.url(url);
            }
            builder = builder.crl_distribution_points(cdp);
        }

        if !config.aia_ocsp_urls.is_empty() || !config.aia_ca_issuer_urls.is_empty() {
            let mut aia = AuthorityInfoAccess::new();
            for url in &config.aia_ocsp_urls {
                aia = aia.ocsp(url);
            }
            for url in &config.aia_ca_issuer_urls {
                aia = aia.ca_issuer(url);
            }
            builder = builder.authority_info_access(aia);
        }

        if let Some(eku) = config.extended_key_usage {
            builder = builder.extended_key_usage(eku);
        }

        let certificate = builder.build_and_sign_with_signer(parent_ca.signer())?;

        let certificate_der = encode_certificate_der(&certificate)?;
        let certificate_pem = encode_certificate_pem(&certificate)?;
        let private_key_der = key_pair.private_key_der()?;
        let private_key_pem = key_pair.private_key_pem()?;

        let ca = CertificateAuthority::load(
            CaType::Intermediate,
            certificate_der.clone(),
            private_key_der.to_vec(),
            config.algorithm,
            0, // Start serial at 0 for new CA
        )?;

        Ok(InitializedCa {
            ca,
            certificate_pem,
            certificate_der,
            private_key_pem,
        })
    }

    /// Generate a key pair and CSR for a subordinate CA (offline workflow)
    ///
    /// This is step 1 of the offline root ceremony:
    /// 1. Generate subordinate key pair + CSR on the subordinate machine
    /// 2. Transfer CSR to the offline root machine
    /// 3. Root signs the CSR via `CertificateAuthority::sign_subordinate_csr()`
    /// 4. Transfer signed certificate back
    /// 5. Import via `import_signed_certificate()`
    pub fn generate_subordinate_csr(config: CaConfig) -> Result<SubordinateCsr> {
        if config.ca_type != CaType::Intermediate {
            return Err(Error::PolicyViolation(
                "generate_subordinate_csr is for Intermediate CAs only".into(),
            ));
        }

        // Generate key pair
        let key_pair = KeyPair::generate(config.algorithm)?;
        let private_key_pem = key_pair.private_key_pem()?;
        let private_key_der = key_pair.private_key_der()?;

        // Build and sign CSR
        let csr = crate::cert::CsrBuilder::new(config.subject.clone()).build_and_sign(&key_pair)?;

        let csr_pem = csr.to_pem();
        let csr_der = csr.der.clone();

        Ok(SubordinateCsr {
            csr_pem,
            csr_der,
            private_key_pem,
            private_key_der: Zeroizing::new(private_key_der.to_vec()),
            algorithm: config.algorithm,
            subject: config.subject,
        })
    }

    /// Import a signed certificate to complete subordinate CA initialization (offline workflow)
    ///
    /// This is step 5 of the offline root ceremony. Takes the subordinate's
    /// private key material (from `generate_subordinate_csr`) and the certificate
    /// signed by the offline root, and produces a fully initialized CA.
    pub fn import_signed_certificate(
        subordinate: SubordinateCsr,
        signed_cert_der: Vec<u8>,
    ) -> Result<InitializedCa> {
        use crate::cert::{encode_certificate_pem, parse_certificate_der};

        // Verify the certificate is valid DER
        let certificate = parse_certificate_der(&signed_cert_der)?;

        // Verify the certificate's public key matches our CSR's key pair
        let key_pair =
            KeyPair::from_pkcs8_der(subordinate.algorithm, &subordinate.private_key_der)?;
        let our_public_key = key_pair.public_key_der()?;
        let cert_spki = certificate
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| Error::Encoding(e.to_string()))?;

        if our_public_key != cert_spki {
            return Err(Error::InvalidCertificate(
                "Certificate public key does not match subordinate key pair".into(),
            ));
        }

        let certificate_pem = encode_certificate_pem(&certificate)?;

        let ca = CertificateAuthority::load(
            CaType::Intermediate,
            signed_cert_der.clone(),
            subordinate.private_key_der.to_vec(),
            subordinate.algorithm,
            0, // Start serial at 0 for new CA
        )?;

        Ok(InitializedCa {
            ca,
            certificate_pem,
            certificate_der: signed_cert_der,
            private_key_pem: subordinate.private_key_pem,
        })
    }
}

/// Convert X.509 Name to DistinguishedName
fn parent_ca_subject_to_dn(name: &x509_cert::name::Name) -> Result<DistinguishedName> {
    DistinguishedName::from_x509_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_ca_init() {
        let config = CaConfig::root("SPORK Test Root CA", AlgorithmId::EcdsaP256).with_subject(
            NameBuilder::new("SPORK Test Root CA")
                .organization("SPORK Project")
                .country("US")
                .build(),
        );

        let result = CaCeremony::init_root(config).unwrap();

        assert!(result.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(result.private_key_pem.contains("BEGIN PRIVATE KEY"));
        assert_eq!(result.ca.ca_type, CaType::Root);
    }

    #[test]
    fn test_intermediate_ca_init() {
        // First create root
        let root_config = CaConfig::root("Test Root", AlgorithmId::EcdsaP256);
        let mut root = CaCeremony::init_root(root_config).unwrap();

        // Then create intermediate
        let int_config = CaConfig::intermediate("Test Intermediate", AlgorithmId::EcdsaP256);
        let intermediate = CaCeremony::init_intermediate(int_config, &mut root.ca).unwrap();

        assert_eq!(intermediate.ca.ca_type, CaType::Intermediate);
    }

    #[test]
    #[cfg(all(feature = "pqc", not(feature = "fips")))] // ML-DSA not yet FIPS 140-3 validated
    fn test_pqc_root_ca() {
        let config = CaConfig::root("PQC Test Root", AlgorithmId::MlDsa65);
        let result = CaCeremony::init_root(config).unwrap();

        assert!(result.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(result.ca.algorithm, AlgorithmId::MlDsa65);
    }

    #[test]
    fn test_offline_subordinate_workflow() {
        // Step 1: Generate subordinate CSR (on subordinate machine)
        let sub_config = CaConfig::intermediate("Offline Sub CA", AlgorithmId::EcdsaP256)
            .with_subject(
                NameBuilder::new("Offline Sub CA")
                    .organization("Test Org")
                    .country("US")
                    .build(),
            );
        let subordinate_csr = CaCeremony::generate_subordinate_csr(sub_config).unwrap();

        assert!(subordinate_csr.csr_pem.contains("CERTIFICATE REQUEST"));
        assert!(subordinate_csr
            .private_key_pem
            .contains("BEGIN PRIVATE KEY"));
        assert_eq!(subordinate_csr.algorithm, AlgorithmId::EcdsaP256);

        // Step 2: Create offline root (on air-gapped machine)
        let root_config = CaConfig::root("Offline Root CA", AlgorithmId::EcdsaP256).with_subject(
            NameBuilder::new("Offline Root CA")
                .organization("Test Org")
                .country("US")
                .build(),
        );
        let mut root = CaCeremony::init_root(root_config).unwrap();

        // Step 3: Root signs the subordinate CSR
        let signed = root
            .ca
            .sign_subordinate_csr(
                &subordinate_csr.csr_der,
                Validity::days_from_now(365 * 10),
                Some(0),
            )
            .unwrap();

        assert!(signed.pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(signed.subject_cn, "Offline Sub CA");

        // Step 4: Import signed cert back into subordinate CA
        let initialized =
            CaCeremony::import_signed_certificate(subordinate_csr, signed.der).unwrap();

        assert_eq!(initialized.ca.ca_type, CaType::Intermediate);
        assert!(initialized.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(initialized.private_key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_generate_csr_rejects_root_type() {
        let config = CaConfig::root("Bad Root", AlgorithmId::EcdsaP256);
        let result = CaCeremony::generate_subordinate_csr(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_import_rejects_mismatched_key() {
        // Generate a CSR
        let sub_config = CaConfig::intermediate("Sub CA", AlgorithmId::EcdsaP256);
        let subordinate_csr = CaCeremony::generate_subordinate_csr(sub_config).unwrap();

        // Create a root and issue a cert for a DIFFERENT key
        let root_config = CaConfig::root("Root CA", AlgorithmId::EcdsaP256);
        let mut root = CaCeremony::init_root(root_config).unwrap();

        // Create a different intermediate (different key pair)
        let other_config = CaConfig::intermediate("Other CA", AlgorithmId::EcdsaP256);
        let other = CaCeremony::init_intermediate(other_config, &mut root.ca).unwrap();

        // Try to import other's cert with our CSR's key — should fail
        let result = CaCeremony::import_signed_certificate(subordinate_csr, other.certificate_der);
        assert!(result.is_err());
    }

    #[test]
    fn test_root_ca_with_extensions() {
        use crate::cert::extensions::oid as ext_oid;

        let config = CaConfig::root("Test Root With Extensions", AlgorithmId::EcdsaP256)
            .with_cdp_urls(vec!["http://crl.example.com/root.crl".to_string()])
            .with_aia(
                vec!["http://ocsp.example.com".to_string()],
                vec!["http://ca.example.com/root.cer".to_string()],
            )
            .with_extended_key_usage(ExtendedKeyUsage::tls_server_client());

        let result = CaCeremony::init_root(config).unwrap();
        assert!(result.certificate_pem.contains("BEGIN CERTIFICATE"));

        // Parse the DER to verify extensions are present
        let cert = crate::cert::parse_certificate_der(&result.certificate_der).unwrap();
        let extensions = cert.tbs_certificate.extensions.as_ref().unwrap();

        // Check that CDP extension is present (OID 2.5.29.31)
        let has_cdp = extensions
            .iter()
            .any(|ext| ext.extn_id == ext_oid::CRL_DISTRIBUTION_POINTS);
        assert!(
            has_cdp,
            "Certificate should have CRL Distribution Points extension"
        );

        // Check that AIA extension is present (OID 1.3.6.1.5.5.7.1.1)
        let has_aia = extensions
            .iter()
            .any(|ext| ext.extn_id == ext_oid::AUTHORITY_INFO_ACCESS);
        assert!(
            has_aia,
            "Certificate should have Authority Information Access extension"
        );

        // Check that EKU extension is present (OID 2.5.29.37)
        let has_eku = extensions
            .iter()
            .any(|ext| ext.extn_id == ext_oid::EXTENDED_KEY_USAGE);
        assert!(
            has_eku,
            "Certificate should have Extended Key Usage extension"
        );
    }

    #[test]
    fn test_intermediate_ca_with_extensions() {
        use crate::cert::extensions::oid as ext_oid;

        // Create root first
        let root_config = CaConfig::root("Extension Test Root", AlgorithmId::EcdsaP256);
        let mut root = CaCeremony::init_root(root_config).unwrap();

        // Create intermediate with CDP and AIA but no EKU
        let int_config =
            CaConfig::intermediate("Extension Test Intermediate", AlgorithmId::EcdsaP256)
                .with_cdp_urls(vec!["http://crl.example.com/intermediate.crl".to_string()])
                .with_aia(
                    vec!["http://ocsp.example.com/intermediate".to_string()],
                    vec!["http://ca.example.com/root.cer".to_string()],
                );

        let intermediate = CaCeremony::init_intermediate(int_config, &mut root.ca).unwrap();
        assert!(intermediate.certificate_pem.contains("BEGIN CERTIFICATE"));

        // Parse and verify extensions
        let cert = crate::cert::parse_certificate_der(&intermediate.certificate_der).unwrap();
        let extensions = cert.tbs_certificate.extensions.as_ref().unwrap();

        let has_cdp = extensions
            .iter()
            .any(|ext| ext.extn_id == ext_oid::CRL_DISTRIBUTION_POINTS);
        assert!(has_cdp, "Intermediate cert should have CDP extension");

        let has_aia = extensions
            .iter()
            .any(|ext| ext.extn_id == ext_oid::AUTHORITY_INFO_ACCESS);
        assert!(has_aia, "Intermediate cert should have AIA extension");

        // EKU not set, so it should NOT be present
        let has_eku = extensions
            .iter()
            .any(|ext| ext.extn_id == ext_oid::EXTENDED_KEY_USAGE);
        assert!(
            !has_eku,
            "Intermediate cert should NOT have EKU when not configured"
        );
    }
}
