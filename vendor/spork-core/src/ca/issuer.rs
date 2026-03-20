//! Certificate Issuance
//!
//! Issue certificates from CSRs with policy enforcement

use der::Encode;
use x509_cert::Certificate;

use crate::algo::AlgorithmId;
use crate::cert::extensions::{
    AuthorityInfoAccess, BasicConstraints, CertificatePolicies, CrlDistributionPoints,
    ExtendedKeyUsage, KeyUsage, KeyUsageFlags, SporkIssuanceInfo, SubjectAltName,
};
use crate::cert::{
    encode_certificate_der, encode_certificate_pem, CertificateBuilder, CertificateRequest,
    DistinguishedName, Validity,
};
use crate::error::{Error, Result};

use super::CertificateAuthority;

/// Certificate profile (determines extensions)
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CertificateProfile {
    /// TLS server certificate
    TlsServer,
    /// TLS client certificate
    TlsClient,
    /// TLS server + client
    TlsServerClient,
    /// Code signing
    CodeSigning,
    /// Email (S/MIME)
    Email,
    /// OCSP responder
    OcspResponder,
    /// Subordinate CA
    SubordinateCa,
    /// Custom (no automatic extensions)
    Custom,
}

impl CertificateProfile {
    fn key_usage(&self, algorithm: &crate::algo::AlgorithmId) -> KeyUsageFlags {
        match self {
            Self::TlsServer => KeyUsageFlags::tls_server(),
            Self::TlsClient => KeyUsageFlags::tls_client(),
            Self::TlsServerClient => KeyUsageFlags::new(
                KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_ENCIPHERMENT,
            ),
            Self::CodeSigning => KeyUsageFlags::code_signing(),
            Self::Email => {
                // RFC 8551 §3.2: RSA uses keyEncipherment; EC uses keyAgreement
                let enc_bit = if algorithm.is_rsa() {
                    KeyUsageFlags::KEY_ENCIPHERMENT
                } else {
                    KeyUsageFlags::KEY_AGREEMENT
                };
                KeyUsageFlags::new(
                    KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::NON_REPUDIATION | enc_bit,
                )
            }
            Self::OcspResponder => KeyUsageFlags::new(KeyUsageFlags::DIGITAL_SIGNATURE),
            Self::SubordinateCa => KeyUsageFlags::ca_default(),
            Self::Custom => KeyUsageFlags::empty(),
        }
    }

    fn extended_key_usage(&self) -> Option<ExtendedKeyUsage> {
        match self {
            Self::TlsServer => Some(ExtendedKeyUsage::tls_server()),
            Self::TlsClient => Some(ExtendedKeyUsage::tls_client()),
            Self::TlsServerClient => Some(ExtendedKeyUsage::tls_server_client()),
            Self::CodeSigning => Some(ExtendedKeyUsage::code_signing()),
            Self::Email => Some(ExtendedKeyUsage::new(vec![
                crate::cert::extensions::oid::EKU_EMAIL_PROTECTION,
            ])),
            Self::OcspResponder => Some(ExtendedKeyUsage::new(vec![
                crate::cert::extensions::oid::EKU_OCSP_SIGNING,
            ])),
            Self::SubordinateCa => None, // CAs don't need EKU
            Self::Custom => None,
        }
    }

    fn basic_constraints(&self) -> Option<BasicConstraints> {
        match self {
            Self::SubordinateCa => Some(BasicConstraints::ca_with_path_len(0)),
            _ => Some(BasicConstraints::end_entity()),
        }
    }
}

/// Certificate issuance request
#[derive(Debug)]
pub struct IssuanceRequest {
    /// CSR to sign
    pub csr: CertificateRequest,
    /// Certificate profile
    pub profile: CertificateProfile,
    /// Validity period (default: 1 year)
    pub validity: Validity,
    /// Subject Alternative Names
    pub san: Option<SubjectAltName>,
    /// Override subject from CSR
    pub subject_override: Option<DistinguishedName>,
}

impl IssuanceRequest {
    /// Create from CSR with profile
    pub fn new(csr: CertificateRequest, profile: CertificateProfile) -> Self {
        Self {
            csr,
            profile,
            validity: Validity::ee_default(),
            san: None,
            subject_override: None,
        }
    }

    /// Set validity period
    pub fn with_validity(mut self, validity: Validity) -> Self {
        self.validity = validity;
        self
    }

    /// Set Subject Alternative Name
    pub fn with_san(mut self, san: SubjectAltName) -> Self {
        self.san = Some(san);
        self
    }

    /// Override subject DN
    pub fn with_subject(mut self, subject: DistinguishedName) -> Self {
        self.subject_override = Some(subject);
        self
    }
}

/// Issued certificate with metadata
#[derive(Debug)]
pub struct IssuedCertificate {
    /// Certificate
    pub certificate: Certificate,
    /// DER encoding
    pub der: Vec<u8>,
    /// PEM encoding
    pub pem: String,
    /// Serial number (hex)
    pub serial_hex: String,
    /// Subject CN
    pub subject_cn: String,
    /// Issuer CN
    pub issuer_cn: String,
    /// Not before
    pub not_before: chrono::DateTime<chrono::Utc>,
    /// Not after
    pub not_after: chrono::DateTime<chrono::Utc>,
    /// Profile used
    pub profile: CertificateProfile,
}

impl CertificateAuthority {
    /// Verify the CA certificate is currently valid (not expired, not before notBefore)
    fn check_ca_validity(&self) -> Result<()> {
        let validity = &self.certificate.tbs_certificate.validity;
        let now = der::DateTime::new(
            chrono::Utc::now()
                .format("%Y")
                .to_string()
                .parse()
                .unwrap_or(2026),
            chrono::Utc::now()
                .format("%m")
                .to_string()
                .parse()
                .unwrap_or(1),
            chrono::Utc::now()
                .format("%d")
                .to_string()
                .parse()
                .unwrap_or(1),
            chrono::Utc::now()
                .format("%H")
                .to_string()
                .parse()
                .unwrap_or(0),
            chrono::Utc::now()
                .format("%M")
                .to_string()
                .parse()
                .unwrap_or(0),
            chrono::Utc::now()
                .format("%S")
                .to_string()
                .parse()
                .unwrap_or(0),
        )
        .map_err(|e| Error::InvalidCertificate(format!("Failed to create current time: {e}")))?;

        let not_before = match &validity.not_before {
            x509_cert::time::Time::UtcTime(t) => t.to_date_time(),
            x509_cert::time::Time::GeneralTime(t) => t.to_date_time(),
        };
        let not_after = match &validity.not_after {
            x509_cert::time::Time::UtcTime(t) => t.to_date_time(),
            x509_cert::time::Time::GeneralTime(t) => t.to_date_time(),
        };

        if now < not_before {
            return Err(Error::InvalidCertificate(
                "CA certificate is not yet valid (notBefore is in the future)".into(),
            ));
        }
        if now > not_after {
            return Err(Error::InvalidCertificate(
                "CA certificate has expired — cannot issue certificates".into(),
            ));
        }
        Ok(())
    }

    /// Issue a certificate from a CSR
    pub fn issue_certificate(&mut self, request: IssuanceRequest) -> Result<IssuedCertificate> {
        // RFC 5280 §6.1.1(c): Verify CA certificate is not expired
        self.check_ca_validity()?;

        // Verify CSR signature
        if !request.csr.verify_signature()? {
            return Err(Error::InvalidCsr(
                "CSR signature verification failed".into(),
            ));
        }

        // Get subject from CSR or override
        let subject = if let Some(subj) = request.subject_override {
            subj
        } else {
            csr_subject_to_dn(request.csr.subject())?
        };

        // Get public key from CSR
        let public_key_der = request
            .csr
            .public_key_info()
            .to_der()
            .map_err(|e| Error::Encoding(e.to_string()))?;

        // Detect algorithm
        let algorithm = request.csr.detect_algorithm()?;

        // Get CA's issuer DN
        let issuer_dn = parent_ca_subject_to_dn(self.subject())?;

        // Build certificate
        let mut builder = CertificateBuilder::new(subject.clone(), public_key_der, algorithm)
            .serial(self.next_serial())
            .validity(request.validity.clone())
            .issuer(issuer_dn)
            .authority_key_identifier(self.subject_key_id.clone());

        // Apply profile extensions
        if let Some(bc) = request.profile.basic_constraints() {
            builder = builder.basic_constraints(bc);
        }

        let ku = request.profile.key_usage(&algorithm);
        if !ku.is_empty() {
            builder = builder.key_usage(KeyUsage::new(ku));
        }

        if let Some(eku) = request.profile.extended_key_usage() {
            builder = builder.extended_key_usage(eku);
        }

        // Add SAN if provided
        if let Some(san) = request.san {
            builder = builder.subject_alt_name(san);
        }

        // Add CRL Distribution Point if configured
        if let Some(ref cdp_url) = self.cdp_url {
            let cdp = CrlDistributionPoints::with_url(cdp_url);
            builder = builder.crl_distribution_points(cdp);
        }

        // Add Authority Information Access if configured
        if let Some(ref aia_base_url) = self.aia_base_url {
            let base = aia_base_url.trim_end_matches('/');
            let ocsp_url = format!("{}/ocsp", base);
            // Use the CA's CN for the issuer cert filename
            let ca_cn = extract_cn(self.subject()).unwrap_or_else(|_| "ca".to_string());
            let ca_issuer_url = format!("{}/{}.crt", base, ca_cn.replace(' ', "-"));
            let aia = AuthorityInfoAccess::new()
                .ocsp(ocsp_url)
                .ca_issuer(ca_issuer_url);
            builder = builder.authority_info_access(aia);
        }

        // Add SPORK Issuance Info extension (CA ID = first 8 bytes of subject_key_id as hex)
        let ca_id = hex::encode(&self.subject_key_id[..8.min(self.subject_key_id.len())]);
        builder = builder.spork_issuance_info(SporkIssuanceInfo::new(ca_id));

        // Mark all issued certs with Development/Evaluation policy
        builder = builder.certificate_policies(CertificatePolicies::evaluation());

        // Sign with CA signer (supports both in-memory and external key stores)
        let certificate = builder.build_and_sign_with_signer(self.signer())?;

        let der = encode_certificate_der(&certificate)?;
        let pem = encode_certificate_pem(&certificate)?;

        // Extract metadata
        let serial_hex = hex::encode(certificate.tbs_certificate.serial_number.as_bytes());
        let subject_cn = subject.common_name.clone();
        let issuer_cn = extract_cn(self.subject())?;

        Ok(IssuedCertificate {
            certificate,
            der,
            pem,
            serial_hex,
            subject_cn,
            issuer_cn,
            not_before: request.validity.not_before,
            not_after: request.validity.not_after,
            profile: request.profile,
        })
    }

    /// Issue a certificate directly (without CSR)
    ///
    /// Generates key pair and certificate in one step.
    pub fn issue_direct(
        &mut self,
        subject: DistinguishedName,
        algorithm: AlgorithmId,
        profile: CertificateProfile,
        validity: Validity,
        san: Option<SubjectAltName>,
    ) -> Result<(IssuedCertificate, zeroize::Zeroizing<String>)> {
        use crate::algo::KeyPair;

        // RFC 5280 §6.1.1(c): Verify CA certificate is not expired
        self.check_ca_validity()?;

        // Generate key pair
        let key_pair = KeyPair::generate(algorithm)?;
        let public_key_der = key_pair.public_key_der()?;
        let private_key_pem = key_pair.private_key_pem()?;

        // Get CA's issuer DN
        let issuer_dn = parent_ca_subject_to_dn(self.subject())?;

        // Build certificate
        let mut builder = CertificateBuilder::new(subject.clone(), public_key_der, algorithm)
            .serial(self.next_serial())
            .validity(validity.clone())
            .issuer(issuer_dn)
            .authority_key_identifier(self.subject_key_id.clone());

        // Apply profile extensions
        if let Some(bc) = profile.basic_constraints() {
            builder = builder.basic_constraints(bc);
        }

        let ku = profile.key_usage(&algorithm);
        if !ku.is_empty() {
            builder = builder.key_usage(KeyUsage::new(ku));
        }

        if let Some(eku) = profile.extended_key_usage() {
            builder = builder.extended_key_usage(eku);
        }

        if let Some(san) = san {
            builder = builder.subject_alt_name(san);
        }

        // Add CRL Distribution Point if configured
        if let Some(ref cdp_url) = self.cdp_url {
            let cdp = CrlDistributionPoints::with_url(cdp_url);
            builder = builder.crl_distribution_points(cdp);
        }

        // Add Authority Information Access if configured
        if let Some(ref aia_base_url) = self.aia_base_url {
            let base = aia_base_url.trim_end_matches('/');
            let ocsp_url = format!("{}/ocsp", base);
            let ca_cn = extract_cn(self.subject()).unwrap_or_else(|_| "ca".to_string());
            let ca_issuer_url = format!("{}/{}.crt", base, ca_cn.replace(' ', "-"));
            let aia = AuthorityInfoAccess::new()
                .ocsp(ocsp_url)
                .ca_issuer(ca_issuer_url);
            builder = builder.authority_info_access(aia);
        }

        // Add SPORK Issuance Info extension (CA ID = first 8 bytes of subject_key_id as hex)
        let ca_id = hex::encode(&self.subject_key_id[..8.min(self.subject_key_id.len())]);
        builder = builder.spork_issuance_info(SporkIssuanceInfo::new(ca_id));

        // Sign with CA signer (supports both in-memory and external key stores)
        let certificate = builder.build_and_sign_with_signer(self.signer())?;

        let der = encode_certificate_der(&certificate)?;
        let pem = encode_certificate_pem(&certificate)?;

        let serial_hex = hex::encode(certificate.tbs_certificate.serial_number.as_bytes());
        let subject_cn = subject.common_name.clone();
        let issuer_cn = extract_cn(self.subject())?;

        let issued = IssuedCertificate {
            certificate,
            der,
            pem,
            serial_hex,
            subject_cn,
            issuer_cn,
            not_before: validity.not_before,
            not_after: validity.not_after,
            profile,
        };

        Ok((issued, private_key_pem))
    }
}

impl CertificateAuthority {
    /// Sign a subordinate CA's CSR (offline root ceremony)
    ///
    /// This is step 3 of the offline root ceremony. The root CA signs
    /// the subordinate's CSR, producing a CA certificate.
    ///
    /// The CSR signature is verified before signing.
    pub fn sign_subordinate_csr(
        &mut self,
        csr_der: &[u8],
        validity: Validity,
        path_length: Option<u8>,
    ) -> Result<IssuedCertificate> {
        // RFC 5280 §6.1.1(c): Verify CA certificate is not expired
        self.check_ca_validity()?;

        let csr = CertificateRequest::from_der(csr_der)?;

        // Verify CSR signature (proof of possession)
        if !csr.verify_signature()? {
            return Err(Error::InvalidCsr(
                "CSR signature verification failed".into(),
            ));
        }

        // Extract subject and public key from CSR
        let subject = csr_subject_to_dn(csr.subject())?;
        let public_key_der = csr
            .public_key_info()
            .to_der()
            .map_err(|e| Error::Encoding(e.to_string()))?;
        let algorithm = csr.detect_algorithm()?;

        // Get CA's issuer DN
        let issuer_dn = parent_ca_subject_to_dn(self.subject())?;

        // Build subordinate CA certificate
        let basic_constraints = match path_length {
            Some(len) => BasicConstraints::ca_with_path_len(len),
            None => BasicConstraints::ca(),
        };

        let ca_id = hex::encode(&self.subject_key_id[..8.min(self.subject_key_id.len())]);

        let mut builder = CertificateBuilder::new(subject.clone(), public_key_der, algorithm)
            .serial(self.next_serial())
            .validity(validity.clone())
            .issuer(issuer_dn)
            .basic_constraints(basic_constraints)
            .key_usage(KeyUsage::new(KeyUsageFlags::ca_default()))
            .authority_key_identifier(self.subject_key_id.clone())
            .spork_issuance_info(SporkIssuanceInfo::new(ca_id))
            .certificate_policies(CertificatePolicies::evaluation());

        // Add CRL Distribution Point if configured on parent
        if let Some(ref cdp_url) = self.cdp_url {
            builder = builder.crl_distribution_points(CrlDistributionPoints::with_url(cdp_url));
        }

        // Add AIA if configured on parent
        if let Some(ref aia_base_url) = self.aia_base_url {
            let base = aia_base_url.trim_end_matches('/');
            let ocsp_url = format!("{}/ocsp", base);
            let ca_cn = extract_cn(self.subject()).unwrap_or_else(|_| "ca".to_string());
            let ca_issuer_url = format!("{}/{}.crt", base, ca_cn.replace(' ', "-"));
            let aia = AuthorityInfoAccess::new()
                .ocsp(ocsp_url)
                .ca_issuer(ca_issuer_url);
            builder = builder.authority_info_access(aia);
        }

        // Sign with CA signer (supports both in-memory and external key stores)
        let certificate = builder.build_and_sign_with_signer(self.signer())?;

        let der = encode_certificate_der(&certificate)?;
        let pem = encode_certificate_pem(&certificate)?;

        let serial_hex = hex::encode(certificate.tbs_certificate.serial_number.as_bytes());
        let subject_cn = subject.common_name.clone();
        let issuer_cn = extract_cn(self.subject())?;

        Ok(IssuedCertificate {
            certificate,
            der,
            pem,
            serial_hex,
            subject_cn,
            issuer_cn,
            not_before: validity.not_before,
            not_after: validity.not_after,
            profile: CertificateProfile::SubordinateCa,
        })
    }

    /// Cross-certify a foreign CA's certificate
    ///
    /// Creates a new certificate with the same subject and public key as the
    /// foreign CA, but issued by this CA. This creates a trust bridge between
    /// two PKI hierarchies.
    ///
    /// The resulting cross-certificate allows relying parties that trust this CA
    /// to also validate certificates issued under the foreign CA's hierarchy.
    pub fn cross_certify(
        &mut self,
        foreign_ca_cert_der: &[u8],
        validity: Validity,
        path_length: Option<u8>,
    ) -> Result<IssuedCertificate> {
        use crate::cert::parse_certificate_der;

        // RFC 5280 §6.1.1(c): Verify CA certificate is not expired
        self.check_ca_validity()?;

        let foreign_cert = parse_certificate_der(foreign_ca_cert_der)?;

        // Extract raw subject Name and public key from foreign certificate.
        // We use the raw Name directly to preserve the exact RDN structure
        // (e.g., multiple OU attributes that DistinguishedName can't represent).
        let raw_subject_name = foreign_cert.tbs_certificate.subject.clone();
        let subject = parent_ca_subject_to_dn(&foreign_cert.tbs_certificate.subject)?;
        let public_key_der = foreign_cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| Error::Encoding(e.to_string()))?;

        // Detect algorithm from the foreign cert's SPKI
        let foreign_alg_oid = foreign_cert
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid;
        let algorithm = spki_oid_to_algorithm(&foreign_alg_oid)?;

        // Get CA's issuer DN
        let issuer_dn = parent_ca_subject_to_dn(self.subject())?;

        let basic_constraints = match path_length {
            Some(len) => BasicConstraints::ca_with_path_len(len),
            None => BasicConstraints::ca(),
        };

        let ca_id = hex::encode(&self.subject_key_id[..8.min(self.subject_key_id.len())]);

        let mut builder = CertificateBuilder::new(subject.clone(), public_key_der, algorithm)
            .raw_subject(raw_subject_name)
            .serial(self.next_serial())
            .validity(validity.clone())
            .issuer(issuer_dn)
            .basic_constraints(basic_constraints)
            .key_usage(KeyUsage::new(KeyUsageFlags::ca_default()))
            .authority_key_identifier(self.subject_key_id.clone())
            .spork_issuance_info(SporkIssuanceInfo::new(ca_id))
            .certificate_policies(CertificatePolicies::evaluation());

        // Add CRL Distribution Point if configured
        if let Some(ref cdp_url) = self.cdp_url {
            builder = builder.crl_distribution_points(CrlDistributionPoints::with_url(cdp_url));
        }

        // Add AIA if configured
        if let Some(ref aia_base_url) = self.aia_base_url {
            let base = aia_base_url.trim_end_matches('/');
            let ocsp_url = format!("{}/ocsp", base);
            let ca_cn = extract_cn(self.subject()).unwrap_or_else(|_| "ca".to_string());
            let ca_issuer_url = format!("{}/{}.crt", base, ca_cn.replace(' ', "-"));
            let aia = AuthorityInfoAccess::new()
                .ocsp(ocsp_url)
                .ca_issuer(ca_issuer_url);
            builder = builder.authority_info_access(aia);
        }

        // Sign with CA signer (supports both in-memory and external key stores)
        let certificate = builder.build_and_sign_with_signer(self.signer())?;

        let der = encode_certificate_der(&certificate)?;
        let pem = encode_certificate_pem(&certificate)?;

        let serial_hex = hex::encode(certificate.tbs_certificate.serial_number.as_bytes());
        let subject_cn = subject.common_name.clone();
        let issuer_cn = extract_cn(self.subject())?;

        Ok(IssuedCertificate {
            certificate,
            der,
            pem,
            serial_hex,
            subject_cn,
            issuer_cn,
            not_before: validity.not_before,
            not_after: validity.not_after,
            profile: CertificateProfile::SubordinateCa,
        })
    }
}

/// Map SPKI algorithm OID to AlgorithmId
fn spki_oid_to_algorithm(oid: &const_oid::ObjectIdentifier) -> Result<AlgorithmId> {
    let oid_str = oid.to_string();
    match oid_str.as_str() {
        "1.2.840.10045.2.1" => Ok(AlgorithmId::EcdsaP256), // ecPublicKey (default P-256)
        "1.2.840.113549.1.1.1" => Ok(AlgorithmId::Rsa2048), // rsaEncryption (default 2048)
        #[cfg(feature = "pqc")]
        "2.16.840.1.101.3.4.3.17" => Ok(AlgorithmId::MlDsa44),
        #[cfg(feature = "pqc")]
        "2.16.840.1.101.3.4.3.18" => Ok(AlgorithmId::MlDsa65),
        #[cfg(feature = "pqc")]
        "2.16.840.1.101.3.4.3.19" => Ok(AlgorithmId::MlDsa87),
        #[cfg(feature = "pqc")]
        "2.16.840.1.101.3.4.3.20" => Ok(AlgorithmId::SlhDsaSha2_128s),
        #[cfg(feature = "pqc")]
        "2.16.840.1.101.3.4.3.22" => Ok(AlgorithmId::SlhDsaSha2_192s),
        #[cfg(feature = "pqc")]
        "2.16.840.1.101.3.4.3.24" => Ok(AlgorithmId::SlhDsaSha2_256s),
        #[cfg(feature = "pqc")]
        "2.16.840.1.114027.80.8.1.1" => Ok(AlgorithmId::MlDsa44EcdsaP256),
        #[cfg(feature = "pqc")]
        "2.16.840.1.114027.80.8.1.2" => Ok(AlgorithmId::MlDsa65EcdsaP256),
        #[cfg(feature = "pqc")]
        "2.16.840.1.114027.80.8.1.3" => Ok(AlgorithmId::MlDsa65EcdsaP384),
        #[cfg(feature = "pqc")]
        "2.16.840.1.114027.80.8.1.4" => Ok(AlgorithmId::MlDsa87EcdsaP384),
        _ => Err(Error::UnsupportedAlgorithm(format!(
            "Unknown SPKI algorithm OID: {}",
            oid_str
        ))),
    }
}

/// Convert CSR subject to DistinguishedName
fn csr_subject_to_dn(name: &x509_cert::name::Name) -> Result<DistinguishedName> {
    parent_ca_subject_to_dn(name)
}

/// Convert X.509 Name to DistinguishedName
fn parent_ca_subject_to_dn(name: &x509_cert::name::Name) -> Result<DistinguishedName> {
    DistinguishedName::from_x509_name(name)
}

/// Extract CN from X.509 Name
fn extract_cn(name: &x509_cert::name::Name) -> Result<String> {
    use der::{Decode, Encode};

    for rdn in name.0.iter() {
        for atav in rdn.0.iter() {
            if atav.oid.to_string() == "2.5.4.3" {
                let value_bytes = atav.value.to_der().map_err(|e| Error::Der(e.to_string()))?;
                if let Ok(s) = der::asn1::PrintableStringRef::from_der(&value_bytes) {
                    return Ok(s.to_string());
                } else if let Ok(s) = der::asn1::Utf8StringRef::from_der(&value_bytes) {
                    return Ok(s.to_string());
                }
            }
        }
    }

    Err(Error::InvalidCertificate("No CN found".into()))
}

#[cfg(test)]
#[cfg(feature = "ceremony")]
mod tests {
    use super::*;
    use crate::algo::KeyPair;
    use crate::ca::{CaCeremony, CaConfig};
    use crate::cert::{CsrBuilder, NameBuilder};

    #[test]
    fn test_issue_from_csr() {
        // Create CA
        let config = CaConfig::root("Test CA", AlgorithmId::EcdsaP256);
        let mut ca = CaCeremony::init_root(config).unwrap().ca;

        // Create CSR
        let ee_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ee_subject = NameBuilder::new("test.example.com")
            .organization("Example Inc")
            .build();
        let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

        // Issue certificate
        let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer).with_san(
            SubjectAltName::new()
                .dns("test.example.com")
                .dns("www.example.com"),
        );

        let issued = ca.issue_certificate(request).unwrap();

        assert!(issued.pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(issued.subject_cn, "test.example.com");
        assert_eq!(issued.profile, CertificateProfile::TlsServer);
    }

    #[test]
    #[cfg(feature = "ceremony")]
    fn test_issue_direct() {
        let config = CaConfig::root("Test CA", AlgorithmId::EcdsaP256);
        let mut ca = CaCeremony::init_root(config).unwrap().ca;

        let subject = NameBuilder::new("direct.example.com").build();
        let (issued, private_key) = ca
            .issue_direct(
                subject,
                AlgorithmId::EcdsaP256,
                CertificateProfile::TlsClient,
                Validity::ee_default(),
                None,
            )
            .unwrap();

        assert!(issued.pem.contains("BEGIN CERTIFICATE"));
        assert!(private_key.as_str().contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    #[cfg(all(feature = "pqc", not(feature = "fips")))] // ML-DSA not yet FIPS 140-3 validated
    fn test_issue_pqc_cert() {
        let config = CaConfig::root("PQC CA", AlgorithmId::MlDsa65);
        let mut ca = CaCeremony::init_root(config).unwrap().ca;

        let subject = NameBuilder::new("pqc.example.com").build();
        let (issued, _) = ca
            .issue_direct(
                subject,
                AlgorithmId::MlDsa65,
                CertificateProfile::TlsServer,
                Validity::ee_default(),
                None,
            )
            .unwrap();

        assert!(issued.pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_sign_subordinate_csr() {
        // Create root CA
        let root_config = CaConfig::root("Root CA", AlgorithmId::EcdsaP256);
        let mut root = CaCeremony::init_root(root_config).unwrap();

        // Generate CSR for subordinate
        let sub_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let sub_subject = NameBuilder::new("Subordinate CA")
            .organization("Test Org")
            .build();
        let csr = CsrBuilder::new(sub_subject)
            .build_and_sign(&sub_key)
            .unwrap();

        // Root signs the CSR
        let issued = root
            .ca
            .sign_subordinate_csr(csr.to_der(), Validity::days_from_now(365 * 5), Some(0))
            .unwrap();

        assert!(issued.pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(issued.subject_cn, "Subordinate CA");
        assert_eq!(issued.profile, CertificateProfile::SubordinateCa);
    }

    #[test]
    fn test_cross_certify() {
        // Create two independent root CAs
        let root_a_config = CaConfig::root("Root CA A", AlgorithmId::EcdsaP256);
        let mut root_a = CaCeremony::init_root(root_a_config).unwrap();

        let root_b_config = CaConfig::root("Root CA B", AlgorithmId::EcdsaP256);
        let root_b = CaCeremony::init_root(root_b_config).unwrap();

        // Root A cross-certifies Root B (creates trust bridge A -> B)
        let cross_cert = root_a
            .ca
            .cross_certify(
                &root_b.certificate_der,
                Validity::days_from_now(365 * 5),
                Some(2),
            )
            .unwrap();

        assert!(cross_cert.pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(cross_cert.subject_cn, "Root CA B");
        // Issuer should be Root CA A
        assert_eq!(cross_cert.issuer_cn, "Root CA A");
    }

    #[test]
    fn test_sign_subordinate_csr_rejects_bad_signature() {
        let root_config = CaConfig::root("Root CA", AlgorithmId::EcdsaP256);
        let mut root = CaCeremony::init_root(root_config).unwrap();

        // Create a CSR then corrupt the signature
        let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Bad CSR").build();
        let csr = CsrBuilder::new(subject).build_and_sign(&key).unwrap();

        let mut bad_der = csr.der.clone();
        // Corrupt last byte of DER (in the signature)
        if let Some(last) = bad_der.last_mut() {
            *last ^= 0xFF;
        }

        let result = root
            .ca
            .sign_subordinate_csr(&bad_der, Validity::days_from_now(365), Some(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_issue_certificate_with_external_signer() {
        use crate::ca::signer::Signer;
        use crate::ca::CertificateAuthority;
        use crate::cert::encode_certificate_der;
        use crate::hsm::{KeySpec, KeyStore, SoftwareKeyStore};
        use std::sync::Arc;

        // Create a SoftwareKeyStore-backed external signer CA
        let store = Arc::new(SoftwareKeyStore::new());
        let key_id = store
            .generate_key("ca-signing-key", KeySpec::EcdsaP256)
            .unwrap();

        // We need the CA's key in the store, so generate a fresh one and reload
        let pub_der = store.public_key_der(&key_id).unwrap();
        let signer = Signer::external(store.clone(), key_id, AlgorithmId::EcdsaP256);

        // Build a self-signed cert for this key to use as the CA cert
        let ca_subject = crate::cert::NameBuilder::new("Software KeyStore CA").build();
        let ca_cert =
            crate::cert::CertificateBuilder::new(ca_subject, pub_der, AlgorithmId::EcdsaP256)
                .validity(crate::cert::Validity::ca_default())
                .basic_constraints(crate::cert::extensions::BasicConstraints::ca())
                .key_usage(KeyUsage::new(KeyUsageFlags::ca_default()))
                .build_and_sign_with_signer(&signer)
                .unwrap();

        let ca_cert_der = encode_certificate_der(&ca_cert).unwrap();

        // Load CA with external signer
        let mut ca =
            CertificateAuthority::load_with_signer(crate::ca::CaType::Root, ca_cert_der, signer, 0)
                .unwrap();

        // Create a CSR for an end-entity cert
        let ee_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ee_subject = NameBuilder::new("ee.example.com")
            .organization("Test Org")
            .build();
        let csr = CsrBuilder::new(ee_subject).build_and_sign(&ee_key).unwrap();

        // Issue certificate using external signer CA
        let request = IssuanceRequest::new(csr, CertificateProfile::TlsServer)
            .with_san(SubjectAltName::new().dns("ee.example.com"));

        let issued = ca.issue_certificate(request).unwrap();

        assert!(issued.pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(issued.subject_cn, "ee.example.com");
        assert_eq!(issued.issuer_cn, "Software KeyStore CA");
    }

    #[test]
    fn test_sign_subordinate_csr_with_external_signer() {
        use crate::ca::signer::Signer;
        use crate::ca::CertificateAuthority;
        use crate::cert::encode_certificate_der;
        use crate::hsm::{KeySpec, KeyStore, SoftwareKeyStore};
        use std::sync::Arc;

        // Set up an external signer CA
        let store = Arc::new(SoftwareKeyStore::new());
        let key_id = store
            .generate_key("root-sign-sub", KeySpec::EcdsaP256)
            .unwrap();
        let pub_der = store.public_key_der(&key_id).unwrap();
        let signer = Signer::external(store.clone(), key_id, AlgorithmId::EcdsaP256);

        let ca_subject = crate::cert::NameBuilder::new("External Root CA").build();
        let ca_cert =
            crate::cert::CertificateBuilder::new(ca_subject, pub_der, AlgorithmId::EcdsaP256)
                .validity(crate::cert::Validity::ca_default())
                .basic_constraints(crate::cert::extensions::BasicConstraints::ca())
                .key_usage(KeyUsage::new(KeyUsageFlags::ca_default()))
                .build_and_sign_with_signer(&signer)
                .unwrap();

        let ca_cert_der = encode_certificate_der(&ca_cert).unwrap();

        let mut ca =
            CertificateAuthority::load_with_signer(crate::ca::CaType::Root, ca_cert_der, signer, 0)
                .unwrap();

        // Generate subordinate CSR
        let sub_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let sub_subject = NameBuilder::new("Sub CA").organization("Test").build();
        let csr = CsrBuilder::new(sub_subject)
            .build_and_sign(&sub_key)
            .unwrap();

        let issued = ca
            .sign_subordinate_csr(csr.to_der(), Validity::days_from_now(365 * 5), Some(0))
            .unwrap();

        assert!(issued.pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(issued.subject_cn, "Sub CA");
        assert_eq!(issued.issuer_cn, "External Root CA");
        assert_eq!(issued.profile, CertificateProfile::SubordinateCa);
    }

    #[test]
    fn test_cross_certify_with_external_signer() {
        use crate::ca::signer::Signer;
        use crate::ca::CertificateAuthority;
        use crate::cert::encode_certificate_der;
        use crate::hsm::{KeySpec, KeyStore, SoftwareKeyStore};
        use std::sync::Arc;

        // Set up external signer CA A
        let store = Arc::new(SoftwareKeyStore::new());
        let key_id = store
            .generate_key("ca-a-cross", KeySpec::EcdsaP256)
            .unwrap();
        let pub_der = store.public_key_der(&key_id).unwrap();
        let signer = Signer::external(store.clone(), key_id, AlgorithmId::EcdsaP256);

        let ca_subject = crate::cert::NameBuilder::new("CA A External").build();
        let ca_cert =
            crate::cert::CertificateBuilder::new(ca_subject, pub_der, AlgorithmId::EcdsaP256)
                .validity(crate::cert::Validity::ca_default())
                .basic_constraints(crate::cert::extensions::BasicConstraints::ca())
                .key_usage(KeyUsage::new(KeyUsageFlags::ca_default()))
                .build_and_sign_with_signer(&signer)
                .unwrap();

        let ca_cert_der = encode_certificate_der(&ca_cert).unwrap();

        let mut ca_a =
            CertificateAuthority::load_with_signer(crate::ca::CaType::Root, ca_cert_der, signer, 0)
                .unwrap();

        // Create CA B (standard in-memory) to cross-certify
        let root_b_config = CaConfig::root("CA B Foreign", AlgorithmId::EcdsaP256);
        let root_b = CaCeremony::init_root(root_b_config).unwrap();

        // CA A cross-certifies CA B
        let cross_cert = ca_a
            .cross_certify(
                &root_b.certificate_der,
                Validity::days_from_now(365 * 3),
                Some(1),
            )
            .unwrap();

        assert!(cross_cert.pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(cross_cert.subject_cn, "CA B Foreign");
        assert_eq!(cross_cert.issuer_cn, "CA A External");
    }
}
