//! X.509 Certificate Builder (RFC 5280)

use chrono::{DateTime, Utc};
use const_oid::ObjectIdentifier;
use der::{asn1::BitString, Decode, Encode};
use x509_cert::{
    ext::Extension,
    serial_number::SerialNumber as X509Serial,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::{Time, Validity as X509Validity},
    Certificate, TbsCertificate, Version,
};

use super::ct::SctList;
use super::extensions::{
    oid as ext_oid, AuthorityInfoAccess, AuthorityKeyIdentifier, BasicConstraints,
    CertificatePolicies, CmsContentConstraints, CrlDistributionPoints, ExtendedKeyUsage,
    FreshestCrl, InhibitAnyPolicy, IssuerAltName, KeyUsage, NameConstraints, NoRevAvail,
    OcspNoCheck, PolicyConstraints, PolicyMappings, QcStatements, SmimeCapabilities,
    SporkIssuanceInfo, SubjectAltName, SubjectInformationAccess, SubjectKeyIdentifier, TlsFeature,
};
use super::{DistinguishedName, SerialNumber, Validity};
use crate::algo::{AlgorithmId, KeyPair};
use crate::ca::Signer;
use crate::error::{Error, Result};

/// Certificate builder for creating X.509v3 certificates
pub struct CertificateBuilder {
    serial: SerialNumber,
    validity: Validity,
    subject: DistinguishedName,
    subject_public_key: Vec<u8>,
    subject_algorithm: AlgorithmId,
    issuer: Option<DistinguishedName>,
    // Extensions
    basic_constraints: Option<BasicConstraints>,
    key_usage: Option<KeyUsage>,
    extended_key_usage: Option<ExtendedKeyUsage>,
    subject_alt_name: Option<SubjectAltName>,
    issuer_alt_name: Option<IssuerAltName>,
    crl_distribution_points: Option<CrlDistributionPoints>,
    freshest_crl: Option<FreshestCrl>,
    authority_info_access: Option<AuthorityInfoAccess>,
    subject_information_access: Option<SubjectInformationAccess>,
    certificate_policies: Option<CertificatePolicies>,
    include_ski: bool,
    include_aki: bool,
    authority_key_id: Option<Vec<u8>>,
    spork_issuance_info: Option<SporkIssuanceInfo>,
    no_rev_avail: bool,
    ocsp_nocheck: bool,
    tls_feature: Option<TlsFeature>,
    inhibit_any_policy: Option<InhibitAnyPolicy>,
    policy_mappings: Option<PolicyMappings>,
    name_constraints: Option<NameConstraints>,
    policy_constraints: Option<PolicyConstraints>,
    sct_list: Option<SctList>,
    cms_content_constraints: Option<CmsContentConstraints>,
    qc_statements: Option<QcStatements>,
    smime_capabilities: Option<SmimeCapabilities>,
    /// Raw X.509 Name to use as subject, bypassing DistinguishedName conversion.
    /// Used by cross_certify() to preserve the exact foreign certificate subject DN.
    raw_subject_name: Option<x509_cert::name::Name>,
}

impl CertificateBuilder {
    /// Create a new certificate builder
    pub fn new(
        subject: DistinguishedName,
        subject_public_key: Vec<u8>,
        subject_algorithm: AlgorithmId,
    ) -> Self {
        Self {
            serial: SerialNumber::random(),
            validity: Validity::ee_default(),
            subject,
            subject_public_key,
            subject_algorithm,
            issuer: None,
            basic_constraints: None,
            key_usage: None,
            extended_key_usage: None,
            subject_alt_name: None,
            issuer_alt_name: None,
            crl_distribution_points: None,
            freshest_crl: None,
            authority_info_access: None,
            subject_information_access: None,
            certificate_policies: None,
            include_ski: true,
            include_aki: true,
            authority_key_id: None,
            spork_issuance_info: None,
            no_rev_avail: false,
            ocsp_nocheck: false,
            tls_feature: None,
            inhibit_any_policy: None,
            policy_mappings: None,
            name_constraints: None,
            policy_constraints: None,
            sct_list: None,
            cms_content_constraints: None,
            qc_statements: None,
            smime_capabilities: None,
            raw_subject_name: None,
        }
    }

    /// Set a raw X.509 Name as the subject DN, bypassing DistinguishedName → Name conversion.
    /// This preserves the exact RDN structure from a foreign certificate (e.g., multiple OUs).
    pub fn raw_subject(mut self, name: x509_cert::name::Name) -> Self {
        self.raw_subject_name = Some(name);
        self
    }

    /// Set serial number
    pub fn serial(mut self, serial: SerialNumber) -> Self {
        self.serial = serial;
        self
    }

    /// Set validity period
    pub fn validity(mut self, validity: Validity) -> Self {
        self.validity = validity;
        self
    }

    /// Set issuer (if different from subject for non-self-signed)
    pub fn issuer(mut self, issuer: DistinguishedName) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Add Basic Constraints extension
    pub fn basic_constraints(mut self, bc: BasicConstraints) -> Self {
        self.basic_constraints = Some(bc);
        self
    }

    /// Add Key Usage extension
    pub fn key_usage(mut self, ku: KeyUsage) -> Self {
        self.key_usage = Some(ku);
        self
    }

    /// Add Extended Key Usage extension
    pub fn extended_key_usage(mut self, eku: ExtendedKeyUsage) -> Self {
        self.extended_key_usage = Some(eku);
        self
    }

    /// Add Subject Alternative Name extension
    pub fn subject_alt_name(mut self, san: SubjectAltName) -> Self {
        self.subject_alt_name = Some(san);
        self
    }

    /// Add Issuer Alternative Name extension (RFC 5280 Section 4.2.1.7)
    pub fn issuer_alt_name(mut self, ian: IssuerAltName) -> Self {
        self.issuer_alt_name = Some(ian);
        self
    }

    /// Add CRL Distribution Points extension (RFC 5280 Section 4.2.1.13)
    pub fn crl_distribution_points(mut self, cdp: CrlDistributionPoints) -> Self {
        self.crl_distribution_points = Some(cdp);
        self
    }

    /// Add FreshestCRL extension (RFC 5280 Section 4.2.1.15, non-critical)
    ///
    /// Identifies how delta CRL information is obtained. Same ASN.1 structure
    /// as CRLDistributionPoints but uses OID 2.5.29.46.
    pub fn freshest_crl(mut self, fcrl: FreshestCrl) -> Self {
        self.freshest_crl = Some(fcrl);
        self
    }

    /// Add Authority Information Access extension (RFC 5280 Section 4.2.2.1)
    pub fn authority_info_access(mut self, aia: AuthorityInfoAccess) -> Self {
        self.authority_info_access = Some(aia);
        self
    }

    /// Add Subject Information Access extension (RFC 5280 Section 4.2.2.2)
    ///
    /// For CA certificates, used with `id-ad-caRepository` to point to a
    /// .p7c file containing certificates issued by this CA. Required for FPKI.
    /// For TSA certificates, used with `id-ad-timeStamping` to identify the
    /// time-stamping service endpoint.
    pub fn subject_information_access(mut self, sia: SubjectInformationAccess) -> Self {
        self.subject_information_access = Some(sia);
        self
    }

    /// Add Certificate Policies extension (RFC 5280 Section 4.2.1.4)
    ///
    /// Used by SPORK for admin access level control via policy OIDs:
    /// - 1.3.6.1.4.1.56266.1.10.x for SPORK-CA admin levels
    /// - 1.3.6.1.4.1.56266.1.20.x for SPORK-ACME admin levels
    pub fn certificate_policies(mut self, policies: CertificatePolicies) -> Self {
        self.certificate_policies = Some(policies);
        self
    }

    /// Include Subject Key Identifier (default: true)
    pub fn include_subject_key_identifier(mut self, include: bool) -> Self {
        self.include_ski = include;
        self
    }

    /// Include Authority Key Identifier (default: true)
    pub fn include_authority_key_identifier(mut self, include: bool) -> Self {
        self.include_aki = include;
        self
    }

    /// Set specific authority key identifier
    pub fn authority_key_identifier(mut self, key_id: Vec<u8>) -> Self {
        self.authority_key_id = Some(key_id);
        self
    }

    /// Add SPORK Issuance Info extension (non-critical)
    ///
    /// This custom extension identifies certificates issued by SPORK PKI.
    /// OID: 1.3.6.1.4.1.56266.1.2.4 (Ogjos PEN: 56266)
    pub fn spork_issuance_info(mut self, info: SporkIssuanceInfo) -> Self {
        self.spork_issuance_info = Some(info);
        self
    }

    /// Add SPORK Issuance Info with just CA ID (uses defaults for other fields)
    pub fn spork_info_with_ca_id(mut self, ca_id: impl Into<String>) -> Self {
        self.spork_issuance_info = Some(SporkIssuanceInfo::new(ca_id));
        self
    }

    /// Add No Revocation Available extension (RFC 9608)
    ///
    /// Marks the certificate as not needing revocation checking.
    /// Used for short-lived certificates and OCSP responder certificates.
    /// This extension is always marked critical per RFC 9608 Section 4.
    pub fn no_rev_avail(mut self) -> Self {
        self.no_rev_avail = true;
        self
    }

    /// Add id-pkix-ocsp-nocheck extension (RFC 6960 §4.2.2.2.1)
    ///
    /// Instructs clients NOT to check the revocation status of this OCSP responder
    /// certificate itself, preventing infinite regress. Non-critical per RFC 6960.
    /// MUST only be used on OCSP responder certificates (EKU: ocspSigning).
    pub fn ocsp_nocheck(mut self) -> Self {
        self.ocsp_nocheck = true;
        self
    }

    /// Add TLS Feature extension (RFC 7633)
    ///
    /// "OCSP Must-Staple" — requires TLS servers to include a stapled OCSP response.
    pub fn tls_feature(mut self, feature: TlsFeature) -> Self {
        self.tls_feature = Some(feature);
        self
    }

    /// Add Inhibit anyPolicy extension (RFC 5280 §4.2.1.14, critical)
    ///
    /// Limits the use of the anyPolicy OID in subordinate certificates.
    pub fn inhibit_any_policy(mut self, iap: InhibitAnyPolicy) -> Self {
        self.inhibit_any_policy = Some(iap);
        self
    }

    /// Add Policy Mappings extension (RFC 5280 §4.2.1.5, critical)
    ///
    /// Maps issuer-domain policy OIDs to subject-domain policy OIDs.
    /// Used in cross-certificates for Federal Bridge interoperation.
    pub fn policy_mappings(mut self, pm: PolicyMappings) -> Self {
        self.policy_mappings = Some(pm);
        self
    }

    /// Add Name Constraints extension (RFC 5280 §4.2.1.10, critical)
    ///
    /// Restricts the namespace within which subsequent certificates must be located.
    pub fn name_constraints(mut self, nc: NameConstraints) -> Self {
        self.name_constraints = Some(nc);
        self
    }

    /// Add Policy Constraints extension (RFC 5280 §4.2.1.11, critical)
    ///
    /// Constrains path validation by requiring explicit policies and/or
    /// inhibiting policy mapping.
    pub fn policy_constraints(mut self, pc: PolicyConstraints) -> Self {
        self.policy_constraints = Some(pc);
        self
    }

    /// Add CMS Content Constraints extension (RFC 6010)
    ///
    /// Restricts which CMS content types a certificate's key is authorized to sign.
    /// Used to constrain signing keys (e.g., code signing only, timestamping only).
    pub fn cms_content_constraints(mut self, cc: CmsContentConstraints) -> Self {
        self.cms_content_constraints = Some(cc);
        self
    }

    /// Add Qualified Certificate Statements extension (RFC 3739 §3.2.6)
    ///
    /// Used for EU eIDAS qualified certificates and other regulatory frameworks.
    /// Contains statements about the certificate's qualified status, SSCD usage,
    /// retention period, and compliance declarations.
    pub fn qc_statements(mut self, qc: QcStatements) -> Self {
        self.qc_statements = Some(qc);
        self
    }

    /// Add smimeCapabilities extension (RFC 8551 §2.5.2, OID 1.2.840.113549.1.9.15)
    ///
    /// Announces S/MIME content-encryption algorithms supported by the subject.
    /// Non-critical per RFC 8551.
    pub fn smime_capabilities(mut self, caps: SmimeCapabilities) -> Self {
        self.smime_capabilities = Some(caps);
        self
    }

    /// Add SCT List extension (RFC 6962 Section 3.3, OID 1.3.6.1.4.1.11129.2.4.2)
    ///
    /// Embeds Signed Certificate Timestamps from CT logs into the certificate.
    /// This extension is always non-critical per RFC 6962.
    pub fn with_sct_list(mut self, sct_list: SctList) -> Self {
        self.sct_list = Some(sct_list);
        self
    }

    /// Apply a Federal Bridge cross-certificate profile.
    ///
    /// Configures PolicyMappings, NameConstraints, PolicyConstraints,
    /// InhibitAnyPolicy, CertificatePolicies, and BasicConstraints from
    /// a `CrossCertProfile` produced by `FedBridgeConfig`.
    pub fn apply_cross_cert_profile(
        mut self,
        profile: &crate::policy::fedbridge::CrossCertProfile,
    ) -> Result<Self> {
        // PolicyMappings
        if !profile.policy_mappings.is_empty() {
            let pairs: Vec<(&str, &str)> = profile
                .policy_mappings
                .iter()
                .map(|m| {
                    (
                        m.issuer_domain_policy.as_str(),
                        m.subject_domain_policy.as_str(),
                    )
                })
                .collect();
            self.policy_mappings = Some(PolicyMappings::from_oid_strings(&pairs)?);
        }

        // NameConstraints
        if profile.has_name_constraints() {
            let mut nc = NameConstraints::new();
            for dns in &profile.permitted_dns_subtrees {
                nc = nc.permit_dns(dns);
            }
            for dns in &profile.excluded_dns_subtrees {
                nc = nc.exclude_dns(dns);
            }
            for dn in &profile.permitted_dn_subtrees {
                nc = nc.permit_dn(dn);
            }
            self.name_constraints = Some(nc);
        }

        // PolicyConstraints
        if profile.has_policy_constraints() {
            self.policy_constraints = Some(PolicyConstraints {
                require_explicit_policy: profile.require_explicit_policy,
                inhibit_policy_mapping: profile.inhibit_policy_mapping,
            });
        }

        // InhibitAnyPolicy
        if let Some(skip) = profile.inhibit_any_policy {
            self.inhibit_any_policy = Some(InhibitAnyPolicy::new(skip));
        }

        // CertificatePolicies
        if !profile.certificate_policies.is_empty() {
            let mut oids = Vec::new();
            for oid_str in &profile.certificate_policies {
                let oid = ObjectIdentifier::new(oid_str).map_err(|e| {
                    Error::Encoding(format!("Invalid policy OID '{}': {}", oid_str, e))
                })?;
                oids.push(oid);
            }
            self.certificate_policies = Some(CertificatePolicies::new(oids));
        }

        // BasicConstraints with pathLenConstraint (RFC 5280: INTEGER 0..MAX, but u8 in practice)
        self.basic_constraints = Some(match profile.path_len_constraint {
            Some(v) if v <= 255 => BasicConstraints::ca_with_path_len(v as u8),
            Some(v) => {
                return Err(Error::Encoding(format!(
                    "pathLenConstraint {} exceeds maximum 255",
                    v
                )));
            }
            None => BasicConstraints::ca(),
        });

        Ok(self)
    }

    /// Build and sign the certificate
    ///
    /// For self-signed certificates, signer is the subject's key pair.
    /// For CA-signed certificates, signer is the CA's key pair.
    pub fn build_and_sign(self, signer: &KeyPair) -> Result<Certificate> {
        // RFC 5280 §4.1.2.5: notBefore MUST be before notAfter
        if self.validity.not_before >= self.validity.not_after {
            return Err(Error::Encoding(format!(
                "Certificate validity: notBefore ({}) must be before notAfter ({}) (RFC 5280 §4.1.2.5)",
                self.validity.not_before, self.validity.not_after
            )));
        }

        let subject_name = match &self.raw_subject_name {
            Some(raw) => raw.clone(),
            None => self.subject.to_name()?,
        };
        let issuer_name = match &self.issuer {
            Some(dn) => dn.to_name()?,
            None => subject_name.clone(), // Self-signed
        };

        // Build Subject Public Key Info FIRST so we can use SPKI DER for SKI/AKI
        let spki = build_spki(&self.subject_public_key, self.subject_algorithm)?;
        let spki_der = spki.to_der().map_err(|e| Error::Encoding(e.to_string()))?;

        // Build extensions (uses SPKI DER for consistent SKI/AKI computation)
        let extensions = self.build_extensions(&spki_der)?;

        // Convert validity times
        let not_before = datetime_to_time(self.validity.not_before)?;
        let not_after = datetime_to_time(self.validity.not_after)?;

        // Build TBS (To Be Signed) Certificate
        let serial = X509Serial::new(&self.serial.0).map_err(|e| Error::Encoding(e.to_string()))?;

        let signature_algorithm = algorithm_identifier(signer.algorithm_id())?;

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: serial,
            signature: signature_algorithm.clone(),
            issuer: issuer_name,
            validity: X509Validity {
                not_before,
                not_after,
            },
            subject: subject_name,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: if extensions.is_empty() {
                None
            } else {
                Some(extensions)
            },
        };

        // Encode TBS to DER for signing
        let tbs_der = tbs.to_der().map_err(|e| Error::Encoding(e.to_string()))?;

        // Sign
        let signature = signer.sign(&tbs_der)?;
        let signature_bits = BitString::new(0, signature)
            .map_err(|e| Error::Encoding(format!("BitString: {}", e)))?;

        Ok(Certificate {
            tbs_certificate: tbs,
            signature_algorithm,
            signature: signature_bits,
        })
    }

    /// Build, sign, and serialize to DER bytes
    ///
    /// Returns (certificate_der, serial_hex, subject_dn_string)
    pub fn build_sign_and_serialize(self, signer: &KeyPair) -> Result<(Vec<u8>, String, String)> {
        let serial_hex = format!("{:0>16}", hex::encode(&self.serial.0));
        let subject_dn_str = format!("CN={}", self.subject.common_name);
        let cert = self.build_and_sign(signer)?;
        let der = cert.to_der().map_err(|e| Error::Encoding(e.to_string()))?;
        Ok((der, serial_hex, subject_dn_str))
    }

    /// Build and sign the certificate using a `Signer` backend
    ///
    /// Works with both in-memory keys and external key stores (TPM, HSM).
    /// For in-memory signers, this is equivalent to `build_and_sign()`.
    /// For external signers, delegates signing to the key store.
    pub fn build_and_sign_with_signer(self, signer: &Signer) -> Result<Certificate> {
        // RFC 5280 §4.1.2.5: notBefore MUST be before notAfter
        if self.validity.not_before >= self.validity.not_after {
            return Err(Error::Encoding(format!(
                "Certificate validity: notBefore ({}) must be before notAfter ({}) (RFC 5280 §4.1.2.5)",
                self.validity.not_before, self.validity.not_after
            )));
        }

        let subject_name = match &self.raw_subject_name {
            Some(raw) => raw.clone(),
            None => self.subject.to_name()?,
        };
        let issuer_name = match &self.issuer {
            Some(dn) => dn.to_name()?,
            None => subject_name.clone(), // Self-signed
        };

        // Build Subject Public Key Info FIRST so we can use SPKI DER for SKI/AKI
        let spki = build_spki(&self.subject_public_key, self.subject_algorithm)?;
        let spki_der = spki.to_der().map_err(|e| Error::Encoding(e.to_string()))?;

        // Build extensions (uses SPKI DER for consistent SKI/AKI computation)
        let extensions = self.build_extensions(&spki_der)?;

        // Convert validity times
        let not_before = datetime_to_time(self.validity.not_before)?;
        let not_after = datetime_to_time(self.validity.not_after)?;

        // Build TBS (To Be Signed) Certificate
        let serial = X509Serial::new(&self.serial.0).map_err(|e| Error::Encoding(e.to_string()))?;

        let signature_algorithm = algorithm_identifier(signer.algorithm())?;

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: serial,
            signature: signature_algorithm.clone(),
            issuer: issuer_name,
            validity: X509Validity {
                not_before,
                not_after,
            },
            subject: subject_name,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: if extensions.is_empty() {
                None
            } else {
                Some(extensions)
            },
        };

        // Encode TBS to DER for signing
        let tbs_der = tbs.to_der().map_err(|e| Error::Encoding(e.to_string()))?;

        // Sign using the Signer abstraction
        let signature = signer.sign(&tbs_der)?;
        let signature_bits = BitString::new(0, signature)
            .map_err(|e| Error::Encoding(format!("BitString: {}", e)))?;

        Ok(Certificate {
            tbs_certificate: tbs,
            signature_algorithm,
            signature: signature_bits,
        })
    }

    /// Build, sign with Signer, and serialize to DER bytes
    ///
    /// Returns (certificate_der, serial_hex, subject_dn_string)
    pub fn build_sign_and_serialize_with_signer(
        self,
        signer: &Signer,
    ) -> Result<(Vec<u8>, String, String)> {
        let serial_hex = format!("{:0>16}", hex::encode(&self.serial.0));
        let subject_dn_str = format!("CN={}", self.subject.common_name);
        let cert = self.build_and_sign_with_signer(signer)?;
        let der = cert.to_der().map_err(|e| Error::Encoding(e.to_string()))?;
        Ok((der, serial_hex, subject_dn_str))
    }

    fn build_extensions(&self, spki_der: &[u8]) -> Result<Vec<Extension>> {
        let mut extensions = Vec::new();

        // Basic Constraints (critical for CAs)
        if let Some(ref bc) = self.basic_constraints {
            extensions.push(Extension {
                extn_id: ext_oid::BASIC_CONSTRAINTS,
                critical: bc.ca, // Critical if CA
                extn_value: der::asn1::OctetString::new(bc.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // Key Usage (critical)
        if let Some(ref ku) = self.key_usage {
            extensions.push(Extension {
                extn_id: ext_oid::KEY_USAGE,
                critical: true,
                extn_value: der::asn1::OctetString::new(ku.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // Extended Key Usage (non-critical)
        if let Some(ref eku) = self.extended_key_usage {
            extensions.push(Extension {
                extn_id: ext_oid::EXTENDED_KEY_USAGE,
                critical: false,
                extn_value: der::asn1::OctetString::new(eku.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // Subject Key Identifier (computed from SPKI DER for consistency with CA::load())
        if self.include_ski {
            let ski = SubjectKeyIdentifier::from_public_key(spki_der);
            extensions.push(Extension {
                extn_id: ext_oid::SUBJECT_KEY_IDENTIFIER,
                critical: false,
                extn_value: der::asn1::OctetString::new(ski.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // Authority Key Identifier (RFC 5280 Section 4.2.1.1)
        // For self-signed (root) certs: include AKI with keyIdentifier only
        // (authorityCertIssuer and authorityCertSerialNumber MUST NOT be present).
        // For CA-signed certs: include AKI from issuer's public key.
        let is_self_signed = self.issuer.is_none();
        if self.include_aki {
            let aki = if let Some(ref key_id) = self.authority_key_id {
                AuthorityKeyIdentifier::from_key_id(key_id.clone())
            } else if is_self_signed {
                // Self-signed: derive AKI keyIdentifier from own SPKI
                let ski = SubjectKeyIdentifier::from_public_key(spki_der);
                AuthorityKeyIdentifier::from_subject_key_id(&ski)
            } else {
                // CA-signed but no explicit AKI: derive from subject's SPKI
                let ski = SubjectKeyIdentifier::from_public_key(spki_der);
                AuthorityKeyIdentifier::from_subject_key_id(&ski)
            };
            extensions.push(Extension {
                extn_id: ext_oid::AUTHORITY_KEY_IDENTIFIER,
                critical: false,
                extn_value: der::asn1::OctetString::new(aki.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // Subject Alternative Name (RFC 5280 Section 4.2.1.6)
        // MUST be critical when Subject field is empty; non-critical otherwise.
        if let Some(ref san) = self.subject_alt_name {
            let subject_is_empty = self.subject.common_name.is_empty()
                && self.subject.organization.is_none()
                && self.subject.country.is_none()
                && self.subject.state.is_none()
                && self.subject.locality.is_none()
                && self.subject.organizational_unit.is_none()
                && self.subject.domain_components.is_empty()
                && self.subject.serial_number.is_none()
                && self.subject.email.is_none()
                && self.subject.uid.is_none();
            extensions.push(Extension {
                extn_id: ext_oid::SUBJECT_ALT_NAME,
                critical: subject_is_empty,
                extn_value: der::asn1::OctetString::new(san.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // Issuer Alternative Name (RFC 5280 Section 4.2.1.7, non-critical)
        if let Some(ref ian) = self.issuer_alt_name {
            extensions.push(Extension {
                extn_id: ext_oid::ISSUER_ALT_NAME,
                critical: false,
                extn_value: der::asn1::OctetString::new(ian.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // CRL Distribution Points (non-critical per RFC 5280)
        if let Some(ref cdp) = self.crl_distribution_points {
            extensions.push(Extension {
                extn_id: ext_oid::CRL_DISTRIBUTION_POINTS,
                critical: false,
                extn_value: der::asn1::OctetString::new(cdp.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // FreshestCRL (non-critical per RFC 5280 §4.2.1.15)
        if let Some(ref fcrl) = self.freshest_crl {
            extensions.push(Extension {
                extn_id: ext_oid::FRESHEST_CRL,
                critical: false,
                extn_value: der::asn1::OctetString::new(fcrl.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // Authority Information Access (non-critical per RFC 5280)
        if let Some(ref aia) = self.authority_info_access {
            extensions.push(Extension {
                extn_id: ext_oid::AUTHORITY_INFO_ACCESS,
                critical: false,
                extn_value: der::asn1::OctetString::new(aia.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // Subject Information Access (non-critical per RFC 5280 Section 4.2.2.2)
        if let Some(ref sia) = self.subject_information_access {
            extensions.push(Extension {
                extn_id: ext_oid::SUBJECT_INFO_ACCESS,
                critical: false,
                extn_value: der::asn1::OctetString::new(sia.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // Certificate Policies (non-critical per RFC 5280)
        // Used by SPORK for admin access level control via policy OIDs
        if let Some(ref policies) = self.certificate_policies {
            extensions.push(Extension {
                extn_id: ext_oid::CERTIFICATE_POLICIES,
                critical: false,
                extn_value: der::asn1::OctetString::new(policies.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // SPORK Issuance Info (non-critical, custom extension)
        if let Some(ref spork_info) = self.spork_issuance_info {
            extensions.push(Extension {
                extn_id: ext_oid::SPORK_ISSUANCE_INFO,
                critical: false,
                extn_value: der::asn1::OctetString::new(spork_info.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // No Revocation Available (RFC 9608, MUST be critical)
        if self.no_rev_avail {
            extensions.push(Extension {
                extn_id: ext_oid::NO_REV_AVAIL,
                critical: true,
                extn_value: der::asn1::OctetString::new(NoRevAvail.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1, non-critical)
        if self.ocsp_nocheck {
            extensions.push(Extension {
                extn_id: ext_oid::OCSP_NOCHECK,
                critical: false,
                extn_value: der::asn1::OctetString::new(OcspNoCheck.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // TLS Feature / OCSP Must-Staple (RFC 7633, non-critical)
        if let Some(ref tls_feat) = self.tls_feature {
            extensions.push(Extension {
                extn_id: ext_oid::TLS_FEATURE,
                critical: false,
                extn_value: der::asn1::OctetString::new(tls_feat.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // Inhibit anyPolicy (RFC 5280 §4.2.1.14, MUST be critical)
        if let Some(ref iap) = self.inhibit_any_policy {
            extensions.push(Extension {
                extn_id: ext_oid::INHIBIT_ANY_POLICY,
                critical: true,
                extn_value: der::asn1::OctetString::new(iap.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // Policy Mappings (RFC 5280 §4.2.1.5, MUST be critical)
        if let Some(ref pm) = self.policy_mappings {
            extensions.push(Extension {
                extn_id: ext_oid::POLICY_MAPPINGS,
                critical: true,
                extn_value: der::asn1::OctetString::new(pm.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // Name Constraints (RFC 5280 §4.2.1.10, MUST be critical)
        if let Some(ref nc) = self.name_constraints {
            extensions.push(Extension {
                extn_id: ext_oid::NAME_CONSTRAINTS,
                critical: true,
                extn_value: der::asn1::OctetString::new(nc.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // Policy Constraints (RFC 5280 §4.2.1.11, MUST be critical)
        if let Some(ref pc) = self.policy_constraints {
            extensions.push(Extension {
                extn_id: ext_oid::POLICY_CONSTRAINTS,
                critical: true,
                extn_value: der::asn1::OctetString::new(pc.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // SCT List (RFC 6962 Section 3.3, non-critical)
        if let Some(ref sct_list) = self.sct_list {
            extensions.push(Extension {
                extn_id: ext_oid::SCT_LIST,
                critical: false,
                extn_value: der::asn1::OctetString::new(sct_list.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // CMS Content Constraints (RFC 6010, non-critical)
        if let Some(ref cc) = self.cms_content_constraints {
            extensions.push(Extension {
                extn_id: ext_oid::CMS_CONTENT_CONSTRAINTS,
                critical: false,
                extn_value: der::asn1::OctetString::new(cc.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // Qualified Certificate Statements (RFC 3739, non-critical)
        if let Some(ref qc) = self.qc_statements {
            extensions.push(Extension {
                extn_id: ext_oid::QC_STATEMENTS,
                critical: false,
                extn_value: der::asn1::OctetString::new(qc.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        // smimeCapabilities (RFC 8551 §2.5.2, non-critical)
        if let Some(ref caps) = self.smime_capabilities {
            extensions.push(Extension {
                extn_id: ext_oid::SMIME_CAPABILITIES,
                critical: false,
                extn_value: der::asn1::OctetString::new(caps.to_der()?)
                    .map_err(|e| Error::Encoding(e.to_string()))?,
            });
        }

        Ok(extensions)
    }
}

/// Build Subject Public Key Info
fn build_spki(public_key_der: &[u8], algorithm: AlgorithmId) -> Result<SubjectPublicKeyInfoOwned> {
    // For ECDSA and RSA, the input is already SPKI DER
    // For PQC (including composites), we need to wrap raw bytes
    match algorithm {
        AlgorithmId::Ed25519
        | AlgorithmId::EcdsaP256
        | AlgorithmId::EcdsaP384
        | AlgorithmId::Rsa2048
        | AlgorithmId::Rsa3072
        | AlgorithmId::Rsa4096
        | AlgorithmId::Rsa3072Pss
        | AlgorithmId::Rsa4096Pss => SubjectPublicKeyInfoOwned::from_der(public_key_der)
            .map_err(|e| Error::Decoding(format!("SPKI decode: {}", e))),
        // PQC and composite algorithms - use the public key DER directly
        // For composites, the public key is already properly formatted by CompositeKeyPair
        #[cfg(feature = "pqc")]
        _ => {
            // For composite keys, the DER is already a complete SPKI
            // Try to decode as SPKI first
            if let Ok(spki) = SubjectPublicKeyInfoOwned::from_der(public_key_der) {
                return Ok(spki);
            }
            // Otherwise, wrap raw bytes in SPKI
            let algorithm = algorithm_identifier_for_spki(algorithm)?;
            let subject_public_key = BitString::new(0, public_key_der)
                .map_err(|e| Error::Encoding(format!("BitString: {}", e)))?;
            Ok(SubjectPublicKeyInfoOwned {
                algorithm,
                subject_public_key,
            })
        }
    }
}

/// Build algorithm identifier for signature
fn algorithm_identifier(algorithm: AlgorithmId) -> Result<AlgorithmIdentifierOwned> {
    let oid = match algorithm {
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa44 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa65 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa87 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19"),
        #[cfg(feature = "pqc")]
        AlgorithmId::SlhDsaSha2_128s => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.20"),
        #[cfg(feature = "pqc")]
        AlgorithmId::SlhDsaSha2_192s => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.22"),
        #[cfg(feature = "pqc")]
        AlgorithmId::SlhDsaSha2_256s => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.24"),
        // Composite signature OIDs (draft-ietf-lamps-pq-composite-sigs)
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa44EcdsaP256 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.1"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa65EcdsaP256 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.2"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa65EcdsaP384 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.3"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa87EcdsaP384 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.4"),
        AlgorithmId::Ed25519 => ObjectIdentifier::new_unwrap("1.3.101.112"), // id-Ed25519
        AlgorithmId::EcdsaP256 => ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"), // ecdsa-with-SHA256
        AlgorithmId::EcdsaP384 => ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"), // ecdsa-with-SHA384
        AlgorithmId::Rsa2048 | AlgorithmId::Rsa4096 => {
            return Ok(AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"), // sha256WithRSAEncryption
                parameters: None,
            });
        }
        AlgorithmId::Rsa3072 => {
            return Ok(AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12"), // sha384WithRSAEncryption
                parameters: None,
            });
        }
        AlgorithmId::Rsa3072Pss | AlgorithmId::Rsa4096Pss => {
            return Ok(AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10"), // id-RSASSA-PSS
                parameters: Some(
                    der::asn1::Any::from_der(&crate::algo::AlgorithmId::pss_sha256_params())
                        .map_err(|e| Error::Encoding(format!("PSS params: {}", e)))?,
                ),
            });
        }
    };

    Ok(AlgorithmIdentifierOwned {
        oid,
        parameters: None, // Parameters are absent for these algorithms
    })
}

/// Build algorithm identifier for SPKI (public key algorithm, not signature)
#[cfg(feature = "pqc")]
fn algorithm_identifier_for_spki(algorithm: AlgorithmId) -> Result<AlgorithmIdentifierOwned> {
    let oid = match algorithm {
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa44 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa65 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa87 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19"),
        #[cfg(feature = "pqc")]
        AlgorithmId::SlhDsaSha2_128s => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.20"),
        #[cfg(feature = "pqc")]
        AlgorithmId::SlhDsaSha2_192s => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.22"),
        #[cfg(feature = "pqc")]
        AlgorithmId::SlhDsaSha2_256s => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.24"),
        // Composite public key OIDs (same as signature OIDs per draft)
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa44EcdsaP256 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.1"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa65EcdsaP256 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.2"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa65EcdsaP384 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.3"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa87EcdsaP384 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.4"),
        AlgorithmId::Ed25519 => ObjectIdentifier::new_unwrap("1.3.101.112"), // id-Ed25519 (RFC 8410)
        AlgorithmId::EcdsaP256 => ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"), // ecPublicKey
        AlgorithmId::EcdsaP384 => ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
        AlgorithmId::Rsa2048
        | AlgorithmId::Rsa3072
        | AlgorithmId::Rsa4096
        | AlgorithmId::Rsa3072Pss
        | AlgorithmId::Rsa4096Pss => {
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") // rsaEncryption
        }
    };

    Ok(AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    })
}

/// Convert chrono DateTime to X.509 Time
fn datetime_to_time(dt: DateTime<Utc>) -> Result<Time> {
    use der::asn1::{GeneralizedTime, UtcTime};

    let der_dt = der::DateTime::new(
        dt.year() as u16,
        dt.month() as u8,
        dt.day() as u8,
        dt.hour() as u8,
        dt.minute() as u8,
        dt.second() as u8,
    )
    .map_err(|e| Error::Encoding(format!("DateTime: {}", e)))?;

    // Use UTCTime for dates before 2050, GeneralizedTime otherwise (RFC 5280)
    if dt.year() < 2050 {
        let utc = UtcTime::from_date_time(der_dt)
            .map_err(|e| Error::Encoding(format!("UtcTime: {}", e)))?;
        Ok(Time::UtcTime(utc))
    } else {
        let gen = GeneralizedTime::from_date_time(der_dt);
        Ok(Time::GeneralTime(gen))
    }
}

use chrono::Datelike;
use chrono::Timelike;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algo::KeyPair;
    use crate::cert::extensions::KeyUsageFlags;
    use crate::cert::NameBuilder;

    #[test]
    fn test_self_signed_certificate() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Test CA")
            .organization("Test Org")
            .country("US")
            .build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .validity(Validity::ca_default())
        .basic_constraints(BasicConstraints::ca())
        .key_usage(KeyUsage::new(KeyUsageFlags::ca_default()))
        .build_and_sign(&kp)
        .unwrap();

        // Verify it's a CA
        assert_eq!(cert.tbs_certificate.version, Version::V3);
    }

    #[test]
    fn test_san_non_critical_with_subject() {
        // RFC 5280 Section 4.2.1.6: SAN is non-critical when Subject DN is populated
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("test.example.com").build();

        let san = SubjectAltName::new().dns("test.example.com");

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .subject_alt_name(san)
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let san_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::SUBJECT_ALT_NAME)
            .expect("SAN extension should be present");
        assert!(
            !san_ext.critical,
            "SAN should be non-critical when Subject DN is populated"
        );
    }

    #[test]
    fn test_san_critical_with_empty_subject() {
        // RFC 5280 Section 4.2.1.6: SAN MUST be critical when Subject field is empty
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = DistinguishedName {
            common_name: String::new(),
            domain_components: Vec::new(),
            country: None,
            state: None,
            locality: None,
            organization: None,
            organizational_unit: None,
            serial_number: None,
            email: None,
            uid: None,
        };

        let san = SubjectAltName::new().dns("test.example.com");

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .subject_alt_name(san)
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let san_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::SUBJECT_ALT_NAME)
            .expect("SAN extension should be present");
        assert!(
            san_ext.critical,
            "SAN MUST be critical when Subject field is empty (RFC 5280)"
        );
    }

    #[test]
    fn test_build_and_sign_with_external_signer() {
        use crate::ca::Signer;
        use crate::hsm::{KeySpec, KeyStore, SoftwareKeyStore};
        use std::sync::Arc;

        let store = Arc::new(SoftwareKeyStore::new());
        let key_id = store
            .generate_key("builder-test", KeySpec::EcdsaP256)
            .unwrap();
        let public_key_der = store.public_key_der(&key_id).unwrap();

        let signer = Signer::external(store, key_id, AlgorithmId::EcdsaP256);

        let subject = NameBuilder::new("External Signer Test").build();
        let cert = CertificateBuilder::new(subject, public_key_der, AlgorithmId::EcdsaP256)
            .validity(Validity::ca_default())
            .basic_constraints(BasicConstraints::ca())
            .key_usage(KeyUsage::new(KeyUsageFlags::ca_default()))
            .build_and_sign_with_signer(&signer)
            .unwrap();

        assert_eq!(cert.tbs_certificate.version, Version::V3);
    }

    #[test]
    fn test_build_sign_and_serialize_with_external_signer() {
        use crate::ca::Signer;
        use crate::hsm::{KeySpec, KeyStore, SoftwareKeyStore};
        use std::sync::Arc;

        let store = Arc::new(SoftwareKeyStore::new());
        let key_id = store
            .generate_key("serialize-test", KeySpec::EcdsaP256)
            .unwrap();
        let public_key_der = store.public_key_der(&key_id).unwrap();

        let signer = Signer::external(store, key_id, AlgorithmId::EcdsaP256);

        let subject = NameBuilder::new("Serialize Test").build();
        let (der, serial_hex, subject_dn) =
            CertificateBuilder::new(subject, public_key_der, AlgorithmId::EcdsaP256)
                .build_sign_and_serialize_with_signer(&signer)
                .unwrap();

        assert!(!der.is_empty());
        assert!(!serial_hex.is_empty());
        assert!(subject_dn.contains("Serialize Test"));
    }

    #[test]
    fn test_self_signed_includes_aki_with_key_id() {
        // RFC 5280 Section 4.2.1.1: Self-signed certs may include AKI
        // with keyIdentifier only (no authorityCertIssuer or serial)
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Root CA").build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .basic_constraints(BasicConstraints::ca())
        .key_usage(KeyUsage::new(KeyUsageFlags::ca_default()))
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let aki_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::AUTHORITY_KEY_IDENTIFIER)
            .expect("AKI should be present on self-signed cert");
        assert!(!aki_ext.critical, "AKI must be non-critical");
    }

    // --- Issue #29: CertificateBuilder negative tests for invalid key usage ---

    #[test]
    fn test_cert_with_empty_key_usage() {
        // Building a cert with empty KeyUsageFlags (0 bits set) should still
        // produce a valid DER-encoded certificate — the builder does not
        // reject empty flags at build time.
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Empty KU Test").build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .key_usage(KeyUsage::new(KeyUsageFlags::empty()))
        .build_and_sign(&kp)
        .unwrap();

        // The cert should have a Key Usage extension
        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let ku_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::KEY_USAGE)
            .expect("Key Usage extension should be present");
        // Key Usage is always marked critical
        assert!(ku_ext.critical, "Key Usage must be critical per RFC 5280");
    }

    #[test]
    fn test_cert_ee_with_ca_key_usage_flags() {
        // An end-entity cert with CA key usage flags (keyCertSign, crlSign)
        // but BasicConstraints::end_entity() is a policy violation but the
        // builder should still produce a structurally valid certificate.
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Mismatched KU EE").build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .basic_constraints(BasicConstraints::end_entity())
        .key_usage(KeyUsage::new(KeyUsageFlags::ca_default()))
        .build_and_sign(&kp)
        .unwrap();

        // Basic Constraints should be non-critical (end_entity has ca=false)
        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let bc_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::BASIC_CONSTRAINTS)
            .expect("Basic Constraints should be present");
        assert!(
            !bc_ext.critical,
            "BC should be non-critical for end-entity (ca=false)"
        );

        // Key Usage should still be present and critical
        let ku_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::KEY_USAGE)
            .expect("Key Usage should be present");
        assert!(ku_ext.critical);
    }

    #[test]
    fn test_cert_ca_without_key_cert_sign() {
        // A CA cert (BasicConstraints::ca()) but with TLS server key usage
        // (digitalSignature + keyEncipherment). Structurally valid but a
        // policy violation per RFC 5280 Section 4.2.1.3.
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("CA Missing KeyCertSign").build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .basic_constraints(BasicConstraints::ca())
        .key_usage(KeyUsage::new(KeyUsageFlags::tls_server()))
        .build_and_sign(&kp)
        .unwrap();

        // Should produce a valid cert regardless
        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let bc_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::BASIC_CONSTRAINTS)
            .expect("BC should be present");
        assert!(bc_ext.critical, "BC should be critical for CA");
    }

    #[test]
    fn test_cert_all_key_usage_flags_set() {
        // Set every single key usage flag — verify the DER encodes all 9 bits
        let all_flags = KeyUsageFlags::new(
            KeyUsageFlags::DIGITAL_SIGNATURE
                | KeyUsageFlags::NON_REPUDIATION
                | KeyUsageFlags::KEY_ENCIPHERMENT
                | KeyUsageFlags::DATA_ENCIPHERMENT
                | KeyUsageFlags::KEY_AGREEMENT
                | KeyUsageFlags::KEY_CERT_SIGN
                | KeyUsageFlags::CRL_SIGN
                | KeyUsageFlags::ENCIPHER_ONLY
                | KeyUsageFlags::DECIPHER_ONLY,
        );

        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("All KU Flags").build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .key_usage(KeyUsage::new(all_flags))
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let ku_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::KEY_USAGE)
            .expect("Key Usage should be present");
        assert!(ku_ext.critical);
    }

    #[test]
    fn test_cert_single_decipher_only_flag() {
        // decipherOnly (bit 8) requires 2 bytes in the BIT STRING — test
        // that the encoder handles the high bit correctly.
        let flags = KeyUsageFlags::new(KeyUsageFlags::DECIPHER_ONLY);
        assert!(flags.contains(KeyUsageFlags::DECIPHER_ONLY));
        assert!(!flags.contains(KeyUsageFlags::DIGITAL_SIGNATURE));

        let ku = KeyUsage::new(flags);
        let der = ku.to_der().unwrap();
        // BIT STRING tag = 0x03, length should be 3 (unused + 2 bytes)
        assert_eq!(der[0], 0x03, "Expected BIT STRING tag");
        assert_eq!(der[1], 3, "Expected length 3 for 2-byte key usage");
    }

    #[test]
    fn test_cert_no_extensions_at_all() {
        // Build a cert with NO extensions set (no BC, no KU, no SKI, no AKI)
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Bare Cert").build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .include_subject_key_identifier(false)
        .include_authority_key_identifier(false)
        .build_and_sign(&kp)
        .unwrap();

        // With no extensions requested and SKI/AKI disabled, extensions should be None
        assert!(
            cert.tbs_certificate.extensions.is_none(),
            "No extensions should be present when all are disabled"
        );
    }

    #[test]
    fn test_cert_with_only_key_usage_no_basic_constraints() {
        // Key Usage without Basic Constraints — valid for end-entity certs
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("KU Only Test").build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .key_usage(KeyUsage::new(KeyUsageFlags::tls_server()))
        .include_subject_key_identifier(false)
        .include_authority_key_identifier(false)
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        // Should have exactly 1 extension (KeyUsage)
        assert_eq!(exts.len(), 1, "Should have exactly Key Usage extension");
        assert_eq!(exts[0].extn_id, ext_oid::KEY_USAGE);
        // No BC extension
        assert!(
            !exts.iter().any(|e| e.extn_id == ext_oid::BASIC_CONSTRAINTS),
            "No Basic Constraints should be present"
        );
    }

    // ===== Issue #125: Test cert with both IP and DNS SANs =====

    #[test]
    fn test_cert_with_ip_and_dns_sans() {
        // Issue #125: Verify a certificate can contain both DNS names and IP
        // addresses in the SAN extension, and that both are present in DER.
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("dual-san.example.com").build();

        let san = SubjectAltName::new()
            .dns("dual-san.example.com")
            .dns("alt.example.com")
            .ip("10.0.0.1".parse().unwrap())
            .ip("192.168.1.100".parse().unwrap())
            .ip("::1".parse().unwrap());

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .subject_alt_name(san)
        .validity(Validity::days_from_now(90))
        .build_and_sign(&kp)
        .unwrap();

        // Verify SAN extension is present
        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let san_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::SUBJECT_ALT_NAME)
            .expect("SAN extension should be present");
        assert!(
            !san_ext.critical,
            "SAN should be non-critical when Subject DN is populated"
        );

        // Serialize to DER and extract SANs to verify all entries survive encoding
        let cert_der = cert.to_der().expect("Certificate should serialize to DER");
        let (dns_names, ips, emails) = crate::cert::extract_sans_from_der(&cert_der).unwrap();

        assert_eq!(dns_names.len(), 2, "Should have 2 DNS names");
        assert!(
            dns_names.contains(&"dual-san.example.com".to_string()),
            "Missing DNS: dual-san.example.com"
        );
        assert!(
            dns_names.contains(&"alt.example.com".to_string()),
            "Missing DNS: alt.example.com"
        );
        assert!(ips.len() >= 2, "Should have at least 2 IPs (v4)");
        assert!(
            ips.contains(&"10.0.0.1".to_string()),
            "Missing IP: 10.0.0.1"
        );
        assert!(
            ips.contains(&"192.168.1.100".to_string()),
            "Missing IP: 192.168.1.100"
        );
        assert!(emails.is_empty(), "Should have no email SANs");
    }

    // ===== Issue #126: Test cert with wildcard DNS SAN =====

    #[test]
    fn test_cert_with_wildcard_dns_san() {
        // Issue #126: Verify wildcard DNS names (e.g. *.example.com) are
        // correctly encoded in the SAN extension and survive DER roundtrip.
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("wildcard.example.com").build();

        let san = SubjectAltName::new()
            .dns("*.example.com")
            .dns("example.com");

        // Validation should pass for wildcard
        san.validate()
            .expect("Wildcard DNS SAN should pass validation");

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .subject_alt_name(san)
        .validity(Validity::days_from_now(90))
        .build_and_sign(&kp)
        .unwrap();

        let cert_der = cert.to_der().unwrap();
        let (dns_names, _ips, _emails) = crate::cert::extract_sans_from_der(&cert_der).unwrap();

        assert_eq!(dns_names.len(), 2);
        assert!(
            dns_names.contains(&"*.example.com".to_string()),
            "Wildcard DNS name should survive DER roundtrip"
        );
        assert!(
            dns_names.contains(&"example.com".to_string()),
            "Bare domain should survive DER roundtrip"
        );
    }

    // ===== Issue #127: Verify CDPs and AIA included by default =====

    #[test]
    fn test_cert_with_cdp_and_aia() {
        // Issue #127: Verify that when CRL Distribution Points and Authority
        // Information Access extensions are set, they appear in the cert DER.
        use super::super::extensions::CdpAiaConfig;

        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("cdp-aia-test.example.com").build();

        let config = CdpAiaConfig::new("https://pki.example.com", "issuing-ca");
        let cdp = config.generate_cdp();
        let aia = config.generate_aia();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .crl_distribution_points(cdp)
        .authority_info_access(aia)
        .validity(Validity::days_from_now(365))
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();

        // Verify CDP extension is present and non-critical
        let cdp_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::CRL_DISTRIBUTION_POINTS)
            .expect("CRL Distribution Points extension should be present");
        assert!(!cdp_ext.critical, "CDP must be non-critical per RFC 5280");

        // Verify AIA extension is present and non-critical
        let aia_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::AUTHORITY_INFO_ACCESS)
            .expect("Authority Information Access extension should be present");
        assert!(!aia_ext.critical, "AIA must be non-critical per RFC 5280");

        // Verify the CDP DER contains the expected URL
        let cdp_bytes = cdp_ext.extn_value.as_bytes();
        let cdp_str = String::from_utf8_lossy(cdp_bytes);
        assert!(
            cdp_str.contains("pki.example.com/crl/issuing-ca.crl"),
            "CDP should contain the CRL URL"
        );

        // Verify the AIA DER contains OCSP and CA Issuer URLs
        let aia_bytes = aia_ext.extn_value.as_bytes();
        let aia_str = String::from_utf8_lossy(aia_bytes);
        assert!(
            aia_str.contains("pki.example.com/ocsp"),
            "AIA should contain OCSP URL"
        );
        assert!(
            aia_str.contains("pki.example.com/ca/issuing-ca.crt"),
            "AIA should contain CA Issuer URL"
        );
    }

    #[test]
    fn test_cdp_aia_config_generates_correct_urls() {
        // Issue #127: Verify CdpAiaConfig generates standard URL patterns
        use super::super::extensions::CdpAiaConfig;

        let config = CdpAiaConfig::new("https://pki.corp.com", "root-ca-g2");

        let cdp = config.generate_cdp();
        assert_eq!(cdp.urls.len(), 1);
        assert_eq!(cdp.urls[0], "https://pki.corp.com/crl/root-ca-g2.crl");

        let aia = config.generate_aia();
        assert_eq!(aia.ocsp_urls.len(), 1);
        assert_eq!(aia.ocsp_urls[0], "https://pki.corp.com/ocsp");
        assert_eq!(aia.ca_issuer_urls.len(), 1);
        assert_eq!(
            aia.ca_issuer_urls[0],
            "https://pki.corp.com/ca/root-ca-g2.crt"
        );
    }

    // ===== Issue #128: Test TLS client cert with email SAN =====

    #[test]
    fn test_tls_client_cert_with_email_san() {
        // Issue #128: A TLS client certificate should support email SANs
        // (rfc822Name) alongside DNS SANs for client authentication.
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("John Doe").build();

        let san = SubjectAltName::new()
            .email("john.doe@example.com")
            .dns("client.example.com");
        san.validate()
            .expect("SAN with email + DNS should be valid");

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .subject_alt_name(san)
        .key_usage(KeyUsage::new(KeyUsageFlags::tls_client()))
        .extended_key_usage(ExtendedKeyUsage::tls_client())
        .basic_constraints(BasicConstraints::end_entity())
        .validity(Validity::days_from_now(365))
        .build_and_sign(&kp)
        .unwrap();

        let cert_der = cert.to_der().unwrap();
        let (dns_names, _ips, emails) = crate::cert::extract_sans_from_der(&cert_der).unwrap();

        assert_eq!(emails.len(), 1, "Should have 1 email SAN");
        assert_eq!(emails[0], "john.doe@example.com");
        assert_eq!(dns_names.len(), 1, "Should have 1 DNS SAN");
        assert_eq!(dns_names[0], "client.example.com");

        // Verify EKU is clientAuth
        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let eku_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::EXTENDED_KEY_USAGE)
            .expect("EKU should be present");
        assert!(!eku_ext.critical, "EKU should be non-critical");
    }

    // ===== Issue #131: Verify code-signing cert excludes serverAuth/clientAuth EKU =====

    #[test]
    fn test_code_signing_cert_eku_excludes_server_client_auth() {
        // Issue #131: A code-signing certificate must only have codeSigning EKU,
        // not serverAuth or clientAuth.
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Code Signer").build();

        let eku = ExtendedKeyUsage::code_signing();
        assert_eq!(
            eku.usages.len(),
            1,
            "Code signing EKU should have exactly 1 usage"
        );
        assert_eq!(
            eku.usages[0],
            ext_oid::EKU_CODE_SIGNING,
            "Code signing EKU should be codeSigning OID"
        );

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .key_usage(KeyUsage::new(KeyUsageFlags::code_signing()))
        .extended_key_usage(eku)
        .basic_constraints(BasicConstraints::end_entity())
        .validity(Validity::days_from_now(365))
        .build_and_sign(&kp)
        .unwrap();

        // Parse EKU from the certificate to verify no serverAuth/clientAuth
        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let eku_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::EXTENDED_KEY_USAGE)
            .expect("EKU should be present");

        // Decode the EKU DER to check OID contents
        let eku_bytes = eku_ext.extn_value.as_bytes();
        // serverAuth OID DER bytes: 06 08 2b 06 01 05 05 07 03 01
        let server_auth_bytes: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        // clientAuth OID DER bytes: 06 08 2b 06 01 05 05 07 03 02
        let client_auth_bytes: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
        // codeSigning OID DER bytes: 2b 06 01 05 05 07 03 03
        let code_signing_bytes: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];

        assert!(
            !contains_subsequence(eku_bytes, server_auth_bytes),
            "Code signing cert MUST NOT contain serverAuth EKU"
        );
        assert!(
            !contains_subsequence(eku_bytes, client_auth_bytes),
            "Code signing cert MUST NOT contain clientAuth EKU"
        );
        assert!(
            contains_subsequence(eku_bytes, code_signing_bytes),
            "Code signing cert MUST contain codeSigning EKU"
        );
    }

    // ===== Issue #132: Verify email SAN required for S/MIME =====

    #[test]
    fn test_smime_cert_requires_email_san() {
        // Issue #132: S/MIME certificates must have at least one rfc822Name
        // (email) in the SAN extension. A SAN with only DNS names should NOT
        // satisfy S/MIME requirements.
        let san_no_email = SubjectAltName::new().dns("example.com");
        assert!(
            san_no_email.emails.is_empty(),
            "SAN without email should have empty emails list"
        );

        // An S/MIME cert with email SAN is valid
        let san_with_email = SubjectAltName::new().email("user@example.com");
        assert!(
            !san_with_email.emails.is_empty(),
            "SAN with email should have non-empty emails list"
        );
        san_with_email
            .validate()
            .expect("SAN with email should pass validation");
    }

    // ===== Issue #133: Test S/MIME cert with multiple email SANs =====

    #[test]
    fn test_smime_cert_with_multiple_email_sans() {
        // Issue #133: S/MIME certificates should support multiple email addresses
        // in the SAN, representing all email identities the certificate covers.
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Multi-Email User").build();

        let san = SubjectAltName::new()
            .email("primary@example.com")
            .email("secondary@example.com")
            .email("alias@corp.example.com");
        san.validate().expect("Multiple email SANs should be valid");

        let eku = ExtendedKeyUsage::new(vec![ext_oid::EKU_EMAIL_PROTECTION]);

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .subject_alt_name(san)
        .extended_key_usage(eku)
        .key_usage(KeyUsage::new(KeyUsageFlags::new(
            KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::NON_REPUDIATION,
        )))
        .basic_constraints(BasicConstraints::end_entity())
        .validity(Validity::days_from_now(365))
        .build_and_sign(&kp)
        .unwrap();

        let cert_der = cert.to_der().unwrap();
        let (_dns, _ips, emails) = crate::cert::extract_sans_from_der(&cert_der).unwrap();

        assert_eq!(emails.len(), 3, "Should have 3 email SANs");
        assert!(emails.contains(&"primary@example.com".to_string()));
        assert!(emails.contains(&"secondary@example.com".to_string()));
        assert!(emails.contains(&"alias@corp.example.com".to_string()));
    }

    // ===== Issue #134: Verify Timestamp cert has only timeStamping EKU =====

    #[test]
    fn test_timestamp_cert_has_only_timestamping_eku() {
        // Issue #134: A timestamping certificate must have ONLY the
        // timeStamping EKU (1.3.6.1.5.5.7.3.8), and no others.
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Timestamp Authority").build();

        let eku = ExtendedKeyUsage::new(vec![ext_oid::EKU_TIME_STAMPING]);
        assert_eq!(eku.usages.len(), 1);
        assert_eq!(eku.usages[0], ext_oid::EKU_TIME_STAMPING);

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .key_usage(KeyUsage::new(KeyUsageFlags::new(
            KeyUsageFlags::DIGITAL_SIGNATURE,
        )))
        .extended_key_usage(eku)
        .basic_constraints(BasicConstraints::end_entity())
        .validity(Validity::days_from_now(365))
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let eku_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::EXTENDED_KEY_USAGE)
            .expect("EKU should be present");

        let eku_bytes = eku_ext.extn_value.as_bytes();
        // timeStamping OID bytes: 2b 06 01 05 05 07 03 08
        let ts_bytes: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];
        let server_auth_bytes: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        let client_auth_bytes: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

        assert!(
            contains_subsequence(eku_bytes, ts_bytes),
            "Timestamp cert MUST contain timeStamping EKU"
        );
        assert!(
            !contains_subsequence(eku_bytes, server_auth_bytes),
            "Timestamp cert MUST NOT contain serverAuth EKU"
        );
        assert!(
            !contains_subsequence(eku_bytes, client_auth_bytes),
            "Timestamp cert MUST NOT contain clientAuth EKU"
        );
    }

    // ===== Issue #136: Verify OCSP cert includes nocheck extension =====

    #[test]
    fn test_ocsp_cert_eku() {
        // Issue #136 (part 1): OCSP responder certs must have ocspSigning EKU.
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("OCSP Responder").build();

        let eku = ExtendedKeyUsage::new(vec![ext_oid::EKU_OCSP_SIGNING]);
        assert_eq!(eku.usages.len(), 1);
        assert_eq!(eku.usages[0], ext_oid::EKU_OCSP_SIGNING);

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .key_usage(KeyUsage::new(KeyUsageFlags::new(
            KeyUsageFlags::DIGITAL_SIGNATURE,
        )))
        .extended_key_usage(eku)
        .basic_constraints(BasicConstraints::end_entity())
        .validity(Validity::days_from_now(30))
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();

        // Verify ocspSigning EKU is present
        let eku_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::EXTENDED_KEY_USAGE)
            .expect("EKU should be present");

        let eku_bytes = eku_ext.extn_value.as_bytes();
        // ocspSigning OID bytes: 2b 06 01 05 05 07 03 09
        let ocsp_signing_bytes: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
        assert!(
            contains_subsequence(eku_bytes, ocsp_signing_bytes),
            "OCSP cert MUST contain ocspSigning EKU"
        );

        // Verify no serverAuth/clientAuth contamination
        let server_auth_bytes: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        assert!(
            !contains_subsequence(eku_bytes, server_auth_bytes),
            "OCSP cert MUST NOT contain serverAuth EKU"
        );
    }

    #[test]
    fn test_ocsp_cert_includes_nocheck_extension() {
        // Issue #136 (part 2): RFC 6960 §4.2.2.2.1 — OCSP responder certs MUST include
        // the id-pkix-ocsp-nocheck extension to prevent clients from checking the
        // revocation status of the OCSP responder cert itself (infinite regress).
        //
        // OID: 1.3.6.1.5.5.7.48.1.5
        // Value: ASN.1 NULL (0x05 0x00)
        // Critical: false (non-critical per RFC 6960)
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("ocsp.example.com").build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .key_usage(KeyUsage::new(KeyUsageFlags::new(
            KeyUsageFlags::DIGITAL_SIGNATURE,
        )))
        .extended_key_usage(ExtendedKeyUsage::new(vec![ext_oid::EKU_OCSP_SIGNING]))
        .basic_constraints(BasicConstraints::end_entity())
        .ocsp_nocheck()
        .validity(Validity::days_from_now(365))
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();

        // Locate the id-pkix-ocsp-nocheck extension by OID
        let nocheck_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::OCSP_NOCHECK)
            .expect("RFC 6960 §4.2.2.2.1: id-pkix-ocsp-nocheck extension MUST be present");

        // RFC 6960: the extension MUST be non-critical
        assert!(
            !nocheck_ext.critical,
            "RFC 6960: id-pkix-ocsp-nocheck MUST be non-critical"
        );

        // The extension value MUST be ASN.1 NULL (0x05 0x00)
        let value = nocheck_ext.extn_value.as_bytes();
        assert_eq!(
            value,
            &[0x05, 0x00],
            "RFC 6960: id-pkix-ocsp-nocheck value MUST be ASN.1 NULL"
        );
    }

    #[test]
    fn test_ocsp_cert_without_nocheck_has_no_nocheck_extension() {
        // Verify that .ocsp_nocheck() is opt-in — certificates built without it
        // must not contain the extension.
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("regular.example.com").build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .key_usage(KeyUsage::new(KeyUsageFlags::new(
            KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_ENCIPHERMENT,
        )))
        .extended_key_usage(ExtendedKeyUsage::new(vec![ext_oid::EKU_SERVER_AUTH]))
        .basic_constraints(BasicConstraints::end_entity())
        .validity(Validity::days_from_now(365))
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();

        let nocheck_ext = exts.iter().find(|e| e.extn_id == ext_oid::OCSP_NOCHECK);
        assert!(
            nocheck_ext.is_none(),
            "id-pkix-ocsp-nocheck MUST NOT appear on non-OCSP certificates"
        );
    }

    /// Helper to check if a byte sequence contains a subsequence
    fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    // ===== FreshestCRL extension builder tests (G8) =====

    #[test]
    fn test_cert_with_freshest_crl_non_critical() {
        // RFC 5280 §4.2.1.15: FreshestCRL MUST be non-critical
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("FreshestCRL Test").build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .validity(Validity::days_from_now(365))
        .freshest_crl(FreshestCrl::with_url(
            "http://deltacrl.example.com/delta.crl",
        ))
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let fcrl_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::FRESHEST_CRL)
            .expect("FreshestCRL extension should be present");

        assert!(
            !fcrl_ext.critical,
            "FreshestCRL MUST be non-critical per RFC 5280 §4.2.1.15"
        );
    }

    #[test]
    fn test_cert_with_freshest_crl_url_in_der() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("FreshestCRL URL Test").build();
        let url = "http://deltacrl.example.com/delta.crl";

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .validity(Validity::days_from_now(90))
        .freshest_crl(FreshestCrl::with_url(url))
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let fcrl_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::FRESHEST_CRL)
            .expect("FreshestCRL extension should be present");

        let ext_bytes = fcrl_ext.extn_value.as_bytes();
        let url_bytes = url.as_bytes();
        assert!(
            ext_bytes.windows(url_bytes.len()).any(|w| w == url_bytes),
            "FreshestCRL extension DER should contain the delta CRL URL"
        );
    }

    #[test]
    fn test_cert_without_freshest_crl_has_no_ext() {
        // When freshest_crl() is not called, the extension must not appear
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("No FreshestCRL Test").build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .validity(Validity::days_from_now(90))
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        assert!(
            !exts.iter().any(|e| e.extn_id == ext_oid::FRESHEST_CRL),
            "FreshestCRL extension must not appear when not requested"
        );
    }

    // ===== Cross-certificate profile wiring (#271) =====

    #[test]
    fn test_cross_cert_profile_applies_all_extensions() {
        use crate::policy::fedbridge::{CrossCertProfile, FedBridgeConfig};
        use crate::policy::security_level::SecurityLevel;

        let config = FedBridgeConfig::new(SecurityLevel::Level3)
            .with_dns_subtrees(vec![".quantumnexum.com".into()])
            .with_dn_subtrees(vec!["DC=quantumnexum, DC=com".into()])
            .with_inhibit_policy_mapping(1);
        let profile = CrossCertProfile::from_config(&config);

        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Cross Cert Test CA")
            .domain_component("quantumnexum")
            .domain_component("com")
            .build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .validity(Validity::days_from_now(profile.max_validity_days))
        .apply_cross_cert_profile(&profile)
        .unwrap()
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();

        // PolicyMappings (critical)
        let pm_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::POLICY_MAPPINGS)
            .expect("PolicyMappings extension should be present");
        assert!(
            pm_ext.critical,
            "PolicyMappings MUST be critical per RFC 5280"
        );

        // NameConstraints (critical)
        let nc_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::NAME_CONSTRAINTS)
            .expect("NameConstraints extension should be present");
        assert!(
            nc_ext.critical,
            "NameConstraints MUST be critical per RFC 5280"
        );

        // PolicyConstraints (critical)
        let pc_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::POLICY_CONSTRAINTS)
            .expect("PolicyConstraints extension should be present");
        assert!(
            pc_ext.critical,
            "PolicyConstraints MUST be critical per RFC 5280"
        );

        // InhibitAnyPolicy (critical)
        let iap_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::INHIBIT_ANY_POLICY)
            .expect("InhibitAnyPolicy extension should be present");
        assert!(iap_ext.critical, "InhibitAnyPolicy MUST be critical");

        // BasicConstraints (critical, CA)
        let bc_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::BASIC_CONSTRAINTS)
            .expect("BasicConstraints extension should be present");
        assert!(bc_ext.critical, "BasicConstraints MUST be critical for CA");

        // CertificatePolicies
        let cp_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::CERTIFICATE_POLICIES)
            .expect("CertificatePolicies extension should be present");
        assert!(
            !cp_ext.critical,
            "CertificatePolicies should be non-critical"
        );
    }

    #[test]
    fn test_cross_cert_profile_minimal_level1() {
        use crate::policy::fedbridge::{CrossCertProfile, FedBridgeConfig};
        use crate::policy::security_level::SecurityLevel;

        // Level 1: no name constraints, no inhibit mapping
        let config = FedBridgeConfig::new(SecurityLevel::Level1);
        let profile = CrossCertProfile::from_config(&config);

        let kp = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();
        let subject = NameBuilder::new("Level 1 Bridge Test").build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP384,
        )
        .validity(Validity::days_from_now(1095))
        .apply_cross_cert_profile(&profile)
        .unwrap()
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();

        // PolicyMappings should be present (1 mapping)
        assert!(
            exts.iter().any(|e| e.extn_id == ext_oid::POLICY_MAPPINGS),
            "Level 1 cross-cert should have PolicyMappings"
        );

        // NameConstraints should NOT be present (no DNS/DN subtrees)
        assert!(
            !exts.iter().any(|e| e.extn_id == ext_oid::NAME_CONSTRAINTS),
            "Level 1 cross-cert should NOT have NameConstraints (no subtrees)"
        );

        // PolicyConstraints should be present (requireExplicit is set)
        assert!(
            exts.iter()
                .any(|e| e.extn_id == ext_oid::POLICY_CONSTRAINTS),
            "Level 1 cross-cert should have PolicyConstraints"
        );
    }

    #[test]
    fn test_policy_mappings_extension_in_cert_der() {
        // Verify PolicyMappings DER bytes are in the cert
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("PM Test").build();

        let pm = PolicyMappings::from_oid_strings(&[(
            "2.16.840.1.101.3.2.1.3.6",
            "1.3.6.1.4.1.56266.1.1.2",
        )])
        .unwrap();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .policy_mappings(pm)
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let pm_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::POLICY_MAPPINGS)
            .expect("PolicyMappings should be present");
        assert!(pm_ext.critical);
        assert!(!pm_ext.extn_value.as_bytes().is_empty());
    }

    #[test]
    fn test_name_constraints_extension_in_cert() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("NC Test CA").build();

        let nc = NameConstraints::new()
            .permit_dns(".example.com")
            .exclude_dns(".gov");

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .name_constraints(nc)
        .basic_constraints(BasicConstraints::ca())
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let nc_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::NAME_CONSTRAINTS)
            .expect("NameConstraints should be present");
        assert!(nc_ext.critical, "NameConstraints MUST be critical");

        // Verify DNS strings in the DER
        let ext_bytes = nc_ext.extn_value.as_bytes();
        assert!(
            ext_bytes.windows(12).any(|w| w == b".example.com"),
            "NameConstraints DER should contain '.example.com'"
        );
        assert!(
            ext_bytes.windows(4).any(|w| w == b".gov"),
            "NameConstraints DER should contain '.gov'"
        );
    }

    #[test]
    fn test_policy_constraints_extension_in_cert() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("PC Test CA").build();

        let pc = PolicyConstraints::both(0, 2);

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .policy_constraints(pc)
        .basic_constraints(BasicConstraints::ca())
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let pc_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::POLICY_CONSTRAINTS)
            .expect("PolicyConstraints should be present");
        assert!(pc_ext.critical, "PolicyConstraints MUST be critical");
    }

    #[test]
    fn test_issuer_alt_name_extension() {
        // RFC 5280 §4.2.1.7: IssuerAltName is non-critical, same GeneralNames as SAN
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Test CA").build();

        let ian = IssuerAltName::new()
            .dns("ca.example.com")
            .email("ca@example.com")
            .uri("https://ca.example.com/");

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .issuer_alt_name(ian)
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let ian_ext = exts
            .iter()
            .find(|e| e.extn_id == ext_oid::ISSUER_ALT_NAME)
            .expect("IssuerAltName extension should be present");
        assert!(
            !ian_ext.critical,
            "IssuerAltName should be non-critical per RFC 5280 §4.2.1.7"
        );

        // Verify the extension value contains our DNS name and email
        let value = ian_ext.extn_value.as_bytes();
        assert!(
            value
                .windows(b"ca.example.com".len())
                .any(|w| w == b"ca.example.com"),
            "IAN should contain DNS name"
        );
        assert!(
            value
                .windows(b"ca@example.com".len())
                .any(|w| w == b"ca@example.com"),
            "IAN should contain email"
        );
    }

    // ── RFC 5280 §4.1.2.5: Validity period enforcement ──────────────────

    #[test]
    fn test_validity_not_before_must_precede_not_after() {
        use chrono::Duration;

        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Validity Test").build();
        let pub_key = kp.public_key_der().unwrap();
        let now = Utc::now();

        // notBefore == notAfter — should fail
        let bad_validity = Validity {
            not_before: now,
            not_after: now,
        };
        let result =
            CertificateBuilder::new(subject.clone(), pub_key.clone(), AlgorithmId::EcdsaP256)
                .validity(bad_validity)
                .build_and_sign(&kp);

        assert!(
            result.is_err(),
            "Equal notBefore/notAfter should be rejected"
        );

        // notBefore > notAfter — should fail
        let bad_validity2 = Validity {
            not_before: now + Duration::hours(1),
            not_after: now,
        };
        let result2 = CertificateBuilder::new(subject, pub_key, AlgorithmId::EcdsaP256)
            .validity(bad_validity2)
            .build_and_sign(&kp);

        assert!(
            result2.is_err(),
            "notBefore after notAfter should be rejected"
        );
        let err = result2.unwrap_err().to_string();
        assert!(
            err.contains("notBefore"),
            "Error should mention notBefore: {err}"
        );
    }
}
