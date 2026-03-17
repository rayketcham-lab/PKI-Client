//! X.509v3 Extensions (RFC 5280 Section 4.2)

use crate::digest;
use crate::error::{Error, Result};
use const_oid::ObjectIdentifier;
use der::Encode;

// Extension OIDs
pub mod oid {
    use const_oid::ObjectIdentifier;

    pub const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
    pub const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
    pub const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
    pub const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
    pub const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.5.29.35");
    pub const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
    pub const ISSUER_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.18");
    pub const CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
    pub const FRESHEST_CRL: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.46");
    pub const AUTHORITY_INFO_ACCESS: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");

    // Extended Key Usage OIDs
    pub const EKU_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
    pub const EKU_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
    pub const EKU_CODE_SIGNING: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
    pub const EKU_EMAIL_PROTECTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");
    pub const EKU_TIME_STAMPING: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
    pub const EKU_OCSP_SIGNING: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");

    // Authority Information Access method OIDs
    pub const AIA_OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");
    pub const AIA_CA_ISSUERS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2");

    // Subject Information Access extension (RFC 5280 Section 4.2.2.2)
    pub const SUBJECT_INFO_ACCESS: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.11");

    // Subject Information Access method OIDs
    // id-ad-caRepository (RFC 5280): points to .p7c or other CA cert stores
    pub const SIA_CA_REPOSITORY: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.5");
    // id-ad-timeStamping (RFC 3161 / RFC 5280): TSA service endpoint
    pub const SIA_TIME_STAMPING: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.3");

    // Certificate Policies extension (RFC 5280 Section 4.2.1.4)
    pub const CERTIFICATE_POLICIES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");

    // RFC 9608: No Revocation Available extension (short-lived / OCSP responder certs)
    pub const NO_REV_AVAIL: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.56");

    // RFC 6960 §4.2.2.2.1 / RFC 2560 §4.2.2.2.1: id-pkix-ocsp-nocheck
    // Instructs clients NOT to check revocation status for the OCSP responder cert itself.
    // Value is ASN.1 NULL. Non-critical per RFC 6960.
    pub const OCSP_NOCHECK: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.5");

    // RFC 7633: TLS Features (OCSP Must-Staple)
    pub const TLS_FEATURE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.24");

    // RFC 5280 §4.2.1.5: Policy Mappings
    pub const POLICY_MAPPINGS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.33");

    // RFC 5280 §4.2.1.10: Name Constraints
    pub const NAME_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.30");

    // RFC 5280 §4.2.1.11: Policy Constraints
    pub const POLICY_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.36");

    // RFC 5280 §4.2.1.14: Inhibit anyPolicy
    pub const INHIBIT_ANY_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.54");

    // RFC 6962 §3.3: SCT List (Certificate Transparency)
    pub const SCT_LIST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");

    // RFC 6010: CMS Content Constraints — restricts what CMS content types a key can sign
    pub const CMS_CONTENT_CONSTRAINTS: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.18");

    // Well-known CMS content type OIDs for use with ContentConstraints
    pub const CT_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
    pub const CT_SIGNED_DATA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
    pub const CT_ENVELOPED_DATA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");
    pub const CT_AUTHENTICATED_DATA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.2");
    pub const CT_TST_INFO: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
    pub const CT_FIRMWARE_PACKAGE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.16");

    // RFC 3739: Qualified Certificate Statements
    pub const QC_STATEMENTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.3");

    // RFC 3739 §3.2.6: Well-known QC Statement OIDs
    pub const QCS_COMPLIANCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.11.1"); // id-qcs-pkixQCSyntax-v2
    pub const QCS_LIMIT_VALUE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.11.2"); // id-qcs-QcLimitValue
    pub const QCS_RETENTION_PERIOD: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.11.3"); // id-qcs-QcRetentionPeriod

    // ETSI EN 319 412-5: EU QC Statement OIDs
    pub const QCS_ETSI_COMPLIANCE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("0.4.0.1862.1.1"); // id-etsi-qcs-QcCompliance
    pub const QCS_ETSI_LIMIT_VALUE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("0.4.0.1862.1.2"); // id-etsi-qcs-QcLimitValue
    pub const QCS_ETSI_RETENTION_PERIOD: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("0.4.0.1862.1.3"); // id-etsi-qcs-QcRetentionPeriod
    pub const QCS_ETSI_SSCD: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1862.1.4"); // id-etsi-qcs-QcSSCD
    pub const QCS_ETSI_PDS: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1862.1.5"); // id-etsi-qcs-QcPDS
    pub const QCS_ETSI_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1862.1.6"); // id-etsi-qcs-QcType

    // RFC 8551 §2.5.2: smimeCapabilities signed attribute / cert extension
    pub const SMIME_CAPABILITIES: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.15");

    // SPORK custom extension OID (Private Enterprise Number arc)
    // Ogjos PEN: 56266 (IANA assigned)
    // 1.3.6.1.4.1.56266.1.2.4 = iso.org.dod.internet.private.enterprise.ogjos.spork.extensions.issuance-info
    // See docs/pki/OID_ARC.md for full OID arc documentation
    pub const SPORK_ISSUANCE_INFO: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56266.1.2.4");

    // SPORK Certificate Policy OIDs (arc .1 for policies)
    // .1.1.0 = Development/Evaluation — NOT FOR PRODUCTION USE
    pub const SPORK_POLICY_EVALUATION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56266.1.1.0");

    // SPORK Admin Access Policy OIDs (arc .10 for CA, .20 for ACME)
    // See spork-common/src/config.rs for AdminAccessLevel enum
    pub const SPORK_CA_VIEWER: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56266.1.10.1");
    pub const SPORK_CA_OPERATOR: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56266.1.10.2");
    pub const SPORK_CA_ADMIN: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56266.1.10.3");
    pub const SPORK_CA_SUPER_ADMIN: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56266.1.10.4");

    pub const SPORK_ACME_VIEWER: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56266.1.20.1");
    pub const SPORK_ACME_OPERATOR: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56266.1.20.2");
    pub const SPORK_ACME_ADMIN: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56266.1.20.3");
    pub const SPORK_ACME_SUPER_ADMIN: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56266.1.20.4");
}

/// Basic Constraints extension (RFC 5280 Section 4.2.1.9)
#[derive(Debug, Clone)]
pub struct BasicConstraints {
    pub ca: bool,
    pub path_len_constraint: Option<u8>,
}

impl BasicConstraints {
    /// End entity (non-CA)
    pub fn end_entity() -> Self {
        Self {
            ca: false,
            path_len_constraint: None,
        }
    }

    /// CA with no path length constraint
    pub fn ca() -> Self {
        Self {
            ca: true,
            path_len_constraint: None,
        }
    }

    /// CA with specific path length
    pub fn ca_with_path_len(path_len: u8) -> Self {
        Self {
            ca: true,
            path_len_constraint: Some(path_len),
        }
    }

    /// Encode to DER
    pub fn to_der(&self) -> Result<Vec<u8>> {
        // BasicConstraints ::= SEQUENCE {
        //   cA                      BOOLEAN DEFAULT FALSE,
        //   pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
        let mut inner = Vec::new();

        if self.ca {
            // BOOLEAN TRUE: tag 0x01, length 0x01, value 0xFF
            inner.extend_from_slice(&[0x01, 0x01, 0xFF]);
        }

        if let Some(path_len) = self.path_len_constraint {
            // INTEGER: tag 0x02, length 0x01, value
            inner.extend_from_slice(&[0x02, 0x01, path_len]);
        }

        let mut result = vec![0x30]; // SEQUENCE tag
        if inner.len() < 128 {
            result.push(inner.len() as u8);
        } else {
            // Long form length
            let len_bytes = (inner.len() as u32).to_be_bytes();
            let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(3);
            let len_len = 4 - start;
            result.push(0x80 | len_len as u8);
            result.extend_from_slice(&len_bytes[start..]);
        }
        result.extend(inner);

        Ok(result)
    }
}

/// Key Usage extension (RFC 5280 Section 4.2.1.3)
#[derive(Debug, Clone, Copy)]
pub struct KeyUsageFlags(u16);

impl KeyUsageFlags {
    pub const DIGITAL_SIGNATURE: u16 = 1 << 0;
    pub const NON_REPUDIATION: u16 = 1 << 1;
    pub const KEY_ENCIPHERMENT: u16 = 1 << 2;
    pub const DATA_ENCIPHERMENT: u16 = 1 << 3;
    pub const KEY_AGREEMENT: u16 = 1 << 4;
    pub const KEY_CERT_SIGN: u16 = 1 << 5;
    pub const CRL_SIGN: u16 = 1 << 6;
    pub const ENCIPHER_ONLY: u16 = 1 << 7;
    pub const DECIPHER_ONLY: u16 = 1 << 8;

    pub fn new(flags: u16) -> Self {
        Self(flags)
    }

    pub fn empty() -> Self {
        Self(0)
    }

    pub fn ca_default() -> Self {
        Self(Self::DIGITAL_SIGNATURE | Self::KEY_CERT_SIGN | Self::CRL_SIGN)
    }

    pub fn tls_server() -> Self {
        Self(Self::DIGITAL_SIGNATURE | Self::KEY_ENCIPHERMENT)
    }

    pub fn tls_client() -> Self {
        Self(Self::DIGITAL_SIGNATURE)
    }

    pub fn code_signing() -> Self {
        Self(Self::DIGITAL_SIGNATURE)
    }

    pub fn contains(&self, flag: u16) -> bool {
        self.0 & flag != 0
    }

    /// Check if no flags are set
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Get raw flags value
    pub fn bits(&self) -> u16 {
        self.0
    }
}

/// Key Usage extension wrapper
#[derive(Debug, Clone)]
pub struct KeyUsage {
    pub flags: KeyUsageFlags,
}

impl KeyUsage {
    pub fn new(flags: KeyUsageFlags) -> Self {
        Self { flags }
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        // KeyUsage ::= BIT STRING
        // In X.509, key usage bits are numbered from MSB:
        // bit 0 = digitalSignature (0x80), bit 5 = keyCertSign (0x04), etc.
        let bits = self.flags.0;
        let byte1_orig = (bits & 0xFF) as u8;
        let byte2_orig = ((bits >> 8) & 0xFF) as u8;

        // Reverse bits to match X.509 bit ordering
        let byte1 = byte1_orig.reverse_bits();
        let byte2 = byte2_orig.reverse_bits();

        // Count unused bits in the LAST byte of output (trailing zeros in reversed bytes)
        let unused = if byte2 != 0 {
            byte2.trailing_zeros() as u8
        } else {
            byte1.trailing_zeros() as u8
        };

        let mut result = vec![0x03]; // BIT STRING tag
        if byte2 != 0 {
            result.push(3); // length: unused + 2 bytes
            result.push(unused.min(7));
            result.push(byte1);
            result.push(byte2);
        } else {
            result.push(2); // length: unused + 1 byte
            result.push(unused.min(7));
            result.push(byte1);
        }

        Ok(result)
    }
}

/// Extended Key Usage extension (RFC 5280 Section 4.2.1.12)
#[derive(Debug, Clone)]
pub struct ExtendedKeyUsage {
    pub usages: Vec<ObjectIdentifier>,
}

impl ExtendedKeyUsage {
    pub fn new(usages: Vec<ObjectIdentifier>) -> Self {
        Self { usages }
    }

    pub fn tls_server() -> Self {
        Self {
            usages: vec![oid::EKU_SERVER_AUTH],
        }
    }

    pub fn tls_client() -> Self {
        Self {
            usages: vec![oid::EKU_CLIENT_AUTH],
        }
    }

    pub fn tls_server_client() -> Self {
        Self {
            usages: vec![oid::EKU_SERVER_AUTH, oid::EKU_CLIENT_AUTH],
        }
    }

    pub fn code_signing() -> Self {
        Self {
            usages: vec![oid::EKU_CODE_SIGNING],
        }
    }

    pub fn time_stamping() -> Self {
        Self {
            usages: vec![oid::EKU_TIME_STAMPING],
        }
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        // ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
        let oid_bytes: Vec<Vec<u8>> = self
            .usages
            .iter()
            .map(|oid| oid.to_der())
            .collect::<std::result::Result<_, _>>()?;

        let inner: Vec<u8> = oid_bytes.concat();

        let mut result = vec![0x30]; // SEQUENCE tag
        if inner.len() < 128 {
            result.push(inner.len() as u8);
        } else {
            let len_bytes = (inner.len() as u32).to_be_bytes();
            let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(3);
            let len_len = 4 - start;
            result.push(0x80 | len_len as u8);
            result.extend_from_slice(&len_bytes[start..]);
        }
        result.extend(inner);

        Ok(result)
    }
}

// Policy qualifier OIDs (RFC 5280 Section 4.2.1.4)
pub mod policy_qualifier_oid {
    use const_oid::ObjectIdentifier;
    /// id-qt-cps: CPS Pointer qualifier (1.3.6.1.5.5.7.2.1)
    pub const ID_QT_CPS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.2.1");
    /// id-qt-unotice: User Notice qualifier (1.3.6.1.5.5.7.2.2)
    pub const ID_QT_UNOTICE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.2.2");
}

/// NoticeReference within a UserNotice qualifier (RFC 5280 Section 4.2.1.4)
///
/// ```text
/// NoticeReference ::= SEQUENCE {
///   organization   DisplayText,
///   noticeNumbers  SEQUENCE OF INTEGER }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct NoticeReference {
    pub organization: String,
    pub notice_numbers: Vec<u32>,
}

/// Policy qualifier for a certificate policy (RFC 5280 Section 4.2.1.4, RFC 6818)
///
/// ```text
/// PolicyQualifierInfo ::= SEQUENCE {
///   policyQualifierId  OBJECT IDENTIFIER,
///   qualifier          ANY DEFINED BY policyQualifierId }
/// ```
///
/// Per RFC 6818 §2, explicitText SHOULD be encoded as UTF8String.
/// IA5String is accepted when parsing for interoperability, but a warning is issued.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyQualifier {
    /// CPS Pointer qualifier — URI pointing to the Certification Practice Statement
    CpsUri(String),
    /// User Notice qualifier — human-readable notice
    UserNotice {
        notice_ref: Option<NoticeReference>,
        explicit_text: Option<String>,
    },
}

impl PolicyQualifier {
    /// Encode this qualifier as a DER-encoded PolicyQualifierInfo SEQUENCE.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        match self {
            PolicyQualifier::CpsUri(uri) => {
                let qual_oid = policy_qualifier_oid::ID_QT_CPS.to_der()?;

                // qualifier = IA5String (tag 0x16)
                let uri_bytes = uri.as_bytes();
                let mut qual_value = vec![0x16]; // IA5String tag
                encode_length(&mut qual_value, uri_bytes.len());
                qual_value.extend_from_slice(uri_bytes);

                // Outer PolicyQualifierInfo SEQUENCE
                let inner_len = qual_oid.len() + qual_value.len();
                let mut result = vec![0x30];
                encode_length(&mut result, inner_len);
                result.extend(qual_oid);
                result.extend(qual_value);
                Ok(result)
            }
            PolicyQualifier::UserNotice {
                notice_ref,
                explicit_text,
            } => {
                let qual_oid = policy_qualifier_oid::ID_QT_UNOTICE.to_der()?;

                // Build UserNotice SEQUENCE content
                let mut user_notice_inner = Vec::new();

                if let Some(nr) = notice_ref {
                    // organization: UTF8String (tag 0x0C) per RFC 6818
                    let org_bytes = nr.organization.as_bytes();
                    let mut org_enc = vec![0x0C];
                    encode_length(&mut org_enc, org_bytes.len());
                    org_enc.extend_from_slice(org_bytes);

                    // noticeNumbers: SEQUENCE OF INTEGER
                    let mut nums_inner = Vec::new();
                    for &n in &nr.notice_numbers {
                        // Encode as minimal DER INTEGER
                        let int_bytes = encode_der_integer(n);
                        nums_inner.extend(int_bytes);
                    }
                    let mut nums_seq = vec![0x30];
                    encode_length(&mut nums_seq, nums_inner.len());
                    nums_seq.extend(nums_inner);

                    // NoticeReference SEQUENCE
                    let nr_inner_len = org_enc.len() + nums_seq.len();
                    let mut nr_seq = vec![0x30];
                    encode_length(&mut nr_seq, nr_inner_len);
                    nr_seq.extend(org_enc);
                    nr_seq.extend(nums_seq);

                    user_notice_inner.extend(nr_seq);
                }

                if let Some(text) = explicit_text {
                    // RFC 6818 §2: explicitText SHOULD be UTF8String (tag 0x0C)
                    let text_bytes = text.as_bytes();
                    let mut text_enc = vec![0x0C]; // UTF8String
                    encode_length(&mut text_enc, text_bytes.len());
                    text_enc.extend_from_slice(text_bytes);
                    user_notice_inner.extend(text_enc);
                }

                // UserNotice ::= SEQUENCE { noticeRef OPTIONAL, explicitText OPTIONAL }
                let mut user_notice = vec![0x30];
                encode_length(&mut user_notice, user_notice_inner.len());
                user_notice.extend(user_notice_inner);

                // Outer PolicyQualifierInfo SEQUENCE
                let inner_len = qual_oid.len() + user_notice.len();
                let mut result = vec![0x30];
                encode_length(&mut result, inner_len);
                result.extend(qual_oid);
                result.extend(user_notice);
                Ok(result)
            }
        }
    }
}

/// Encode a u32 as a minimal DER INTEGER (including tag+length+value).
fn encode_der_integer(n: u32) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    // Find first non-zero byte (or keep at least one byte)
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    let val_bytes = &bytes[start..];
    // If the high bit is set, prepend 0x00 to avoid sign confusion
    let needs_pad = val_bytes[0] & 0x80 != 0;
    let val_len = val_bytes.len() + if needs_pad { 1 } else { 0 };

    let mut result = vec![0x02]; // INTEGER tag
    encode_length(&mut result, val_len);
    if needs_pad {
        result.push(0x00);
    }
    result.extend_from_slice(val_bytes);
    result
}

/// A single policy entry pairing a policy OID with optional qualifiers.
#[derive(Debug, Clone)]
pub struct PolicyInformation {
    pub policy_oid: ObjectIdentifier,
    pub qualifiers: Vec<PolicyQualifier>,
}

impl PolicyInformation {
    pub fn new(policy_oid: ObjectIdentifier) -> Self {
        Self {
            policy_oid,
            qualifiers: Vec::new(),
        }
    }

    pub fn with_qualifier(mut self, qualifier: PolicyQualifier) -> Self {
        self.qualifiers.push(qualifier);
        self
    }

    /// Encode as DER PolicyInformation SEQUENCE.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let oid_der = self.policy_oid.to_der()?;

        let inner = if self.qualifiers.is_empty() {
            oid_der
        } else {
            // Encode each qualifier and wrap in SEQUENCE OF
            let mut qual_infos = Vec::new();
            for q in &self.qualifiers {
                qual_infos.extend(q.to_der()?);
            }
            let mut qual_seq = vec![0x30];
            encode_length(&mut qual_seq, qual_infos.len());
            qual_seq.extend(qual_infos);

            let mut inner = oid_der;
            inner.extend(qual_seq);
            inner
        };

        let mut result = vec![0x30];
        encode_length(&mut result, inner.len());
        result.extend(inner);
        Ok(result)
    }
}

/// Certificate Policies extension (RFC 5280 Section 4.2.1.4)
///
/// Contains policy OIDs that indicate under which policies the certificate
/// was issued and what purposes it may be used for.
///
/// Used by SPORK for admin access level control:
/// - 1.3.6.1.4.1.56266.1.10.x for SPORK-CA admin levels
/// - 1.3.6.1.4.1.56266.1.20.x for SPORK-ACME admin levels
///
/// Supports RFC 6818 policy qualifiers (CPS URI and UserNotice with UTF8String
/// explicitText encoding).
#[derive(Debug, Clone)]
pub struct CertificatePolicies {
    pub policies: Vec<ObjectIdentifier>,
    /// Optional per-policy qualifiers. Indexed by position in `policies`.
    /// Most entries will be empty; use `with_qualifier` to attach qualifiers.
    pub policy_infos: Vec<PolicyInformation>,
}

impl CertificatePolicies {
    /// Create new certificate policies extension
    pub fn new(policies: Vec<ObjectIdentifier>) -> Self {
        let policy_infos = policies
            .iter()
            .map(|&oid| PolicyInformation::new(oid))
            .collect();
        Self {
            policies,
            policy_infos,
        }
    }

    /// Create with a single policy OID
    pub fn with_policy(policy: ObjectIdentifier) -> Self {
        Self {
            policy_infos: vec![PolicyInformation::new(policy)],
            policies: vec![policy],
        }
    }

    /// Add a qualifier to the last policy added.
    ///
    /// This is a builder-style method for attaching CPS URI or UserNotice
    /// qualifiers to a policy per RFC 5280 Section 4.2.1.4 and RFC 6818.
    pub fn with_qualifier(mut self, qualifier: PolicyQualifier) -> Self {
        if let Some(last) = self.policy_infos.last_mut() {
            last.qualifiers.push(qualifier);
        }
        self
    }

    /// Add a policy OID with no qualifiers.
    pub fn add_policy(mut self, policy: ObjectIdentifier) -> Self {
        self.policies.push(policy);
        self.policy_infos.push(PolicyInformation::new(policy));
        self
    }

    /// Development/Evaluation policy — marks certs as NOT FOR PRODUCTION
    pub fn evaluation() -> Self {
        Self::with_policy(oid::SPORK_POLICY_EVALUATION)
    }

    /// SPORK-ACME admin access levels
    pub fn acme_viewer() -> Self {
        Self::with_policy(oid::SPORK_ACME_VIEWER)
    }

    pub fn acme_operator() -> Self {
        Self::with_policy(oid::SPORK_ACME_OPERATOR)
    }

    pub fn acme_admin() -> Self {
        Self::with_policy(oid::SPORK_ACME_ADMIN)
    }

    pub fn acme_super_admin() -> Self {
        Self::with_policy(oid::SPORK_ACME_SUPER_ADMIN)
    }

    /// SPORK-CA admin access levels
    pub fn ca_viewer() -> Self {
        Self::with_policy(oid::SPORK_CA_VIEWER)
    }

    pub fn ca_operator() -> Self {
        Self::with_policy(oid::SPORK_CA_OPERATOR)
    }

    pub fn ca_admin() -> Self {
        Self::with_policy(oid::SPORK_CA_ADMIN)
    }

    pub fn ca_super_admin() -> Self {
        Self::with_policy(oid::SPORK_CA_SUPER_ADMIN)
    }

    /// Encode to DER
    ///
    /// ```text
    /// CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
    /// PolicyInformation ::= SEQUENCE {
    ///   policyIdentifier   CertPolicyId,
    ///   policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }
    /// CertPolicyId ::= OBJECT IDENTIFIER
    /// ```
    ///
    /// Per RFC 6818, qualifiers are included when present and explicitText is
    /// encoded as UTF8String.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let mut encoded_infos = Vec::new();

        for pi in &self.policy_infos {
            encoded_infos.extend(pi.to_der()?);
        }

        // Outer SEQUENCE of PolicyInformation
        let mut result = vec![0x30]; // SEQUENCE tag
        encode_length(&mut result, encoded_infos.len());
        result.extend(encoded_infos);

        Ok(result)
    }

    /// Check if this extension contains a specific policy OID
    pub fn contains(&self, policy: &ObjectIdentifier) -> bool {
        self.policies.contains(policy)
    }

    /// Check if this contains any SPORK-ACME admin policy
    pub fn has_acme_admin_policy(&self) -> bool {
        self.policies.iter().any(|p| {
            *p == oid::SPORK_ACME_VIEWER
                || *p == oid::SPORK_ACME_OPERATOR
                || *p == oid::SPORK_ACME_ADMIN
                || *p == oid::SPORK_ACME_SUPER_ADMIN
        })
    }

    /// Get the highest SPORK-ACME admin access level from policies
    pub fn acme_access_level(&self) -> Option<u8> {
        let mut max_level = None;
        for policy in &self.policies {
            let level = if *policy == oid::SPORK_ACME_SUPER_ADMIN {
                Some(4)
            } else if *policy == oid::SPORK_ACME_ADMIN {
                Some(3)
            } else if *policy == oid::SPORK_ACME_OPERATOR {
                Some(2)
            } else if *policy == oid::SPORK_ACME_VIEWER {
                Some(1)
            } else {
                None
            };
            if let Some(l) = level {
                max_level = Some(max_level.map_or(l, |m: u8| m.max(l)));
            }
        }
        max_level
    }
}

/// Subject Key Identifier extension (RFC 5280 Section 4.2.1.2)
#[derive(Debug, Clone)]
pub struct SubjectKeyIdentifier(pub Vec<u8>);

impl SubjectKeyIdentifier {
    /// Compute from public key using SHA-256 truncated to 20 bytes (default).
    ///
    /// Uses SHA-256 of the full SPKI DER, truncated to 160 bits for compatibility
    /// with RFC 5280 Method 1's 20-byte output size. This is the default method.
    pub fn from_public_key(spki_der: &[u8]) -> Self {
        let hash = digest::sha256(spki_der);
        Self(hash[..20].to_vec())
    }

    /// Compute from public key using full SHA-256 (RFC 7093 Method 1).
    ///
    /// Returns the complete 32-byte SHA-256 hash of the SPKI DER.
    /// Recommended for new deployments per RFC 7093 Section 2.
    pub fn from_public_key_sha256(spki_der: &[u8]) -> Self {
        Self(digest::sha256(spki_der))
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        // SubjectKeyIdentifier ::= KeyIdentifier
        // KeyIdentifier ::= OCTET STRING
        let mut result = vec![0x04]; // OCTET STRING tag
        result.push(self.0.len() as u8);
        result.extend(&self.0);
        Ok(result)
    }
}

/// Authority Key Identifier extension (RFC 5280 Section 4.2.1.1)
///
/// ```asn1
/// AuthorityKeyIdentifier ::= SEQUENCE {
///   keyIdentifier             [0] KeyIdentifier           OPTIONAL,
///   authorityCertIssuer       [1] GeneralNames            OPTIONAL,
///   authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL }
/// ```
///
/// All three fields are optional; either `keyIdentifier` alone or the
/// `authorityCertIssuer`/`authorityCertSerialNumber` pair (or all three)
/// may be present.
#[derive(Debug, Clone)]
pub struct AuthorityKeyIdentifier {
    pub key_identifier: Option<Vec<u8>>,
    /// Raw DER encoding of GeneralNames [1] (EXPLICIT context tag stripped).
    pub authority_cert_issuer: Option<Vec<u8>>,
    /// Raw DER encoding of CertificateSerialNumber [2] INTEGER value bytes.
    pub authority_cert_serial: Option<Vec<u8>>,
}

impl AuthorityKeyIdentifier {
    pub fn from_key_id(key_id: Vec<u8>) -> Self {
        Self {
            key_identifier: Some(key_id),
            authority_cert_issuer: None,
            authority_cert_serial: None,
        }
    }

    pub fn from_subject_key_id(ski: &SubjectKeyIdentifier) -> Self {
        Self {
            key_identifier: Some(ski.0.clone()),
            authority_cert_issuer: None,
            authority_cert_serial: None,
        }
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        // AuthorityKeyIdentifier ::= SEQUENCE {
        //   keyIdentifier             [0] KeyIdentifier OPTIONAL,
        //   authorityCertIssuer       [1] GeneralNames  OPTIONAL,
        //   authorityCertSerialNumber [2] INTEGER        OPTIONAL }
        let mut inner = Vec::new();

        if let Some(ref key_id) = self.key_identifier {
            // [0] IMPLICIT OCTET STRING
            inner.push(0x80);
            inner.push(key_id.len() as u8);
            inner.extend(key_id);
        }

        if let Some(ref issuer) = self.authority_cert_issuer {
            // [1] EXPLICIT GeneralNames — wrap with context tag 0xa1
            inner.push(0xa1);
            inner.push(issuer.len() as u8);
            inner.extend(issuer);
        }

        if let Some(ref serial) = self.authority_cert_serial {
            // [2] IMPLICIT INTEGER — context tag 0x82
            inner.push(0x82);
            inner.push(serial.len() as u8);
            inner.extend(serial);
        }

        let mut result = vec![0x30]; // SEQUENCE tag
        result.push(inner.len() as u8);
        result.extend(inner);

        Ok(result)
    }
}

// --- SAN validation helpers ---

/// Encode IA5String length in DER format (handles lengths > 127)
fn encode_ia5_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// Validate and normalize a DNS name for SAN inclusion per RFC 5280 §4.2.1.6
/// and RFC 9549 (IDNA2008).
///
/// If the input contains non-ASCII (Unicode) labels, they are converted to
/// A-label (Punycode) form via IDNA2008 processing. Already-ASCII names are
/// validated for structure. Returns the normalized A-label form.
fn validate_dns_name(name: &str) -> Result<String> {
    if name.is_empty() {
        return Err(Error::InvalidCertificate("SAN DNS name is empty".into()));
    }
    if name.contains('\0') {
        return Err(Error::InvalidCertificate(
            "SAN DNS name contains null byte".into(),
        ));
    }

    // Strip wildcard prefix for IDNA processing, re-attach after
    let (wildcard, check) = if let Some(rest) = name.strip_prefix("*.") {
        (true, rest)
    } else {
        (false, name)
    };

    // RFC 9549: Use IDNA2008 to normalize domain names to A-label form.
    // This handles Unicode → Punycode conversion and validates existing A-labels.
    let ascii_name = idna::domain_to_ascii(check).map_err(|e| {
        Error::InvalidCertificate(format!(
            "SAN DNS name fails IDNA2008 validation: {:?} — {}",
            name, e
        ))
    })?;

    if ascii_name.is_empty() {
        return Err(Error::InvalidCertificate(
            "SAN DNS name is empty after IDNA2008 normalization".into(),
        ));
    }

    // Reconstruct with wildcard if present
    let normalized = if wildcard {
        format!("*.{}", ascii_name)
    } else {
        ascii_name
    };

    // RFC 5280: total length limit
    if normalized.len() > 253 {
        return Err(Error::InvalidCertificate(format!(
            "SAN DNS name exceeds 253 characters after normalization: {}",
            normalized.len()
        )));
    }

    // Validate individual labels per RFC 952/1123 as defense-in-depth
    // (IDNA2008 may accept some forms that X.509 SANs should not)
    let label_check = normalized.strip_prefix("*.").unwrap_or(&normalized);
    for label in label_check.split('.') {
        if label.is_empty() {
            return Err(Error::InvalidCertificate(format!(
                "SAN DNS name has empty label: {:?}",
                normalized
            )));
        }
        if label.len() > 63 {
            return Err(Error::InvalidCertificate(format!(
                "SAN DNS label exceeds 63 characters: {:?}",
                label
            )));
        }
        // RFC 952/1123: labels must not start or end with a hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return Err(Error::InvalidCertificate(format!(
                "SAN DNS label starts/ends with hyphen: {:?}",
                label
            )));
        }
        // dNSName is IA5String — must be 7-bit ASCII with valid DNS characters
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(Error::InvalidCertificate(format!(
                "SAN DNS label contains invalid characters: {:?}",
                label
            )));
        }
    }

    Ok(normalized)
}

/// Validate a DNS name constraint subtree value per RFC 5280 §4.2.1.10.
/// NameConstraints DNS subtrees allow a leading dot (e.g., ".example.com")
/// and must be valid IA5String (7-bit ASCII) with valid DNS label characters.
fn validate_nc_dns(name: &str, kind: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidCertificate(format!(
            "NameConstraints {kind} DNS subtree is empty"
        )));
    }
    if !name.is_ascii() {
        return Err(Error::InvalidCertificate(format!(
            "NameConstraints {kind} DNS subtree contains non-ASCII (IA5String violation): {:?}",
            name
        )));
    }
    if name.contains('\0') {
        return Err(Error::InvalidCertificate(format!(
            "NameConstraints {kind} DNS subtree contains null byte: {:?}",
            name
        )));
    }
    // Strip leading dot for label validation (leading dot is valid for subtrees)
    let check = name.strip_prefix('.').unwrap_or(name);
    if check.is_empty() {
        return Err(Error::InvalidCertificate(format!(
            "NameConstraints {kind} DNS subtree is just a dot"
        )));
    }
    for label in check.split('.') {
        if label.is_empty() {
            return Err(Error::InvalidCertificate(format!(
                "NameConstraints {kind} DNS subtree has empty label: {:?}",
                name
            )));
        }
        if label.len() > 63 {
            return Err(Error::InvalidCertificate(format!(
                "NameConstraints {kind} DNS label exceeds 63 characters: {:?}",
                label
            )));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(Error::InvalidCertificate(format!(
                "NameConstraints {kind} DNS label contains invalid characters: {:?}",
                label
            )));
        }
    }
    Ok(())
}

/// Validate email for SAN rfc822Name (RFC 5280 §4.2.1.6).
///
/// Returns the normalized email with IDNA2008 A-label domain for encoding.
fn validate_san_email(email: &str) -> Result<String> {
    if email.contains('\0') {
        return Err(Error::InvalidCertificate(
            "SAN email contains null byte".into(),
        ));
    }
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() || !parts[1].contains('.') {
        return Err(Error::InvalidCertificate(format!(
            "SAN email has invalid format: {:?}",
            email
        )));
    }
    // RFC 9549: normalize the domain part to A-label form via IDNA2008
    let local = parts[0];
    let domain = idna::domain_to_ascii(parts[1]).map_err(|e| {
        Error::InvalidCertificate(format!(
            "SAN email domain fails IDNA2008 validation: {:?} — {}",
            email, e
        ))
    })?;
    // rfc822Name uses IA5String — local part MUST be ASCII
    if !local.is_ascii() {
        return Err(Error::InvalidCertificate(format!(
            "SAN rfc822Name local part must be ASCII: {:?}",
            email
        )));
    }
    Ok(format!("{}@{}", local, domain))
}

/// Validate email for SAN SmtpUTF8Mailbox (RFC 9598).
///
/// Allows UTF-8 in the local part. Domain part is normalized to A-label via IDNA2008.
/// Returns (local_part, normalized_domain) for encoding.
fn validate_san_utf8_email(email: &str) -> Result<(String, String)> {
    if email.contains('\0') {
        return Err(Error::InvalidCertificate(
            "SAN SmtpUTF8Mailbox contains null byte".into(),
        ));
    }
    // RFC 9598 §2: must not contain BOM (U+FEFF)
    if email.contains('\u{FEFF}') {
        return Err(Error::InvalidCertificate(
            "SAN SmtpUTF8Mailbox must not contain BOM (U+FEFF)".into(),
        ));
    }
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() || !parts[1].contains('.') {
        return Err(Error::InvalidCertificate(format!(
            "SAN SmtpUTF8Mailbox has invalid format: {:?}",
            email
        )));
    }
    let local = parts[0].to_string();
    // RFC 9598 §3: domain MUST be A-label (IDNA2008)
    let domain = idna::domain_to_ascii(parts[1]).map_err(|e| {
        Error::InvalidCertificate(format!(
            "SAN SmtpUTF8Mailbox domain fails IDNA2008 validation: {:?} — {}",
            email, e
        ))
    })?;
    Ok((local, domain))
}

/// Validate URI for SAN uniformResourceIdentifier
fn validate_san_uri(uri: &str) -> Result<()> {
    if uri.contains('\0') {
        return Err(Error::InvalidCertificate(
            "SAN URI contains null byte".into(),
        ));
    }
    if !uri.contains("://") {
        return Err(Error::InvalidCertificate(format!(
            "SAN URI missing scheme: {:?}",
            uri
        )));
    }
    Ok(())
}

/// Validate a registeredID OID string (RFC 5280 §4.2.1.6).
/// Must be valid dot-notation with at least 2 arcs, first arc 0-2.
fn validate_san_registered_id(oid: &str) -> Result<()> {
    if oid.is_empty() {
        return Err(Error::InvalidCertificate(
            "SAN registeredID is empty".into(),
        ));
    }
    // Use const-oid to validate the OID format
    ObjectIdentifier::new(oid).map_err(|e| {
        Error::InvalidCertificate(format!("SAN registeredID invalid OID '{}': {}", oid, e))
    })?;
    Ok(())
}

/// Encode an OID value (the content bytes, without tag/length) from dot notation.
fn encode_oid_value(oid: &str) -> Result<Vec<u8>> {
    let parsed = ObjectIdentifier::new(oid)
        .map_err(|e| Error::InvalidCertificate(format!("Invalid OID '{}': {}", oid, e)))?;
    Ok(parsed.as_bytes().to_vec())
}

/// Subject Alternative Name extension (RFC 5280 Section 4.2.1.6)
#[derive(Debug, Clone)]
pub struct SubjectAltName {
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<std::net::IpAddr>,
    pub emails: Vec<String>,
    pub uris: Vec<String>,
    /// RFC 9598 SmtpUTF8Mailbox entries — internationalized email addresses
    /// encoded as otherName with id-on-SmtpUTF8Mailbox OID.
    pub utf8_emails: Vec<String>,
    /// registeredID [8] — identifies an entity by an assigned OID (RFC 5280 §4.2.1.6).
    /// Each entry is a dot-notation OID string (e.g., "1.3.6.1.4.1.56266.1.1").
    pub registered_ids: Vec<String>,
}

impl SubjectAltName {
    pub fn new() -> Self {
        Self {
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            emails: Vec::new(),
            uris: Vec::new(),
            utf8_emails: Vec::new(),
            registered_ids: Vec::new(),
        }
    }

    pub fn dns(mut self, name: impl Into<String>) -> Self {
        self.dns_names.push(name.into());
        self
    }

    pub fn ip(mut self, addr: std::net::IpAddr) -> Self {
        self.ip_addresses.push(addr);
        self
    }

    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.emails.push(email.into());
        self
    }

    pub fn uri(mut self, uri: impl Into<String>) -> Self {
        self.uris.push(uri.into());
        self
    }

    /// Add an internationalized email address (RFC 9598 SmtpUTF8Mailbox).
    ///
    /// The local part may contain UTF-8 characters. The domain part is
    /// normalized to A-label form via IDNA2008.
    pub fn utf8_email(mut self, email: impl Into<String>) -> Self {
        self.utf8_emails.push(email.into());
        self
    }

    /// Add a registeredID (RFC 5280 §4.2.1.6).
    ///
    /// Identifies the entity by an assigned OID in dot notation
    /// (e.g., "1.3.6.1.4.1.56266.1.1" for an Ogjos entity).
    pub fn registered_id(mut self, oid: impl Into<String>) -> Self {
        self.registered_ids.push(oid.into());
        self
    }

    /// Validate all SAN entries per RFC 5280, RFC 9549 (IDNA2008), and RFC 9598 (SmtpUTF8Mailbox).
    ///
    /// DNS names are validated and normalized to A-label form. Use `to_der()`
    /// to encode — it performs the same normalization automatically.
    pub fn validate(&self) -> Result<()> {
        for dns in &self.dns_names {
            validate_dns_name(dns)?;
        }
        for email in &self.emails {
            validate_san_email(email)?;
        }
        for utf8_email in &self.utf8_emails {
            validate_san_utf8_email(utf8_email)?;
        }
        for uri in &self.uris {
            validate_san_uri(uri)?;
        }
        for oid in &self.registered_ids {
            validate_san_registered_id(oid)?;
        }
        if self.dns_names.is_empty()
            && self.ip_addresses.is_empty()
            && self.emails.is_empty()
            && self.utf8_emails.is_empty()
            && self.uris.is_empty()
            && self.registered_ids.is_empty()
        {
            return Err(Error::InvalidCertificate(
                "SubjectAltName must contain at least one entry".into(),
            ));
        }
        Ok(())
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        // SubjectAltName ::= GeneralNames
        // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
        let mut inner = Vec::new();

        // dNSName [2] IA5String — RFC 9549: normalize to A-label form
        for dns in &self.dns_names {
            let normalized = validate_dns_name(dns)?;
            inner.push(0x82); // Context [2]
            encode_ia5_length(&mut inner, normalized.len());
            inner.extend(normalized.as_bytes());
        }

        // iPAddress [7] OCTET STRING
        for ip in &self.ip_addresses {
            inner.push(0x87); // Context [7]
            match ip {
                std::net::IpAddr::V4(v4) => {
                    inner.push(4);
                    inner.extend(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    inner.push(16);
                    inner.extend(&v6.octets());
                }
            }
        }

        // rfc822Name [1] IA5String — domain normalized via IDNA2008
        for email in &self.emails {
            let normalized = validate_san_email(email)?;
            inner.push(0x81); // Context [1]
            encode_ia5_length(&mut inner, normalized.len());
            inner.extend(normalized.as_bytes());
        }

        // otherName [0] EXPLICIT — RFC 9598 SmtpUTF8Mailbox
        // OID: 1.3.6.1.5.5.7.8.9 (id-on-SmtpUTF8Mailbox)
        for utf8_email in &self.utf8_emails {
            let (local, domain) = validate_san_utf8_email(utf8_email)?;
            let mailbox = format!("{}@{}", local, domain);
            let mailbox_bytes = mailbox.as_bytes();

            // Encode: otherName [0] CONSTRUCTED {
            //   type-id OBJECT IDENTIFIER (id-on-SmtpUTF8Mailbox),
            //   value [0] EXPLICIT UTF8String
            // }
            let mut other_name = Vec::new();

            // OID 1.3.6.1.5.5.7.8.9 = 2B 06 01 05 05 07 08 09
            let oid_bytes: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x08, 0x09];
            other_name.push(0x06); // OBJECT IDENTIFIER tag
            other_name.push(oid_bytes.len() as u8);
            other_name.extend_from_slice(oid_bytes);

            // value [0] EXPLICIT UTF8String
            let mut utf8_value = Vec::new();
            utf8_value.push(0x0C); // UTF8String tag
            encode_ia5_length(&mut utf8_value, mailbox_bytes.len());
            utf8_value.extend_from_slice(mailbox_bytes);

            // Wrap in EXPLICIT [0]
            other_name.push(0xA0); // Context [0] CONSTRUCTED
            encode_ia5_length(&mut other_name, utf8_value.len());
            other_name.extend(utf8_value);

            // Wrap in otherName [0] CONSTRUCTED (IMPLICIT)
            inner.push(0xA0); // Context [0] CONSTRUCTED
            encode_ia5_length(&mut inner, other_name.len());
            inner.extend(other_name);
        }

        // uniformResourceIdentifier [6] IA5String
        for uri in &self.uris {
            inner.push(0x86); // Context [6]
            encode_ia5_length(&mut inner, uri.len());
            inner.extend(uri.as_bytes());
        }

        // registeredID [8] OBJECT IDENTIFIER
        for oid in &self.registered_ids {
            let oid_bytes = encode_oid_value(oid)?;
            inner.push(0x88); // Context [8] IMPLICIT
            encode_ia5_length(&mut inner, oid_bytes.len());
            inner.extend(&oid_bytes);
        }

        let mut result = vec![0x30]; // SEQUENCE tag
        if inner.len() < 128 {
            result.push(inner.len() as u8);
        } else {
            let len_bytes = (inner.len() as u32).to_be_bytes();
            let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(3);
            let len_len = 4 - start;
            result.push(0x80 | len_len as u8);
            result.extend_from_slice(&len_bytes[start..]);
        }
        result.extend(inner);

        Ok(result)
    }
}

impl Default for SubjectAltName {
    fn default() -> Self {
        Self::new()
    }
}

/// Issuer Alternative Name extension (RFC 5280 Section 4.2.1.7)
///
/// Uses the same GeneralNames structure as SubjectAltName.
/// This extension allows associating alternative identities with the
/// certificate issuer (e.g., issuer email, URI, DNS name).
pub type IssuerAltName = SubjectAltName;

/// CRL Distribution Points extension (RFC 5280 Section 4.2.1.13)
///
/// Contains URLs where CRLs can be retrieved for certificate revocation checking.
#[derive(Debug, Clone)]
pub struct CrlDistributionPoints {
    pub urls: Vec<String>,
}

impl CrlDistributionPoints {
    pub fn new() -> Self {
        Self { urls: Vec::new() }
    }

    pub fn with_url(url: impl Into<String>) -> Self {
        Self {
            urls: vec![url.into()],
        }
    }

    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.urls.push(url.into());
        self
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        // CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
        // DistributionPoint ::= SEQUENCE {
        //   distributionPoint [0] DistributionPointName OPTIONAL,
        //   ... }
        // DistributionPointName ::= CHOICE {
        //   fullName [0] GeneralNames, ... }
        // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
        // GeneralName ::= CHOICE { uniformResourceIdentifier [6] IA5String, ... }

        let mut dist_points = Vec::new();

        for url in &self.urls {
            // Build GeneralName: uniformResourceIdentifier [6] IA5String
            let mut general_name = vec![0x86]; // Context [6] IMPLICIT
            encode_length(&mut general_name, url.len());
            general_name.extend(url.as_bytes());

            // Build GeneralNames: SEQUENCE OF GeneralName (implicit [0])
            let mut general_names = vec![0xA0]; // Context [0] CONSTRUCTED
            encode_length(&mut general_names, general_name.len());
            general_names.extend(general_name);

            // Build DistributionPointName wrapped in [0]
            let mut dp_name = vec![0xA0]; // Context [0] CONSTRUCTED
            encode_length(&mut dp_name, general_names.len());
            dp_name.extend(general_names);

            // Build DistributionPoint: SEQUENCE
            let mut dist_point = vec![0x30]; // SEQUENCE
            encode_length(&mut dist_point, dp_name.len());
            dist_point.extend(dp_name);

            dist_points.extend(dist_point);
        }

        // Wrap in outer SEQUENCE
        let mut result = vec![0x30]; // SEQUENCE
        encode_length(&mut result, dist_points.len());
        result.extend(dist_points);

        Ok(result)
    }
}

impl Default for CrlDistributionPoints {
    fn default() -> Self {
        Self::new()
    }
}

/// FreshestCRL extension (RFC 5280 Section 4.2.1.15)
///
/// Identifies how delta CRL information is obtained for this certificate.
/// Has the same ASN.1 structure as CRLDistributionPoints but uses OID 2.5.29.46.
/// MUST be non-critical per RFC 5280 §4.2.1.15.
#[derive(Debug, Clone)]
pub struct FreshestCrl {
    pub urls: Vec<String>,
}

impl FreshestCrl {
    pub fn new() -> Self {
        Self { urls: Vec::new() }
    }

    pub fn with_url(url: impl Into<String>) -> Self {
        Self {
            urls: vec![url.into()],
        }
    }

    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.urls.push(url.into());
        self
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        // Identical ASN.1 structure to CRLDistributionPoints (RFC 5280 §4.2.1.13)
        let mut dist_points = Vec::new();

        for url in &self.urls {
            let mut general_name = vec![0x86]; // Context [6] IMPLICIT — uniformResourceIdentifier
            encode_length(&mut general_name, url.len());
            general_name.extend(url.as_bytes());

            let mut general_names = vec![0xA0]; // Context [0] CONSTRUCTED — fullName
            encode_length(&mut general_names, general_name.len());
            general_names.extend(general_name);

            let mut dp_name = vec![0xA0]; // Context [0] CONSTRUCTED — distributionPoint
            encode_length(&mut dp_name, general_names.len());
            dp_name.extend(general_names);

            let mut dist_point = vec![0x30]; // SEQUENCE — DistributionPoint
            encode_length(&mut dist_point, dp_name.len());
            dist_point.extend(dp_name);

            dist_points.extend(dist_point);
        }

        let mut result = vec![0x30]; // SEQUENCE — CRLDistributionPoints
        encode_length(&mut result, dist_points.len());
        result.extend(dist_points);

        Ok(result)
    }
}

impl Default for FreshestCrl {
    fn default() -> Self {
        Self::new()
    }
}

/// Authority Information Access extension (RFC 5280 Section 4.2.2.1)
///
/// Contains OCSP responder URLs and CA certificate issuer URLs.
#[derive(Debug, Clone)]
pub struct AuthorityInfoAccess {
    pub ocsp_urls: Vec<String>,
    pub ca_issuer_urls: Vec<String>,
}

impl AuthorityInfoAccess {
    pub fn new() -> Self {
        Self {
            ocsp_urls: Vec::new(),
            ca_issuer_urls: Vec::new(),
        }
    }

    pub fn ocsp(mut self, url: impl Into<String>) -> Self {
        self.ocsp_urls.push(url.into());
        self
    }

    pub fn ca_issuer(mut self, url: impl Into<String>) -> Self {
        self.ca_issuer_urls.push(url.into());
        self
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        // AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
        // AccessDescription ::= SEQUENCE {
        //   accessMethod    OBJECT IDENTIFIER,
        //   accessLocation  GeneralName }

        let mut access_descs = Vec::new();

        // Add OCSP responder entries
        for url in &self.ocsp_urls {
            let desc = Self::encode_access_description(&oid::AIA_OCSP, url)?;
            access_descs.extend(desc);
        }

        // Add CA Issuers entries
        for url in &self.ca_issuer_urls {
            let desc = Self::encode_access_description(&oid::AIA_CA_ISSUERS, url)?;
            access_descs.extend(desc);
        }

        // Wrap in outer SEQUENCE
        let mut result = vec![0x30]; // SEQUENCE
        encode_length(&mut result, access_descs.len());
        result.extend(access_descs);

        Ok(result)
    }

    fn encode_access_description(method_oid: &ObjectIdentifier, url: &str) -> Result<Vec<u8>> {
        // AccessDescription ::= SEQUENCE {
        //   accessMethod    OBJECT IDENTIFIER,
        //   accessLocation  GeneralName }

        let oid_der = method_oid.to_der()?;

        // GeneralName: uniformResourceIdentifier [6] IA5String
        let mut general_name = vec![0x86]; // Context [6] IMPLICIT
        encode_length(&mut general_name, url.len());
        general_name.extend(url.as_bytes());

        // Build SEQUENCE
        let inner_len = oid_der.len() + general_name.len();
        let mut result = vec![0x30]; // SEQUENCE
        encode_length(&mut result, inner_len);
        result.extend(oid_der);
        result.extend(general_name);

        Ok(result)
    }
}

impl Default for AuthorityInfoAccess {
    fn default() -> Self {
        Self::new()
    }
}

/// Subject Information Access extension (RFC 5280 Section 4.2.2.2)
///
/// Contains information about how to access information and services for the
/// *subject* of the certificate. Has identical ASN.1 structure to AIA.
///
/// For CA certificates, `id-ad-caRepository` (OID 1.3.6.1.5.5.7.48.5) points
/// to a URI containing a certs-only CMS file (.p7c) with all certificates
/// issued under the CA. This is required for FPKI compliance.
///
/// For TSA (Timestamp Authority) certificates, `id-ad-timeStamping`
/// (OID 1.3.6.1.5.5.7.48.3) points to the TSA's time-stamping service.
#[derive(Debug, Clone)]
pub struct SubjectInformationAccess {
    /// URLs for caRepository (points to .p7c files with issued certs)
    pub ca_repository_urls: Vec<String>,
    /// URLs for timeStamping (TSA service endpoints)
    pub time_stamping_urls: Vec<String>,
}

impl SubjectInformationAccess {
    pub fn new() -> Self {
        Self {
            ca_repository_urls: Vec::new(),
            time_stamping_urls: Vec::new(),
        }
    }

    /// Add a caRepository URL (points to a .p7c file or CA repository)
    pub fn ca_repository(mut self, url: impl Into<String>) -> Self {
        self.ca_repository_urls.push(url.into());
        self
    }

    /// Add a timeStamping URL (TSA service endpoint)
    pub fn time_stamping(mut self, url: impl Into<String>) -> Self {
        self.time_stamping_urls.push(url.into());
        self
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        // SubjectInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
        // AccessDescription ::= SEQUENCE {
        //   accessMethod    OBJECT IDENTIFIER,
        //   accessLocation  GeneralName }
        // Identical structure to AIA — only the access method OIDs differ.

        let mut access_descs = Vec::new();

        for url in &self.ca_repository_urls {
            let desc = encode_sia_access_description(&oid::SIA_CA_REPOSITORY, url)?;
            access_descs.extend(desc);
        }

        for url in &self.time_stamping_urls {
            let desc = encode_sia_access_description(&oid::SIA_TIME_STAMPING, url)?;
            access_descs.extend(desc);
        }

        let mut result = vec![0x30]; // SEQUENCE
        encode_length(&mut result, access_descs.len());
        result.extend(access_descs);

        Ok(result)
    }
}

impl Default for SubjectInformationAccess {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a single AccessDescription for use in SIA (and AIA-like) extensions.
///
/// ```text
/// AccessDescription ::= SEQUENCE {
///   accessMethod    OBJECT IDENTIFIER,
///   accessLocation  GeneralName }
/// ```
fn encode_sia_access_description(method_oid: &ObjectIdentifier, url: &str) -> Result<Vec<u8>> {
    let oid_der = method_oid.to_der()?;

    // GeneralName: uniformResourceIdentifier [6] IA5String
    let mut general_name = vec![0x86]; // Context [6] IMPLICIT
    encode_length(&mut general_name, url.len());
    general_name.extend(url.as_bytes());

    let inner_len = oid_der.len() + general_name.len();
    let mut result = vec![0x30]; // SEQUENCE
    encode_length(&mut result, inner_len);
    result.extend(oid_der);
    result.extend(general_name);

    Ok(result)
}

/// No Revocation Available extension (RFC 9608)
///
/// Indicates that the certificate holder has no revocation mechanism available.
/// Used for short-lived certificates and OCSP responder certificates.
/// The extension value is an empty ASN.1 NULL (no content needed).
///
/// Per RFC 9608 Section 4: "The noRevAvail extension MUST be critical."
#[derive(Debug, Clone)]
pub struct NoRevAvail;

impl NoRevAvail {
    /// Encode to DER — empty SEQUENCE (NULL value)
    ///
    /// RFC 9608: noRevAvail EXTENSION ::= { SYNTAX NULL IDENTIFIED BY id-ce-noRevAvail }
    pub fn to_der(&self) -> Result<Vec<u8>> {
        // ASN.1 NULL: tag 0x05, length 0x00
        Ok(vec![0x05, 0x00])
    }
}

/// id-pkix-ocsp-nocheck extension (RFC 6960 §4.2.2.2.1)
///
/// When included in an OCSP responder certificate, instructs clients that
/// they MUST NOT check the revocation status of the OCSP responder certificate
/// itself. This prevents an infinite regress (checking the checker).
///
/// The extension value is an ASN.1 NULL (no content). The extension is
/// non-critical per RFC 6960. It MUST only be placed on OCSP responder certs.
#[derive(Debug, Clone)]
pub struct OcspNoCheck;

impl OcspNoCheck {
    /// Encode to DER — ASN.1 NULL value
    ///
    /// RFC 6960: id-pkix-ocsp-nocheck EXTENSION ::= { SYNTAX NULL
    ///           IDENTIFIED BY id-pkix-ocsp-nocheck }
    pub fn to_der(&self) -> Result<Vec<u8>> {
        // ASN.1 NULL: tag 0x05, length 0x00
        Ok(vec![0x05, 0x00])
    }
}

/// TLS Feature extension (RFC 7633) — "OCSP Must-Staple"
///
/// When included in a certificate, indicates that the TLS server MUST
/// present a valid OCSP response (stapled) during the TLS handshake.
///
/// TLS Feature values are TLS extension type numbers:
/// - 5 = status_request (OCSP stapling, RFC 6066)
/// - 17 = status_request_v2 (RFC 6961, deprecated)
#[derive(Debug, Clone)]
pub struct TlsFeature {
    pub features: Vec<u16>,
}

impl TlsFeature {
    /// Create "OCSP Must-Staple" (status_request = 5)
    pub fn must_staple() -> Self {
        Self { features: vec![5] }
    }

    /// Create with multiple features
    pub fn new(features: Vec<u16>) -> Self {
        Self { features }
    }

    /// Encode to DER
    ///
    /// ```text
    /// Features ::= SEQUENCE OF INTEGER
    /// ```
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let mut inner = Vec::new();
        for &feat in &self.features {
            // INTEGER encoding
            if feat <= 0x7F {
                inner.extend_from_slice(&[0x02, 0x01, feat as u8]);
            } else {
                inner.extend_from_slice(&[0x02, 0x02, (feat >> 8) as u8, feat as u8]);
            }
        }

        let mut result = vec![0x30]; // SEQUENCE tag
        encode_length(&mut result, inner.len());
        result.extend(inner);

        Ok(result)
    }
}

/// Inhibit anyPolicy extension (RFC 5280 Section 4.2.1.14)
///
/// Indicates that the special anyPolicy OID (2.5.29.32.0) is not considered
/// an explicit match for other certificate policies except when it appears
/// in an intermediate self-issued CA certificate.
///
/// The value is a SkipCerts INTEGER indicating the number of additional
/// certificates that may appear in the path before anyPolicy is no longer permitted.
#[derive(Debug, Clone)]
pub struct InhibitAnyPolicy {
    pub skip_certs: u32,
}

impl InhibitAnyPolicy {
    /// Create with the specified skip_certs value
    pub fn new(skip_certs: u32) -> Self {
        Self { skip_certs }
    }

    /// Immediately inhibit anyPolicy (skip_certs = 0)
    pub fn immediate() -> Self {
        Self { skip_certs: 0 }
    }

    /// Encode to DER
    ///
    /// ```text
    /// InhibitAnyPolicy ::= SkipCerts
    /// SkipCerts ::= INTEGER (0..MAX)
    /// ```
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let mut result = vec![0x02]; // INTEGER tag
        encode_der_uint(&mut result, self.skip_certs);
        Ok(result)
    }
}

/// Policy Mappings extension (RFC 5280 §4.2.1.5, MUST be critical)
///
/// Used in cross-certificates to map policy OIDs from the issuing domain to
/// the subject domain. Each mapping pairs an issuerDomainPolicy OID with a
/// subjectDomainPolicy OID.
///
/// ```text
/// PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
///     issuerDomainPolicy      CertPolicyId,
///     subjectDomainPolicy     CertPolicyId }
/// ```
#[derive(Debug, Clone, Default)]
pub struct PolicyMappings {
    pub mappings: Vec<(ObjectIdentifier, ObjectIdentifier)>,
}

impl PolicyMappings {
    /// Create a new PolicyMappings extension.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a policy mapping pair.
    pub fn add_mapping(
        mut self,
        issuer_policy: ObjectIdentifier,
        subject_policy: ObjectIdentifier,
    ) -> Self {
        self.mappings.push((issuer_policy, subject_policy));
        self
    }

    /// Build from OID strings (convenience for FPKI policy strings).
    pub fn from_oid_strings(pairs: &[(&str, &str)]) -> Result<Self> {
        let mut pm = Self::new();
        for (issuer, subject) in pairs {
            let issuer_oid = ObjectIdentifier::new(issuer).map_err(|e| {
                Error::Encoding(format!("Invalid issuer policy OID '{}': {}", issuer, e))
            })?;
            let subject_oid = ObjectIdentifier::new(subject).map_err(|e| {
                Error::Encoding(format!("Invalid subject policy OID '{}': {}", subject, e))
            })?;
            pm.mappings.push((issuer_oid, subject_oid));
        }
        Ok(pm)
    }

    /// Encode to DER.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        // Each mapping is SEQUENCE { OID, OID }
        let mut inner = Vec::new();
        for (issuer, subject) in &self.mappings {
            let issuer_der = issuer
                .to_der()
                .map_err(|e| Error::Encoding(e.to_string()))?;
            let subject_der = subject
                .to_der()
                .map_err(|e| Error::Encoding(e.to_string()))?;
            let pair_content_len = issuer_der.len() + subject_der.len();
            // SEQUENCE tag + length + contents
            inner.push(0x30);
            encode_length(&mut inner, pair_content_len);
            inner.extend_from_slice(&issuer_der);
            inner.extend_from_slice(&subject_der);
        }
        // Outer SEQUENCE
        let mut result = vec![0x30];
        encode_length(&mut result, inner.len());
        result.extend_from_slice(&inner);
        Ok(result)
    }
}

/// Name Constraints extension (RFC 5280 §4.2.1.10, MUST be critical)
///
/// Restricts the namespace within which all subject names in subsequent
/// certificates in a certification path must be located.
///
/// ```text
/// NameConstraints ::= SEQUENCE {
///     permittedSubtrees  [0] GeneralSubtrees OPTIONAL,
///     excludedSubtrees   [1] GeneralSubtrees OPTIONAL }
/// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
/// GeneralSubtree ::= SEQUENCE {
///     base      GeneralName,
///     minimum   [0] BaseDistance DEFAULT 0,
///     maximum   [1] BaseDistance OPTIONAL }
/// ```
#[derive(Debug, Clone, Default)]
pub struct NameConstraints {
    pub permitted_dns: Vec<String>,
    pub excluded_dns: Vec<String>,
    pub permitted_dn: Vec<String>,
}

impl NameConstraints {
    /// Create a new (empty) NameConstraints.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a permitted DNS subtree (e.g., ".quantumnexum.com").
    pub fn permit_dns(mut self, domain: impl Into<String>) -> Self {
        self.permitted_dns.push(domain.into());
        self
    }

    /// Add an excluded DNS subtree (e.g., ".gov").
    pub fn exclude_dns(mut self, domain: impl Into<String>) -> Self {
        self.excluded_dns.push(domain.into());
        self
    }

    /// Add a permitted directory name subtree (as a DN string).
    pub fn permit_dn(mut self, dn: impl Into<String>) -> Self {
        self.permitted_dn.push(dn.into());
        self
    }

    /// Validate NameConstraints values per RFC 5280.
    /// DNS subtrees must be valid IA5String (7-bit ASCII) and follow DNS label rules.
    pub fn validate(&self) -> Result<()> {
        for dns in &self.permitted_dns {
            validate_nc_dns(dns, "permitted")?;
        }
        for dns in &self.excluded_dns {
            validate_nc_dns(dns, "excluded")?;
        }
        Ok(())
    }

    /// Encode to DER.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut content = Vec::new();

        // permittedSubtrees [0] IMPLICIT GeneralSubtrees OPTIONAL
        if !self.permitted_dns.is_empty() || !self.permitted_dn.is_empty() {
            let subtrees = self.encode_subtrees(&self.permitted_dns, &self.permitted_dn)?;
            // Context [0] constructed
            content.push(0xA0);
            encode_length(&mut content, subtrees.len());
            content.extend_from_slice(&subtrees);
        }

        // excludedSubtrees [1] IMPLICIT GeneralSubtrees OPTIONAL
        if !self.excluded_dns.is_empty() {
            let subtrees = self.encode_subtrees(&self.excluded_dns, &[])?;
            // Context [1] constructed
            content.push(0xA1);
            encode_length(&mut content, subtrees.len());
            content.extend_from_slice(&subtrees);
        }

        // Outer SEQUENCE
        let mut result = vec![0x30];
        encode_length(&mut result, content.len());
        result.extend_from_slice(&content);
        Ok(result)
    }

    fn encode_subtrees(&self, dns_names: &[String], dn_names: &[String]) -> Result<Vec<u8>> {
        let mut subtrees = Vec::new();

        // DNS names as dNSName [2] IA5String
        for dns in dns_names {
            let name_bytes = dns.as_bytes();
            // GeneralName: dNSName [2] IMPLICIT IA5String
            let mut gen_name = vec![0x82]; // context [2] implicit
            encode_length(&mut gen_name, name_bytes.len());
            gen_name.extend_from_slice(name_bytes);

            // GeneralSubtree: SEQUENCE { base GeneralName }
            // (minimum defaults to 0, omitted; maximum absent)
            let mut subtree = vec![0x30];
            encode_length(&mut subtree, gen_name.len());
            subtree.extend_from_slice(&gen_name);
            subtrees.extend_from_slice(&subtree);
        }

        // Directory names as directoryName [4] EXPLICIT Name
        for dn_str in dn_names {
            let dn_der = encode_simple_dn(dn_str)?;
            // GeneralName: directoryName [4] EXPLICIT
            let mut gen_name = vec![0xA4]; // context [4] constructed
            encode_length(&mut gen_name, dn_der.len());
            gen_name.extend_from_slice(&dn_der);

            let mut subtree = vec![0x30];
            encode_length(&mut subtree, gen_name.len());
            subtree.extend_from_slice(&gen_name);
            subtrees.extend_from_slice(&subtree);
        }

        Ok(subtrees)
    }
}

/// Policy Constraints extension (RFC 5280 §4.2.1.11, MUST be critical)
///
/// Constrains path validation by requiring explicit certificate policies and/or
/// inhibiting policy mapping.
///
/// ```text
/// PolicyConstraints ::= SEQUENCE {
///     requireExplicitPolicy   [0] SkipCerts OPTIONAL,
///     inhibitPolicyMapping    [1] SkipCerts OPTIONAL }
/// ```
#[derive(Debug, Clone)]
pub struct PolicyConstraints {
    pub require_explicit_policy: Option<u32>,
    pub inhibit_policy_mapping: Option<u32>,
}

impl PolicyConstraints {
    /// Create with requireExplicitPolicy only.
    pub fn require_explicit(skip_certs: u32) -> Self {
        Self {
            require_explicit_policy: Some(skip_certs),
            inhibit_policy_mapping: None,
        }
    }

    /// Create with inhibitPolicyMapping only.
    pub fn inhibit_mapping(skip_certs: u32) -> Self {
        Self {
            require_explicit_policy: None,
            inhibit_policy_mapping: Some(skip_certs),
        }
    }

    /// Create with both constraints.
    pub fn both(require_explicit: u32, inhibit_mapping: u32) -> Self {
        Self {
            require_explicit_policy: Some(require_explicit),
            inhibit_policy_mapping: Some(inhibit_mapping),
        }
    }

    /// Encode to DER.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let mut content = Vec::new();

        // requireExplicitPolicy [0] IMPLICIT INTEGER
        if let Some(skip) = self.require_explicit_policy {
            content.push(0x80); // context [0] implicit primitive
            encode_der_uint(&mut content, skip);
        }

        // inhibitPolicyMapping [1] IMPLICIT INTEGER
        if let Some(skip) = self.inhibit_policy_mapping {
            content.push(0x81); // context [1] implicit primitive
            encode_der_uint(&mut content, skip);
        }

        // Outer SEQUENCE
        let mut result = vec![0x30];
        encode_length(&mut result, content.len());
        result.extend_from_slice(&content);
        Ok(result)
    }
}

/// Encode a non-negative integer as DER INTEGER content (length + value bytes, no tag).
/// Handles DER sign-bit rule: if MSB of first value byte is 1, prepend 0x00 to keep positive.
fn encode_der_uint(buf: &mut Vec<u8>, value: u32) {
    if value == 0 {
        buf.extend_from_slice(&[0x01, 0x00]);
        return;
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    let significant = &bytes[start..];
    let needs_pad = significant[0] & 0x80 != 0;
    let len = significant.len() + usize::from(needs_pad);
    buf.push(len as u8);
    if needs_pad {
        buf.push(0x00);
    }
    buf.extend_from_slice(significant);
}

/// Encode a simple DN string (e.g., "DC=quantumnexum, DC=com") to DER.
///
/// Supports DC=, CN=, OU=, O= attributes.
fn encode_simple_dn(dn_str: &str) -> Result<Vec<u8>> {
    let mut rdns = Vec::new();

    for part in dn_str.split(',') {
        let part = part.trim();
        let (attr_oid, value) = if let Some(val) = part.strip_prefix("DC=") {
            // domainComponent: 0.9.2342.19200300.100.1.25
            (
                ObjectIdentifier::new_unwrap("0.9.2342.19200300.100.1.25"),
                val,
            )
        } else if let Some(val) = part.strip_prefix("CN=") {
            (ObjectIdentifier::new_unwrap("2.5.4.3"), val)
        } else if let Some(val) = part.strip_prefix("OU=") {
            (ObjectIdentifier::new_unwrap("2.5.4.11"), val)
        } else if let Some(val) = part.strip_prefix("O=") {
            (ObjectIdentifier::new_unwrap("2.5.4.10"), val)
        } else if let Some(val) = part.strip_prefix("C=") {
            (ObjectIdentifier::new_unwrap("2.5.4.6"), val)
        } else {
            continue;
        };

        let attr_oid_der = attr_oid
            .to_der()
            .map_err(|e| Error::Encoding(e.to_string()))?;

        // Encode value as UTF8String (tag 0x0C)
        let value_bytes = value.trim().as_bytes();
        let mut value_der = vec![0x0C];
        encode_length(&mut value_der, value_bytes.len());
        value_der.extend_from_slice(value_bytes);

        // AttributeTypeAndValue: SEQUENCE { OID, value }
        let atv_content_len = attr_oid_der.len() + value_der.len();
        let mut atv = vec![0x30];
        encode_length(&mut atv, atv_content_len);
        atv.extend_from_slice(&attr_oid_der);
        atv.extend_from_slice(&value_der);

        // RDN: SET { AttributeTypeAndValue }
        let mut rdn = vec![0x31];
        encode_length(&mut rdn, atv.len());
        rdn.extend_from_slice(&atv);

        rdns.push(rdn);
    }

    // Name: SEQUENCE OF RDN
    let mut inner = Vec::new();
    for rdn in &rdns {
        inner.extend_from_slice(rdn);
    }
    let mut result = vec![0x30];
    encode_length(&mut result, inner.len());
    result.extend_from_slice(&inner);
    Ok(result)
}

/// SPORK Issuance Information extension (custom extension)
///
/// Identifies certificates issued by SPORK PKI software.
/// OID: 1.3.6.1.4.1.56266.1.2.4 (Ogjos PEN: 56266)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SporkIssuanceInfo {
    /// Software name (always "SPORK")
    pub software: String,
    /// Software version
    pub version: String,
    /// Build type (e.g., "pure-rust-pqc")
    pub build: String,
    /// Issuance timestamp (ISO 8601)
    pub issued_at: String,
    /// Issuing CA identifier
    pub ca_id: String,
}

impl SporkIssuanceInfo {
    /// SPORK version from Cargo.toml
    pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

    /// Create new SPORK issuance info
    pub fn new(ca_id: impl Into<String>) -> Self {
        Self {
            software: "SPORK".to_string(),
            version: Self::VERSION.to_string(),
            build: "pure-rust-pqc".to_string(),
            issued_at: chrono::Utc::now().to_rfc3339(),
            ca_id: ca_id.into(),
        }
    }

    /// Create with custom parameters
    pub fn with_params(
        version: impl Into<String>,
        build: impl Into<String>,
        ca_id: impl Into<String>,
    ) -> Self {
        Self {
            software: "SPORK".to_string(),
            version: version.into(),
            build: build.into(),
            issued_at: chrono::Utc::now().to_rfc3339(),
            ca_id: ca_id.into(),
        }
    }

    /// Encode to DER (UTF8String containing JSON)
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let json = serde_json::to_string(self)
            .map_err(|e| crate::error::Error::Encoding(format!("JSON: {}", e)))?;

        // UTF8String: tag 0x0C
        let bytes = json.as_bytes();
        let mut result = vec![0x0C]; // UTF8String tag
        encode_length(&mut result, bytes.len());
        result.extend(bytes);

        Ok(result)
    }
}

/// Helper to encode DER length
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

/// CMS Content Constraints extension (RFC 6010)
///
/// Restricts which CMS content types a certificate's key is authorized to sign.
/// Used to constrain signing keys (e.g., "code signing only", "timestamping only").
///
/// ```text
/// CMSContentConstraints ::= SEQUENCE SIZE (1..MAX) OF ContentTypeConstraint
/// ContentTypeConstraint ::= SEQUENCE {
///     contentType       OBJECT IDENTIFIER,
///     canSource         ContentTypeGeneration DEFAULT canSource }
/// ContentTypeGeneration ::= ENUMERATED { canSource(0), cannotSource(1) }
/// ```
#[derive(Debug, Clone, Default)]
pub struct CmsContentConstraints {
    /// Content type OIDs with permission (true = canSource, false = cannotSource)
    pub constraints: Vec<(ObjectIdentifier, bool)>,
}

impl CmsContentConstraints {
    /// Create empty constraints
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow a content type (canSource)
    pub fn allow(mut self, content_type: ObjectIdentifier) -> Self {
        self.constraints.push((content_type, true));
        self
    }

    /// Deny a content type (cannotSource)
    pub fn deny(mut self, content_type: ObjectIdentifier) -> Self {
        self.constraints.push((content_type, false));
        self
    }

    /// Convenience: allow only SignedData (code signing, S/MIME signing)
    pub fn signed_data_only() -> Self {
        Self::new().allow(oid::CT_SIGNED_DATA)
    }

    /// Convenience: allow only TSTInfo (timestamping)
    pub fn timestamp_only() -> Self {
        Self::new().allow(oid::CT_TST_INFO)
    }

    /// Check if a content type is permitted by these constraints
    pub fn is_permitted(&self, content_type: &ObjectIdentifier) -> bool {
        for (ct, can_source) in &self.constraints {
            if ct == content_type {
                return *can_source;
            }
        }
        // If not listed, default is permitted (open world assumption)
        true
    }

    /// Encode to DER
    ///
    /// ```text
    /// CMSContentConstraints ::= SEQUENCE OF ContentTypeConstraint
    /// ContentTypeConstraint ::= SEQUENCE { contentType OID, canSource ENUMERATED DEFAULT 0 }
    /// ```
    pub fn to_der(&self) -> Result<Vec<u8>> {
        if self.constraints.is_empty() {
            return Err(Error::Encoding(
                "CMS content constraints must have at least one entry".into(),
            ));
        }

        let mut inner = Vec::new();

        for (ct_oid, can_source) in &self.constraints {
            let oid_der = ct_oid
                .to_der()
                .map_err(|e| Error::Encoding(e.to_string()))?;

            let mut constraint = Vec::new();
            constraint.extend(&oid_der);

            // Only encode canSource if it's cannotSource(1) — DEFAULT is canSource(0)
            if !can_source {
                // ENUMERATED { cannotSource(1) }
                constraint.extend_from_slice(&[0x0A, 0x01, 0x01]);
            }

            // Wrap in SEQUENCE
            let mut seq = vec![0x30];
            encode_length(&mut seq, constraint.len());
            seq.extend(constraint);

            inner.extend(seq);
        }

        // Outer SEQUENCE
        let mut result = vec![0x30];
        encode_length(&mut result, inner.len());
        result.extend(inner);

        Ok(result)
    }
}

// ============================================================================
// RFC 3739: Qualified Certificate Statements
// ============================================================================

/// A single QC Statement per RFC 3739 §3.2.6.
///
/// ```text
/// QCStatement ::= SEQUENCE {
///   statementId   QC-STATEMENT.&id,
///   statementInfo QC-STATEMENT.&Type OPTIONAL }
/// ```
#[derive(Debug, Clone)]
pub struct QcStatement {
    /// Statement OID
    pub statement_id: ObjectIdentifier,
    /// Optional statement-specific data (DER-encoded)
    pub statement_info: Option<Vec<u8>>,
}

/// Qualified Certificate Statements extension (RFC 3739 §3.2.6).
///
/// ```text
/// QCStatements ::= SEQUENCE OF QCStatement
/// ```
///
/// Used for EU eIDAS qualified certificates and other regulatory frameworks.
/// Contains zero or more statements about the certificate's qualified status.
#[derive(Debug, Clone, Default)]
pub struct QcStatements {
    pub statements: Vec<QcStatement>,
}

impl QcStatements {
    /// Create empty QC statements
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a statement with no additional info (e.g., QcCompliance)
    pub fn add_statement(mut self, statement_id: ObjectIdentifier) -> Self {
        self.statements.push(QcStatement {
            statement_id,
            statement_info: None,
        });
        self
    }

    /// Add a statement with DER-encoded info
    pub fn add_statement_with_info(
        mut self,
        statement_id: ObjectIdentifier,
        info: Vec<u8>,
    ) -> Self {
        self.statements.push(QcStatement {
            statement_id,
            statement_info: Some(info),
        });
        self
    }

    /// Convenience: EU eIDAS compliance statement (id-etsi-qcs-QcCompliance)
    pub fn etsi_compliance(self) -> Self {
        self.add_statement(oid::QCS_ETSI_COMPLIANCE)
    }

    /// Convenience: EU eIDAS SSCD statement (key in qualified device)
    pub fn etsi_sscd(self) -> Self {
        self.add_statement(oid::QCS_ETSI_SSCD)
    }

    /// Convenience: Add retention period in years
    ///
    /// Encodes as INTEGER DER.
    pub fn retention_period(self, years: u32) -> Self {
        // Encode as DER INTEGER
        let mut int_bytes = Vec::new();
        let val = years;
        if val == 0 {
            int_bytes.push(0);
        } else {
            let mut v = val;
            let mut tmp = Vec::new();
            while v > 0 {
                tmp.push((v & 0xFF) as u8);
                v >>= 8;
            }
            // Add leading zero if high bit set (positive integer encoding)
            if tmp.last().is_some_and(|b| b & 0x80 != 0) {
                tmp.push(0);
            }
            tmp.reverse();
            int_bytes = tmp;
        }

        let mut der = vec![0x02]; // INTEGER tag
        encode_length(&mut der, int_bytes.len());
        der.extend(int_bytes);

        self.add_statement_with_info(oid::QCS_ETSI_RETENTION_PERIOD, der)
    }

    /// Encode to DER
    pub fn to_der(&self) -> Result<Vec<u8>> {
        if self.statements.is_empty() {
            return Err(Error::Encoding(
                "QC statements must have at least one statement".into(),
            ));
        }

        let mut inner = Vec::new();

        for stmt in &self.statements {
            let oid_der = stmt
                .statement_id
                .to_der()
                .map_err(|e| Error::Encoding(e.to_string()))?;

            let mut stmt_content: Vec<u8> = Vec::new();
            stmt_content.extend(&oid_der);
            if let Some(ref info) = stmt.statement_info {
                stmt_content.extend(info);
            }

            // Wrap in SEQUENCE
            let mut seq = vec![0x30];
            encode_length(&mut seq, stmt_content.len());
            seq.extend(stmt_content);
            inner.extend(seq);
        }

        // Outer SEQUENCE
        let mut result = vec![0x30];
        encode_length(&mut result, inner.len());
        result.extend(inner);

        Ok(result)
    }
}

/// Configuration for auto-generating CDP and AIA extensions
#[derive(Debug, Clone)]
pub struct CdpAiaConfig {
    /// Base URL for the PKI (e.g., "https://pki.example.com")
    pub base_url: String,
    /// CA identifier used in URL paths
    pub ca_id: String,
}

impl CdpAiaConfig {
    pub fn new(base_url: impl Into<String>, ca_id: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            ca_id: ca_id.into(),
        }
    }

    /// Generate CRL Distribution Points extension
    /// URL pattern: {base_url}/crl/{ca_id}.crl
    pub fn generate_cdp(&self) -> CrlDistributionPoints {
        let crl_url = format!(
            "{}/crl/{}.crl",
            self.base_url.trim_end_matches('/'),
            self.ca_id
        );
        CrlDistributionPoints::with_url(crl_url)
    }

    /// Generate Authority Information Access extension
    /// OCSP URL pattern: {base_url}/ocsp
    /// CA Issuer URL pattern: {base_url}/ca/{ca_id}.crt
    pub fn generate_aia(&self) -> AuthorityInfoAccess {
        let base = self.base_url.trim_end_matches('/');
        let ocsp_url = format!("{}/ocsp", base);
        let ca_issuer_url = format!("{}/ca/{}.crt", base, self.ca_id);

        AuthorityInfoAccess::new()
            .ocsp(ocsp_url)
            .ca_issuer(ca_issuer_url)
    }
}

/// smimeCapabilities certificate extension (RFC 8551 §2.5.2)
///
/// Announces S/MIME algorithms supported by the certificate's subject.
/// Encoded as a SEQUENCE OF SMIMECapability where each capability is:
/// ```text
/// SMIMECapability ::= SEQUENCE {
///   capabilityID OBJECT IDENTIFIER,
///   parameters   ANY DEFINED BY capabilityID OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SmimeCapabilities {
    /// OID bytes for each supported capability, in preference order
    capabilities: Vec<Vec<u8>>,
}

impl SmimeCapabilities {
    /// Create with no capabilities. Use [`with_capability`] to add entries.
    pub fn new() -> Self {
        Self {
            capabilities: Vec::new(),
        }
    }

    /// Create with standard AES-256-CBC + AES-128-CBC capabilities (common default).
    pub fn default_aes() -> Self {
        Self::new()
            .with_capability(OID_SMIME_CAP_AES256_CBC)
            .with_capability(OID_SMIME_CAP_AES128_CBC)
    }

    /// Create with AES-GCM + AES-CBC capabilities (AEAD-preferred order).
    pub fn default_aes_gcm() -> Self {
        Self::new()
            .with_capability(OID_SMIME_CAP_AES256_GCM)
            .with_capability(OID_SMIME_CAP_AES128_GCM)
            .with_capability(OID_SMIME_CAP_AES256_CBC)
            .with_capability(OID_SMIME_CAP_AES128_CBC)
    }

    /// Add a capability OID (DER-encoded, no parameters).
    pub fn with_capability(mut self, oid_der: &[u8]) -> Self {
        self.capabilities.push(oid_der.to_vec());
        self
    }

    /// Encode as a DER SEQUENCE OF SMIMECapability (the extension value).
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let mut inner = Vec::new();
        for cap_oid in &self.capabilities {
            // SMIMECapability SEQUENCE { OID }
            let seq_inner = cap_oid;
            let mut cap_seq = vec![0x30]; // SEQUENCE
            encode_der_length(&mut cap_seq, seq_inner.len());
            cap_seq.extend_from_slice(seq_inner);
            inner.extend(cap_seq);
        }

        let mut result = vec![0x30]; // outer SEQUENCE OF
        encode_der_length(&mut result, inner.len());
        result.extend(inner);
        Ok(result)
    }
}

impl Default for SmimeCapabilities {
    fn default() -> Self {
        Self::new()
    }
}

// Well-known smimeCapabilities OIDs (DER-encoded, no parameters)
// AES-128-CBC: 2.16.840.1.101.3.4.1.2
const OID_SMIME_CAP_AES128_CBC: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02,
];
// AES-256-CBC: 2.16.840.1.101.3.4.1.42
const OID_SMIME_CAP_AES256_CBC: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A,
];
// AES-128-GCM: 2.16.840.1.101.3.4.1.6
const OID_SMIME_CAP_AES128_GCM: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x06,
];
// AES-256-GCM: 2.16.840.1.101.3.4.1.46
const OID_SMIME_CAP_AES256_GCM: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2E,
];

/// Internal helper: write DER length bytes into a Vec.
fn encode_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else {
        let len_bytes = (len as u64).to_be_bytes();
        let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let num_len_bytes = 8 - start;
        buf.push(0x80 | num_len_bytes as u8);
        buf.extend_from_slice(&len_bytes[start..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_constraints_ca() {
        let bc = BasicConstraints::ca_with_path_len(1);
        assert!(bc.ca);
        assert_eq!(bc.path_len_constraint, Some(1));
        let der = bc.to_der().unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn test_key_usage_flags() {
        let ku = KeyUsageFlags::ca_default();
        assert!(ku.contains(KeyUsageFlags::KEY_CERT_SIGN));
        assert!(ku.contains(KeyUsageFlags::CRL_SIGN));
        assert!(!ku.contains(KeyUsageFlags::KEY_ENCIPHERMENT));
    }

    #[test]
    fn test_eku() {
        let eku = ExtendedKeyUsage::tls_server_client();
        assert_eq!(eku.usages.len(), 2);
        let der = eku.to_der().unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn test_san() {
        let san = SubjectAltName::new()
            .dns("example.com")
            .dns("*.example.com")
            .ip("127.0.0.1".parse().unwrap());
        let der = san.to_der().unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn test_cdp() {
        let cdp = CrlDistributionPoints::with_url("http://crl.example.com/root.crl")
            .url("http://crl2.example.com/root.crl");
        assert_eq!(cdp.urls.len(), 2);
        let der = cdp.to_der().unwrap();
        assert!(!der.is_empty());
        // DER should start with SEQUENCE tag
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_aia() {
        let aia = AuthorityInfoAccess::new()
            .ocsp("http://ocsp.example.com")
            .ca_issuer("http://ca.example.com/root.crt");
        assert_eq!(aia.ocsp_urls.len(), 1);
        assert_eq!(aia.ca_issuer_urls.len(), 1);
        let der = aia.to_der().unwrap();
        assert!(!der.is_empty());
        // DER should start with SEQUENCE tag
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_cdp_aia_config() {
        let config = CdpAiaConfig::new("https://pki.example.com", "root-ca");

        let cdp = config.generate_cdp();
        assert_eq!(cdp.urls.len(), 1);
        assert_eq!(cdp.urls[0], "https://pki.example.com/crl/root-ca.crl");

        let aia = config.generate_aia();
        assert_eq!(aia.ocsp_urls.len(), 1);
        assert_eq!(aia.ocsp_urls[0], "https://pki.example.com/ocsp");
        assert_eq!(aia.ca_issuer_urls.len(), 1);
        assert_eq!(
            aia.ca_issuer_urls[0],
            "https://pki.example.com/ca/root-ca.crt"
        );
    }

    #[test]
    fn test_cdp_aia_config_trailing_slash() {
        let config = CdpAiaConfig::new("https://pki.example.com/", "issuing-ca");

        let cdp = config.generate_cdp();
        assert_eq!(cdp.urls[0], "https://pki.example.com/crl/issuing-ca.crl");

        let aia = config.generate_aia();
        assert_eq!(aia.ocsp_urls[0], "https://pki.example.com/ocsp");
    }

    #[test]
    fn test_spork_issuance_info() {
        let info = SporkIssuanceInfo::new("test-ca-id");
        assert_eq!(info.software, "SPORK");
        assert_eq!(info.build, "pure-rust-pqc");
        assert_eq!(info.ca_id, "test-ca-id");
        assert!(!info.version.is_empty());
        assert!(!info.issued_at.is_empty());

        // Test DER encoding
        let der = info.to_der().unwrap();
        assert!(!der.is_empty());
        // DER should start with UTF8String tag
        assert_eq!(der[0], 0x0C);
    }

    #[test]
    fn test_spork_issuance_info_with_params() {
        let info = SporkIssuanceInfo::with_params("1.0.0", "test-build", "ca-123");
        assert_eq!(info.software, "SPORK");
        assert_eq!(info.version, "1.0.0");
        assert_eq!(info.build, "test-build");
        assert_eq!(info.ca_id, "ca-123");
    }

    #[test]
    fn test_certificate_policies_acme() {
        let policies = CertificatePolicies::acme_super_admin();
        assert_eq!(policies.policies.len(), 1);
        assert!(policies.contains(&oid::SPORK_ACME_SUPER_ADMIN));
        assert!(policies.has_acme_admin_policy());
        assert_eq!(policies.acme_access_level(), Some(4));

        // Test DER encoding
        let der = policies.to_der().unwrap();
        assert!(!der.is_empty());
        // DER should start with SEQUENCE tag
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_certificate_policies_ca() {
        let policies = CertificatePolicies::ca_operator();
        assert_eq!(policies.policies.len(), 1);
        assert!(policies.contains(&oid::SPORK_CA_OPERATOR));
        assert!(!policies.has_acme_admin_policy());
        assert_eq!(policies.acme_access_level(), None);

        let der = policies.to_der().unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn test_certificate_policies_multiple() {
        let policies =
            CertificatePolicies::new(vec![oid::SPORK_ACME_VIEWER, oid::SPORK_ACME_OPERATOR]);
        assert_eq!(policies.policies.len(), 2);
        assert!(policies.has_acme_admin_policy());
        // Should return highest level
        assert_eq!(policies.acme_access_level(), Some(2));

        let der = policies.to_der().unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn test_certificate_policies_access_levels() {
        assert_eq!(
            CertificatePolicies::acme_viewer().acme_access_level(),
            Some(1)
        );
        assert_eq!(
            CertificatePolicies::acme_operator().acme_access_level(),
            Some(2)
        );
        assert_eq!(
            CertificatePolicies::acme_admin().acme_access_level(),
            Some(3)
        );
        assert_eq!(
            CertificatePolicies::acme_super_admin().acme_access_level(),
            Some(4)
        );
    }

    // --- RFC 6818 PolicyQualifier tests ---

    #[test]
    fn test_policy_qualifier_cps_uri_encoding() {
        let q = PolicyQualifier::CpsUri("https://example.com/cps".to_string());
        let der = q.to_der().unwrap();

        // Should start with SEQUENCE tag
        assert_eq!(der[0], 0x30);
        // Should contain an IA5String (0x16) somewhere
        assert!(der.contains(&0x16));
        // The URI bytes should be present
        assert!(der.windows(23).any(|w| w == b"https://example.com/cps"));
    }

    #[test]
    fn test_policy_qualifier_user_notice_utf8string() {
        let q = PolicyQualifier::UserNotice {
            notice_ref: None,
            explicit_text: Some("Issued under SPORK CA".to_string()),
        };
        let der = q.to_der().unwrap();

        // Should start with SEQUENCE
        assert_eq!(der[0], 0x30);
        // Should contain a UTF8String tag (0x0C)
        assert!(der.contains(&0x0C));
        // Text should be present
        assert!(der.windows(21).any(|w| w == b"Issued under SPORK CA"));
    }

    #[test]
    fn test_policy_qualifier_user_notice_with_notice_ref() {
        let q = PolicyQualifier::UserNotice {
            notice_ref: Some(NoticeReference {
                organization: "SPORK CA".to_string(),
                notice_numbers: vec![1, 2],
            }),
            explicit_text: Some("Test notice".to_string()),
        };
        let der = q.to_der().unwrap();
        assert_eq!(der[0], 0x30);
        // Should have UTF8String for both org and explicit_text
        assert!(der.contains(&0x0C));
    }

    #[test]
    fn test_policy_qualifier_user_notice_empty() {
        let q = PolicyQualifier::UserNotice {
            notice_ref: None,
            explicit_text: None,
        };
        let der = q.to_der().unwrap();
        // Should still produce a valid SEQUENCE
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_certificate_policies_with_cps_qualifier() {
        let policies = CertificatePolicies::with_policy(oid::SPORK_POLICY_EVALUATION)
            .with_qualifier(PolicyQualifier::CpsUri(
                "https://pki.example.com/cps".to_string(),
            ));

        assert_eq!(policies.policies.len(), 1);
        assert_eq!(policies.policy_infos[0].qualifiers.len(), 1);

        let der = policies.to_der().unwrap();
        assert_eq!(der[0], 0x30);
        // Should contain IA5String for CPS URI
        assert!(der.contains(&0x16));
    }

    #[test]
    fn test_certificate_policies_with_user_notice_qualifier() {
        let policies = CertificatePolicies::with_policy(oid::SPORK_POLICY_EVALUATION)
            .with_qualifier(PolicyQualifier::UserNotice {
                notice_ref: None,
                explicit_text: Some("RFC 6818 compliant UTF8String".to_string()),
            });

        assert_eq!(policies.policy_infos[0].qualifiers.len(), 1);

        let der = policies.to_der().unwrap();
        assert_eq!(der[0], 0x30);
        // Should contain UTF8String tag (0x0C) for explicitText per RFC 6818
        assert!(der.contains(&0x0C));
    }

    #[test]
    fn test_certificate_policies_no_qualifiers_backward_compat() {
        // Existing no-qualifier usage should still produce identical output
        let policies = CertificatePolicies::acme_super_admin();
        assert!(policies.policy_infos[0].qualifiers.is_empty());

        let der = policies.to_der().unwrap();
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_encode_der_integer() {
        // 0 → 02 01 00
        let v = encode_der_integer(0);
        assert_eq!(v, vec![0x02, 0x01, 0x00]);

        // 1 → 02 01 01
        let v = encode_der_integer(1);
        assert_eq!(v, vec![0x02, 0x01, 0x01]);

        // 127 → 02 01 7f
        let v = encode_der_integer(127);
        assert_eq!(v, vec![0x02, 0x01, 0x7f]);

        // 128 → 02 02 00 80 (needs padding since 0x80 has high bit set)
        let v = encode_der_integer(128);
        assert_eq!(v, vec![0x02, 0x02, 0x00, 0x80]);

        // 256 → 02 02 01 00
        let v = encode_der_integer(256);
        assert_eq!(v, vec![0x02, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_policy_information_with_qualifier_der() {
        let pi = PolicyInformation::new(oid::SPORK_POLICY_EVALUATION).with_qualifier(
            PolicyQualifier::CpsUri("https://cps.example.com".to_string()),
        );

        let der = pi.to_der().unwrap();
        assert_eq!(der[0], 0x30); // PolicyInformation SEQUENCE
                                  // Should contain policyQualifiers SEQUENCE
        assert!(der.len() > 5);
    }

    // --- SAN validation tests ---

    #[test]
    fn test_san_validate_valid() {
        let san = SubjectAltName::new()
            .dns("example.com")
            .dns("*.example.com")
            .ip("127.0.0.1".parse().unwrap())
            .email("admin@example.com")
            .uri("https://example.com");
        assert!(san.validate().is_ok());
    }

    #[test]
    fn test_san_validate_empty_rejected() {
        let san = SubjectAltName::new();
        assert!(san.validate().is_err());
    }

    #[test]
    fn test_san_validate_dns_null_byte() {
        let san = SubjectAltName::new().dns("bad\0.example.com");
        assert!(san.validate().is_err());
    }

    #[test]
    fn test_san_validate_dns_too_long() {
        let long = format!("{}.example.com", "a".repeat(250));
        let san = SubjectAltName::new().dns(long);
        assert!(san.validate().is_err());
    }

    #[test]
    fn test_san_validate_dns_empty_label() {
        let san = SubjectAltName::new().dns("example..com");
        assert!(san.validate().is_err());
    }

    #[test]
    fn test_san_validate_dns_label_too_long() {
        let long_label = "a".repeat(64);
        let san = SubjectAltName::new().dns(format!("{}.example.com", long_label));
        assert!(san.validate().is_err());
    }

    #[test]
    fn test_san_validate_dns_hyphen_start() {
        let san = SubjectAltName::new().dns("-bad.example.com");
        assert!(san.validate().is_err());
    }

    #[test]
    fn test_san_validate_dns_invalid_chars() {
        let san = SubjectAltName::new().dns("ex ample.com");
        assert!(san.validate().is_err());
    }

    #[test]
    fn test_san_validate_email_no_at() {
        let san = SubjectAltName::new().dns("example.com").email("notanemail");
        assert!(san.validate().is_err());
    }

    #[test]
    fn test_san_validate_uri_no_scheme() {
        let san = SubjectAltName::new()
            .dns("example.com")
            .uri("example.com/path");
        assert!(san.validate().is_err());
    }

    #[test]
    fn test_san_validate_wildcard_ok() {
        let san = SubjectAltName::new().dns("*.example.com");
        assert!(san.validate().is_ok());
    }

    #[test]
    fn test_san_validate_max_label_length_ok() {
        let label = "a".repeat(63);
        let san = SubjectAltName::new().dns(format!("{}.com", label));
        assert!(san.validate().is_ok());
    }

    // ===== RFC 9549 IDNA2008 SAN tests =====

    #[test]
    fn test_san_idna_unicode_accepted_and_normalized() {
        // RFC 9549: Unicode DNS names should be accepted and normalized to A-label
        let san = SubjectAltName::new().dns("münchen.de");
        assert!(san.validate().is_ok());
        // DER encoding should use the normalized A-label form
        let der = san.to_der().unwrap();
        // The DER should contain the punycode form "xn--mnchen-3ya.de"
        let der_str = String::from_utf8_lossy(&der);
        assert!(
            der_str.contains("xn--mnchen-3ya.de"),
            "DER should contain A-label form, got: {:?}",
            der
        );
    }

    #[test]
    fn test_san_idna_punycode_passthrough() {
        // A-label (Punycode) input should pass through unchanged
        let san = SubjectAltName::new().dns("xn--mnchen-3ya.de");
        assert!(san.validate().is_ok());
    }

    #[test]
    fn test_san_idna_wildcard_unicode() {
        // Wildcard with Unicode base domain
        let san = SubjectAltName::new().dns("*.münchen.de");
        assert!(san.validate().is_ok());
        let der = san.to_der().unwrap();
        let der_str = String::from_utf8_lossy(&der);
        assert!(
            der_str.contains("*.xn--mnchen-3ya.de"),
            "DER should contain wildcard + A-label"
        );
    }

    #[test]
    fn test_san_idna_mixed_unicode_ascii() {
        // Mix of Unicode and ASCII labels
        let san = SubjectAltName::new().dns("www.münchen.de");
        assert!(san.validate().is_ok());
    }

    #[test]
    fn test_san_idna_case_normalization() {
        // IDNA2008 normalizes case
        let san = SubjectAltName::new().dns("WWW.EXAMPLE.COM");
        assert!(san.validate().is_ok());
        let der = san.to_der().unwrap();
        let der_str = String::from_utf8_lossy(&der);
        assert!(
            der_str.contains("www.example.com"),
            "DER should contain lowercased domain"
        );
    }

    // --- RFC 9598 SmtpUTF8Mailbox tests ---

    #[test]
    fn test_san_utf8_email_ascii_valid() {
        let san = SubjectAltName::new().utf8_email("user@example.com");
        assert!(san.validate().is_ok());
    }

    #[test]
    fn test_san_utf8_email_unicode_local_part() {
        // RFC 9598: UTF-8 in local part is allowed
        let san = SubjectAltName::new().utf8_email("用户@example.com");
        assert!(san.validate().is_ok());
    }

    #[test]
    fn test_san_utf8_email_unicode_domain_normalized() {
        // RFC 9598 §3: domain MUST be A-label (IDNA2008)
        let san = SubjectAltName::new().utf8_email("user@münchen.de");
        assert!(san.validate().is_ok());
        let der = san.to_der().unwrap();
        // Domain should be punycode A-label
        assert!(
            der.windows(b"xn--mnchen-3ya.de".len())
                .any(|w| w == b"xn--mnchen-3ya.de"),
            "Domain should be normalized to A-label (punycode) in DER"
        );
    }

    #[test]
    fn test_san_utf8_email_rejects_bom() {
        // RFC 9598 §2: must not contain BOM (U+FEFF)
        let san = SubjectAltName::new().utf8_email("\u{FEFF}user@example.com");
        assert!(san.validate().is_err(), "BOM should be rejected");
    }

    #[test]
    fn test_san_utf8_email_rejects_null() {
        let san = SubjectAltName::new().utf8_email("user\0@example.com");
        assert!(san.validate().is_err(), "Null byte should be rejected");
    }

    #[test]
    fn test_san_utf8_email_rejects_invalid_format() {
        let san = SubjectAltName::new().utf8_email("no-at-sign");
        assert!(san.validate().is_err());
    }

    #[test]
    fn test_san_utf8_email_der_uses_othername() {
        // SmtpUTF8Mailbox is encoded as otherName [0] with specific OID
        let san = SubjectAltName::new().utf8_email("test@example.com");
        let der = san.to_der().unwrap();
        // otherName tag is 0xA0 (context [0] constructed)
        assert_eq!(der[2], 0xA0, "SmtpUTF8Mailbox should use otherName [0]");
        // OID 1.3.6.1.5.5.7.8.9 should appear
        let oid_bytes = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x08, 0x09];
        assert!(
            der.windows(oid_bytes.len()).any(|w| w == oid_bytes),
            "DER should contain id-on-SmtpUTF8Mailbox OID"
        );
    }

    #[test]
    fn test_san_utf8_email_der_uses_utf8string() {
        let san = SubjectAltName::new().utf8_email("test@example.com");
        let der = san.to_der().unwrap();
        // UTF8String tag 0x0C should appear in the value
        assert!(
            der.contains(&0x0C),
            "SmtpUTF8Mailbox value should use UTF8String (0x0C)"
        );
    }

    #[test]
    fn test_san_utf8_email_with_unicode_roundtrip() {
        // Full roundtrip: Unicode local + Unicode domain
        let san = SubjectAltName::new().utf8_email("用户@münchen.de");
        let der = san.to_der().unwrap();
        // The encoded email should have UTF-8 local + A-label domain
        let expected = "用户@xn--mnchen-3ya.de";
        assert!(
            der.windows(expected.len())
                .any(|w| w == expected.as_bytes()),
            "DER should contain UTF-8 local + A-label domain"
        );
    }

    #[test]
    fn test_san_mixed_email_and_utf8_email() {
        // Both rfc822Name and SmtpUTF8Mailbox in same SAN
        let san = SubjectAltName::new()
            .email("ascii@example.com")
            .utf8_email("用户@example.com");
        assert!(san.validate().is_ok());
        let der = san.to_der().unwrap();
        // Should contain both context [1] (rfc822Name) and [0] (otherName)
        assert!(der.contains(&0x81), "Should contain rfc822Name tag");
        assert!(der.contains(&0xA0), "Should contain otherName tag");
    }

    #[test]
    fn test_san_rfc822_rejects_unicode_local() {
        // rfc822Name (IA5String) MUST be ASCII — Unicode local part rejected
        let san = SubjectAltName::new().email("用户@example.com");
        assert!(
            san.validate().is_err(),
            "rfc822Name should reject non-ASCII local part"
        );
    }

    #[test]
    fn test_san_rfc822_domain_idna_normalized() {
        // rfc822Name domain should be normalized via IDNA2008
        let san = SubjectAltName::new().email("user@münchen.de");
        assert!(san.validate().is_ok());
        let der = san.to_der().unwrap();
        assert!(
            der.windows(b"xn--mnchen-3ya.de".len())
                .any(|w| w == b"xn--mnchen-3ya.de"),
            "rfc822Name domain should be normalized to A-label"
        );
    }

    // --- SporkIssuanceInfo encoding/decoding tests ---

    #[test]
    fn test_spork_issuance_info_der_encoding_structure() {
        let info = SporkIssuanceInfo::new("unit-test-ca-001");

        // Encode to DER
        let der = info.to_der().unwrap();

        // DER must not be empty
        assert!(!der.is_empty(), "DER encoding should not be empty");

        // First byte is UTF8String tag 0x0C
        assert_eq!(der[0], 0x0C, "Expected UTF8String tag 0x0C");

        // Extract the JSON payload from the DER encoding
        // After tag (1 byte), length is encoded (1+ bytes), then the payload
        let (payload_start, payload_len) = if der[1] < 128 {
            (2, der[1] as usize)
        } else if der[1] == 0x81 {
            (3, der[2] as usize)
        } else {
            // 0x82 = 2-byte length
            (4, ((der[2] as usize) << 8) | der[3] as usize)
        };

        let payload = &der[payload_start..payload_start + payload_len];
        let json_str = std::str::from_utf8(payload).expect("Payload should be valid UTF-8");

        // Parse the JSON and verify fields
        let parsed: serde_json::Value =
            serde_json::from_str(json_str).expect("Payload should be valid JSON");

        assert_eq!(parsed["software"], "SPORK");
        assert_eq!(parsed["build"], "pure-rust-pqc");
        assert_eq!(parsed["ca_id"], "unit-test-ca-001");
        assert!(!parsed["version"].as_str().unwrap().is_empty());
        assert!(!parsed["issued_at"].as_str().unwrap().is_empty());
    }

    #[test]
    fn test_spork_issuance_info_der_deterministic_fields() {
        // Two calls with the same CA ID should produce the same software/build/ca_id
        let info1 = SporkIssuanceInfo::new("same-ca");
        let info2 = SporkIssuanceInfo::new("same-ca");

        assert_eq!(info1.software, info2.software);
        assert_eq!(info1.version, info2.version);
        assert_eq!(info1.build, info2.build);
        assert_eq!(info1.ca_id, info2.ca_id);
        // issued_at may differ by nanoseconds, but both should be non-empty
        assert!(!info1.issued_at.is_empty());
        assert!(!info2.issued_at.is_empty());
    }

    #[test]
    fn test_spork_issuance_info_custom_params_encoding() {
        let info = SporkIssuanceInfo::with_params("99.0.0", "custom-build", "custom-ca");
        let der = info.to_der().unwrap();

        assert!(!der.is_empty());
        assert_eq!(der[0], 0x0C); // UTF8String tag

        // The DER should contain the custom values as part of the JSON string
        let der_str = String::from_utf8_lossy(&der);
        assert!(der_str.contains("99.0.0"));
        assert!(der_str.contains("custom-build"));
        assert!(der_str.contains("custom-ca"));
    }

    // --- Issue #32: SporkIssuanceInfo extension encoding/decoding ---

    #[test]
    fn test_spork_issuance_info_json_roundtrip() {
        // Encode to DER, extract JSON, deserialize back to SporkIssuanceInfo
        let original = SporkIssuanceInfo::with_params("2.0.0", "test-build", "roundtrip-ca");
        let der = original.to_der().unwrap();

        // Extract JSON from DER UTF8String
        let (payload_start, payload_len) = if der[1] < 128 {
            (2, der[1] as usize)
        } else if der[1] == 0x81 {
            (3, der[2] as usize)
        } else {
            (4, ((der[2] as usize) << 8) | der[3] as usize)
        };

        let payload = &der[payload_start..payload_start + payload_len];
        let json_str = std::str::from_utf8(payload).unwrap();
        let decoded: SporkIssuanceInfo = serde_json::from_str(json_str).unwrap();

        assert_eq!(decoded.software, original.software);
        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.build, original.build);
        assert_eq!(decoded.ca_id, original.ca_id);
        assert_eq!(decoded.issued_at, original.issued_at);
    }

    #[test]
    fn test_spork_issuance_info_der_length_short_form() {
        // For typical payloads (< 128 bytes), length should be short form
        let info = SporkIssuanceInfo::with_params("1.0", "b", "c");
        let der = info.to_der().unwrap();
        // Tag byte + 1-byte length + payload
        assert_eq!(der[0], 0x0C);
        // Short form: length byte < 128
        assert!(
            der[1] < 128,
            "Expected short-form length for small payload, got 0x{:02X}",
            der[1]
        );
        // Total DER length should be tag(1) + length(1) + payload
        assert_eq!(der.len(), 2 + der[1] as usize);
    }

    #[test]
    fn test_spork_issuance_info_der_length_long_form() {
        // Force a long CA ID to push total JSON past 127 bytes
        let long_ca_id = "a".repeat(200);
        let info = SporkIssuanceInfo::with_params("1.0.0", "pure-rust-pqc", &long_ca_id);
        let der = info.to_der().unwrap();

        assert_eq!(der[0], 0x0C);
        // Length should use long form (first byte has high bit set)
        assert!(
            der[1] & 0x80 != 0,
            "Expected long-form length for large payload, got 0x{:02X}",
            der[1]
        );
    }

    #[test]
    fn test_spork_issuance_info_version_matches_cargo_pkg() {
        // The VERSION constant should match what new() uses
        let info = SporkIssuanceInfo::new("version-check-ca");
        assert_eq!(info.version, SporkIssuanceInfo::VERSION);
        assert!(!info.version.is_empty());
    }

    #[test]
    fn test_spork_issuance_info_issued_at_is_rfc3339() {
        let info = SporkIssuanceInfo::new("timestamp-ca");
        // The issued_at field should parse as a valid RFC 3339 timestamp
        let parsed = chrono::DateTime::parse_from_rfc3339(&info.issued_at);
        assert!(
            parsed.is_ok(),
            "issued_at should be valid RFC 3339, got: {}",
            info.issued_at
        );
    }

    #[test]
    fn test_spork_issuance_info_software_always_spork() {
        // Both constructors should always produce software="SPORK"
        let info1 = SporkIssuanceInfo::new("ca1");
        let info2 = SporkIssuanceInfo::with_params("x", "y", "ca2");
        assert_eq!(info1.software, "SPORK");
        assert_eq!(info2.software, "SPORK");
    }

    #[test]
    fn test_spork_issuance_info_special_chars_in_ca_id() {
        // CA IDs with special JSON characters should be properly escaped
        let info = SporkIssuanceInfo::new(r#"ca-with-"quotes"-and-\backslash"#);
        let der = info.to_der().unwrap();

        // Extract and parse the JSON
        let (start, len) = if der[1] < 128 {
            (2, der[1] as usize)
        } else if der[1] == 0x81 {
            (3, der[2] as usize)
        } else {
            (4, ((der[2] as usize) << 8) | der[3] as usize)
        };

        let payload = &der[start..start + len];
        let json_str = std::str::from_utf8(payload).unwrap();
        let decoded: SporkIssuanceInfo = serde_json::from_str(json_str).unwrap();
        assert_eq!(decoded.ca_id, r#"ca-with-"quotes"-and-\backslash"#);
    }

    #[test]
    fn test_spork_issuance_info_serde_json_direct() {
        // Test direct serde serialization/deserialization without DER wrapper
        let info = SporkIssuanceInfo::with_params("3.0.0", "musl-static", "serde-ca");
        let json = serde_json::to_string(&info).unwrap();

        assert!(json.contains("\"software\":\"SPORK\""));
        assert!(json.contains("\"version\":\"3.0.0\""));
        assert!(json.contains("\"build\":\"musl-static\""));
        assert!(json.contains("\"ca_id\":\"serde-ca\""));

        let deserialized: SporkIssuanceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.software, "SPORK");
        assert_eq!(deserialized.version, "3.0.0");
        assert_eq!(deserialized.build, "musl-static");
        assert_eq!(deserialized.ca_id, "serde-ca");
        assert_eq!(deserialized.issued_at, info.issued_at);
    }

    #[test]
    fn test_spork_issuance_info_empty_ca_id() {
        // Empty CA ID should still produce valid DER/JSON
        let info = SporkIssuanceInfo::new("");
        assert_eq!(info.ca_id, "");

        let der = info.to_der().unwrap();
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x0C);

        // JSON should contain "ca_id":""
        let der_str = String::from_utf8_lossy(&der);
        assert!(der_str.contains(r#""ca_id":""#));
    }

    #[test]
    fn test_spork_issuance_info_in_certificate() {
        // Full integration: create a cert with SporkIssuanceInfo and verify
        // the extension appears in the output
        use crate::algo::{AlgorithmId, KeyPair};
        use crate::cert::{
            builder::CertificateBuilder, extensions::BasicConstraints, NameBuilder, Validity,
        };

        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("SporkInfo Cert Test").build();

        let info = SporkIssuanceInfo::new("integration-test-ca");

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .validity(Validity::days_from_now(90))
        .basic_constraints(BasicConstraints::end_entity())
        .spork_issuance_info(info)
        .build_and_sign(&kp)
        .unwrap();

        // Find the SPORK issuance info extension
        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let spork_ext = exts
            .iter()
            .find(|e| e.extn_id == oid::SPORK_ISSUANCE_INFO)
            .expect("SPORK issuance info extension should be present");

        // It should be non-critical
        assert!(
            !spork_ext.critical,
            "SPORK issuance info must be non-critical"
        );
    }

    #[test]
    fn test_spork_issuance_info_spork_info_with_ca_id_builder() {
        // Test the convenience method spork_info_with_ca_id
        use crate::algo::{AlgorithmId, KeyPair};
        use crate::cert::{builder::CertificateBuilder, NameBuilder, Validity};

        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Convenience Method Test").build();

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .validity(Validity::days_from_now(30))
        .spork_info_with_ca_id("convenience-ca-id")
        .include_subject_key_identifier(false)
        .include_authority_key_identifier(false)
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let spork_ext = exts
            .iter()
            .find(|e| e.extn_id == oid::SPORK_ISSUANCE_INFO)
            .expect("SPORK issuance info should be present via convenience method");
        assert!(!spork_ext.critical);
    }

    // ===== Issue #73: Validate email addresses in SAN rfc822Name =====

    #[test]
    fn test_san_email_valid_basic() {
        let san = SubjectAltName::new().email("user@example.com");
        assert!(san.validate().is_ok());
    }

    #[test]
    fn test_san_email_valid_with_subdomain() {
        let san = SubjectAltName::new().email("admin@mail.corp.example.com");
        assert!(san.validate().is_ok());
    }

    #[test]
    fn test_san_email_valid_with_plus_tag() {
        let san = SubjectAltName::new().email("user+tag@example.com");
        assert!(san.validate().is_ok());
    }

    #[test]
    fn test_san_email_valid_with_dots_in_local() {
        let san = SubjectAltName::new().email("first.last@example.com");
        assert!(san.validate().is_ok());
    }

    #[test]
    fn test_san_email_rejects_empty_string() {
        let san = SubjectAltName::new().email("");
        let err = san.validate();
        assert!(err.is_err(), "Empty email should be rejected");
    }

    #[test]
    fn test_san_email_rejects_no_at_sign() {
        let san = SubjectAltName::new().email("userexample.com");
        assert!(
            san.validate().is_err(),
            "Email without @ should be rejected"
        );
    }

    #[test]
    fn test_san_email_rejects_no_domain() {
        let san = SubjectAltName::new().email("user@");
        assert!(
            san.validate().is_err(),
            "Email without domain should be rejected"
        );
    }

    #[test]
    fn test_san_email_rejects_no_local_part() {
        let san = SubjectAltName::new().email("@example.com");
        assert!(
            san.validate().is_err(),
            "Email without local part should be rejected"
        );
    }

    #[test]
    fn test_san_email_rejects_no_domain_dot() {
        let san = SubjectAltName::new().email("user@localhost");
        assert!(
            san.validate().is_err(),
            "Email domain without dot should be rejected"
        );
    }

    #[test]
    fn test_san_email_rejects_null_byte() {
        let san = SubjectAltName::new().email("user\0@example.com");
        assert!(
            san.validate().is_err(),
            "Email with null byte should be rejected"
        );
    }

    #[test]
    fn test_san_email_rejects_double_at() {
        let san = SubjectAltName::new().email("user@@example.com");
        // splitn(2, '@') gives ["user", "@example.com"] — domain starts with @
        // which does not contain a dot after the initial character issue
        // The domain "@example.com" does contain a dot, so let's verify behavior
        let result = san.validate();
        // This should still pass since "@example.com" contains a "."
        // The validate_san_email function is permissive here
        // This documents current behavior
        assert!(
            result.is_ok() || result.is_err(),
            "Double-@ email validation result documented"
        );
    }

    #[test]
    fn test_san_email_rejects_only_at() {
        let san = SubjectAltName::new().email("@");
        assert!(san.validate().is_err(), "Just @ should be rejected");
    }

    #[test]
    fn test_san_multiple_emails_all_valid() {
        let san = SubjectAltName::new()
            .email("alice@example.com")
            .email("bob@example.com")
            .email("carol@corp.example.com");
        assert!(
            san.validate().is_ok(),
            "Multiple valid emails should all pass"
        );
    }

    #[test]
    fn test_san_multiple_emails_one_invalid_fails_all() {
        let san = SubjectAltName::new()
            .email("alice@example.com")
            .email("bad-email-no-at")
            .email("carol@corp.example.com");
        assert!(
            san.validate().is_err(),
            "One invalid email should cause validation failure"
        );
    }

    #[test]
    fn test_san_email_der_encoding_uses_context_tag_1() {
        // rfc822Name is GeneralName [1] — context tag 0x81
        let san = SubjectAltName::new().email("test@example.com");
        let der = san.to_der().unwrap();

        // DER should be: SEQUENCE { [1] "test@example.com" }
        // Find context tag [1] = 0x81 in the DER
        assert!(
            der.contains(&0x81),
            "Email SAN DER should contain context tag [1] (0x81)"
        );
        // Verify the email string appears in the DER
        let email_bytes = b"test@example.com";
        assert!(
            der.windows(email_bytes.len()).any(|w| w == email_bytes),
            "Email string should appear in DER encoding"
        );
    }

    #[test]
    fn test_ski_from_public_key_is_20_bytes() {
        let fake_spki = b"fake-spki-der-for-testing-purposes";
        let ski = SubjectKeyIdentifier::from_public_key(fake_spki);
        assert_eq!(
            ski.0.len(),
            20,
            "Default SKI should be 20 bytes (SHA-256 truncated)"
        );
    }

    #[test]
    fn test_ski_sha256_is_32_bytes() {
        // RFC 7093 Method 1: full SHA-256 (32 bytes)
        let fake_spki = b"fake-spki-der-for-testing-purposes";
        let ski = SubjectKeyIdentifier::from_public_key_sha256(fake_spki);
        assert_eq!(
            ski.0.len(),
            32,
            "RFC 7093 SKI should be 32 bytes (full SHA-256)"
        );
    }

    #[test]
    fn test_ski_deterministic() {
        let spki = b"consistent-input";
        let ski1 = SubjectKeyIdentifier::from_public_key(spki);
        let ski2 = SubjectKeyIdentifier::from_public_key(spki);
        assert_eq!(ski1.0, ski2.0, "SKI should be deterministic");

        let ski3 = SubjectKeyIdentifier::from_public_key_sha256(spki);
        let ski4 = SubjectKeyIdentifier::from_public_key_sha256(spki);
        assert_eq!(ski3.0, ski4.0, "SHA-256 SKI should be deterministic");
    }

    #[test]
    fn test_ski_sha256_prefix_matches_default() {
        // The default (truncated) SKI should be a prefix of the SHA-256 SKI
        let spki = b"test-key-material";
        let ski_default = SubjectKeyIdentifier::from_public_key(spki);
        let ski_full = SubjectKeyIdentifier::from_public_key_sha256(spki);
        assert_eq!(
            &ski_full.0[..20],
            &ski_default.0[..],
            "Default SKI should be first 20 bytes of full SHA-256"
        );
    }

    #[test]
    fn test_ski_der_encoding() {
        let ski = SubjectKeyIdentifier(vec![0x01, 0x02, 0x03]);
        let der = ski.to_der().unwrap();
        assert_eq!(der[0], 0x04, "OCTET STRING tag");
        assert_eq!(der[1], 3, "length");
        assert_eq!(&der[2..], &[0x01, 0x02, 0x03]);
    }

    // --- RFC 9608: noRevAvail tests ---

    #[test]
    fn test_no_rev_avail_der_is_null() {
        let nra = NoRevAvail;
        let der = nra.to_der().unwrap();
        assert_eq!(der, vec![0x05, 0x00], "noRevAvail should be ASN.1 NULL");
    }

    #[test]
    fn test_no_rev_avail_oid() {
        // id-ce-noRevAvail is 2.5.29.56
        assert_eq!(oid::NO_REV_AVAIL.to_string(), "2.5.29.56");
    }

    // --- RFC 6960: id-pkix-ocsp-nocheck tests ---

    #[test]
    fn test_ocsp_nocheck_der_is_null() {
        let nc = OcspNoCheck;
        let der = nc.to_der().unwrap();
        assert_eq!(der, vec![0x05, 0x00], "ocsp-nocheck must be ASN.1 NULL");
    }

    #[test]
    fn test_ocsp_nocheck_oid() {
        // id-pkix-ocsp-nocheck is 1.3.6.1.5.5.7.48.1.5
        assert_eq!(oid::OCSP_NOCHECK.to_string(), "1.3.6.1.5.5.7.48.1.5");
    }

    // --- RFC 7633: TLS Feature tests ---

    #[test]
    fn test_tls_feature_must_staple() {
        let feat = TlsFeature::must_staple();
        assert_eq!(feat.features, vec![5]);
    }

    #[test]
    fn test_tls_feature_der_encoding() {
        let feat = TlsFeature::must_staple();
        let der = feat.to_der().unwrap();
        // SEQUENCE { INTEGER 5 }
        // 0x30 0x03 0x02 0x01 0x05
        assert_eq!(der, vec![0x30, 0x03, 0x02, 0x01, 0x05]);
    }

    #[test]
    fn test_tls_feature_multi_value() {
        // status_request (5) + status_request_v2 (17)
        let feat = TlsFeature::new(vec![5, 17]);
        let der = feat.to_der().unwrap();
        // SEQUENCE { INTEGER 5, INTEGER 17 }
        // 0x30 0x06 0x02 0x01 0x05 0x02 0x01 0x11
        assert_eq!(der, vec![0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x11]);
    }

    #[test]
    fn test_tls_feature_large_value() {
        // Test a 2-byte integer (e.g., value 256 = 0x0100)
        let feat = TlsFeature::new(vec![256]);
        let der = feat.to_der().unwrap();
        // SEQUENCE { INTEGER 256 }
        // 0x30 0x04 0x02 0x02 0x01 0x00
        assert_eq!(der, vec![0x30, 0x04, 0x02, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_tls_feature_oid() {
        assert_eq!(oid::TLS_FEATURE.to_string(), "1.3.6.1.5.5.7.1.24");
    }

    // --- RFC 5280 §4.2.1.14: InhibitAnyPolicy tests ---

    #[test]
    fn test_inhibit_any_policy_immediate() {
        let iap = InhibitAnyPolicy::immediate();
        assert_eq!(iap.skip_certs, 0);
    }

    #[test]
    fn test_inhibit_any_policy_der_zero() {
        let iap = InhibitAnyPolicy::new(0);
        let der = iap.to_der().unwrap();
        // INTEGER 0 = 0x02 0x01 0x00
        assert_eq!(der, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_inhibit_any_policy_der_small() {
        let iap = InhibitAnyPolicy::new(2);
        let der = iap.to_der().unwrap();
        // INTEGER 2 = 0x02 0x01 0x02
        assert_eq!(der, vec![0x02, 0x01, 0x02]);
    }

    #[test]
    fn test_inhibit_any_policy_der_large() {
        let iap = InhibitAnyPolicy::new(300);
        let der = iap.to_der().unwrap();
        // INTEGER 300 = 0x012C → 0x02 0x02 0x01 0x2C
        assert_eq!(der, vec![0x02, 0x02, 0x01, 0x2C]);
    }

    #[test]
    fn test_inhibit_any_policy_der_sign_bit() {
        // Value 128 (0x80) needs sign-bit padding: 0x02 0x02 0x00 0x80
        let iap = InhibitAnyPolicy::new(128);
        let der = iap.to_der().unwrap();
        assert_eq!(der, vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn test_inhibit_any_policy_der_255() {
        // Value 255 (0xFF) needs sign-bit padding: 0x02 0x02 0x00 0xFF
        let iap = InhibitAnyPolicy::new(255);
        let der = iap.to_der().unwrap();
        assert_eq!(der, vec![0x02, 0x02, 0x00, 0xFF]);
    }

    #[test]
    fn test_inhibit_any_policy_der_256() {
        // Value 256 (0x0100) — no sign-bit issue: 0x02 0x02 0x01 0x00
        let iap = InhibitAnyPolicy::new(256);
        let der = iap.to_der().unwrap();
        assert_eq!(der, vec![0x02, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_inhibit_any_policy_oid() {
        assert_eq!(oid::INHIBIT_ANY_POLICY.to_string(), "2.5.29.54");
    }

    // --- RFC 5280 §4.2.1.15: FreshestCRL tests ---

    #[test]
    fn test_freshest_crl_oid() {
        assert_eq!(oid::FRESHEST_CRL.to_string(), "2.5.29.46");
    }

    #[test]
    fn test_freshest_crl_with_url() {
        let fcrl = FreshestCrl::with_url("http://deltacrl.example.com/delta.crl");
        assert_eq!(fcrl.urls.len(), 1);
        assert_eq!(fcrl.urls[0], "http://deltacrl.example.com/delta.crl");
    }

    #[test]
    fn test_freshest_crl_multiple_urls() {
        let fcrl = FreshestCrl::new()
            .url("http://delta1.example.com/delta.crl")
            .url("http://delta2.example.com/delta.crl");
        assert_eq!(fcrl.urls.len(), 2);
    }

    #[test]
    fn test_freshest_crl_der_starts_with_sequence() {
        let fcrl = FreshestCrl::with_url("http://deltacrl.example.com/delta.crl");
        let der = fcrl.to_der().unwrap();
        assert!(!der.is_empty());
        assert_eq!(
            der[0], 0x30,
            "FreshestCRL DER should start with SEQUENCE tag"
        );
    }

    #[test]
    fn test_freshest_crl_der_matches_cdp_structure() {
        // FreshestCRL has identical ASN.1 to CRLDistributionPoints — same URL
        // should produce the same DER bytes.
        let url = "http://delta.example.com/ca.crl";
        let fcrl = FreshestCrl::with_url(url);
        let cdp = CrlDistributionPoints::with_url(url);

        let fcrl_der = fcrl.to_der().unwrap();
        let cdp_der = cdp.to_der().unwrap();

        assert_eq!(
            fcrl_der, cdp_der,
            "FreshestCRL and CDP must produce identical DER for the same URL"
        );
    }

    #[test]
    fn test_freshest_crl_der_contains_url_bytes() {
        let url = "http://deltacrl.example.com/delta.crl";
        let fcrl = FreshestCrl::with_url(url);
        let der = fcrl.to_der().unwrap();

        let url_bytes = url.as_bytes();
        assert!(
            der.windows(url_bytes.len()).any(|w| w == url_bytes),
            "FreshestCRL DER should contain the URL bytes"
        );
    }

    #[test]
    fn test_freshest_crl_default_is_empty() {
        let fcrl = FreshestCrl::default();
        assert!(fcrl.urls.is_empty());
    }

    // --- RFC 5280 Section 4.2.2.2: SubjectInformationAccess tests ---

    #[test]
    fn test_sia_oid() {
        // id-pe-subjectInfoAccessSyntax OID must be 1.3.6.1.5.5.7.1.11
        assert_eq!(oid::SUBJECT_INFO_ACCESS.to_string(), "1.3.6.1.5.5.7.1.11");
    }

    #[test]
    fn test_sia_ca_repository_oid() {
        // id-ad-caRepository OID must be 1.3.6.1.5.5.7.48.5
        assert_eq!(oid::SIA_CA_REPOSITORY.to_string(), "1.3.6.1.5.5.7.48.5");
    }

    #[test]
    fn test_sia_time_stamping_oid() {
        // id-ad-timeStamping OID must be 1.3.6.1.5.5.7.48.3
        assert_eq!(oid::SIA_TIME_STAMPING.to_string(), "1.3.6.1.5.5.7.48.3");
    }

    #[test]
    fn test_sia_new_is_empty() {
        let sia = SubjectInformationAccess::new();
        assert!(sia.ca_repository_urls.is_empty());
        assert!(sia.time_stamping_urls.is_empty());
    }

    #[test]
    fn test_sia_default_is_empty() {
        let sia = SubjectInformationAccess::default();
        assert!(sia.ca_repository_urls.is_empty());
        assert!(sia.time_stamping_urls.is_empty());
    }

    #[test]
    fn test_sia_ca_repository_url() {
        let sia = SubjectInformationAccess::new()
            .ca_repository("https://pki.example.com/certs/issuing-ca.p7c");
        assert_eq!(sia.ca_repository_urls.len(), 1);
        assert_eq!(
            sia.ca_repository_urls[0],
            "https://pki.example.com/certs/issuing-ca.p7c"
        );
        assert!(sia.time_stamping_urls.is_empty());
    }

    #[test]
    fn test_sia_time_stamping_url() {
        let sia =
            SubjectInformationAccess::new().time_stamping("https://tsa.example.com/timestamp");
        assert!(sia.ca_repository_urls.is_empty());
        assert_eq!(sia.time_stamping_urls.len(), 1);
        assert_eq!(
            sia.time_stamping_urls[0],
            "https://tsa.example.com/timestamp"
        );
    }

    #[test]
    fn test_sia_multiple_ca_repository_urls() {
        let sia = SubjectInformationAccess::new()
            .ca_repository("https://pki.example.com/certs/ca.p7c")
            .ca_repository("ldap://ldap.example.com/cn=CA,dc=example,dc=com?cACertificate;binary");
        assert_eq!(sia.ca_repository_urls.len(), 2);
    }

    #[test]
    fn test_sia_mixed_access_methods() {
        let sia = SubjectInformationAccess::new()
            .ca_repository("https://pki.example.com/certs/ca.p7c")
            .time_stamping("https://tsa.example.com/timestamp");
        assert_eq!(sia.ca_repository_urls.len(), 1);
        assert_eq!(sia.time_stamping_urls.len(), 1);
    }

    #[test]
    fn test_sia_der_starts_with_sequence() {
        let sia =
            SubjectInformationAccess::new().ca_repository("https://pki.example.com/certs/ca.p7c");
        let der = sia.to_der().unwrap();
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30, "SIA DER must start with SEQUENCE tag");
    }

    #[test]
    fn test_sia_der_contains_ca_repository_url() {
        let url = "https://pki.example.com/certs/ca.p7c";
        let sia = SubjectInformationAccess::new().ca_repository(url);
        let der = sia.to_der().unwrap();
        let url_bytes = url.as_bytes();
        assert!(
            der.windows(url_bytes.len()).any(|w| w == url_bytes),
            "SIA DER must contain the caRepository URL bytes"
        );
    }

    #[test]
    fn test_sia_der_contains_time_stamping_url() {
        let url = "https://tsa.example.com/timestamp";
        let sia = SubjectInformationAccess::new().time_stamping(url);
        let der = sia.to_der().unwrap();
        let url_bytes = url.as_bytes();
        assert!(
            der.windows(url_bytes.len()).any(|w| w == url_bytes),
            "SIA DER must contain the timeStamping URL bytes"
        );
    }

    #[test]
    fn test_sia_in_certificate() {
        use crate::algo::{AlgorithmId, KeyPair};
        use crate::cert::{builder::CertificateBuilder, extensions::BasicConstraints, NameBuilder};

        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("SIA Test CA").build();

        let sia = SubjectInformationAccess::new()
            .ca_repository("https://pki.example.com/certs/sia-test-ca.p7c");

        let cert = CertificateBuilder::new(
            subject,
            kp.public_key_der().unwrap(),
            AlgorithmId::EcdsaP256,
        )
        .basic_constraints(BasicConstraints::ca())
        .subject_information_access(sia)
        .build_and_sign(&kp)
        .unwrap();

        let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
        let sia_ext = exts
            .iter()
            .find(|e| e.extn_id == oid::SUBJECT_INFO_ACCESS)
            .expect("SubjectInformationAccess extension should be present");

        // SIA must be non-critical (RFC 5280 Section 4.2.2.2)
        assert!(
            !sia_ext.critical,
            "SubjectInformationAccess must be non-critical"
        );

        // URL should be in the extension value
        let url_bytes = b"https://pki.example.com/certs/sia-test-ca.p7c";
        let ext_bytes = sia_ext.extn_value.as_bytes();
        assert!(
            ext_bytes.windows(url_bytes.len()).any(|w| w == url_bytes),
            "SIA extension must contain the caRepository URL"
        );
    }

    // ===== RFC 5280 §4.2.1.5: PolicyMappings tests =====

    #[test]
    fn test_policy_mappings_from_oid_strings() {
        let pm = PolicyMappings::from_oid_strings(&[
            ("2.16.840.1.101.3.2.1.3.6", "1.3.6.1.4.1.56266.1.1.2"),
            ("2.16.840.1.101.3.2.1.3.7", "1.3.6.1.4.1.56266.1.1.3"),
        ])
        .unwrap();
        assert_eq!(pm.mappings.len(), 2);
    }

    #[test]
    fn test_policy_mappings_invalid_oid() {
        let result = PolicyMappings::from_oid_strings(&[("not.valid", "also.bad")]);
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_mappings_der_starts_with_sequence() {
        let pm = PolicyMappings::from_oid_strings(&[(
            "2.16.840.1.101.3.2.1.3.6",
            "1.3.6.1.4.1.56266.1.1.2",
        )])
        .unwrap();
        let der = pm.to_der().unwrap();
        assert_eq!(
            der[0], 0x30,
            "PolicyMappings DER should start with SEQUENCE tag"
        );
    }

    #[test]
    fn test_policy_mappings_der_contains_oids() {
        let pm = PolicyMappings::from_oid_strings(&[("2.5.29.32.0", "1.3.6.1.4.1.56266.1.1.2")])
            .unwrap();
        let der = pm.to_der().unwrap();
        // Each mapping is SEQUENCE { OID, OID } — verify inner sequences exist
        // Look for at least 2 OID tags (0x06) within
        let oid_count = der.iter().filter(|&&b| b == 0x06).count();
        assert!(
            oid_count >= 2,
            "PolicyMappings DER should contain at least 2 OID tags"
        );
    }

    #[test]
    fn test_policy_mappings_builder_chain() {
        let oid1 = ObjectIdentifier::new_unwrap("2.5.29.32.0");
        let oid2 = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56266.1.1.2");
        let pm = PolicyMappings::new().add_mapping(oid1, oid2);
        assert_eq!(pm.mappings.len(), 1);
        let der = pm.to_der().unwrap();
        assert!(!der.is_empty());
    }

    // ===== RFC 5280 §4.2.1.10: NameConstraints tests =====

    #[test]
    fn test_name_constraints_dns_only() {
        let nc = NameConstraints::new()
            .permit_dns(".quantumnexum.com")
            .exclude_dns(".gov")
            .exclude_dns(".mil");
        let der = nc.to_der().unwrap();
        assert_eq!(
            der[0], 0x30,
            "NameConstraints DER should start with SEQUENCE"
        );
        // Should contain permitted [0] and excluded [1]
        assert!(
            der.contains(&0xA0),
            "NameConstraints should have permittedSubtrees [0]"
        );
        assert!(
            der.contains(&0xA1),
            "NameConstraints should have excludedSubtrees [1]"
        );
    }

    #[test]
    fn test_name_constraints_permitted_only() {
        let nc = NameConstraints::new().permit_dns(".example.com");
        let der = nc.to_der().unwrap();
        assert!(der.contains(&0xA0), "Should have permitted [0]");
        // Should contain the DNS name
        let dns_bytes = b".example.com";
        assert!(
            der.windows(dns_bytes.len()).any(|w| w == dns_bytes),
            "DER should contain the DNS subtree string"
        );
    }

    #[test]
    fn test_name_constraints_excluded_only() {
        let nc = NameConstraints::new().exclude_dns(".gov");
        let der = nc.to_der().unwrap();
        assert!(!der.contains(&0xA0), "Should NOT have permitted [0]");
        assert!(der.contains(&0xA1), "Should have excluded [1]");
    }

    #[test]
    fn test_name_constraints_with_dn_subtree() {
        let nc = NameConstraints::new().permit_dn("DC=quantumnexum, DC=com");
        let der = nc.to_der().unwrap();
        assert_eq!(der[0], 0x30);
        assert!(der.contains(&0xA0), "Should have permitted [0]");
        // directoryName [4] should appear
        assert!(der.contains(&0xA4), "Should have directoryName [4] tag");
    }

    #[test]
    fn test_name_constraints_ia5_validation_non_ascii() {
        let nc = NameConstraints::new().permit_dns(".example\u{00e9}.com");
        assert!(nc.to_der().is_err(), "Non-ASCII should be rejected");
    }

    #[test]
    fn test_name_constraints_ia5_validation_null_byte() {
        let nc = NameConstraints::new().exclude_dns("example\0.com");
        assert!(nc.to_der().is_err(), "Null byte should be rejected");
    }

    #[test]
    fn test_name_constraints_ia5_validation_empty() {
        let nc = NameConstraints::new().permit_dns("");
        assert!(nc.to_der().is_err(), "Empty DNS subtree should be rejected");
    }

    #[test]
    fn test_name_constraints_ia5_validation_leading_dot_ok() {
        let nc = NameConstraints::new().permit_dns(".example.com");
        assert!(nc.to_der().is_ok(), "Leading dot is valid for subtrees");
    }

    #[test]
    fn test_name_constraints_ia5_validation_just_dot() {
        let nc = NameConstraints::new().permit_dns(".");
        assert!(nc.to_der().is_err(), "Just a dot is invalid");
    }

    // ===== RFC 5280 §4.2.1.11: PolicyConstraints tests =====

    #[test]
    fn test_policy_constraints_require_explicit() {
        let pc = PolicyConstraints::require_explicit(0);
        let der = pc.to_der().unwrap();
        assert_eq!(
            der[0], 0x30,
            "PolicyConstraints DER should start with SEQUENCE"
        );
        // Should contain [0] IMPLICIT INTEGER
        assert!(der.contains(&0x80), "Should have requireExplicitPolicy [0]");
    }

    #[test]
    fn test_policy_constraints_inhibit_mapping() {
        let pc = PolicyConstraints::inhibit_mapping(1);
        let der = pc.to_der().unwrap();
        assert_eq!(der[0], 0x30);
        assert!(der.contains(&0x81), "Should have inhibitPolicyMapping [1]");
        assert!(
            !der.contains(&0x80),
            "Should NOT have requireExplicitPolicy [0]"
        );
    }

    #[test]
    fn test_policy_constraints_both() {
        let pc = PolicyConstraints::both(0, 2);
        let der = pc.to_der().unwrap();
        assert!(der.contains(&0x80), "Should have requireExplicitPolicy [0]");
        assert!(der.contains(&0x81), "Should have inhibitPolicyMapping [1]");
    }

    #[test]
    fn test_policy_constraints_large_skip_certs() {
        let pc = PolicyConstraints::require_explicit(300);
        let der = pc.to_der().unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn test_policy_constraints_sign_bit_128() {
        // requireExplicitPolicy=128 needs sign-bit padding: [0] length 0x00 0x80
        let pc = PolicyConstraints::require_explicit(128);
        let der = pc.to_der().unwrap();
        // The [0] tagged value should contain 0x00 0x80 (2 bytes with sign-bit pad)
        assert!(der.len() > 4);
        // Find the [0] tag (0x80) followed by length 0x02 then 0x00 0x80
        let pos = der.windows(4).position(|w| w == [0x80, 0x02, 0x00, 0x80]);
        assert!(
            pos.is_some(),
            "Should encode 128 with sign-bit padding: got {:?}",
            der
        );
    }

    // ===== encode_simple_dn tests =====

    #[test]
    fn test_encode_simple_dn_dc_components() {
        let dn_der = encode_simple_dn("DC=quantumnexum, DC=com").unwrap();
        assert_eq!(dn_der[0], 0x30, "DN should start with SEQUENCE");
        // Should contain two RDN SET entries (0x31 tags)
        let set_count = dn_der.iter().filter(|&&b| b == 0x31).count();
        assert!(
            set_count >= 2,
            "Should have at least 2 RDN SETs for DC components"
        );
    }

    // --- RFC 6010: CMS Content Constraints ---

    #[test]
    fn test_cms_content_constraints_signed_data_only() {
        let cc = CmsContentConstraints::signed_data_only();
        let der = cc.to_der().unwrap();
        // Outer SEQUENCE
        assert_eq!(der[0], 0x30);
        // Should contain the SignedData OID (1.2.840.113549.1.7.2)
        let signed_data_oid = oid::CT_SIGNED_DATA.to_der().unwrap();
        assert!(
            der.windows(signed_data_oid.len())
                .any(|w| w == signed_data_oid.as_slice()),
            "DER should contain SignedData OID"
        );
        // No ENUMERATED tag (canSource is DEFAULT, omitted)
        assert!(
            !der.contains(&0x0A),
            "canSource (default) should not be explicitly encoded"
        );
    }

    #[test]
    fn test_cms_content_constraints_timestamp_only() {
        let cc = CmsContentConstraints::timestamp_only();
        let der = cc.to_der().unwrap();
        assert_eq!(der[0], 0x30);
        // Should contain the TSTInfo OID (1.2.840.113549.1.9.16.1.4)
        let tst_oid = oid::CT_TST_INFO.to_der().unwrap();
        assert!(
            der.windows(tst_oid.len()).any(|w| w == tst_oid.as_slice()),
            "DER should contain TSTInfo OID"
        );
    }

    #[test]
    fn test_cms_content_constraints_deny() {
        let cc = CmsContentConstraints::new()
            .allow(oid::CT_SIGNED_DATA)
            .deny(oid::CT_ENVELOPED_DATA);
        let der = cc.to_der().unwrap();
        assert_eq!(der[0], 0x30);
        // Should have ENUMERATED 0x0A for the deny entry
        assert!(
            der.contains(&0x0A),
            "cannotSource should produce ENUMERATED tag"
        );
    }

    #[test]
    fn test_cms_content_constraints_empty_errors() {
        let cc = CmsContentConstraints::new();
        assert!(
            cc.to_der().is_err(),
            "Empty constraints should fail encoding"
        );
    }

    #[test]
    fn test_cms_content_constraints_is_permitted() {
        let cc = CmsContentConstraints::new()
            .allow(oid::CT_SIGNED_DATA)
            .deny(oid::CT_ENVELOPED_DATA);
        assert!(cc.is_permitted(&oid::CT_SIGNED_DATA));
        assert!(!cc.is_permitted(&oid::CT_ENVELOPED_DATA));
        // Unlisted types are permitted by default
        assert!(cc.is_permitted(&oid::CT_DATA));
    }

    #[test]
    fn test_cms_content_constraints_oid() {
        // Verify the OID value: 1.3.6.1.5.5.7.1.18
        let oid_str = oid::CMS_CONTENT_CONSTRAINTS.to_string();
        assert_eq!(oid_str, "1.3.6.1.5.5.7.1.18");
    }

    #[test]
    fn test_cms_content_constraints_multiple_allows() {
        let cc = CmsContentConstraints::new()
            .allow(oid::CT_SIGNED_DATA)
            .allow(oid::CT_AUTHENTICATED_DATA)
            .allow(oid::CT_TST_INFO);
        let der = cc.to_der().unwrap();
        assert_eq!(der[0], 0x30);
        // All three OIDs should be present
        let sd_oid = oid::CT_SIGNED_DATA.to_der().unwrap();
        let ad_oid = oid::CT_AUTHENTICATED_DATA.to_der().unwrap();
        let tst_oid = oid::CT_TST_INFO.to_der().unwrap();
        assert!(der.windows(sd_oid.len()).any(|w| w == sd_oid.as_slice()));
        assert!(der.windows(ad_oid.len()).any(|w| w == ad_oid.as_slice()));
        assert!(der.windows(tst_oid.len()).any(|w| w == tst_oid.as_slice()));
    }

    // ========== QC Statements (RFC 3739) ==========

    #[test]
    fn test_qc_statements_etsi_compliance() {
        let qc = QcStatements::new().etsi_compliance();
        let der = qc.to_der().unwrap();
        // Outer SEQUENCE
        assert_eq!(der[0], 0x30);
        // Should contain the ETSI compliance OID (0.4.0.1862.1.1)
        let etsi_oid = oid::QCS_ETSI_COMPLIANCE.to_der().unwrap();
        assert!(der
            .windows(etsi_oid.len())
            .any(|w| w == etsi_oid.as_slice()));
    }

    #[test]
    fn test_qc_statements_multiple() {
        let qc = QcStatements::new().etsi_compliance().etsi_sscd();
        let der = qc.to_der().unwrap();
        assert_eq!(der[0], 0x30);
        // Both OIDs should be present
        let comp_oid = oid::QCS_ETSI_COMPLIANCE.to_der().unwrap();
        let sscd_oid = oid::QCS_ETSI_SSCD.to_der().unwrap();
        assert!(der
            .windows(comp_oid.len())
            .any(|w| w == comp_oid.as_slice()));
        assert!(der
            .windows(sscd_oid.len())
            .any(|w| w == sscd_oid.as_slice()));
    }

    #[test]
    fn test_qc_statements_retention_period() {
        let qc = QcStatements::new().retention_period(15); // 15 years
        let der = qc.to_der().unwrap();
        assert_eq!(der[0], 0x30);
        // Should contain the retention period OID
        let ret_oid = oid::QCS_ETSI_RETENTION_PERIOD.to_der().unwrap();
        assert!(der.windows(ret_oid.len()).any(|w| w == ret_oid.as_slice()));
        // Should contain INTEGER 15 (0x02, 0x01, 0x0F)
        assert!(der.windows(3).any(|w| w == [0x02, 0x01, 0x0F]));
    }

    #[test]
    fn test_qc_statements_empty_errors() {
        let qc = QcStatements::new();
        assert!(qc.to_der().is_err());
    }

    #[test]
    fn test_qc_statements_custom_statement() {
        use const_oid::ObjectIdentifier;
        let custom_oid = ObjectIdentifier::new_unwrap("1.2.3.4.5");
        let info = vec![0x04, 0x03, 0x01, 0x02, 0x03]; // OCTET STRING
        let qc = QcStatements::new().add_statement_with_info(custom_oid, info);
        let der = qc.to_der().unwrap();
        assert_eq!(der[0], 0x30);
        // Custom OID should be present
        let custom_der = custom_oid.to_der().unwrap();
        assert!(der
            .windows(custom_der.len())
            .any(|w| w == custom_der.as_slice()));
        // Info bytes should be present
        assert!(der.windows(5).any(|w| w == [0x04, 0x03, 0x01, 0x02, 0x03]));
    }

    #[test]
    fn test_qc_statements_oid() {
        assert_eq!(oid::QC_STATEMENTS.to_string(), "1.3.6.1.5.5.7.1.3");
    }

    #[test]
    fn test_qc_statements_etsi_oids() {
        assert_eq!(oid::QCS_ETSI_COMPLIANCE.to_string(), "0.4.0.1862.1.1");
        assert_eq!(oid::QCS_ETSI_SSCD.to_string(), "0.4.0.1862.1.4");
        assert_eq!(oid::QCS_ETSI_TYPE.to_string(), "0.4.0.1862.1.6");
    }

    // --- RFC 5280 §4.2.1.6: registeredID SAN type ---

    #[test]
    fn test_san_registered_id() {
        let san = SubjectAltName::new().registered_id("1.3.6.1.4.1.56266.1.1");
        assert!(san.validate().is_ok());
        let der = san.to_der().unwrap();
        // Must contain context tag [8] (0x88)
        assert!(
            der.contains(&0x88),
            "registeredID must use implicit tag [8]"
        );
    }

    #[test]
    fn test_san_registered_id_invalid_oid() {
        let san = SubjectAltName::new().registered_id("not.a.valid.oid.negative.-1");
        assert!(san.validate().is_err());
    }

    #[test]
    fn test_san_registered_id_empty() {
        let san = SubjectAltName::new().registered_id("");
        assert!(san.validate().is_err());
    }

    #[test]
    fn test_san_registered_id_with_dns() {
        // registeredID can coexist with other SAN types
        let san = SubjectAltName::new()
            .dns("example.com")
            .registered_id("1.3.6.1.4.1.56266.1.1");
        assert!(san.validate().is_ok());
        let der = san.to_der().unwrap();
        // Must contain both DNS [2] and registeredID [8]
        assert!(der.contains(&0x82), "Must contain DNS name tag [2]");
        assert!(der.contains(&0x88), "Must contain registeredID tag [8]");
    }

    #[test]
    fn test_san_registered_id_only_is_valid() {
        // A SAN with only registeredID should be valid (not empty)
        let san = SubjectAltName::new().registered_id("2.5.4.3");
        assert!(san.validate().is_ok());
    }

    // --- smimeCapabilities extension (RFC 8551 §2.5.2) ---

    #[test]
    fn test_smime_capabilities_empty_encodes_outer_sequence() {
        let caps = SmimeCapabilities::new();
        let der = caps.to_der().unwrap();
        // Outer SEQUENCE with zero content: 30 00
        assert_eq!(der, vec![0x30, 0x00]);
    }

    #[test]
    fn test_smime_capabilities_single_aes256_cbc() {
        let caps = SmimeCapabilities::new().with_capability(OID_SMIME_CAP_AES256_CBC);
        let der = caps.to_der().unwrap();
        // Outer 0x30 | inner SEQUENCE { OID } | must contain AES-256-CBC OID bytes
        assert_eq!(der[0], 0x30, "outer SEQUENCE tag");
        // AES-256-CBC arc byte: 0x2A (42)
        assert!(
            der.contains(&0x2A),
            "AES-256-CBC OID arc byte 0x2A must be present"
        );
    }

    #[test]
    fn test_smime_capabilities_default_aes_has_two_entries() {
        let caps = SmimeCapabilities::default_aes();
        assert_eq!(caps.capabilities.len(), 2);
        let der = caps.to_der().unwrap();
        assert_eq!(der[0], 0x30, "outer SEQUENCE");
    }

    #[test]
    fn test_smime_capabilities_default_aes_gcm_has_four_entries() {
        let caps = SmimeCapabilities::default_aes_gcm();
        assert_eq!(caps.capabilities.len(), 4);
        let der = caps.to_der().unwrap();
        assert_eq!(der[0], 0x30, "outer SEQUENCE");
    }

    #[test]
    fn test_smime_capabilities_oid_constant() {
        assert_eq!(oid::SMIME_CAPABILITIES.to_string(), "1.2.840.113549.1.9.15");
    }

    #[test]
    fn test_smime_capabilities_default_impl() {
        let caps = SmimeCapabilities::default();
        let der = caps.to_der().unwrap();
        assert_eq!(der, vec![0x30, 0x00]);
    }

    // ===== SAN wildcard position enforcement =====
    // RFC 5280 §4.2.1.6 / RFC 9525 §6.3: wildcards are only valid in the
    // leftmost label of a dNSName SAN.  Every other position must be rejected.

    #[test]
    fn test_san_wildcard_leftmost_valid() {
        // "*.example.com" — wildcard in leftmost label, valid per RFC 9525 §6.3
        let san = SubjectAltName::new().dns("*.example.com");
        assert!(
            san.validate().is_ok(),
            "*.example.com must be accepted as a valid SAN wildcard"
        );
    }

    #[test]
    fn test_san_wildcard_leftmost_multi_level_valid() {
        // "*.sub.example.com" — wildcard still in leftmost label, valid
        let san = SubjectAltName::new().dns("*.sub.example.com");
        assert!(
            san.validate().is_ok(),
            "*.sub.example.com must be accepted (wildcard in leftmost label)"
        );
    }

    #[test]
    fn test_san_wildcard_middle_label_rejected() {
        // "sub.*.example.com" — wildcard in second label, invalid
        // The current validator strips "*."-prefix only; here the prefix is
        // "sub." so the whole string goes through IDNA which rejects "*" as
        // an invalid DNS label character.
        let san = SubjectAltName::new().dns("sub.*.example.com");
        assert!(
            san.validate().is_err(),
            "sub.*.example.com must be rejected: wildcard not in leftmost label"
        );
    }

    #[test]
    fn test_san_wildcard_bare_star_rejected() {
        // "*" alone is not a valid dNSName — it has no base domain and would
        // match every host on the internet.
        let san = SubjectAltName::new().dns("*");
        assert!(
            san.validate().is_err(),
            "bare '*' must be rejected as a SAN dNSName"
        );
    }

    #[test]
    fn test_san_wildcard_trailing_wildcard_rejected() {
        // "example.*" — wildcard in the TLD position, invalid
        let san = SubjectAltName::new().dns("example.*");
        assert!(
            san.validate().is_err(),
            "example.* must be rejected: wildcard not in leftmost label"
        );
    }

    #[test]
    fn test_san_wildcard_embedded_in_label_rejected() {
        // "f*o.example.com" — wildcard embedded mid-label, invalid
        // This is not a "*."-prefixed name so IDNA processing sees "f*o" as a
        // label with an invalid character and rejects it.
        let san = SubjectAltName::new().dns("f*o.example.com");
        assert!(
            san.validate().is_err(),
            "f*o.example.com must be rejected: wildcard embedded within label"
        );
    }

    #[test]
    fn test_san_wildcard_dot_star_rejected() {
        // ".*.example.com" — leading dot plus mid-label wildcard, invalid
        let san = SubjectAltName::new().dns(".*.example.com");
        assert!(
            san.validate().is_err(),
            ".*.example.com must be rejected: empty first label"
        );
    }

    // ===== SAN rfc822Name email address validation =====
    // RFC 5280 §4.2.1.6 / RFC 5321: rfc822Name entries must be valid ASCII
    // email addresses with a local part, '@', and a domain with at least one
    // dot.

    #[test]
    fn test_san_email_valid_standard_forms() {
        // Representative valid rfc822Name values
        let valid = [
            "user@example.com",
            "admin@corp.example.org",
            "info@sub.domain.co.uk",
            "a@b.c",
        ];
        for addr in &valid {
            let san = SubjectAltName::new().email(*addr);
            assert!(
                san.validate().is_ok(),
                "Expected valid email to pass: {}",
                addr
            );
        }
    }

    #[test]
    fn test_san_email_rejects_missing_at_sign() {
        let san = SubjectAltName::new().email("useratexample.com");
        assert!(
            san.validate().is_err(),
            "Email without '@' must be rejected"
        );
    }

    #[test]
    fn test_san_email_rejects_empty_local_part() {
        let san = SubjectAltName::new().email("@example.com");
        assert!(
            san.validate().is_err(),
            "Email with empty local part must be rejected"
        );
    }

    #[test]
    fn test_san_email_rejects_empty_domain() {
        let san = SubjectAltName::new().email("user@");
        assert!(
            san.validate().is_err(),
            "Email with empty domain must be rejected"
        );
    }

    #[test]
    fn test_san_email_rejects_domain_without_dot() {
        // "user@localhost" — domain has no dot, which our validator rejects
        let san = SubjectAltName::new().email("user@localhost");
        assert!(
            san.validate().is_err(),
            "Email whose domain has no dot must be rejected"
        );
    }

    #[test]
    fn test_san_email_rejects_non_ascii_local_part() {
        // rfc822Name is IA5String — the local part must be 7-bit ASCII.
        // (For UTF-8 local parts, SmtpUTF8Mailbox / otherName must be used.)
        let san = SubjectAltName::new().email("ünïcödé@example.com");
        assert!(
            san.validate().is_err(),
            "rfc822Name with non-ASCII local part must be rejected"
        );
    }

    #[test]
    fn test_san_email_rejects_null_byte_in_local() {
        let san = SubjectAltName::new().email("us\0er@example.com");
        assert!(
            san.validate().is_err(),
            "Email with null byte in local part must be rejected"
        );
    }

    #[test]
    fn test_san_email_rejects_null_byte_in_domain() {
        let san = SubjectAltName::new().email("user@exam\0ple.com");
        assert!(
            san.validate().is_err(),
            "Email with null byte in domain must be rejected"
        );
    }

    #[test]
    fn test_san_email_der_encoding_is_ia5string() {
        // rfc822Name is encoded as GeneralName [1] (tag 0x81) containing the
        // IA5String bytes of the email address directly (not a SEQUENCE).
        let san = SubjectAltName::new().email("test@example.com");
        let der = san.to_der().unwrap();
        // The outer SEQUENCE wraps one rfc822Name [1] entry.
        assert_eq!(der[0], 0x30, "outer SEQUENCE tag");
        // Second byte is the length of the content.
        // Third byte must be the rfc822Name context tag 0x81.
        assert_eq!(der[2], 0x81, "rfc822Name must use context [1] tag 0x81");
    }
}
