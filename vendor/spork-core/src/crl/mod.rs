//! Certificate Revocation List (CRL) generation and handling
//!
//! RFC 5280 compliant CRL generation.

pub mod generator;

use chrono::{DateTime, Duration, Utc};
use std::str::FromStr;

use crate::digest;

use crate::algo::{AlgorithmId, KeyPair};
use crate::ca::Signer;
use crate::cert::DistinguishedName;
use crate::error::{Error, Result};

/// RFC 5280 CRL Reason Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RevocationReason {
    /// Reason not specified
    Unspecified = 0,
    /// Key has been compromised
    KeyCompromise = 1,
    /// CA has been compromised
    CaCompromise = 2,
    /// Affiliation has changed
    AffiliationChanged = 3,
    /// Certificate has been superseded
    Superseded = 4,
    /// Entity has ceased operation
    CessationOfOperation = 5,
    /// Certificate is on hold
    CertificateHold = 6,
    /// Remove from CRL
    RemoveFromCrl = 8,
    /// Privilege has been withdrawn
    PrivilegeWithdrawn = 9,
    /// AA has been compromised
    AaCompromise = 10,
}

impl RevocationReason {
    /// Convert from u8
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(RevocationReason::Unspecified),
            1 => Some(RevocationReason::KeyCompromise),
            2 => Some(RevocationReason::CaCompromise),
            3 => Some(RevocationReason::AffiliationChanged),
            4 => Some(RevocationReason::Superseded),
            5 => Some(RevocationReason::CessationOfOperation),
            6 => Some(RevocationReason::CertificateHold),
            8 => Some(RevocationReason::RemoveFromCrl),
            9 => Some(RevocationReason::PrivilegeWithdrawn),
            10 => Some(RevocationReason::AaCompromise),
            _ => None,
        }
    }

    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            RevocationReason::Unspecified => "unspecified",
            RevocationReason::KeyCompromise => "keyCompromise",
            RevocationReason::CaCompromise => "caCompromise",
            RevocationReason::AffiliationChanged => "affiliationChanged",
            RevocationReason::Superseded => "superseded",
            RevocationReason::CessationOfOperation => "cessationOfOperation",
            RevocationReason::CertificateHold => "certificateHold",
            RevocationReason::RemoveFromCrl => "removeFromCRL",
            RevocationReason::PrivilegeWithdrawn => "privilegeWithdrawn",
            RevocationReason::AaCompromise => "aaCompromise",
        }
    }
}

impl FromStr for RevocationReason {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unspecified" => Ok(RevocationReason::Unspecified),
            "keycompromise" => Ok(RevocationReason::KeyCompromise),
            "cacompromise" => Ok(RevocationReason::CaCompromise),
            "affiliationchanged" => Ok(RevocationReason::AffiliationChanged),
            "superseded" => Ok(RevocationReason::Superseded),
            "cessationofoperation" => Ok(RevocationReason::CessationOfOperation),
            "certificatehold" => Ok(RevocationReason::CertificateHold),
            "removefromcrl" => Ok(RevocationReason::RemoveFromCrl),
            "privilegewithdrawn" => Ok(RevocationReason::PrivilegeWithdrawn),
            "aacompromise" => Ok(RevocationReason::AaCompromise),
            _ => Err(format!("Unknown revocation reason: {}", s)),
        }
    }
}

/// A revoked certificate entry
#[derive(Debug, Clone)]
pub struct RevokedCertificate {
    /// Certificate serial number
    pub serial: Vec<u8>,
    /// When the certificate was revoked
    pub revocation_date: DateTime<Utc>,
    /// Reason for revocation (optional)
    pub reason: Option<RevocationReason>,
    /// Invalidity date (optional, when key was actually compromised)
    pub invalidity_date: Option<DateTime<Utc>>,
    /// Certificate Issuer (RFC 5280 §5.3.3) — required in indirect CRLs when
    /// the certificate issuer differs from the CRL issuer.
    pub certificate_issuer: Option<DistinguishedName>,
}

impl RevokedCertificate {
    /// Create a new revoked certificate entry
    pub fn new(serial: Vec<u8>, revocation_date: DateTime<Utc>) -> Self {
        Self {
            serial,
            revocation_date,
            reason: None,
            invalidity_date: None,
            certificate_issuer: None,
        }
    }

    /// Set the revocation reason
    pub fn with_reason(mut self, reason: RevocationReason) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Set the invalidity date
    pub fn with_invalidity_date(mut self, date: DateTime<Utc>) -> Self {
        self.invalidity_date = Some(date);
        self
    }

    /// Set the certificate issuer (RFC 5280 §5.3.3).
    /// Required in indirect CRLs when the certificate issuer differs from the CRL issuer.
    pub fn with_certificate_issuer(mut self, issuer: DistinguishedName) -> Self {
        self.certificate_issuer = Some(issuer);
        self
    }

    /// Get serial as hex string
    pub fn serial_hex(&self) -> String {
        hex::encode(&self.serial)
    }
}

/// CRL Builder for creating RFC 5280 compliant CRLs
pub struct CrlBuilder {
    issuer: DistinguishedName,
    this_update: DateTime<Utc>,
    next_update: Option<DateTime<Utc>>,
    crl_number: u64,
    revoked_certificates: Vec<RevokedCertificate>,
    issuer_key_identifier: Option<Vec<u8>>,
    /// Delta CRL distribution URL for FreshestCRL extension (RFC 5280 §5.2.6)
    freshest_crl_url: Option<String>,
    /// ExpiredCertsOnCRL date (RFC 5280 §5.2.7) — indicates that revocation
    /// information for expired certificates is included starting from this date.
    /// This extension MUST be non-critical.
    expired_certs_on_crl: Option<DateTime<Utc>>,
    /// RFC 5280 §5.2.5: IDP scope — only contains end-entity certificates
    only_contains_user_certs: bool,
    /// RFC 5280 §5.2.5: IDP scope — only contains CA certificates
    only_contains_ca_certs: bool,
    /// RFC 5280 §5.2.5: IDP indirectCRL — CRL covers certs issued by other CAs
    indirect_crl: bool,
    /// Previous CRL number for monotonicity enforcement (RFC 5280 §5.2.3)
    previous_crl_number: Option<u64>,
}

impl CrlBuilder {
    /// Create a new CRL builder
    pub fn new(issuer: DistinguishedName) -> Self {
        Self {
            issuer,
            this_update: Utc::now(),
            next_update: None,
            crl_number: 1,
            revoked_certificates: Vec::new(),
            issuer_key_identifier: None,
            freshest_crl_url: None,
            expired_certs_on_crl: None,
            only_contains_user_certs: false,
            only_contains_ca_certs: false,
            indirect_crl: false,
            previous_crl_number: None,
        }
    }

    /// Set the thisUpdate time
    pub fn this_update(mut self, time: DateTime<Utc>) -> Self {
        self.this_update = time;
        self
    }

    /// Set the nextUpdate time
    pub fn next_update(mut self, time: DateTime<Utc>) -> Self {
        self.next_update = Some(time);
        self
    }

    /// Set nextUpdate to a number of hours from now
    pub fn next_update_hours(mut self, hours: i64) -> Self {
        self.next_update = Some(Utc::now() + Duration::hours(hours));
        self
    }

    /// Set the CRL number
    pub fn crl_number(mut self, number: u64) -> Self {
        self.crl_number = number;
        self
    }

    /// Set the previous CRL number for monotonicity enforcement.
    ///
    /// RFC 5280 §5.2.3: CRL numbers MUST increase monotonically. When set,
    /// `build_and_sign` will reject the CRL if `crl_number <= previous`.
    pub fn previous_crl_number(mut self, previous: u64) -> Self {
        self.previous_crl_number = Some(previous);
        self
    }

    /// Add a revoked certificate
    pub fn add_revoked(mut self, cert: RevokedCertificate) -> Self {
        self.revoked_certificates.push(cert);
        self
    }

    /// Add multiple revoked certificates
    pub fn add_revoked_list(mut self, certs: Vec<RevokedCertificate>) -> Self {
        self.revoked_certificates.extend(certs);
        self
    }

    /// Set the Authority Key Identifier
    pub fn issuer_key_id(mut self, key_id: Vec<u8>) -> Self {
        self.issuer_key_identifier = Some(key_id);
        self
    }

    /// Set the FreshestCRL (delta CRL) distribution point URL.
    /// Per RFC 5280 §5.2.6, base CRLs SHOULD include this when delta CRLs are issued.
    pub fn freshest_crl_url(mut self, url: impl Into<String>) -> Self {
        self.freshest_crl_url = Some(url.into());
        self
    }

    /// Set the ExpiredCertsOnCRL date (RFC 5280 §5.2.7).
    ///
    /// When present, indicates that revocation information for certificates
    /// that expired on or after this date is included in the CRL. This allows
    /// CAs to retain revocation status for expired certificates (e.g., for
    /// historical signature validation). This extension MUST be non-critical.
    pub fn expired_certs_on_crl(mut self, date: DateTime<Utc>) -> Self {
        self.expired_certs_on_crl = Some(date);
        self
    }

    /// Set IDP scope to only contain end-entity certificates (RFC 5280 §5.2.5).
    ///
    /// When set, the IssuingDistributionPoint extension will include
    /// `onlyContainsUserCerts [1] BOOLEAN TRUE`, indicating this CRL
    /// only contains revocation entries for end-entity certificates.
    /// MUST NOT be used together with `only_contains_ca_certs`.
    pub fn only_user_certs(mut self) -> Self {
        self.only_contains_user_certs = true;
        self
    }

    /// Set IDP scope to only contain CA certificates (RFC 5280 §5.2.5).
    ///
    /// When set, the IssuingDistributionPoint extension will include
    /// `onlyContainsCACerts [2] BOOLEAN TRUE`, indicating this CRL
    /// only contains revocation entries for CA certificates.
    /// MUST NOT be used together with `only_contains_user_certs`.
    pub fn only_ca_certs(mut self) -> Self {
        self.only_contains_ca_certs = true;
        self
    }

    /// Mark this CRL as indirect (RFC 5280 §5.2.5).
    ///
    /// An indirect CRL covers certificates issued by authorities other
    /// than the CRL issuer. Entries in an indirect CRL SHOULD include
    /// the Certificate Issuer extension (§5.3.3).
    pub fn indirect_crl(mut self) -> Self {
        self.indirect_crl = true;
        self
    }

    /// Build and sign the CRL
    pub fn build_and_sign(self, issuer_key: &KeyPair) -> Result<Crl> {
        // RFC 5280 §5.2.3: CRL numbers MUST increase monotonically
        if let Some(prev) = self.previous_crl_number {
            if self.crl_number <= prev {
                return Err(Error::Encoding(format!(
                    "CRL number {} must be greater than previous CRL number {} (RFC 5280 §5.2.3)",
                    self.crl_number, prev
                )));
            }
        }

        // RFC 5280 §5.2.5: onlyContainsUserCerts and onlyContainsCACerts
        // MUST NOT both be set to TRUE
        if self.only_contains_user_certs && self.only_contains_ca_certs {
            return Err(Error::Encoding(
                "IDP onlyContainsUserCerts and onlyContainsCACerts cannot both be TRUE (RFC 5280 §5.2.5)".to_string(),
            ));
        }

        // RFC 5280 §5.1.2.4: thisUpdate must not be in the future
        let now = Utc::now();
        if self.this_update > now + chrono::Duration::minutes(5) {
            return Err(Error::Encoding(format!(
                "CRL thisUpdate ({}) is in the future (now: {})",
                self.this_update, now
            )));
        }

        // RFC 5280 §5.1.2.5: nextUpdate MUST be later than thisUpdate
        if let Some(next) = &self.next_update {
            if *next <= self.this_update {
                return Err(Error::Encoding(format!(
                    "CRL nextUpdate ({}) must be later than thisUpdate ({})",
                    next, self.this_update
                )));
            }
        }

        // Build TBSCertList (already DER-encoded)
        let tbs_der = self.build_tbs_cert_list(issuer_key)?;

        // Sign
        let signature = issuer_key.sign(&tbs_der)?;

        // Build final CRL
        let crl_der = self.build_certificate_list(&tbs_der, &signature, issuer_key)?;

        // Convert to PEM
        let pem = format!(
            "-----BEGIN X509 CRL-----\n{}\n-----END X509 CRL-----",
            base64_encode(&crl_der)
        );

        Ok(Crl {
            der: crl_der,
            pem,
            crl_number: self.crl_number,
            this_update: self.this_update,
            next_update: self.next_update,
            revoked_count: self.revoked_certificates.len(),
        })
    }

    /// Build and sign the CRL using a Signer (supports TPM/HSM-backed keys)
    pub fn build_and_sign_with_signer(self, signer: &Signer) -> Result<Crl> {
        // RFC 5280 §5.2.3: CRL numbers MUST increase monotonically
        if let Some(prev) = self.previous_crl_number {
            if self.crl_number <= prev {
                return Err(Error::Encoding(format!(
                    "CRL number {} must be greater than previous CRL number {} (RFC 5280 §5.2.3)",
                    self.crl_number, prev
                )));
            }
        }

        // RFC 5280 §5.2.5: onlyContainsUserCerts and onlyContainsCACerts
        // MUST NOT both be set to TRUE
        if self.only_contains_user_certs && self.only_contains_ca_certs {
            return Err(Error::Encoding(
                "IDP onlyContainsUserCerts and onlyContainsCACerts cannot both be TRUE (RFC 5280 §5.2.5)".to_string(),
            ));
        }

        let algorithm = signer.algorithm();
        let tbs_der = self.build_tbs_cert_list_for_algorithm(algorithm)?;
        let signature = signer.sign(&tbs_der)?;
        let crl_der = self.build_certificate_list_for_algorithm(&tbs_der, &signature, algorithm)?;

        let pem = format!(
            "-----BEGIN X509 CRL-----\n{}\n-----END X509 CRL-----",
            base64_encode(&crl_der)
        );

        Ok(Crl {
            der: crl_der,
            pem,
            crl_number: self.crl_number,
            this_update: self.this_update,
            next_update: self.next_update,
            revoked_count: self.revoked_certificates.len(),
        })
    }

    fn build_tbs_cert_list(&self, issuer_key: &KeyPair) -> Result<Vec<u8>> {
        self.build_tbs_cert_list_internal(issuer_key.algorithm_id(), Some(issuer_key))
    }

    fn build_revoked_certificates(&self) -> Result<Vec<u8>> {
        // SEQUENCE OF RevokedCertificate
        let mut entries = Vec::new();

        for cert in &self.revoked_certificates {
            let entry = self.build_revoked_cert_entry(cert)?;
            entries.extend_from_slice(&entry);
        }

        let mut result = Vec::new();
        result.push(0x30); // SEQUENCE
        encode_length(&mut result, entries.len());
        result.extend_from_slice(&entries);

        Ok(result)
    }

    fn build_revoked_cert_entry(&self, cert: &RevokedCertificate) -> Result<Vec<u8>> {
        // RevokedCertificate ::= SEQUENCE {
        //     userCertificate         CertificateSerialNumber,
        //     revocationDate          Time,
        //     crlEntryExtensions      Extensions OPTIONAL
        // }

        let mut entry = Vec::new();

        // userCertificate (INTEGER)
        entry.push(0x02);
        entry.push(cert.serial.len() as u8);
        entry.extend_from_slice(&cert.serial);

        // revocationDate
        let revocation_date = encode_utc_time(cert.revocation_date)?;
        entry.extend_from_slice(&revocation_date);

        // crlEntryExtensions (optional)
        if cert.reason.is_some()
            || cert.invalidity_date.is_some()
            || cert.certificate_issuer.is_some()
        {
            let ext = self.build_entry_extensions(cert)?;
            entry.extend_from_slice(&ext);
        }

        // Wrap in SEQUENCE
        let mut result = Vec::new();
        result.push(0x30);
        encode_length(&mut result, entry.len());
        result.extend_from_slice(&entry);

        Ok(result)
    }

    fn build_entry_extensions(&self, cert: &RevokedCertificate) -> Result<Vec<u8>> {
        let mut extensions = Vec::new();

        // CRL Reason extension
        if let Some(reason) = cert.reason {
            // Extension ::= SEQUENCE {
            //     extnID      OBJECT IDENTIFIER,
            //     critical    BOOLEAN DEFAULT FALSE,
            //     extnValue   OCTET STRING
            // }
            let mut ext = Vec::new();

            // OID for CRL Reason: 2.5.29.21
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x15];
            ext.extend_from_slice(&oid);

            // extnValue (OCTET STRING containing ENUMERATED)
            let value = vec![0x0A, 0x01, reason as u8]; // ENUMERATED

            ext.push(0x04); // OCTET STRING
            ext.push(value.len() as u8);
            ext.extend_from_slice(&value);

            // Wrap in SEQUENCE
            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            ext_seq.push(ext.len() as u8);
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        // Invalidity Date extension
        if let Some(date) = cert.invalidity_date {
            let mut ext = Vec::new();

            // OID for Invalidity Date: 2.5.29.24
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x18];
            ext.extend_from_slice(&oid);

            // extnValue (OCTET STRING containing GeneralizedTime)
            let date_str = date.format("%Y%m%d%H%M%SZ").to_string();
            let mut value = Vec::new();
            value.push(0x18); // GeneralizedTime
            value.push(date_str.len() as u8);
            value.extend_from_slice(date_str.as_bytes());

            ext.push(0x04); // OCTET STRING
            ext.push(value.len() as u8);
            ext.extend_from_slice(&value);

            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            ext_seq.push(ext.len() as u8);
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        // Certificate Issuer extension (RFC 5280 §5.3.3) — critical
        // Used in indirect CRLs to identify the issuer of the revoked certificate.
        if let Some(ref issuer) = cert.certificate_issuer {
            let mut ext = Vec::new();

            // OID for Certificate Issuer: 2.5.29.29
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x1D];
            ext.extend_from_slice(&oid);

            // critical = TRUE (RFC 5280 §5.3.3: this extension MUST be critical)
            ext.push(0x01); // BOOLEAN tag
            ext.push(0x01); // length 1
            ext.push(0xFF); // TRUE

            // extnValue: GeneralNames ::= SEQUENCE OF GeneralName
            // We encode a directoryName [4] EXPLICIT Name
            let issuer_der = issuer.to_der()?;
            // directoryName [4] EXPLICIT — context-specific constructed
            let mut dir_name = Vec::new();
            dir_name.push(0xA4); // [4] EXPLICIT CONSTRUCTED
            encode_length(&mut dir_name, issuer_der.len());
            dir_name.extend_from_slice(&issuer_der);

            // Wrap in SEQUENCE (GeneralNames)
            let mut gen_names = Vec::new();
            gen_names.push(0x30);
            encode_length(&mut gen_names, dir_name.len());
            gen_names.extend_from_slice(&dir_name);

            // Wrap in OCTET STRING (extnValue)
            ext.push(0x04);
            encode_length(&mut ext, gen_names.len());
            ext.extend_from_slice(&gen_names);

            // Wrap in Extension SEQUENCE
            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            encode_length(&mut ext_seq, ext.len());
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        // Wrap all extensions in SEQUENCE
        let mut result = Vec::new();
        result.push(0x30);
        encode_length(&mut result, extensions.len());
        result.extend_from_slice(&extensions);

        Ok(result)
    }

    fn build_extensions(&self, issuer_key: &KeyPair) -> Result<Vec<u8>> {
        let mut extensions = Vec::new();

        // CRL Number extension (required)
        {
            let mut ext = Vec::new();

            // OID for CRL Number: 2.5.29.20
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x14];
            ext.extend_from_slice(&oid);

            // extnValue (OCTET STRING containing INTEGER)
            let crl_num_bytes = encode_integer(self.crl_number);
            ext.push(0x04); // OCTET STRING
            encode_length(&mut ext, crl_num_bytes.len());
            ext.extend_from_slice(&crl_num_bytes);

            // Wrap in SEQUENCE
            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            encode_length(&mut ext_seq, ext.len());
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        // Authority Key Identifier extension
        {
            let key_id = if let Some(ref kid) = self.issuer_key_identifier {
                kid.clone()
            } else {
                // Compute from public key
                let pub_key = issuer_key.public_key_bytes();
                digest::sha256(&pub_key)[..20].to_vec() // Use first 20 bytes
            };

            let mut ext = Vec::new();

            // OID for AKI: 2.5.29.35
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x23];
            ext.extend_from_slice(&oid);

            // extnValue (OCTET STRING containing AuthorityKeyIdentifier)
            // AuthorityKeyIdentifier ::= SEQUENCE {
            //     keyIdentifier             [0] KeyIdentifier OPTIONAL
            // }
            let mut aki = Vec::new();
            aki.push(0x80); // [0] IMPLICIT OCTET STRING
            aki.push(key_id.len() as u8);
            aki.extend_from_slice(&key_id);

            let mut aki_seq = Vec::new();
            aki_seq.push(0x30);
            aki_seq.push(aki.len() as u8);
            aki_seq.extend_from_slice(&aki);

            ext.push(0x04); // OCTET STRING
            encode_length(&mut ext, aki_seq.len());
            ext.extend_from_slice(&aki_seq);

            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            encode_length(&mut ext_seq, ext.len());
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        // Issuing Distribution Point (IDP) extension (RFC 5280 §5.2.5) — critical
        if self.only_contains_user_certs || self.only_contains_ca_certs || self.indirect_crl {
            encode_idp_scope_extension(
                &mut extensions,
                self.only_contains_user_certs,
                self.only_contains_ca_certs,
                self.indirect_crl,
            );
        }

        // FreshestCRL extension (RFC 5280 §5.2.6) — non-critical
        if let Some(ref url) = self.freshest_crl_url {
            encode_freshest_crl_extension(&mut extensions, url);
        }

        // ExpiredCertsOnCRL extension (RFC 5280 §5.2.7) — non-critical
        if let Some(date) = self.expired_certs_on_crl {
            encode_expired_certs_on_crl_extension(&mut extensions, date);
        }

        // Wrap all extensions in SEQUENCE
        let mut result = Vec::new();
        result.push(0x30);
        encode_length(&mut result, extensions.len());
        result.extend_from_slice(&extensions);

        Ok(result)
    }

    fn build_certificate_list(
        &self,
        tbs_der: &[u8],
        signature: &[u8],
        issuer_key: &KeyPair,
    ) -> Result<Vec<u8>> {
        self.build_certificate_list_for_algorithm(tbs_der, signature, issuer_key.algorithm_id())
    }

    /// Build TBSCertList using AlgorithmId (for signer-based signing)
    fn build_tbs_cert_list_for_algorithm(&self, algorithm: AlgorithmId) -> Result<Vec<u8>> {
        self.build_tbs_cert_list_internal(algorithm, None)
    }

    /// Shared TBSCertList builder. If issuer_key is provided, uses it for AKI computation;
    /// otherwise falls back to pre-set issuer_key_identifier.
    fn build_tbs_cert_list_internal(
        &self,
        algorithm: AlgorithmId,
        issuer_key: Option<&KeyPair>,
    ) -> Result<Vec<u8>> {
        // TBSCertList ::= SEQUENCE {
        //     version                 Version OPTIONAL,
        //     signature               AlgorithmIdentifier,
        //     issuer                  Name,
        //     thisUpdate              Time,
        //     nextUpdate              Time OPTIONAL,
        //     revokedCertificates     SEQUENCE OF RevokedCertificate OPTIONAL,
        //     crlExtensions           [0] EXPLICIT Extensions OPTIONAL
        // }
        let mut tbs = Vec::new();

        // version (v2 = 1)
        tbs.push(0x02); // INTEGER
        tbs.push(0x01);
        tbs.push(0x01); // v2

        // signature algorithm
        let algo_der = algorithm.signature_algorithm_der()?;
        tbs.extend_from_slice(&algo_der);

        // issuer
        let issuer_der = self.issuer.to_der()?;
        tbs.extend_from_slice(&issuer_der);

        // thisUpdate
        let this_update_der = encode_utc_time(self.this_update)?;
        tbs.extend_from_slice(&this_update_der);

        // nextUpdate (optional)
        if let Some(next) = self.next_update {
            let next_update_der = encode_utc_time(next)?;
            tbs.extend_from_slice(&next_update_der);
        }

        // revokedCertificates (optional)
        if !self.revoked_certificates.is_empty() {
            let revoked_der = self.build_revoked_certificates()?;
            tbs.extend_from_slice(&revoked_der);
        }

        // crlExtensions [0] EXPLICIT
        let extensions = if let Some(key) = issuer_key {
            self.build_extensions(key)?
        } else {
            self.build_extensions_with_key_id()?
        };
        if !extensions.is_empty() {
            let mut ext_tagged = Vec::new();
            ext_tagged.push(0xA0); // [0] EXPLICIT
            encode_length(&mut ext_tagged, extensions.len());
            ext_tagged.extend_from_slice(&extensions);
            tbs.extend_from_slice(&ext_tagged);
        }

        // Wrap in SEQUENCE
        let mut result = Vec::new();
        result.push(0x30); // SEQUENCE
        encode_length(&mut result, tbs.len());
        result.extend_from_slice(&tbs);

        Ok(result)
    }

    /// Build extensions using pre-set issuer_key_identifier (required for signer path)
    fn build_extensions_with_key_id(&self) -> Result<Vec<u8>> {
        let mut extensions = Vec::new();

        // CRL Number extension (required)
        {
            let mut ext = Vec::new();
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x14];
            ext.extend_from_slice(&oid);

            let crl_num_bytes = encode_integer(self.crl_number);
            ext.push(0x04); // OCTET STRING
            encode_length(&mut ext, crl_num_bytes.len());
            ext.extend_from_slice(&crl_num_bytes);

            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            encode_length(&mut ext_seq, ext.len());
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        // Authority Key Identifier extension
        if let Some(ref kid) = self.issuer_key_identifier {
            let mut ext = Vec::new();
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x23];
            ext.extend_from_slice(&oid);

            let mut aki = Vec::new();
            aki.push(0x80); // [0] IMPLICIT OCTET STRING
            aki.push(kid.len() as u8);
            aki.extend_from_slice(kid);

            let mut aki_seq = Vec::new();
            aki_seq.push(0x30);
            aki_seq.push(aki.len() as u8);
            aki_seq.extend_from_slice(&aki);

            ext.push(0x04); // OCTET STRING
            encode_length(&mut ext, aki_seq.len());
            ext.extend_from_slice(&aki_seq);

            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            encode_length(&mut ext_seq, ext.len());
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        // Issuing Distribution Point (IDP) extension (RFC 5280 §5.2.5) — critical
        if self.only_contains_user_certs || self.only_contains_ca_certs || self.indirect_crl {
            encode_idp_scope_extension(
                &mut extensions,
                self.only_contains_user_certs,
                self.only_contains_ca_certs,
                self.indirect_crl,
            );
        }

        // FreshestCRL extension (RFC 5280 §5.2.6) — non-critical
        if let Some(ref url) = self.freshest_crl_url {
            encode_freshest_crl_extension(&mut extensions, url);
        }

        // ExpiredCertsOnCRL extension (RFC 5280 §5.2.7) — non-critical
        if let Some(date) = self.expired_certs_on_crl {
            encode_expired_certs_on_crl_extension(&mut extensions, date);
        }

        // Wrap all extensions in SEQUENCE
        let mut result = Vec::new();
        result.push(0x30);
        encode_length(&mut result, extensions.len());
        result.extend_from_slice(&extensions);

        Ok(result)
    }

    /// Build CertificateList from TBS, signature, and algorithm
    fn build_certificate_list_for_algorithm(
        &self,
        tbs_der: &[u8],
        signature: &[u8],
        algorithm: AlgorithmId,
    ) -> Result<Vec<u8>> {
        // CertificateList ::= SEQUENCE {
        //     tbsCertList          TBSCertList,
        //     signatureAlgorithm   AlgorithmIdentifier,
        //     signatureValue       BIT STRING
        // }

        let mut inner = Vec::new();

        // tbsCertList (already DER encoded)
        inner.extend_from_slice(tbs_der);

        // signatureAlgorithm
        let algo_der = algorithm.signature_algorithm_der()?;
        inner.extend_from_slice(&algo_der);

        // signatureValue (BIT STRING)
        inner.push(0x03); // BIT STRING
        encode_length(&mut inner, signature.len() + 1);
        inner.push(0x00); // unused bits
        inner.extend_from_slice(signature);

        // Wrap in SEQUENCE
        let mut result = Vec::new();
        result.push(0x30);
        encode_length(&mut result, inner.len());
        result.extend_from_slice(&inner);

        Ok(result)
    }
}

/// A generated CRL
#[derive(Debug, Clone)]
pub struct Crl {
    /// DER-encoded CRL
    pub der: Vec<u8>,
    /// PEM-encoded CRL
    pub pem: String,
    /// CRL number
    pub crl_number: u64,
    /// This update time
    pub this_update: DateTime<Utc>,
    /// Next update time
    pub next_update: Option<DateTime<Utc>>,
    /// Number of revoked certificates
    pub revoked_count: usize,
}

impl Crl {
    /// Save CRL to a file
    pub fn save_pem(&self, path: &std::path::Path) -> Result<()> {
        std::fs::write(path, &self.pem).map_err(Error::Io)
    }

    /// Save DER to a file
    pub fn save_der(&self, path: &std::path::Path) -> Result<()> {
        std::fs::write(path, &self.der).map_err(Error::Io)
    }
}

/// Encode the FreshestCRL extension (OID 2.5.29.46) into the extensions buffer.
/// Encode IssuingDistributionPoint extension with scope flags (RFC 5280 §5.2.5).
///
/// This extension MUST be critical. The IDP SEQUENCE contains only the scope
/// boolean flags (no distributionPoint). Per RFC 5280:
///   onlyContainsUserCerts [1] BOOLEAN DEFAULT FALSE
///   onlyContainsCACerts   [2] BOOLEAN DEFAULT FALSE
///
/// Only non-default (TRUE) values are encoded, using context-specific tags.
fn encode_idp_scope_extension(
    extensions: &mut Vec<u8>,
    only_user_certs: bool,
    only_ca_certs: bool,
    indirect_crl: bool,
) {
    let mut ext = Vec::new();

    // OID: 2.5.29.28 (issuingDistributionPoint)
    let oid = [0x06, 0x03, 0x55, 0x1D, 0x1C];
    ext.extend_from_slice(&oid);

    // critical = TRUE (RFC 5280 §5.2.5: this extension MUST be critical)
    ext.push(0x01); // BOOLEAN tag
    ext.push(0x01); // length 1
    ext.push(0xFF); // TRUE

    // IssuingDistributionPoint ::= SEQUENCE { ... }
    let mut idp = Vec::new();

    // onlyContainsUserCerts [1] BOOLEAN TRUE
    if only_user_certs {
        idp.push(0x81); // [1] IMPLICIT BOOLEAN
        idp.push(0x01); // length 1
        idp.push(0xFF); // TRUE
    }

    // onlyContainsCACerts [2] BOOLEAN TRUE
    if only_ca_certs {
        idp.push(0x82); // [2] IMPLICIT BOOLEAN
        idp.push(0x01); // length 1
        idp.push(0xFF); // TRUE
    }

    // indirectCRL [4] BOOLEAN TRUE (RFC 5280 §5.2.5)
    if indirect_crl {
        idp.push(0x84); // [4] IMPLICIT BOOLEAN
        idp.push(0x01); // length 1
        idp.push(0xFF); // TRUE
    }

    // Wrap in SEQUENCE
    let mut idp_seq = Vec::new();
    idp_seq.push(0x30);
    encode_length(&mut idp_seq, idp.len());
    idp_seq.extend_from_slice(&idp);

    // Wrap in OCTET STRING (extnValue)
    ext.push(0x04);
    encode_length(&mut ext, idp_seq.len());
    ext.extend_from_slice(&idp_seq);

    // Wrap in Extension SEQUENCE
    let mut ext_seq = Vec::new();
    ext_seq.push(0x30);
    encode_length(&mut ext_seq, ext.len());
    ext_seq.extend_from_slice(&ext);
    extensions.extend_from_slice(&ext_seq);
}

/// Per RFC 5280 §5.2.6, this MUST be non-critical and uses the same ASN.1 structure
/// as CRLDistributionPoints (SEQUENCE OF DistributionPoint).
fn encode_freshest_crl_extension(extensions: &mut Vec<u8>, url: &str) {
    // Build the DistributionPoint structure:
    //   DistributionPoint ::= SEQUENCE {
    //     distributionPoint [0] DistributionPointName OPTIONAL }
    //   DistributionPointName ::= CHOICE { fullName [0] GeneralNames }
    //   GeneralNames ::= SEQUENCE OF GeneralName
    //   GeneralName ::= uniformResourceIdentifier [6] IA5String
    let url_bytes = url.as_bytes();

    // [6] IMPLICIT IA5String (uniformResourceIdentifier)
    let mut general_name = Vec::new();
    general_name.push(0x86); // context [6] IMPLICIT
    encode_length(&mut general_name, url_bytes.len());
    general_name.extend_from_slice(url_bytes);

    // [0] IMPLICIT (fullName — GeneralNames wrapping)
    let mut full_name = Vec::new();
    full_name.push(0xA0); // context [0] CONSTRUCTED
    encode_length(&mut full_name, general_name.len());
    full_name.extend_from_slice(&general_name);

    // [0] IMPLICIT (distributionPoint field)
    let mut dp_name = Vec::new();
    dp_name.push(0xA0); // context [0] CONSTRUCTED
    encode_length(&mut dp_name, full_name.len());
    dp_name.extend_from_slice(&full_name);

    // DistributionPoint SEQUENCE
    let mut dp = Vec::new();
    dp.push(0x30);
    encode_length(&mut dp, dp_name.len());
    dp.extend_from_slice(&dp_name);

    // CRLDistributionPoints (SEQUENCE OF)
    let mut cdps = Vec::new();
    cdps.push(0x30);
    encode_length(&mut cdps, dp.len());
    cdps.extend_from_slice(&dp);

    // Extension SEQUENCE
    let mut ext = Vec::new();
    // OID for FreshestCRL: 2.5.29.46
    ext.extend_from_slice(&[0x06, 0x03, 0x55, 0x1D, 0x2E]);
    // critical = FALSE (default, omitted)
    // extnValue OCTET STRING
    ext.push(0x04);
    encode_length(&mut ext, cdps.len());
    ext.extend_from_slice(&cdps);

    let mut ext_seq = Vec::new();
    ext_seq.push(0x30);
    encode_length(&mut ext_seq, ext.len());
    ext_seq.extend_from_slice(&ext);
    extensions.extend_from_slice(&ext_seq);
}

/// Encode the ExpiredCertsOnCRL extension (RFC 5280 §5.2.7).
///
/// ```text
/// id-ce-expiredCertsOnCRL  OBJECT IDENTIFIER ::= { id-ce 27 }
/// ExpiredCertsOnCRL ::= GeneralizedTime
/// ```
///
/// This non-critical extension indicates that the CRL includes revocation
/// information for certificates that expired on or after the specified date.
fn encode_expired_certs_on_crl_extension(extensions: &mut Vec<u8>, date: DateTime<Utc>) {
    let gen_time = encode_generalized_time(date);

    let mut ext = Vec::new();
    // OID for ExpiredCertsOnCRL: 2.5.29.27 → 06 03 55 1D 1B
    ext.extend_from_slice(&[0x06, 0x03, 0x55, 0x1D, 0x1B]);
    // critical = FALSE (default, omitted per DER rules)
    // extnValue OCTET STRING wrapping GeneralizedTime
    ext.push(0x04);
    encode_length(&mut ext, gen_time.len());
    ext.extend_from_slice(&gen_time);

    let mut ext_seq = Vec::new();
    ext_seq.push(0x30);
    encode_length(&mut ext_seq, ext.len());
    ext_seq.extend_from_slice(&ext);
    extensions.extend_from_slice(&ext_seq);
}

// Helper functions
fn encode_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 65536 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

fn encode_utc_time(time: DateTime<Utc>) -> Result<Vec<u8>> {
    // Use UTCTime for dates before 2050, GeneralizedTime after
    let year = time.format("%Y").to_string().parse::<u32>().unwrap_or(2000);

    let mut result = Vec::new();

    if year < 2050 {
        // UTCTime: YYMMDDHHMMSSZ
        let time_str = time.format("%y%m%d%H%M%SZ").to_string();
        result.push(0x17); // UTCTime
        result.push(time_str.len() as u8);
        result.extend_from_slice(time_str.as_bytes());
    } else {
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        let time_str = time.format("%Y%m%d%H%M%SZ").to_string();
        result.push(0x18); // GeneralizedTime
        result.push(time_str.len() as u8);
        result.extend_from_slice(time_str.as_bytes());
    }

    Ok(result)
}

/// Encode a GeneralizedTime value (YYYYMMDDHHMMSSZ)
fn encode_generalized_time(time: DateTime<Utc>) -> Vec<u8> {
    let time_str = time.format("%Y%m%d%H%M%SZ").to_string();
    let mut result = Vec::new();
    result.push(0x18); // GeneralizedTime tag
    result.push(time_str.len() as u8);
    result.extend_from_slice(time_str.as_bytes());
    result
}

fn encode_integer(value: u64) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();

    // Remove leading zeros, but keep at least one byte
    while bytes.len() > 1 && bytes[0] == 0 && (bytes[1] & 0x80) == 0 {
        bytes.remove(0);
    }

    // Add leading zero if high bit is set (to keep it positive)
    if !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
        bytes.insert(0, 0);
    }

    let mut result = Vec::new();
    result.push(0x02); // INTEGER
    result.push(bytes.len() as u8);
    result.extend_from_slice(&bytes);

    result
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);

    // Split into 64-character lines
    encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| String::from_utf8_lossy(chunk))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Delta CRL Builder for RFC 5280 compliant delta CRLs
///
/// A delta CRL contains only the entries that have changed since a
/// specified base CRL was issued.
pub struct DeltaCrlBuilder {
    issuer: DistinguishedName,
    base_crl_number: u64,
    delta_crl_number: u64,
    this_update: DateTime<Utc>,
    next_update: Option<DateTime<Utc>>,
    revocations_since_base: Vec<RevokedCertificate>,
    issuer_key_identifier: Option<Vec<u8>>,
}

impl DeltaCrlBuilder {
    /// Create a new delta CRL builder
    ///
    /// # Arguments
    /// * `issuer` - The issuer's distinguished name
    /// * `base_crl_number` - The CRL number of the base CRL this delta refers to
    pub fn new(issuer: DistinguishedName, base_crl_number: u64) -> Self {
        Self {
            issuer,
            base_crl_number,
            delta_crl_number: base_crl_number + 1,
            this_update: Utc::now(),
            next_update: None,
            revocations_since_base: Vec::new(),
            issuer_key_identifier: None,
        }
    }

    /// Set the delta CRL number (defaults to base + 1)
    pub fn delta_crl_number(mut self, number: u64) -> Self {
        self.delta_crl_number = number;
        self
    }

    /// Set the thisUpdate time
    pub fn this_update(mut self, time: DateTime<Utc>) -> Self {
        self.this_update = time;
        self
    }

    /// Set the nextUpdate time
    pub fn next_update(mut self, time: DateTime<Utc>) -> Self {
        self.next_update = Some(time);
        self
    }

    /// Set nextUpdate to hours from now (delta CRLs typically have shorter validity)
    pub fn next_update_hours(mut self, hours: i64) -> Self {
        self.next_update = Some(Utc::now() + Duration::hours(hours));
        self
    }

    /// Add a certificate revoked since the base CRL
    pub fn add_revocation(mut self, cert: RevokedCertificate) -> Self {
        self.revocations_since_base.push(cert);
        self
    }

    /// Add a revocation by serial and reason
    pub fn add_revocation_entry(
        mut self,
        serial: &[u8],
        reason: RevocationReason,
        revoked_at: DateTime<Utc>,
    ) -> Self {
        self.revocations_since_base
            .push(RevokedCertificate::new(serial.to_vec(), revoked_at).with_reason(reason));
        self
    }

    /// Add multiple revocations
    pub fn add_revocations(mut self, certs: Vec<RevokedCertificate>) -> Self {
        self.revocations_since_base.extend(certs);
        self
    }

    /// Set the Authority Key Identifier
    pub fn issuer_key_id(mut self, key_id: Vec<u8>) -> Self {
        self.issuer_key_identifier = Some(key_id);
        self
    }

    /// Build and sign the delta CRL
    pub fn build_and_sign(self, issuer_key: &KeyPair) -> Result<DeltaCrl> {
        // RFC 5280 §5.1.2.4: thisUpdate must not be in the future
        let now = Utc::now();
        if self.this_update > now + chrono::Duration::minutes(5) {
            return Err(Error::Encoding(format!(
                "Delta CRL thisUpdate ({}) is in the future (now: {})",
                self.this_update, now
            )));
        }

        // Build TBSCertList with delta CRL extensions
        let tbs_der = self.build_tbs_cert_list(issuer_key)?;

        // Sign
        let signature = issuer_key.sign(&tbs_der)?;

        // Build final CRL
        let crl_der = self.build_certificate_list(&tbs_der, &signature, issuer_key)?;

        // Convert to PEM
        let pem = format!(
            "-----BEGIN X509 CRL-----\n{}\n-----END X509 CRL-----",
            base64_encode(&crl_der)
        );

        Ok(DeltaCrl {
            der: crl_der,
            pem,
            base_crl_number: self.base_crl_number,
            delta_crl_number: self.delta_crl_number,
            this_update: self.this_update,
            next_update: self.next_update,
            revoked_count: self.revocations_since_base.len(),
        })
    }

    fn build_tbs_cert_list(&self, issuer_key: &KeyPair) -> Result<Vec<u8>> {
        let mut tbs = Vec::new();

        // version (v2 = 1)
        tbs.push(0x02);
        tbs.push(0x01);
        tbs.push(0x01);

        // signature algorithm
        let algo_der = issuer_key.algorithm_id().signature_algorithm_der()?;
        tbs.extend_from_slice(&algo_der);

        // issuer
        let issuer_der = self.issuer.to_der()?;
        tbs.extend_from_slice(&issuer_der);

        // thisUpdate
        let this_update_der = encode_utc_time(self.this_update)?;
        tbs.extend_from_slice(&this_update_der);

        // nextUpdate
        if let Some(next) = self.next_update {
            let next_update_der = encode_utc_time(next)?;
            tbs.extend_from_slice(&next_update_der);
        }

        // revokedCertificates
        if !self.revocations_since_base.is_empty() {
            let revoked_der = self.build_revoked_certificates()?;
            tbs.extend_from_slice(&revoked_der);
        }

        // crlExtensions [0] EXPLICIT - includes deltaCRLIndicator
        let extensions = self.build_delta_extensions(issuer_key)?;
        if !extensions.is_empty() {
            let mut ext_tagged = Vec::new();
            ext_tagged.push(0xA0);
            encode_length(&mut ext_tagged, extensions.len());
            ext_tagged.extend_from_slice(&extensions);
            tbs.extend_from_slice(&ext_tagged);
        }

        // Wrap in SEQUENCE
        let mut result = Vec::new();
        result.push(0x30);
        encode_length(&mut result, tbs.len());
        result.extend_from_slice(&tbs);

        Ok(result)
    }

    fn build_revoked_certificates(&self) -> Result<Vec<u8>> {
        let mut entries = Vec::new();

        for cert in &self.revocations_since_base {
            let entry = self.build_revoked_cert_entry(cert)?;
            entries.extend_from_slice(&entry);
        }

        let mut result = Vec::new();
        result.push(0x30);
        encode_length(&mut result, entries.len());
        result.extend_from_slice(&entries);

        Ok(result)
    }

    fn build_revoked_cert_entry(&self, cert: &RevokedCertificate) -> Result<Vec<u8>> {
        let mut entry = Vec::new();

        // userCertificate (INTEGER)
        entry.push(0x02);
        entry.push(cert.serial.len() as u8);
        entry.extend_from_slice(&cert.serial);

        // revocationDate
        let revocation_date = encode_utc_time(cert.revocation_date)?;
        entry.extend_from_slice(&revocation_date);

        // crlEntryExtensions
        if cert.reason.is_some()
            || cert.invalidity_date.is_some()
            || cert.certificate_issuer.is_some()
        {
            let ext = self.build_entry_extensions(cert)?;
            entry.extend_from_slice(&ext);
        }

        let mut result = Vec::new();
        result.push(0x30);
        encode_length(&mut result, entry.len());
        result.extend_from_slice(&entry);

        Ok(result)
    }

    fn build_entry_extensions(&self, cert: &RevokedCertificate) -> Result<Vec<u8>> {
        let mut extensions = Vec::new();

        if let Some(reason) = cert.reason {
            let mut ext = Vec::new();
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x15]; // CRL Reason
            ext.extend_from_slice(&oid);

            let value = vec![0x0A, 0x01, reason as u8]; // ENUMERATED

            ext.push(0x04);
            ext.push(value.len() as u8);
            ext.extend_from_slice(&value);

            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            ext_seq.push(ext.len() as u8);
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        if let Some(date) = cert.invalidity_date {
            let mut ext = Vec::new();
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x18]; // Invalidity Date
            ext.extend_from_slice(&oid);

            let date_str = date.format("%Y%m%d%H%M%SZ").to_string();
            let mut value = Vec::new();
            value.push(0x18); // GeneralizedTime
            value.push(date_str.len() as u8);
            value.extend_from_slice(date_str.as_bytes());

            ext.push(0x04);
            ext.push(value.len() as u8);
            ext.extend_from_slice(&value);

            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            ext_seq.push(ext.len() as u8);
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        // Certificate Issuer extension (RFC 5280 §5.3.3) — critical
        if let Some(ref issuer) = cert.certificate_issuer {
            let mut ext = Vec::new();

            // OID for Certificate Issuer: 2.5.29.29
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x1D];
            ext.extend_from_slice(&oid);

            // critical = TRUE
            ext.push(0x01);
            ext.push(0x01);
            ext.push(0xFF);

            let issuer_der = issuer.to_der()?;
            let mut dir_name = Vec::new();
            dir_name.push(0xA4); // [4] EXPLICIT CONSTRUCTED (directoryName)
            encode_length(&mut dir_name, issuer_der.len());
            dir_name.extend_from_slice(&issuer_der);

            let mut gen_names = Vec::new();
            gen_names.push(0x30);
            encode_length(&mut gen_names, dir_name.len());
            gen_names.extend_from_slice(&dir_name);

            ext.push(0x04);
            encode_length(&mut ext, gen_names.len());
            ext.extend_from_slice(&gen_names);

            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            encode_length(&mut ext_seq, ext.len());
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        let mut result = Vec::new();
        result.push(0x30);
        encode_length(&mut result, extensions.len());
        result.extend_from_slice(&extensions);

        Ok(result)
    }

    fn build_delta_extensions(&self, issuer_key: &KeyPair) -> Result<Vec<u8>> {
        let mut extensions = Vec::new();

        // Delta CRL Indicator extension (critical)
        // OID: 2.5.29.27 - indicates this is a delta CRL and points to base
        {
            let mut ext = Vec::new();
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x1B]; // deltaCRLIndicator
            ext.extend_from_slice(&oid);

            // critical = TRUE
            ext.push(0x01); // BOOLEAN
            ext.push(0x01);
            ext.push(0xFF); // TRUE

            // extnValue (OCTET STRING containing INTEGER - base CRL number)
            let base_num_bytes = encode_integer(self.base_crl_number);
            ext.push(0x04);
            encode_length(&mut ext, base_num_bytes.len());
            ext.extend_from_slice(&base_num_bytes);

            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            encode_length(&mut ext_seq, ext.len());
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        // CRL Number extension
        {
            let mut ext = Vec::new();
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x14];
            ext.extend_from_slice(&oid);

            let crl_num_bytes = encode_integer(self.delta_crl_number);
            ext.push(0x04);
            encode_length(&mut ext, crl_num_bytes.len());
            ext.extend_from_slice(&crl_num_bytes);

            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            encode_length(&mut ext_seq, ext.len());
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        // Authority Key Identifier
        {
            let key_id = if let Some(ref kid) = self.issuer_key_identifier {
                kid.clone()
            } else {
                let pub_key = issuer_key.public_key_bytes();
                digest::sha256(&pub_key)[..20].to_vec()
            };

            let mut ext = Vec::new();
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x23];
            ext.extend_from_slice(&oid);

            let mut aki = Vec::new();
            aki.push(0x80);
            aki.push(key_id.len() as u8);
            aki.extend_from_slice(&key_id);

            let mut aki_seq = Vec::new();
            aki_seq.push(0x30);
            aki_seq.push(aki.len() as u8);
            aki_seq.extend_from_slice(&aki);

            ext.push(0x04);
            encode_length(&mut ext, aki_seq.len());
            ext.extend_from_slice(&aki_seq);

            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            encode_length(&mut ext_seq, ext.len());
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        let mut result = Vec::new();
        result.push(0x30);
        encode_length(&mut result, extensions.len());
        result.extend_from_slice(&extensions);

        Ok(result)
    }

    fn build_certificate_list(
        &self,
        tbs_der: &[u8],
        signature: &[u8],
        issuer_key: &KeyPair,
    ) -> Result<Vec<u8>> {
        let mut inner = Vec::new();
        inner.extend_from_slice(tbs_der);

        let algo_der = issuer_key.algorithm_id().signature_algorithm_der()?;
        inner.extend_from_slice(&algo_der);

        inner.push(0x03);
        encode_length(&mut inner, signature.len() + 1);
        inner.push(0x00);
        inner.extend_from_slice(signature);

        let mut result = Vec::new();
        result.push(0x30);
        encode_length(&mut result, inner.len());
        result.extend_from_slice(&inner);

        Ok(result)
    }
}

/// A generated Delta CRL
#[derive(Debug, Clone)]
pub struct DeltaCrl {
    /// DER-encoded delta CRL
    pub der: Vec<u8>,
    /// PEM-encoded delta CRL
    pub pem: String,
    /// Base CRL number this delta refers to
    pub base_crl_number: u64,
    /// This delta CRL's number
    pub delta_crl_number: u64,
    /// This update time
    pub this_update: DateTime<Utc>,
    /// Next update time
    pub next_update: Option<DateTime<Utc>>,
    /// Number of entries in this delta
    pub revoked_count: usize,
}

impl DeltaCrl {
    /// Save delta CRL to a file (PEM format)
    pub fn save_pem(&self, path: &std::path::Path) -> Result<()> {
        std::fs::write(path, &self.pem).map_err(Error::Io)
    }

    /// Save delta CRL to a file (DER format)
    pub fn save_der(&self, path: &std::path::Path) -> Result<()> {
        std::fs::write(path, &self.der).map_err(Error::Io)
    }
}

/// CRL Shard Manager for partitioning large CRLs
///
/// For PKI deployments with millions of certificates, a single CRL becomes
/// impractically large. Sharding distributes revoked certificates across
/// multiple CRL partitions based on serial number hash.
pub struct CrlShardManager {
    /// Number of shards to create
    shard_count: u32,
    /// Maximum entries per shard (advisory)
    max_shard_size: usize,
}

impl CrlShardManager {
    /// Create a new shard manager
    ///
    /// # Arguments
    /// * `shard_count` - Number of CRL partitions (power of 2 recommended)
    /// * `max_shard_size` - Advisory maximum entries per shard
    pub fn new(shard_count: u32, max_shard_size: usize) -> Self {
        Self {
            shard_count,
            max_shard_size,
        }
    }

    /// Determine which shard a certificate serial number belongs to
    ///
    /// Uses SHA-256 hash of the serial for consistent distribution
    pub fn assign_partition(&self, serial: &[u8]) -> u32 {
        let hash = digest::sha256(serial);
        let val = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
        val % self.shard_count
    }

    /// Partition a list of revoked certificates into shards
    pub fn partition_entries(
        &self,
        entries: &[RevokedCertificate],
    ) -> Vec<Vec<RevokedCertificate>> {
        let mut shards: Vec<Vec<RevokedCertificate>> =
            (0..self.shard_count).map(|_| Vec::new()).collect();

        for entry in entries {
            let shard_idx = self.assign_partition(&entry.serial) as usize;
            shards[shard_idx].push(entry.clone());
        }

        shards
    }

    /// Build a CRL shard with Issuing Distribution Point extension
    ///
    /// # Arguments
    /// * `shard_num` - The shard number (0-indexed)
    /// * `entries` - Revoked certificates for this shard
    /// * `issuer` - CA's distinguished name
    /// * `issuer_key` - CA's signing key
    /// * `crl_number` - CRL number for this shard
    /// * `base_url` - Base URL for the CRL distribution point
    pub fn build_shard(
        &self,
        shard_num: u32,
        entries: &[RevokedCertificate],
        issuer: DistinguishedName,
        issuer_key: &KeyPair,
        crl_number: u64,
        base_url: &str,
    ) -> Result<CrlShard> {
        let distribution_point = format!("{}/shard/{}.crl", base_url, shard_num);

        // Build CRL with IDP extension
        let tbs_der = self.build_sharded_tbs(
            shard_num,
            entries,
            &issuer,
            issuer_key,
            crl_number,
            &distribution_point,
        )?;

        let signature = issuer_key.sign(&tbs_der)?;
        let crl_der = self.build_certificate_list(&tbs_der, &signature, issuer_key)?;

        let pem = format!(
            "-----BEGIN X509 CRL-----\n{}\n-----END X509 CRL-----",
            base64_encode(&crl_der)
        );

        Ok(CrlShard {
            der: crl_der,
            pem,
            shard_number: shard_num,
            crl_number,
            distribution_point,
            entry_count: entries.len(),
            this_update: Utc::now(),
        })
    }

    fn build_sharded_tbs(
        &self,
        shard_num: u32,
        entries: &[RevokedCertificate],
        issuer: &DistinguishedName,
        issuer_key: &KeyPair,
        crl_number: u64,
        distribution_point: &str,
    ) -> Result<Vec<u8>> {
        let mut tbs = Vec::new();

        // version (v2 = 1)
        tbs.push(0x02);
        tbs.push(0x01);
        tbs.push(0x01);

        // signature algorithm
        let algo_der = issuer_key.algorithm_id().signature_algorithm_der()?;
        tbs.extend_from_slice(&algo_der);

        // issuer
        let issuer_der = issuer.to_der()?;
        tbs.extend_from_slice(&issuer_der);

        // thisUpdate
        let this_update = Utc::now();
        let this_update_der = encode_utc_time(this_update)?;
        tbs.extend_from_slice(&this_update_der);

        // nextUpdate (24 hours)
        let next_update = this_update + Duration::hours(24);
        let next_update_der = encode_utc_time(next_update)?;
        tbs.extend_from_slice(&next_update_der);

        // revokedCertificates
        if !entries.is_empty() {
            let revoked_der = self.build_revoked_list(entries)?;
            tbs.extend_from_slice(&revoked_der);
        }

        // crlExtensions with IDP
        let extensions =
            self.build_shard_extensions(shard_num, issuer_key, crl_number, distribution_point)?;
        let mut ext_tagged = Vec::new();
        ext_tagged.push(0xA0);
        encode_length(&mut ext_tagged, extensions.len());
        ext_tagged.extend_from_slice(&extensions);
        tbs.extend_from_slice(&ext_tagged);

        let mut result = Vec::new();
        result.push(0x30);
        encode_length(&mut result, tbs.len());
        result.extend_from_slice(&tbs);

        Ok(result)
    }

    fn build_revoked_list(&self, entries: &[RevokedCertificate]) -> Result<Vec<u8>> {
        let mut list = Vec::new();

        for entry in entries {
            let mut e = Vec::new();
            e.push(0x02);
            e.push(entry.serial.len() as u8);
            e.extend_from_slice(&entry.serial);

            let date_der = encode_utc_time(entry.revocation_date)?;
            e.extend_from_slice(&date_der);

            // Add entry extensions if present
            if entry.reason.is_some() || entry.certificate_issuer.is_some() {
                let mut all_exts = Vec::new();

                if let Some(reason) = entry.reason {
                    let mut ext = Vec::new();
                    let oid = [0x06, 0x03, 0x55, 0x1D, 0x15];
                    ext.extend_from_slice(&oid);

                    let value = vec![0x0A, 0x01, reason as u8]; // ENUMERATED

                    ext.push(0x04);
                    ext.push(value.len() as u8);
                    ext.extend_from_slice(&value);

                    let mut ext_seq = Vec::new();
                    ext_seq.push(0x30);
                    ext_seq.push(ext.len() as u8);
                    ext_seq.extend_from_slice(&ext);
                    all_exts.extend_from_slice(&ext_seq);
                }

                // Certificate Issuer (RFC 5280 §5.3.3) — critical
                if let Some(ref issuer) = entry.certificate_issuer {
                    let mut ext = Vec::new();
                    let oid = [0x06, 0x03, 0x55, 0x1D, 0x1D];
                    ext.extend_from_slice(&oid);

                    ext.push(0x01); // critical = TRUE
                    ext.push(0x01);
                    ext.push(0xFF);

                    let issuer_der = issuer.to_der()?;
                    let mut dir_name = Vec::new();
                    dir_name.push(0xA4);
                    encode_length(&mut dir_name, issuer_der.len());
                    dir_name.extend_from_slice(&issuer_der);

                    let mut gen_names = Vec::new();
                    gen_names.push(0x30);
                    encode_length(&mut gen_names, dir_name.len());
                    gen_names.extend_from_slice(&dir_name);

                    ext.push(0x04);
                    encode_length(&mut ext, gen_names.len());
                    ext.extend_from_slice(&gen_names);

                    let mut ext_seq = Vec::new();
                    ext_seq.push(0x30);
                    encode_length(&mut ext_seq, ext.len());
                    ext_seq.extend_from_slice(&ext);
                    all_exts.extend_from_slice(&ext_seq);
                }

                let mut exts_wrapper = Vec::new();
                exts_wrapper.push(0x30);
                encode_length(&mut exts_wrapper, all_exts.len());
                exts_wrapper.extend_from_slice(&all_exts);

                e.extend_from_slice(&exts_wrapper);
            }

            let mut entry_seq = Vec::new();
            entry_seq.push(0x30);
            encode_length(&mut entry_seq, e.len());
            entry_seq.extend_from_slice(&e);

            list.extend_from_slice(&entry_seq);
        }

        let mut result = Vec::new();
        result.push(0x30);
        encode_length(&mut result, list.len());
        result.extend_from_slice(&list);

        Ok(result)
    }

    fn build_shard_extensions(
        &self,
        _shard_num: u32,
        issuer_key: &KeyPair,
        crl_number: u64,
        distribution_point: &str,
    ) -> Result<Vec<u8>> {
        let mut extensions = Vec::new();

        // CRL Number
        {
            let mut ext = Vec::new();
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x14];
            ext.extend_from_slice(&oid);

            let num_bytes = encode_integer(crl_number);
            ext.push(0x04);
            encode_length(&mut ext, num_bytes.len());
            ext.extend_from_slice(&num_bytes);

            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            encode_length(&mut ext_seq, ext.len());
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        // Authority Key Identifier
        {
            let pub_key = issuer_key.public_key_bytes();
            let key_id = digest::sha256(&pub_key)[..20].to_vec();

            let mut ext = Vec::new();
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x23];
            ext.extend_from_slice(&oid);

            let mut aki = Vec::new();
            aki.push(0x80);
            aki.push(key_id.len() as u8);
            aki.extend_from_slice(&key_id);

            let mut aki_seq = Vec::new();
            aki_seq.push(0x30);
            aki_seq.push(aki.len() as u8);
            aki_seq.extend_from_slice(&aki);

            ext.push(0x04);
            encode_length(&mut ext, aki_seq.len());
            ext.extend_from_slice(&aki_seq);

            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            encode_length(&mut ext_seq, ext.len());
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        // Issuing Distribution Point (IDP) extension
        // OID: 2.5.29.28
        // Critical: TRUE
        {
            let mut ext = Vec::new();
            let oid = [0x06, 0x03, 0x55, 0x1D, 0x1C]; // issuingDistributionPoint
            ext.extend_from_slice(&oid);

            // critical = TRUE
            ext.push(0x01);
            ext.push(0x01);
            ext.push(0xFF);

            // IssuingDistributionPoint ::= SEQUENCE {
            //     distributionPoint          [0] DistributionPointName OPTIONAL
            //     onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
            //     onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
            //     onlySomeReasons            [3] ReasonFlags OPTIONAL,
            //     indirectCRL                [4] BOOLEAN DEFAULT FALSE,
            //     onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE
            // }
            let mut idp = Vec::new();

            // distributionPoint [0] containing fullName [0]
            // DistributionPointName ::= CHOICE {
            //     fullName                [0]     GeneralNames
            // }
            // GeneralNames ::= SEQUENCE OF GeneralName
            // GeneralName ::= uniformResourceIdentifier [6] IA5String

            // URI value
            let uri_bytes = distribution_point.as_bytes();
            let mut uri = Vec::new();
            uri.push(0x86); // [6] IMPLICIT IA5String (uniformResourceIdentifier)
            encode_length(&mut uri, uri_bytes.len());
            uri.extend_from_slice(uri_bytes);

            // fullName [0]
            let mut full_name = Vec::new();
            full_name.push(0xA0); // [0]
            encode_length(&mut full_name, uri.len());
            full_name.extend_from_slice(&uri);

            // distributionPoint [0]
            let mut dp = Vec::new();
            dp.push(0xA0); // [0]
            encode_length(&mut dp, full_name.len());
            dp.extend_from_slice(&full_name);

            idp.extend_from_slice(&dp);

            // Wrap in SEQUENCE
            let mut idp_seq = Vec::new();
            idp_seq.push(0x30);
            encode_length(&mut idp_seq, idp.len());
            idp_seq.extend_from_slice(&idp);

            // Wrap in OCTET STRING
            ext.push(0x04);
            encode_length(&mut ext, idp_seq.len());
            ext.extend_from_slice(&idp_seq);

            let mut ext_seq = Vec::new();
            ext_seq.push(0x30);
            encode_length(&mut ext_seq, ext.len());
            ext_seq.extend_from_slice(&ext);
            extensions.extend_from_slice(&ext_seq);
        }

        let mut result = Vec::new();
        result.push(0x30);
        encode_length(&mut result, extensions.len());
        result.extend_from_slice(&extensions);

        Ok(result)
    }

    fn build_certificate_list(
        &self,
        tbs_der: &[u8],
        signature: &[u8],
        issuer_key: &KeyPair,
    ) -> Result<Vec<u8>> {
        let mut inner = Vec::new();
        inner.extend_from_slice(tbs_der);

        let algo_der = issuer_key.algorithm_id().signature_algorithm_der()?;
        inner.extend_from_slice(&algo_der);

        inner.push(0x03);
        encode_length(&mut inner, signature.len() + 1);
        inner.push(0x00);
        inner.extend_from_slice(signature);

        let mut result = Vec::new();
        result.push(0x30);
        encode_length(&mut result, inner.len());
        result.extend_from_slice(&inner);

        Ok(result)
    }

    /// Get the number of shards
    pub fn shard_count(&self) -> u32 {
        self.shard_count
    }

    /// Get the max shard size
    pub fn max_shard_size(&self) -> usize {
        self.max_shard_size
    }
}

/// A CRL shard (partition)
#[derive(Debug, Clone)]
pub struct CrlShard {
    /// DER-encoded CRL shard
    pub der: Vec<u8>,
    /// PEM-encoded CRL shard
    pub pem: String,
    /// Shard number
    pub shard_number: u32,
    /// CRL number
    pub crl_number: u64,
    /// Distribution point URL for this shard
    pub distribution_point: String,
    /// Number of entries in this shard
    pub entry_count: usize,
    /// This update time
    pub this_update: DateTime<Utc>,
}

impl CrlShard {
    /// Save to file (PEM format)
    pub fn save_pem(&self, path: &std::path::Path) -> Result<()> {
        std::fs::write(path, &self.pem).map_err(Error::Io)
    }

    /// Save to file (DER format)
    pub fn save_der(&self, path: &std::path::Path) -> Result<()> {
        std::fs::write(path, &self.der).map_err(Error::Io)
    }
}

/// Full CRL validation per RFC 5280 §6.3.3.
///
/// Performs all three CRL processing steps:
/// - Step (a): Verify CRL is current (thisUpdate <= now <= nextUpdate)
/// - Step (b): Search revokedCertificates for the target serial
/// - Step (g): Validate CRL signature against issuer certificate
///
/// Returns `Ok(CrlRevocationStatus)` — either Good or Revoked with reason.
/// Returns `Err` if the CRL fails timing or signature validation.
pub fn validate_crl_for_certificate(
    crl_der: &[u8],
    issuer_cert_der: &[u8],
    serial_number: &[u8],
) -> Result<CrlRevocationStatus> {
    // Step (a): Verify CRL timing
    let now = Utc::now();
    if !validate_crl_timing(crl_der, now)? {
        return Err(Error::InvalidCertificate(
            "CRL is not current (expired or not yet valid)".into(),
        ));
    }

    // Step (g): Verify CRL signature
    if !verify_crl_signature(crl_der, issuer_cert_der)? {
        return Err(Error::InvalidCertificate(
            "CRL signature verification failed".into(),
        ));
    }

    // Step (b): Check serial number in revokedCertificates
    check_certificate_status(crl_der, serial_number)
}

/// Validate a CRL's time validity.
///
/// RFC 5280 §6.3.3 step (a): Verify that the current time is within
/// the CRL's validity period. Specifically:
/// - thisUpdate MUST be <= current time (CRL must be issued)
/// - If nextUpdate is present, current time MUST be <= nextUpdate
///
/// Returns `Ok(true)` if valid, `Ok(false)` if expired or not yet valid.
pub fn validate_crl_timing(crl_der: &[u8], now: DateTime<Utc>) -> Result<bool> {
    // Parse outer SEQUENCE
    if crl_der.len() < 10 || crl_der[0] != 0x30 {
        return Err(Error::InvalidCertificate(
            "CRL does not start with SEQUENCE".into(),
        ));
    }
    let (outer_content_offset, _outer_len) = read_der_length(&crl_der[1..])?;
    let content = &crl_der[1 + outer_content_offset..];

    // TBSCertList SEQUENCE
    if content.is_empty() || content[0] != 0x30 {
        return Err(Error::InvalidCertificate(
            "CRL TBSCertList not a SEQUENCE".into(),
        ));
    }
    let (tbs_len_offset, tbs_len) = read_der_length(&content[1..])?;
    let tbs_content = &content[1 + tbs_len_offset..1 + tbs_len_offset + tbs_len];

    // Walk TBSCertList fields to find thisUpdate and nextUpdate
    let mut pos = 0;

    // Skip optional version (INTEGER)
    if pos < tbs_content.len() && tbs_content[pos] == 0x02 {
        let (len_offset, len) = read_der_length(&tbs_content[pos + 1..])?;
        pos += 1 + len_offset + len;
    }

    // Skip signature AlgorithmIdentifier (SEQUENCE)
    if pos < tbs_content.len() && tbs_content[pos] == 0x30 {
        let (len_offset, len) = read_der_length(&tbs_content[pos + 1..])?;
        pos += 1 + len_offset + len;
    }

    // Skip issuer Name (SEQUENCE)
    if pos < tbs_content.len() && tbs_content[pos] == 0x30 {
        let (len_offset, len) = read_der_length(&tbs_content[pos + 1..])?;
        pos += 1 + len_offset + len;
    }

    // thisUpdate Time (UTCTime 0x17 or GeneralizedTime 0x18)
    let this_update =
        if pos < tbs_content.len() && (tbs_content[pos] == 0x17 || tbs_content[pos] == 0x18) {
            let (len_offset, len) = read_der_length(&tbs_content[pos + 1..])?;
            let time_bytes = &tbs_content[pos + 1 + len_offset..pos + 1 + len_offset + len];
            let time_str = std::str::from_utf8(time_bytes)
                .map_err(|_| Error::InvalidCertificate("Invalid thisUpdate encoding".into()))?;
            let parsed = parse_der_time(tbs_content[pos], time_str)?;
            pos += 1 + len_offset + len;
            parsed
        } else {
            return Err(Error::InvalidCertificate(
                "Missing thisUpdate in CRL".into(),
            ));
        };

    // Optional nextUpdate
    let next_update =
        if pos < tbs_content.len() && (tbs_content[pos] == 0x17 || tbs_content[pos] == 0x18) {
            let (len_offset, len) = read_der_length(&tbs_content[pos + 1..])?;
            let time_bytes = &tbs_content[pos + 1 + len_offset..pos + 1 + len_offset + len];
            let time_str = std::str::from_utf8(time_bytes)
                .map_err(|_| Error::InvalidCertificate("Invalid nextUpdate encoding".into()))?;
            Some(parse_der_time(tbs_content[pos], time_str)?)
        } else {
            None
        };

    // RFC 5280 §6.3.3(a): thisUpdate <= now
    if this_update > now {
        return Ok(false);
    }

    // RFC 5280 §6.3.3(a): if nextUpdate present, now <= nextUpdate
    if let Some(next) = next_update {
        if now > next {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Parse a DER-encoded time value (UTCTime or GeneralizedTime) to DateTime<Utc>.
fn parse_der_time(tag: u8, time_str: &str) -> Result<DateTime<Utc>> {
    use chrono::NaiveDateTime;

    if tag == 0x17 {
        // UTCTime: YYMMDDHHMMSSZ
        let s = time_str.trim_end_matches('Z');
        if s.len() < 12 {
            return Err(Error::InvalidCertificate(format!(
                "UTCTime too short: {}",
                time_str
            )));
        }
        let year: i32 = s[0..2].parse().map_err(|_| {
            Error::InvalidCertificate(format!("Invalid UTCTime year: {}", time_str))
        })?;
        // RFC 5280 §4.1.2.5.1: values 00-49 map to 2000-2049, 50-99 to 1950-1999
        let full_year = if year >= 50 { 1950 + year } else { 2000 + year };
        let month: u32 = s[2..4].parse().map_err(|_| {
            Error::InvalidCertificate(format!("Invalid UTCTime month: {}", time_str))
        })?;
        let day: u32 = s[4..6]
            .parse()
            .map_err(|_| Error::InvalidCertificate(format!("Invalid UTCTime day: {}", time_str)))?;
        let hour: u32 = s[6..8].parse().map_err(|_| {
            Error::InvalidCertificate(format!("Invalid UTCTime hour: {}", time_str))
        })?;
        let min: u32 = s[8..10]
            .parse()
            .map_err(|_| Error::InvalidCertificate(format!("Invalid UTCTime min: {}", time_str)))?;
        let sec: u32 = s[10..12]
            .parse()
            .map_err(|_| Error::InvalidCertificate(format!("Invalid UTCTime sec: {}", time_str)))?;

        Ok(NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(full_year, month, day).ok_or_else(|| {
                Error::InvalidCertificate(format!("Invalid date in UTCTime: {}", time_str))
            })?,
            chrono::NaiveTime::from_hms_opt(hour, min, sec).ok_or_else(|| {
                Error::InvalidCertificate(format!("Invalid time in UTCTime: {}", time_str))
            })?,
        )
        .and_utc())
    } else {
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        let s = time_str.trim_end_matches('Z');
        if s.len() < 14 {
            return Err(Error::InvalidCertificate(format!(
                "GeneralizedTime too short: {}",
                time_str
            )));
        }
        let year: i32 = s[0..4]
            .parse()
            .map_err(|_| Error::InvalidCertificate(format!("Invalid year: {}", time_str)))?;
        let month: u32 = s[4..6]
            .parse()
            .map_err(|_| Error::InvalidCertificate(format!("Invalid month: {}", time_str)))?;
        let day: u32 = s[6..8]
            .parse()
            .map_err(|_| Error::InvalidCertificate(format!("Invalid day: {}", time_str)))?;
        let hour: u32 = s[8..10]
            .parse()
            .map_err(|_| Error::InvalidCertificate(format!("Invalid hour: {}", time_str)))?;
        let min: u32 = s[10..12]
            .parse()
            .map_err(|_| Error::InvalidCertificate(format!("Invalid min: {}", time_str)))?;
        let sec: u32 = s[12..14]
            .parse()
            .map_err(|_| Error::InvalidCertificate(format!("Invalid sec: {}", time_str)))?;

        Ok(NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(year, month, day)
                .ok_or_else(|| Error::InvalidCertificate(format!("Invalid date: {}", time_str)))?,
            chrono::NaiveTime::from_hms_opt(hour, min, sec)
                .ok_or_else(|| Error::InvalidCertificate(format!("Invalid time: {}", time_str)))?,
        )
        .and_utc())
    }
}

/// Verify a CRL's signature against the issuing CA's certificate.
///
/// RFC 5280 §6.3.3 step (g): "Validate the signature on the complete CRL."
///
/// The CRL DER structure is:
/// ```text
/// CertificateList  ::=  SEQUENCE {
///     tbsCertList          TBSCertList,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING
/// }
/// ```
///
/// We extract the TBS portion (raw bytes), the signature algorithm OID,
/// and the signature value, then verify using the issuer's certificate.
pub fn verify_crl_signature(crl_der: &[u8], issuer_cert_der: &[u8]) -> Result<bool> {
    // Parse outer SEQUENCE
    if crl_der.len() < 10 || crl_der[0] != 0x30 {
        return Err(Error::InvalidCertificate(
            "CRL does not start with SEQUENCE".into(),
        ));
    }

    // Read outer SEQUENCE length
    let (outer_content_offset, _outer_len) = read_der_length(&crl_der[1..])?;
    let content = &crl_der[1 + outer_content_offset..];

    // Extract TBSCertList (first element — must be a SEQUENCE)
    if content.is_empty() || content[0] != 0x30 {
        return Err(Error::InvalidCertificate(
            "CRL TBSCertList not a SEQUENCE".into(),
        ));
    }
    let (tbs_len_offset, tbs_len) = read_der_length(&content[1..])?;
    let tbs_total = 1 + tbs_len_offset + tbs_len;
    let tbs_bytes = &content[..tbs_total];

    let remaining = &content[tbs_total..];

    // Parse signatureAlgorithm SEQUENCE to extract OID
    if remaining.is_empty() || remaining[0] != 0x30 {
        return Err(Error::InvalidCertificate(
            "CRL signatureAlgorithm not a SEQUENCE".into(),
        ));
    }
    let (sig_alg_len_offset, sig_alg_len) = read_der_length(&remaining[1..])?;
    let sig_alg_content = &remaining[1 + sig_alg_len_offset..1 + sig_alg_len_offset + sig_alg_len];
    let sig_alg_total = 1 + sig_alg_len_offset + sig_alg_len;

    // Extract OID from AlgorithmIdentifier
    let sig_alg_oid = extract_oid_from_der(sig_alg_content)?;

    let remaining = &remaining[sig_alg_total..];

    // Extract signatureValue BIT STRING
    if remaining.is_empty() || remaining[0] != 0x03 {
        return Err(Error::InvalidCertificate(
            "CRL signatureValue not a BIT STRING".into(),
        ));
    }
    let (sig_len_offset, sig_len) = read_der_length(&remaining[1..])?;
    let sig_content = &remaining[1 + sig_len_offset..1 + sig_len_offset + sig_len];

    // BIT STRING: first byte is unused bits count (should be 0)
    if sig_content.is_empty() {
        return Err(Error::InvalidCertificate(
            "CRL signatureValue is empty".into(),
        ));
    }
    let signature_bytes = &sig_content[1..]; // skip unused bits byte

    crate::cert::verify::verify_raw_signature(
        &sig_alg_oid,
        issuer_cert_der,
        tbs_bytes,
        signature_bytes,
    )
}

/// Extract a dotted OID string from DER-encoded OID content.
///
/// Expects data starting with OID tag (0x06).
fn extract_oid_from_der(data: &[u8]) -> Result<String> {
    if data.is_empty() || data[0] != 0x06 {
        return Err(Error::InvalidCertificate("Expected OID tag (0x06)".into()));
    }
    let (len_offset, oid_len) = read_der_length(&data[1..])?;
    let oid_bytes = &data[1 + len_offset..1 + len_offset + oid_len];

    if oid_bytes.is_empty() {
        return Err(Error::InvalidCertificate("Empty OID".into()));
    }

    // First byte encodes first two components: first * 40 + second
    let first = oid_bytes[0] / 40;
    let second = oid_bytes[0] % 40;
    let mut components = vec![first as u32, second as u32];

    // Remaining bytes use base-128 encoding (high bit = continuation)
    let mut value: u32 = 0;
    for &byte in &oid_bytes[1..] {
        value = value
            .checked_shl(7)
            .ok_or_else(|| Error::InvalidCertificate("OID component overflow".into()))?
            | (byte & 0x7F) as u32;
        if byte & 0x80 == 0 {
            components.push(value);
            value = 0;
        }
    }

    Ok(components
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("."))
}

/// Result of checking a certificate's revocation status against a CRL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrlRevocationStatus {
    /// Certificate serial is not listed in the CRL (good).
    Good,
    /// Certificate serial is revoked, with optional reason code.
    Revoked {
        /// Revocation reason (RFC 5280 §5.3.1), if present.
        reason: Option<RevocationReason>,
    },
}

/// Check a certificate's revocation status by examining a CRL.
///
/// RFC 5280 §6.3.3 step (b): search for the certificate serial in the
/// revokedCertificates list of the CRL. Returns the revocation status.
///
/// This function parses the CRL DER to find the revokedCertificates
/// SEQUENCE OF and compares each entry's serial number against the target.
pub fn check_certificate_status(
    crl_der: &[u8],
    serial_number: &[u8],
) -> Result<CrlRevocationStatus> {
    // Parse outer SEQUENCE
    if crl_der.len() < 10 || crl_der[0] != 0x30 {
        return Err(Error::InvalidCertificate(
            "CRL does not start with SEQUENCE".into(),
        ));
    }
    let (outer_content_offset, _outer_len) = read_der_length(&crl_der[1..])?;
    let content = &crl_der[1 + outer_content_offset..];

    // TBSCertList is the first element (SEQUENCE)
    if content.is_empty() || content[0] != 0x30 {
        return Err(Error::InvalidCertificate(
            "CRL TBSCertList not a SEQUENCE".into(),
        ));
    }
    let (tbs_len_offset, tbs_len) = read_der_length(&content[1..])?;
    let tbs_content = &content[1 + tbs_len_offset..1 + tbs_len_offset + tbs_len];

    // Walk TBSCertList fields:
    //   version (optional INTEGER, tag 0x02)
    //   signature AlgorithmIdentifier (SEQUENCE)
    //   issuer Name (SEQUENCE)
    //   thisUpdate Time
    //   nextUpdate Time (optional)
    //   revokedCertificates SEQUENCE OF (optional)
    //   extensions [0] EXPLICIT Extensions (optional)
    let mut pos = 0;

    // Skip optional version (INTEGER)
    if pos < tbs_content.len() && tbs_content[pos] == 0x02 {
        let (len_offset, len) = read_der_length(&tbs_content[pos + 1..])?;
        pos += 1 + len_offset + len;
    }

    // Skip signature AlgorithmIdentifier (SEQUENCE)
    if pos < tbs_content.len() && tbs_content[pos] == 0x30 {
        let (len_offset, len) = read_der_length(&tbs_content[pos + 1..])?;
        pos += 1 + len_offset + len;
    }

    // Skip issuer Name (SEQUENCE)
    if pos < tbs_content.len() && tbs_content[pos] == 0x30 {
        let (len_offset, len) = read_der_length(&tbs_content[pos + 1..])?;
        pos += 1 + len_offset + len;
    }

    // Skip thisUpdate Time (UTCTime 0x17 or GeneralizedTime 0x18)
    if pos < tbs_content.len() && (tbs_content[pos] == 0x17 || tbs_content[pos] == 0x18) {
        let (len_offset, len) = read_der_length(&tbs_content[pos + 1..])?;
        pos += 1 + len_offset + len;
    }

    // Skip optional nextUpdate Time
    if pos < tbs_content.len() && (tbs_content[pos] == 0x17 || tbs_content[pos] == 0x18) {
        let (len_offset, len) = read_der_length(&tbs_content[pos + 1..])?;
        pos += 1 + len_offset + len;
    }

    // revokedCertificates is an optional SEQUENCE OF
    if pos >= tbs_content.len() || tbs_content[pos] != 0x30 {
        // No revokedCertificates — CRL is empty
        return Ok(CrlRevocationStatus::Good);
    }

    // Check if this SEQUENCE is revokedCertificates or extensions [0]
    // Extensions are tagged [0] EXPLICIT (0xA0), so if we see 0x30 it's revokedCertificates
    let (revoked_len_offset, revoked_len) = read_der_length(&tbs_content[pos + 1..])?;
    let revoked_end = pos + 1 + revoked_len_offset + revoked_len;
    let mut rpos = pos + 1 + revoked_len_offset;

    // Walk each revokedCertificate entry
    while rpos < revoked_end {
        if tbs_content[rpos] != 0x30 {
            break;
        }
        let (entry_len_offset, entry_len) = read_der_length(&tbs_content[rpos + 1..])?;
        let entry_start = rpos + 1 + entry_len_offset;
        let entry_end = entry_start + entry_len;

        // First field: userCertificate (INTEGER)
        if entry_start < entry_end && tbs_content[entry_start] == 0x02 {
            let (serial_len_offset, serial_len) = read_der_length(&tbs_content[entry_start + 1..])?;
            let serial_start = entry_start + 1 + serial_len_offset;
            let entry_serial = &tbs_content[serial_start..serial_start + serial_len];

            // Compare serial numbers (strip leading zeros for comparison)
            let target = strip_leading_zeros(serial_number);
            let entry = strip_leading_zeros(entry_serial);

            if target == entry {
                // Found — extract optional reason code from extensions
                let reason =
                    extract_revocation_reason(&tbs_content[serial_start + serial_len..entry_end]);
                return Ok(CrlRevocationStatus::Revoked { reason });
            }
        }

        rpos = entry_end;
    }

    Ok(CrlRevocationStatus::Good)
}

/// Strip leading zero bytes from a byte slice (for serial number comparison).
fn strip_leading_zeros(data: &[u8]) -> &[u8] {
    let start = data.iter().position(|&b| b != 0).unwrap_or(data.len());
    &data[start..]
}

/// Extract CRL reason code from revoked certificate entry extensions.
///
/// The extensions follow the revocationDate in a revokedCertificate entry.
/// CRL Reason is OID 2.5.29.21, encoded as ENUMERATED.
fn extract_revocation_reason(data: &[u8]) -> Option<RevocationReason> {
    // After revocationDate, there may be no extensions at all
    if data.is_empty() {
        return None;
    }

    // Skip revocationDate (UTCTime or GeneralizedTime) if present
    let mut pos = 0;
    if pos < data.len() && (data[pos] == 0x17 || data[pos] == 0x18) {
        let (len_offset, len) = read_der_length(&data[pos + 1..]).ok()?;
        pos += 1 + len_offset + len;
    }

    // Extensions are wrapped in SEQUENCE
    if pos >= data.len() || data[pos] != 0x30 {
        return None;
    }
    let (exts_len_offset, exts_len) = read_der_length(&data[pos + 1..]).ok()?;
    let exts_end = pos + 1 + exts_len_offset + exts_len;
    let mut epos = pos + 1 + exts_len_offset;

    // CRL Reason OID: 2.5.29.21 = 55 1D 15
    let reason_oid = [0x55, 0x1D, 0x15];

    while epos < exts_end {
        if data[epos] != 0x30 {
            break;
        }
        let (ext_len_offset, ext_len) = read_der_length(&data[epos + 1..]).ok()?;
        let ext_start = epos + 1 + ext_len_offset;
        let ext_end = ext_start + ext_len;
        let ext_bytes = &data[ext_start..ext_end];

        // Check if this extension contains the CRL Reason OID
        if ext_bytes.len() >= 5 {
            // OID tag (0x06) + length (0x03) + OID value
            if ext_bytes[0] == 0x06 && ext_bytes[1] == 0x03 && ext_bytes[2..5] == reason_oid {
                // Find ENUMERATED value inside the OCTET STRING wrapping
                for window in ext_bytes.windows(3) {
                    if window[0] == 0x0A && window[1] == 0x01 {
                        // ENUMERATED, length 1, value
                        return RevocationReason::from_u8(window[2]);
                    }
                }
            }
        }

        epos = ext_end;
    }

    None
}

/// Extract the CRL Number from a CRL's DER encoding.
///
/// RFC 5280 §5.2.3: The CRL Number is a non-critical extension (OID 2.5.29.20)
/// containing an INTEGER value that increases monotonically.
///
/// Returns `Ok(Some(n))` if found, `Ok(None)` if no CRL Number extension present.
pub fn extract_crl_number(crl_der: &[u8]) -> Result<Option<u64>> {
    if crl_der.len() < 10 || crl_der[0] != 0x30 {
        return Err(Error::InvalidCertificate(
            "CRL does not start with SEQUENCE".into(),
        ));
    }
    let (outer_content_offset, _) = read_der_length(&crl_der[1..])?;
    let content = &crl_der[1 + outer_content_offset..];

    if content.is_empty() || content[0] != 0x30 {
        return Err(Error::InvalidCertificate(
            "CRL TBSCertList not a SEQUENCE".into(),
        ));
    }
    let (tbs_len_offset, tbs_len) = read_der_length(&content[1..])?;
    let tbs_content = &content[1 + tbs_len_offset..1 + tbs_len_offset + tbs_len];

    // Walk TBSCertList to find extensions [0] EXPLICIT
    let mut pos = 0;

    // Skip version (INTEGER), signature (SEQUENCE), issuer (SEQUENCE)
    for expected_tag in &[0x02u8, 0x30, 0x30] {
        if pos < tbs_content.len() && tbs_content[pos] == *expected_tag {
            let (lo, l) = read_der_length(&tbs_content[pos + 1..])?;
            pos += 1 + lo + l;
        }
    }

    // Skip thisUpdate + optional nextUpdate
    for _ in 0..2 {
        if pos < tbs_content.len() && (tbs_content[pos] == 0x17 || tbs_content[pos] == 0x18) {
            let (lo, l) = read_der_length(&tbs_content[pos + 1..])?;
            pos += 1 + lo + l;
        }
    }

    // Skip optional revokedCertificates (SEQUENCE, tag 0x30)
    if pos < tbs_content.len() && tbs_content[pos] == 0x30 {
        let (lo, l) = read_der_length(&tbs_content[pos + 1..])?;
        pos += 1 + lo + l;
    }

    // Look for extensions [0] EXPLICIT (tag 0xA0)
    if pos >= tbs_content.len() || tbs_content[pos] != 0xA0 {
        return Ok(None);
    }
    let (ext_wrapper_lo, _) = read_der_length(&tbs_content[pos + 1..])?;
    pos += 1 + ext_wrapper_lo;

    // Inner SEQUENCE of extensions
    if pos >= tbs_content.len() || tbs_content[pos] != 0x30 {
        return Ok(None);
    }
    let (exts_lo, exts_len) = read_der_length(&tbs_content[pos + 1..])?;
    let exts_end = pos + 1 + exts_lo + exts_len;
    let mut epos = pos + 1 + exts_lo;

    // CRL Number OID: 2.5.29.20 = 55 1D 14
    let crl_number_oid = [0x55, 0x1D, 0x14];

    while epos < exts_end {
        if tbs_content[epos] != 0x30 {
            break;
        }
        let (ext_lo, ext_len) = read_der_length(&tbs_content[epos + 1..])?;
        let ext_start = epos + 1 + ext_lo;
        let ext_end = ext_start + ext_len;

        // OID
        if ext_start < ext_end && tbs_content[ext_start] == 0x06 {
            let (oid_lo, oid_len) = read_der_length(&tbs_content[ext_start + 1..])?;
            let oid_start = ext_start + 1 + oid_lo;
            let oid_bytes = &tbs_content[oid_start..oid_start + oid_len];

            if oid_bytes == crl_number_oid {
                // Skip past OID + optional BOOLEAN (critical) to OCTET STRING
                let mut vpos = oid_start + oid_len;
                if vpos < ext_end && tbs_content[vpos] == 0x01 {
                    // Skip critical BOOLEAN
                    let (blo, bl) = read_der_length(&tbs_content[vpos + 1..])?;
                    vpos += 1 + blo + bl;
                }
                // OCTET STRING wrapping the INTEGER value
                if vpos < ext_end && tbs_content[vpos] == 0x04 {
                    let (os_lo, _os_len) = read_der_length(&tbs_content[vpos + 1..])?;
                    vpos += 1 + os_lo;
                    // Inner INTEGER
                    if vpos < ext_end && tbs_content[vpos] == 0x02 {
                        let (int_lo, int_len) = read_der_length(&tbs_content[vpos + 1..])?;
                        let int_start = vpos + 1 + int_lo;
                        let int_bytes = &tbs_content[int_start..int_start + int_len];
                        let mut val: u64 = 0;
                        for &b in int_bytes {
                            val = val.saturating_mul(256);
                            val = val.saturating_add(b as u64);
                        }
                        return Ok(Some(val));
                    }
                }
            }
        }
        epos = ext_end;
    }

    Ok(None)
}

/// Validate that a new CRL's number is greater than the previous CRL's number.
///
/// RFC 5280 §5.2.3: CRL numbers SHOULD increase monotonically. This function
/// enforces that invariant by comparing two CRL DER encodings.
///
/// Returns `Ok(true)` if the new CRL number > previous, `Ok(false)` if not,
/// or `Ok(true)` if either CRL lacks a CRL Number extension (can't validate).
pub fn validate_crl_number_monotonicity(
    previous_crl_der: &[u8],
    new_crl_der: &[u8],
) -> Result<bool> {
    let prev = extract_crl_number(previous_crl_der)?;
    let next = extract_crl_number(new_crl_der)?;

    match (prev, next) {
        (Some(p), Some(n)) => Ok(n > p),
        _ => Ok(true), // Can't validate without CRL numbers
    }
}

/// Read a DER length encoding. Returns (bytes consumed, length value).
fn read_der_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(Error::InvalidCertificate("Unexpected end of DER".into()));
    }

    if data[0] < 0x80 {
        // Short form: single byte
        Ok((1, data[0] as usize))
    } else if data[0] == 0x81 {
        // Long form: 1 byte length
        if data.len() < 2 {
            return Err(Error::InvalidCertificate("DER length truncated".into()));
        }
        Ok((2, data[1] as usize))
    } else if data[0] == 0x82 {
        // Long form: 2 byte length
        if data.len() < 3 {
            return Err(Error::InvalidCertificate("DER length truncated".into()));
        }
        Ok((3, ((data[1] as usize) << 8) | (data[2] as usize)))
    } else if data[0] == 0x83 {
        // Long form: 3 byte length
        if data.len() < 4 {
            return Err(Error::InvalidCertificate("DER length truncated".into()));
        }
        Ok((
            4,
            ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize),
        ))
    } else {
        Err(Error::InvalidCertificate(format!(
            "Unsupported DER length encoding: 0x{:02x}",
            data[0]
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algo::AlgorithmId;
    use crate::cert::NameBuilder;

    #[test]
    fn test_revocation_reason() {
        assert_eq!(RevocationReason::KeyCompromise as u8, 1);
        assert_eq!(
            RevocationReason::from_u8(1),
            Some(RevocationReason::KeyCompromise)
        );
        assert_eq!(RevocationReason::KeyCompromise.as_str(), "keyCompromise");
    }

    #[test]
    fn test_revoked_certificate() {
        let revoked = RevokedCertificate::new(vec![0x01, 0x02, 0x03], Utc::now())
            .with_reason(RevocationReason::KeyCompromise);

        assert_eq!(revoked.serial_hex(), "010203");
        assert_eq!(revoked.reason, Some(RevocationReason::KeyCompromise));
    }

    #[test]
    fn test_crl_builder() {
        let issuer = NameBuilder::new("Test CA").build();
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

        let revoked = RevokedCertificate::new(vec![0x01], Utc::now())
            .with_reason(RevocationReason::Superseded);

        let crl = CrlBuilder::new(issuer)
            .crl_number(1)
            .next_update_hours(24)
            .add_revoked(revoked)
            .build_and_sign(&issuer_key)
            .unwrap();

        assert!(crl.pem.contains("BEGIN X509 CRL"));
        assert_eq!(crl.crl_number, 1);
        assert_eq!(crl.revoked_count, 1);
    }

    #[test]
    fn test_revocation_reason_all_from_u8() {
        let expected = [
            (0, RevocationReason::Unspecified),
            (1, RevocationReason::KeyCompromise),
            (2, RevocationReason::CaCompromise),
            (3, RevocationReason::AffiliationChanged),
            (4, RevocationReason::Superseded),
            (5, RevocationReason::CessationOfOperation),
            (6, RevocationReason::CertificateHold),
            (8, RevocationReason::RemoveFromCrl),
            (9, RevocationReason::PrivilegeWithdrawn),
            (10, RevocationReason::AaCompromise),
        ];
        for (val, reason) in &expected {
            assert_eq!(
                RevocationReason::from_u8(*val),
                Some(*reason),
                "from_u8({}) failed",
                val
            );
        }
        assert_eq!(expected.len(), 10);
    }

    #[test]
    fn test_revocation_reason_invalid_u8() {
        // 7 is not a valid CRL reason code (gap in RFC 5280)
        assert_eq!(RevocationReason::from_u8(7), None);
        assert_eq!(RevocationReason::from_u8(11), None);
        assert_eq!(RevocationReason::from_u8(255), None);
    }

    #[test]
    fn test_revocation_reason_from_str_all() {
        let cases = [
            ("unspecified", RevocationReason::Unspecified),
            ("keyCompromise", RevocationReason::KeyCompromise),
            ("caCompromise", RevocationReason::CaCompromise),
            ("affiliationChanged", RevocationReason::AffiliationChanged),
            ("superseded", RevocationReason::Superseded),
            (
                "cessationOfOperation",
                RevocationReason::CessationOfOperation,
            ),
            ("certificateHold", RevocationReason::CertificateHold),
            ("removeFromCRL", RevocationReason::RemoveFromCrl),
            ("privilegeWithdrawn", RevocationReason::PrivilegeWithdrawn),
            ("aaCompromise", RevocationReason::AaCompromise),
        ];
        for (s, expected) in &cases {
            assert_eq!(
                RevocationReason::from_str(s).unwrap(),
                *expected,
                "from_str({:?}) failed",
                s
            );
        }
    }

    #[test]
    fn test_revocation_reason_from_str_invalid() {
        assert!(RevocationReason::from_str("invalid").is_err());
        assert!(RevocationReason::from_str("").is_err());
    }

    #[test]
    fn test_revocation_reason_as_str_all() {
        let reasons = [
            (RevocationReason::Unspecified, "unspecified"),
            (RevocationReason::KeyCompromise, "keyCompromise"),
            (RevocationReason::CaCompromise, "caCompromise"),
            (RevocationReason::AffiliationChanged, "affiliationChanged"),
            (RevocationReason::Superseded, "superseded"),
            (
                RevocationReason::CessationOfOperation,
                "cessationOfOperation",
            ),
            (RevocationReason::CertificateHold, "certificateHold"),
            (RevocationReason::RemoveFromCrl, "removeFromCRL"),
            (RevocationReason::PrivilegeWithdrawn, "privilegeWithdrawn"),
            (RevocationReason::AaCompromise, "aaCompromise"),
        ];
        for (reason, expected) in &reasons {
            assert_eq!(reason.as_str(), *expected);
        }
    }

    #[test]
    fn test_revoked_certificate_with_invalidity_date() {
        let now = Utc::now();
        let earlier = now - chrono::Duration::days(7);
        let revoked = RevokedCertificate::new(vec![0xDE, 0xAD], now)
            .with_reason(RevocationReason::KeyCompromise)
            .with_invalidity_date(earlier);

        assert_eq!(revoked.serial_hex(), "dead");
        assert_eq!(revoked.reason, Some(RevocationReason::KeyCompromise));
        assert_eq!(revoked.invalidity_date, Some(earlier));
        assert_eq!(revoked.revocation_date, now);
    }

    #[test]
    fn test_revoked_certificate_default_fields() {
        let now = Utc::now();
        let revoked = RevokedCertificate::new(vec![0x01, 0x02], now);
        assert!(revoked.reason.is_none());
        assert!(revoked.invalidity_date.is_none());
        assert_eq!(revoked.serial_hex(), "0102");
    }

    #[test]
    fn test_crl_shard_manager_deterministic() {
        let manager = CrlShardManager::new(4, 1000);
        let serial = vec![0x01, 0x02, 0x03];
        let shard1 = manager.assign_partition(&serial);
        let shard2 = manager.assign_partition(&serial);
        assert_eq!(shard1, shard2);
        assert!(shard1 < 4);
    }

    #[test]
    fn test_crl_shard_manager_partition_entries() {
        let manager = CrlShardManager::new(4, 1000);
        let now = Utc::now();
        let entries: Vec<RevokedCertificate> = (0..100u8)
            .map(|i| RevokedCertificate::new(vec![i], now))
            .collect();

        let shards = manager.partition_entries(&entries);
        assert_eq!(shards.len(), 4);
        // All entries should be distributed
        let total: usize = shards.iter().map(|s| s.len()).sum();
        assert_eq!(total, 100);
        // Each shard should have at least some entries (probabilistic but ~25 each)
        for shard in &shards {
            assert!(!shard.is_empty(), "Expected non-empty shard");
        }
    }

    #[test]
    fn test_crl_shard_manager_accessors() {
        let manager = CrlShardManager::new(8, 5000);
        assert_eq!(manager.shard_count(), 8);
        assert_eq!(manager.max_shard_size(), 5000);
    }

    #[test]
    fn test_crl_builder_empty() {
        let issuer = NameBuilder::new("Empty CRL CA").build();
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

        let crl = CrlBuilder::new(issuer)
            .crl_number(42)
            .build_and_sign(&issuer_key)
            .unwrap();

        assert_eq!(crl.crl_number, 42);
        assert_eq!(crl.revoked_count, 0);
        assert!(crl.pem.contains("BEGIN X509 CRL"));
        assert!(crl.pem.contains("END X509 CRL"));
        assert!(!crl.der.is_empty());
    }

    #[test]
    fn test_crl_builder_multiple_revoked() {
        let issuer = NameBuilder::new("Multi CRL CA").build();
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let now = Utc::now();

        let revoked_list = vec![
            RevokedCertificate::new(vec![0x01], now).with_reason(RevocationReason::KeyCompromise),
            RevokedCertificate::new(vec![0x02], now).with_reason(RevocationReason::Superseded),
            RevokedCertificate::new(vec![0x03], now)
                .with_reason(RevocationReason::CessationOfOperation),
        ];

        let crl = CrlBuilder::new(issuer)
            .crl_number(5)
            .add_revoked_list(revoked_list)
            .build_and_sign(&issuer_key)
            .unwrap();

        assert_eq!(crl.revoked_count, 3);
        assert_eq!(crl.crl_number, 5);
    }

    #[test]
    fn test_delta_crl_builder_defaults() {
        let issuer = NameBuilder::new("Delta CRL CA").build();
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let now = Utc::now();

        let delta = DeltaCrlBuilder::new(issuer, 10)
            .add_revocation(
                RevokedCertificate::new(vec![0xAA], now)
                    .with_reason(RevocationReason::KeyCompromise),
            )
            .build_and_sign(&issuer_key)
            .unwrap();

        assert_eq!(delta.base_crl_number, 10);
        assert_eq!(delta.delta_crl_number, 11); // base + 1
        assert_eq!(delta.revoked_count, 1);
        assert!(delta.pem.contains("BEGIN X509 CRL"));
    }

    #[test]
    fn test_delta_crl_builder_custom_number() {
        let issuer = NameBuilder::new("Delta CA").build();
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

        let delta = DeltaCrlBuilder::new(issuer, 100)
            .delta_crl_number(200)
            .build_and_sign(&issuer_key)
            .unwrap();

        assert_eq!(delta.base_crl_number, 100);
        assert_eq!(delta.delta_crl_number, 200);
        assert_eq!(delta.revoked_count, 0);
    }

    #[test]
    fn test_crl_with_freshest_crl_extension() {
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("Test CA").build();
        let delta_url = "http://crl.example.com/delta.crl";

        let crl = CrlBuilder::new(issuer_dn)
            .crl_number(1)
            .freshest_crl_url(delta_url)
            .build_and_sign(&issuer_key)
            .unwrap();

        // Verify the CRL DER contains the FreshestCRL OID (2.5.29.46 = 55 1D 2E)
        let der = &crl.der;
        let oid_bytes = [0x55, 0x1D, 0x2E];
        let found = der.windows(oid_bytes.len()).any(|w| w == oid_bytes);
        assert!(found, "CRL should contain FreshestCRL OID 2.5.29.46");

        // Verify the URL is present in the DER
        assert!(
            der.windows(delta_url.len())
                .any(|w| w == delta_url.as_bytes()),
            "CRL should contain the delta CRL URL"
        );
    }

    #[test]
    fn test_crl_without_freshest_crl_extension() {
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("Test CA").build();

        let crl = CrlBuilder::new(issuer_dn)
            .crl_number(1)
            .build_and_sign(&issuer_key)
            .unwrap();

        // Verify the CRL DER does NOT contain the FreshestCRL OID
        let oid_bytes = [0x55, 0x1D, 0x2E];
        let found = crl.der.windows(oid_bytes.len()).any(|w| w == oid_bytes);
        assert!(
            !found,
            "CRL without freshest_crl_url should not contain FreshestCRL OID"
        );
    }

    #[test]
    fn test_crl_next_update_before_this_update_rejected() {
        // RFC 5280 §5.1.2.5: nextUpdate MUST be later than thisUpdate
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("Test CA").build();
        let now = Utc::now();

        let result = CrlBuilder::new(issuer_dn)
            .crl_number(1)
            .this_update(now)
            .next_update(now - Duration::hours(1)) // Before thisUpdate
            .build_and_sign(&issuer_key);

        assert!(
            result.is_err(),
            "CRL with nextUpdate before thisUpdate must be rejected"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nextUpdate") && err.contains("thisUpdate"),
            "Error should mention nextUpdate/thisUpdate, got: {}",
            err
        );
    }

    #[test]
    fn test_crl_next_update_equal_to_this_update_rejected() {
        // nextUpdate == thisUpdate is also invalid (zero validity period)
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("Test CA").build();
        let now = Utc::now();

        let result = CrlBuilder::new(issuer_dn)
            .crl_number(1)
            .this_update(now)
            .next_update(now) // Equal to thisUpdate
            .build_and_sign(&issuer_key);

        assert!(
            result.is_err(),
            "CRL with nextUpdate equal to thisUpdate must be rejected"
        );
    }

    #[test]
    fn test_crl_next_update_after_this_update_ok() {
        // Valid: nextUpdate is after thisUpdate
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("Test CA").build();

        let crl = CrlBuilder::new(issuer_dn)
            .crl_number(1)
            .next_update_hours(6)
            .build_and_sign(&issuer_key)
            .unwrap();

        assert!(!crl.der.is_empty());
    }

    #[test]
    fn test_crl_this_update_in_future_rejected() {
        // RFC 5280 §5.1.2.4: thisUpdate must not be in the future
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("Test CA").build();
        let future = Utc::now() + Duration::hours(2);

        let result = CrlBuilder::new(issuer_dn)
            .crl_number(1)
            .this_update(future)
            .next_update(future + Duration::hours(6))
            .build_and_sign(&issuer_key);

        assert!(
            result.is_err(),
            "CRL with thisUpdate in the future must be rejected"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("future"),
            "Error should mention future, got: {}",
            err
        );
    }

    // --- RFC 5280 §5.2.7: ExpiredCertsOnCRL ---

    #[test]
    fn test_crl_expired_certs_on_crl_extension() {
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("ExpiredCerts CA").build();
        let cutoff = Utc::now() - Duration::days(365);

        let crl = CrlBuilder::new(issuer_dn)
            .crl_number(1)
            .next_update_hours(24)
            .expired_certs_on_crl(cutoff)
            .build_and_sign(&issuer_key)
            .unwrap();

        // CRL must contain the ExpiredCertsOnCRL OID: 2.5.29.27 → 55 1D 1B
        let oid = &[0x55, 0x1D, 0x1B];
        assert!(
            crl.der.windows(oid.len()).any(|w| w == oid),
            "CRL must contain ExpiredCertsOnCRL OID (2.5.29.27)"
        );

        // Must contain a GeneralizedTime tag (0x18)
        assert!(
            crl.der.contains(&0x18),
            "CRL must contain GeneralizedTime value for ExpiredCertsOnCRL"
        );
    }

    #[test]
    fn test_crl_without_expired_certs_on_crl() {
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("Normal CA").build();

        let crl = CrlBuilder::new(issuer_dn)
            .crl_number(1)
            .next_update_hours(24)
            .build_and_sign(&issuer_key)
            .unwrap();

        // CRL must NOT contain the ExpiredCertsOnCRL OID
        let oid = &[0x55, 0x1D, 0x1B];
        assert!(
            !crl.der.windows(oid.len()).any(|w| w == oid),
            "CRL without expired_certs_on_crl should not contain the OID"
        );
    }

    #[test]
    fn test_crl_expired_certs_on_crl_with_revoked_entries() {
        // Verify extension works alongside revoked certificate entries
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("Archival CA").build();
        let cutoff = Utc::now() - Duration::days(730); // 2 years ago

        let crl = CrlBuilder::new(issuer_dn)
            .crl_number(42)
            .next_update_hours(24)
            .expired_certs_on_crl(cutoff)
            .add_revoked(
                RevokedCertificate::new(vec![0x01], Utc::now() - Duration::days(30))
                    .with_reason(RevocationReason::KeyCompromise),
            )
            .build_and_sign(&issuer_key)
            .unwrap();

        assert_eq!(crl.revoked_count, 1);

        // Both the CRL Number OID (2.5.29.20) and ExpiredCertsOnCRL OID (2.5.29.27) must be present
        let crl_num_oid = &[0x55, 0x1D, 0x14];
        let expired_oid = &[0x55, 0x1D, 0x1B];
        assert!(crl.der.windows(crl_num_oid.len()).any(|w| w == crl_num_oid));
        assert!(crl.der.windows(expired_oid.len()).any(|w| w == expired_oid));
    }

    #[test]
    fn test_verify_crl_signature_ecdsa_p256() {
        use crate::cert::CertificateBuilder;
        use crate::cert::{encode_certificate_der, Validity};

        // Create a self-signed CA cert
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_pub = ca_key.public_key_der().unwrap();
        let ca_dn = NameBuilder::new("CRL Verify Test CA").build();
        let ca_cert = CertificateBuilder::new(ca_dn.clone(), ca_pub, AlgorithmId::EcdsaP256)
            .basic_constraints(crate::cert::extensions::BasicConstraints::ca())
            .validity(Validity::days_from_now(365))
            .build_and_sign(&ca_key)
            .unwrap();
        let ca_cert_der = encode_certificate_der(&ca_cert).unwrap();

        // Generate a CRL signed by this CA
        let crl = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .add_revoked(
                RevokedCertificate::new(vec![0x01], Utc::now())
                    .with_reason(RevocationReason::KeyCompromise),
            )
            .build_and_sign(&ca_key)
            .unwrap();

        // Verify the CRL signature
        let result = verify_crl_signature(&crl.der, &ca_cert_der);
        assert!(
            result.is_ok(),
            "CRL signature verification failed: {:?}",
            result.err()
        );
        assert!(result.unwrap(), "CRL signature should be valid");
    }

    #[test]
    fn test_verify_crl_signature_wrong_key_fails() {
        use crate::cert::CertificateBuilder;
        use crate::cert::{encode_certificate_der, Validity};

        // Create two different CA keys
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let wrong_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let wrong_pub = wrong_key.public_key_der().unwrap();

        let ca_dn = NameBuilder::new("CRL Verify Wrong Key CA").build();
        // Create a cert with the wrong key (not the CRL signer)
        let wrong_cert = CertificateBuilder::new(ca_dn.clone(), wrong_pub, AlgorithmId::EcdsaP256)
            .basic_constraints(crate::cert::extensions::BasicConstraints::ca())
            .validity(Validity::days_from_now(365))
            .build_and_sign(&wrong_key)
            .unwrap();
        let wrong_cert_der = encode_certificate_der(&wrong_cert).unwrap();

        // Generate a CRL signed by the real CA key
        let crl = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .build_and_sign(&ca_key)
            .unwrap();

        // Verify with wrong CA cert — should fail
        let result = verify_crl_signature(&crl.der, &wrong_cert_der);
        assert!(
            result.is_err() || !result.unwrap(),
            "CRL signature verification should fail with wrong key"
        );
    }

    #[test]
    fn test_verify_crl_signature_ecdsa_p384() {
        use crate::cert::CertificateBuilder;
        use crate::cert::{encode_certificate_der, Validity};

        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();
        let ca_pub = ca_key.public_key_der().unwrap();
        let ca_dn = NameBuilder::new("CRL Verify P384 CA").build();
        let ca_cert = CertificateBuilder::new(ca_dn.clone(), ca_pub, AlgorithmId::EcdsaP384)
            .basic_constraints(crate::cert::extensions::BasicConstraints::ca())
            .validity(Validity::days_from_now(365))
            .build_and_sign(&ca_key)
            .unwrap();
        let ca_cert_der = encode_certificate_der(&ca_cert).unwrap();

        let crl = CrlBuilder::new(ca_dn)
            .crl_number(5)
            .next_update_hours(48)
            .build_and_sign(&ca_key)
            .unwrap();

        let result = verify_crl_signature(&crl.der, &ca_cert_der);
        assert!(
            result.is_ok(),
            "P-384 CRL sig verify failed: {:?}",
            result.err()
        );
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_crl_signature_invalid_der() {
        let result = verify_crl_signature(&[0x01, 0x02, 0x03], &[]);
        assert!(result.is_err(), "Should reject invalid CRL DER");
    }

    #[test]
    fn test_extract_oid_from_der() {
        // ECDSA with SHA-256: 1.2.840.10045.4.3.2
        let oid_der = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
        let oid = extract_oid_from_der(oid_der).unwrap();
        assert_eq!(oid, "1.2.840.10045.4.3.2");

        // ECDSA with SHA-384: 1.2.840.10045.4.3.3
        let oid_der = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
        let oid = extract_oid_from_der(oid_der).unwrap();
        assert_eq!(oid, "1.2.840.10045.4.3.3");

        // RSA with SHA-256: 1.2.840.113549.1.1.11
        let oid_der = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        ];
        let oid = extract_oid_from_der(oid_der).unwrap();
        assert_eq!(oid, "1.2.840.113549.1.1.11");
    }

    #[test]
    fn test_read_der_length() {
        // Short form
        assert_eq!(read_der_length(&[0x05]).unwrap(), (1, 5));
        assert_eq!(read_der_length(&[0x7F]).unwrap(), (1, 127));

        // Long form: 1 byte
        assert_eq!(read_der_length(&[0x81, 0x80]).unwrap(), (2, 128));
        assert_eq!(read_der_length(&[0x81, 0xFF]).unwrap(), (2, 255));

        // Long form: 2 bytes
        assert_eq!(read_der_length(&[0x82, 0x01, 0x00]).unwrap(), (3, 256));

        // Empty data
        assert!(read_der_length(&[]).is_err());
    }

    #[test]
    fn test_check_certificate_status_revoked() {
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("Status Check CA").build();

        let serial_revoked = vec![0x01];
        let serial_good = vec![0x02];

        let crl = CrlBuilder::new(issuer_dn)
            .crl_number(1)
            .next_update_hours(24)
            .add_revoked(
                RevokedCertificate::new(serial_revoked.clone(), Utc::now())
                    .with_reason(RevocationReason::KeyCompromise),
            )
            .build_and_sign(&issuer_key)
            .unwrap();

        // Serial 0x01 should be revoked with KeyCompromise reason
        let status = check_certificate_status(&crl.der, &serial_revoked).unwrap();
        match status {
            CrlRevocationStatus::Revoked { reason } => {
                assert_eq!(reason, Some(RevocationReason::KeyCompromise));
            }
            CrlRevocationStatus::Good => panic!("Expected Revoked, got Good"),
        }

        // Serial 0x02 should be Good (not in CRL)
        let status = check_certificate_status(&crl.der, &serial_good).unwrap();
        assert_eq!(status, CrlRevocationStatus::Good);
    }

    #[test]
    fn test_check_certificate_status_empty_crl() {
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("Empty CRL CA").build();

        let crl = CrlBuilder::new(issuer_dn)
            .crl_number(1)
            .next_update_hours(24)
            .build_and_sign(&issuer_key)
            .unwrap();

        let status = check_certificate_status(&crl.der, &[0x01]).unwrap();
        assert_eq!(status, CrlRevocationStatus::Good);
    }

    #[test]
    fn test_check_certificate_status_multiple_entries() {
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("Multi Entry CRL CA").build();

        let crl = CrlBuilder::new(issuer_dn)
            .crl_number(1)
            .next_update_hours(24)
            .add_revoked(
                RevokedCertificate::new(vec![0x0A], Utc::now())
                    .with_reason(RevocationReason::Superseded),
            )
            .add_revoked(
                RevokedCertificate::new(vec![0x0B], Utc::now())
                    .with_reason(RevocationReason::CaCompromise),
            )
            .add_revoked(
                RevokedCertificate::new(vec![0x0C], Utc::now())
                    .with_reason(RevocationReason::CessationOfOperation),
            )
            .build_and_sign(&issuer_key)
            .unwrap();

        // Check each serial
        match check_certificate_status(&crl.der, &[0x0A]).unwrap() {
            CrlRevocationStatus::Revoked { reason } => {
                assert_eq!(reason, Some(RevocationReason::Superseded));
            }
            _ => panic!("0x0A should be revoked"),
        }

        match check_certificate_status(&crl.der, &[0x0B]).unwrap() {
            CrlRevocationStatus::Revoked { reason } => {
                assert_eq!(reason, Some(RevocationReason::CaCompromise));
            }
            _ => panic!("0x0B should be revoked"),
        }

        match check_certificate_status(&crl.der, &[0x0C]).unwrap() {
            CrlRevocationStatus::Revoked { reason } => {
                assert_eq!(reason, Some(RevocationReason::CessationOfOperation));
            }
            _ => panic!("0x0C should be revoked"),
        }

        // Non-revoked serial
        assert_eq!(
            check_certificate_status(&crl.der, &[0x0D]).unwrap(),
            CrlRevocationStatus::Good
        );
    }

    #[test]
    fn test_check_certificate_status_leading_zeros() {
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("Leading Zero CA").build();

        let crl = CrlBuilder::new(issuer_dn)
            .crl_number(1)
            .next_update_hours(24)
            .add_revoked(RevokedCertificate::new(vec![0x00, 0x01], Utc::now()))
            .build_and_sign(&issuer_key)
            .unwrap();

        // Should match with or without leading zeros
        match check_certificate_status(&crl.der, &[0x01]).unwrap() {
            CrlRevocationStatus::Revoked { .. } => {}
            CrlRevocationStatus::Good => panic!("Should find serial 0x01 as revoked"),
        }
    }

    #[test]
    fn test_validate_crl_timing_current_crl() {
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("Timing CA").build();

        let crl = CrlBuilder::new(issuer_dn)
            .crl_number(1)
            .next_update_hours(24)
            .build_and_sign(&issuer_key)
            .unwrap();

        // CRL was just issued, so it should be valid now
        let result = validate_crl_timing(&crl.der, Utc::now()).unwrap();
        assert!(result, "CRL just issued should be valid");
    }

    #[test]
    fn test_validate_crl_timing_expired() {
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("Expired CRL CA").build();

        let crl = CrlBuilder::new(issuer_dn)
            .crl_number(1)
            .next_update_hours(1) // expires in 1 hour
            .build_and_sign(&issuer_key)
            .unwrap();

        // Check 2 hours in the future — should be expired
        let future = Utc::now() + Duration::hours(2);
        let result = validate_crl_timing(&crl.der, future).unwrap();
        assert!(
            !result,
            "CRL should be expired 2 hours after 1-hour validity"
        );
    }

    #[test]
    fn test_validate_crl_timing_not_yet_valid() {
        let issuer_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let issuer_dn = NameBuilder::new("Future CRL CA").build();

        let crl = CrlBuilder::new(issuer_dn)
            .crl_number(1)
            .next_update_hours(24)
            .build_and_sign(&issuer_key)
            .unwrap();

        // Check 1 hour in the past — thisUpdate would be after this time
        let past = Utc::now() - Duration::hours(1);
        let result = validate_crl_timing(&crl.der, past).unwrap();
        assert!(!result, "CRL should not be valid before thisUpdate");
    }

    #[test]
    fn test_validate_crl_for_certificate_full() {
        use crate::cert::CertificateBuilder;
        use crate::cert::{encode_certificate_der, Validity};

        // Create a CA with cert for signature verification
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_pub = ca_key.public_key_der().unwrap();
        let ca_dn = NameBuilder::new("Full CRL Validation CA").build();
        let ca_cert = CertificateBuilder::new(ca_dn.clone(), ca_pub, AlgorithmId::EcdsaP256)
            .basic_constraints(crate::cert::extensions::BasicConstraints::ca())
            .validity(Validity::days_from_now(365))
            .build_and_sign(&ca_key)
            .unwrap();
        let ca_cert_der = encode_certificate_der(&ca_cert).unwrap();

        // Build CRL with one revoked cert
        let crl = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .add_revoked(
                RevokedCertificate::new(vec![0x42], Utc::now())
                    .with_reason(RevocationReason::KeyCompromise),
            )
            .build_and_sign(&ca_key)
            .unwrap();

        // Full validation: revoked serial
        let status = validate_crl_for_certificate(&crl.der, &ca_cert_der, &[0x42]).unwrap();
        match status {
            CrlRevocationStatus::Revoked { reason } => {
                assert_eq!(reason, Some(RevocationReason::KeyCompromise));
            }
            _ => panic!("Serial 0x42 should be revoked"),
        }

        // Full validation: good serial
        let status = validate_crl_for_certificate(&crl.der, &ca_cert_der, &[0x43]).unwrap();
        assert_eq!(status, CrlRevocationStatus::Good);
    }

    #[test]
    fn test_validate_crl_for_certificate_wrong_issuer() {
        use crate::cert::CertificateBuilder;
        use crate::cert::{encode_certificate_der, Validity};

        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let wrong_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let wrong_pub = wrong_key.public_key_der().unwrap();

        let ca_dn = NameBuilder::new("Right CA").build();
        let wrong_dn = NameBuilder::new("Wrong CA").build();

        // Cert from wrong CA
        let wrong_cert = CertificateBuilder::new(wrong_dn, wrong_pub, AlgorithmId::EcdsaP256)
            .basic_constraints(crate::cert::extensions::BasicConstraints::ca())
            .validity(Validity::days_from_now(365))
            .build_and_sign(&wrong_key)
            .unwrap();
        let wrong_cert_der = encode_certificate_der(&wrong_cert).unwrap();

        let crl = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .build_and_sign(&ca_key)
            .unwrap();

        // Should fail — signature won't verify with wrong issuer cert
        let result = validate_crl_for_certificate(&crl.der, &wrong_cert_der, &[0x01]);
        assert!(result.is_err(), "Should reject CRL with wrong issuer cert");
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_verify_crl_signature_rsa2048() {
        use crate::cert::CertificateBuilder;
        use crate::cert::{encode_certificate_der, Validity};

        let ca_key = KeyPair::generate(AlgorithmId::Rsa2048).unwrap();
        let ca_pub = ca_key.public_key_der().unwrap();
        let ca_dn = NameBuilder::new("CRL RSA2048 CA").build();
        let ca_cert = CertificateBuilder::new(ca_dn.clone(), ca_pub, AlgorithmId::Rsa2048)
            .basic_constraints(crate::cert::extensions::BasicConstraints::ca())
            .validity(Validity::days_from_now(365))
            .build_and_sign(&ca_key)
            .unwrap();
        let ca_cert_der = encode_certificate_der(&ca_cert).unwrap();

        let crl = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .add_revoked(
                RevokedCertificate::new(vec![0x01], Utc::now())
                    .with_reason(RevocationReason::KeyCompromise),
            )
            .build_and_sign(&ca_key)
            .unwrap();

        let result = verify_crl_signature(&crl.der, &ca_cert_der);
        assert!(
            result.is_ok(),
            "RSA-2048 CRL signature verification failed: {:?}",
            result.err()
        );
        assert!(result.unwrap(), "RSA-2048 CRL signature should be valid");
    }

    #[test]
    fn test_verify_crl_signature_rsa4096() {
        use crate::cert::CertificateBuilder;
        use crate::cert::{encode_certificate_der, Validity};

        let ca_key = KeyPair::generate(AlgorithmId::Rsa4096).unwrap();
        let ca_pub = ca_key.public_key_der().unwrap();
        let ca_dn = NameBuilder::new("CRL RSA4096 CA").build();
        let ca_cert = CertificateBuilder::new(ca_dn.clone(), ca_pub, AlgorithmId::Rsa4096)
            .basic_constraints(crate::cert::extensions::BasicConstraints::ca())
            .validity(Validity::days_from_now(365))
            .build_and_sign(&ca_key)
            .unwrap();
        let ca_cert_der = encode_certificate_der(&ca_cert).unwrap();

        let crl = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .add_revoked(
                RevokedCertificate::new(vec![0x10], Utc::now())
                    .with_reason(RevocationReason::Superseded),
            )
            .build_and_sign(&ca_key)
            .unwrap();

        let result = verify_crl_signature(&crl.der, &ca_cert_der);
        assert!(
            result.is_ok(),
            "RSA-4096 CRL signature verification failed: {:?}",
            result.err()
        );
        assert!(result.unwrap(), "RSA-4096 CRL signature should be valid");
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_verify_crl_signature_ed25519() {
        use crate::cert::CertificateBuilder;
        use crate::cert::{encode_certificate_der, Validity};

        let ca_key = KeyPair::generate(AlgorithmId::Ed25519).unwrap();
        let ca_pub = ca_key.public_key_der().unwrap();
        let ca_dn = NameBuilder::new("CRL Ed25519 CA").build();
        let ca_cert = CertificateBuilder::new(ca_dn.clone(), ca_pub, AlgorithmId::Ed25519)
            .basic_constraints(crate::cert::extensions::BasicConstraints::ca())
            .validity(Validity::days_from_now(365))
            .build_and_sign(&ca_key)
            .unwrap();
        let ca_cert_der = encode_certificate_der(&ca_cert).unwrap();

        let crl = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .add_revoked(
                RevokedCertificate::new(vec![0x20], Utc::now())
                    .with_reason(RevocationReason::CaCompromise),
            )
            .build_and_sign(&ca_key)
            .unwrap();

        let result = verify_crl_signature(&crl.der, &ca_cert_der);
        assert!(
            result.is_ok(),
            "Ed25519 CRL signature verification failed: {:?}",
            result.err()
        );
        assert!(result.unwrap(), "Ed25519 CRL signature should be valid");
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_validate_crl_for_certificate_rsa() {
        use crate::cert::CertificateBuilder;
        use crate::cert::{encode_certificate_der, Validity};

        let ca_key = KeyPair::generate(AlgorithmId::Rsa2048).unwrap();
        let ca_pub = ca_key.public_key_der().unwrap();
        let ca_dn = NameBuilder::new("Full CRL RSA CA").build();
        let ca_cert = CertificateBuilder::new(ca_dn.clone(), ca_pub, AlgorithmId::Rsa2048)
            .basic_constraints(crate::cert::extensions::BasicConstraints::ca())
            .validity(Validity::days_from_now(365))
            .build_and_sign(&ca_key)
            .unwrap();
        let ca_cert_der = encode_certificate_der(&ca_cert).unwrap();

        let crl = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .add_revoked(
                RevokedCertificate::new(vec![0x55], Utc::now())
                    .with_reason(RevocationReason::PrivilegeWithdrawn),
            )
            .build_and_sign(&ca_key)
            .unwrap();

        // Full validation: revoked serial
        let status = validate_crl_for_certificate(&crl.der, &ca_cert_der, &[0x55]).unwrap();
        match status {
            CrlRevocationStatus::Revoked { reason } => {
                assert_eq!(reason, Some(RevocationReason::PrivilegeWithdrawn));
            }
            _ => panic!("Serial 0x55 should be revoked"),
        }

        // Full validation: good serial
        let status = validate_crl_for_certificate(&crl.der, &ca_cert_der, &[0x56]).unwrap();
        assert_eq!(status, CrlRevocationStatus::Good);
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_validate_crl_for_certificate_ed25519() {
        use crate::cert::CertificateBuilder;
        use crate::cert::{encode_certificate_der, Validity};

        let ca_key = KeyPair::generate(AlgorithmId::Ed25519).unwrap();
        let ca_pub = ca_key.public_key_der().unwrap();
        let ca_dn = NameBuilder::new("Full CRL Ed25519 CA").build();
        let ca_cert = CertificateBuilder::new(ca_dn.clone(), ca_pub, AlgorithmId::Ed25519)
            .basic_constraints(crate::cert::extensions::BasicConstraints::ca())
            .validity(Validity::days_from_now(365))
            .build_and_sign(&ca_key)
            .unwrap();
        let ca_cert_der = encode_certificate_der(&ca_cert).unwrap();

        let crl = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .add_revoked(
                RevokedCertificate::new(vec![0x77], Utc::now())
                    .with_reason(RevocationReason::AffiliationChanged),
            )
            .build_and_sign(&ca_key)
            .unwrap();

        let status = validate_crl_for_certificate(&crl.der, &ca_cert_der, &[0x77]).unwrap();
        match status {
            CrlRevocationStatus::Revoked { reason } => {
                assert_eq!(reason, Some(RevocationReason::AffiliationChanged));
            }
            _ => panic!("Serial 0x77 should be revoked"),
        }

        let status = validate_crl_for_certificate(&crl.der, &ca_cert_der, &[0x78]).unwrap();
        assert_eq!(status, CrlRevocationStatus::Good);
    }

    // ---- CRL Number Extraction Tests (RFC 5280 §5.2.3) ----

    #[test]
    fn test_extract_crl_number() {
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_dn = NameBuilder::new("CRL Number Test CA").build();
        let crl = CrlBuilder::new(ca_dn)
            .crl_number(42)
            .next_update_hours(24)
            .build_and_sign(&ca_key)
            .unwrap();

        let num = extract_crl_number(&crl.der).unwrap();
        assert_eq!(num, Some(42));
    }

    #[test]
    fn test_extract_crl_number_large() {
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_dn = NameBuilder::new("CRL Number Large CA").build();
        let crl = CrlBuilder::new(ca_dn)
            .crl_number(999999)
            .next_update_hours(24)
            .build_and_sign(&ca_key)
            .unwrap();

        let num = extract_crl_number(&crl.der).unwrap();
        assert_eq!(num, Some(999999));
    }

    #[test]
    fn test_validate_crl_number_monotonicity_increasing() {
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_dn = NameBuilder::new("Monotonicity CA").build();
        let crl1 = CrlBuilder::new(ca_dn.clone())
            .crl_number(5)
            .next_update_hours(24)
            .build_and_sign(&ca_key)
            .unwrap();
        let crl2 = CrlBuilder::new(ca_dn)
            .crl_number(6)
            .next_update_hours(24)
            .build_and_sign(&ca_key)
            .unwrap();

        assert!(validate_crl_number_monotonicity(&crl1.der, &crl2.der).unwrap());
    }

    #[test]
    fn test_validate_crl_number_monotonicity_not_increasing() {
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_dn = NameBuilder::new("Monotonicity Fail CA").build();
        let crl1 = CrlBuilder::new(ca_dn.clone())
            .crl_number(10)
            .next_update_hours(24)
            .build_and_sign(&ca_key)
            .unwrap();
        let crl2 = CrlBuilder::new(ca_dn)
            .crl_number(10)
            .next_update_hours(24)
            .build_and_sign(&ca_key)
            .unwrap();

        assert!(!validate_crl_number_monotonicity(&crl1.der, &crl2.der).unwrap());
    }

    #[test]
    fn test_validate_crl_number_monotonicity_decreasing() {
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_dn = NameBuilder::new("Decreasing CA").build();
        let crl1 = CrlBuilder::new(ca_dn.clone())
            .crl_number(100)
            .next_update_hours(24)
            .build_and_sign(&ca_key)
            .unwrap();
        let crl2 = CrlBuilder::new(ca_dn)
            .crl_number(50)
            .next_update_hours(24)
            .build_and_sign(&ca_key)
            .unwrap();

        assert!(!validate_crl_number_monotonicity(&crl1.der, &crl2.der).unwrap());
    }

    #[test]
    fn test_idp_only_user_certs() {
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_dn = DistinguishedName::simple("IDP Test CA");

        let crl = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .only_user_certs()
            .build_and_sign(&ca_key)
            .unwrap();

        // Verify IDP OID (2.5.29.28 = 55 1D 1C) is present in the CRL
        let idp_oid: &[u8] = &[0x55, 0x1D, 0x1C];
        assert!(
            crl.der.windows(idp_oid.len()).any(|w| w == idp_oid),
            "CRL should contain IssuingDistributionPoint extension"
        );

        // Verify onlyContainsUserCerts [1] BOOLEAN TRUE (0x81 0x01 0xFF)
        let user_certs_flag: &[u8] = &[0x81, 0x01, 0xFF];
        assert!(
            crl.der
                .windows(user_certs_flag.len())
                .any(|w| w == user_certs_flag),
            "CRL should contain onlyContainsUserCerts = TRUE"
        );

        // Verify onlyContainsCACerts [2] is NOT present
        let ca_certs_flag: &[u8] = &[0x82, 0x01, 0xFF];
        assert!(
            !crl.der
                .windows(ca_certs_flag.len())
                .any(|w| w == ca_certs_flag),
            "CRL should NOT contain onlyContainsCACerts = TRUE"
        );
    }

    #[test]
    fn test_idp_only_ca_certs() {
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_dn = DistinguishedName::simple("IDP Test CA");

        let crl = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .only_ca_certs()
            .build_and_sign(&ca_key)
            .unwrap();

        // Verify onlyContainsCACerts [2] BOOLEAN TRUE (0x82 0x01 0xFF)
        let ca_certs_flag: &[u8] = &[0x82, 0x01, 0xFF];
        assert!(
            crl.der
                .windows(ca_certs_flag.len())
                .any(|w| w == ca_certs_flag),
            "CRL should contain onlyContainsCACerts = TRUE"
        );

        // Verify onlyContainsUserCerts [1] is NOT present
        let user_certs_flag: &[u8] = &[0x81, 0x01, 0xFF];
        assert!(
            !crl.der
                .windows(user_certs_flag.len())
                .any(|w| w == user_certs_flag),
            "CRL should NOT contain onlyContainsUserCerts = TRUE"
        );
    }

    #[test]
    fn test_idp_mutual_exclusion() {
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_dn = DistinguishedName::simple("IDP Test CA");

        // RFC 5280 §5.2.5: both flags MUST NOT be TRUE simultaneously
        let result = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .only_user_certs()
            .only_ca_certs()
            .build_and_sign(&ca_key);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("onlyContainsUserCerts"),
            "Error should mention the conflicting flags: {err}"
        );
    }

    #[test]
    fn test_idp_not_present_by_default() {
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_dn = DistinguishedName::simple("IDP Test CA");

        let crl = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .build_and_sign(&ca_key)
            .unwrap();

        // IDP OID should NOT be present when no scope flags are set
        let idp_oid: &[u8] = &[0x55, 0x1D, 0x1C];
        assert!(
            !crl.der.windows(idp_oid.len()).any(|w| w == idp_oid),
            "CRL should NOT contain IDP extension when no scope flags set"
        );
    }

    #[test]
    fn test_idp_critical_flag() {
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_dn = DistinguishedName::simple("IDP Test CA");

        let crl = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .only_user_certs()
            .build_and_sign(&ca_key)
            .unwrap();

        // Find IDP OID and verify critical=TRUE follows it
        let idp_oid: &[u8] = &[0x55, 0x1D, 0x1C];
        let pos = crl
            .der
            .windows(idp_oid.len())
            .position(|w| w == idp_oid)
            .expect("IDP OID must be present");

        // After OID (5 bytes), critical BOOLEAN TRUE should follow: 01 01 FF
        let critical_marker = &crl.der[pos + idp_oid.len()..pos + idp_oid.len() + 3];
        assert_eq!(
            critical_marker,
            &[0x01, 0x01, 0xFF],
            "IDP extension must be marked critical (RFC 5280 §5.2.5)"
        );
    }

    #[test]
    fn test_idp_indirect_crl() {
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_dn = DistinguishedName::simple("Indirect CRL CA");

        let crl = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .indirect_crl()
            .build_and_sign(&ca_key)
            .unwrap();

        // Verify IDP OID (2.5.29.28) is present
        let idp_oid: &[u8] = &[0x55, 0x1D, 0x1C];
        assert!(
            crl.der.windows(idp_oid.len()).any(|w| w == idp_oid),
            "CRL should contain IssuingDistributionPoint extension"
        );

        // Verify indirectCRL [4] BOOLEAN TRUE (0x84 0x01 0xFF)
        let indirect_flag: &[u8] = &[0x84, 0x01, 0xFF];
        assert!(
            crl.der
                .windows(indirect_flag.len())
                .any(|w| w == indirect_flag),
            "CRL should contain indirectCRL = TRUE"
        );

        // Verify onlyContainsUserCerts and onlyContainsCACerts are NOT present
        let user_certs_flag: &[u8] = &[0x81, 0x01, 0xFF];
        assert!(
            !crl.der
                .windows(user_certs_flag.len())
                .any(|w| w == user_certs_flag),
            "Indirect CRL should NOT contain onlyContainsUserCerts"
        );
    }

    #[test]
    fn test_certificate_issuer_entry_extension() {
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_dn = DistinguishedName::simple("CRL Issuer CA");
        let other_ca_dn = DistinguishedName::simple("Other Issuing CA");

        let revoked = RevokedCertificate::new(vec![0x42], Utc::now())
            .with_reason(RevocationReason::KeyCompromise)
            .with_certificate_issuer(other_ca_dn);

        let crl = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .indirect_crl()
            .add_revoked(revoked)
            .build_and_sign(&ca_key)
            .unwrap();

        // Verify Certificate Issuer OID (2.5.29.29 = 55 1D 1D) is present
        let cert_issuer_oid: &[u8] = &[0x55, 0x1D, 0x1D];
        assert!(
            crl.der
                .windows(cert_issuer_oid.len())
                .any(|w| w == cert_issuer_oid),
            "CRL entry should contain Certificate Issuer extension"
        );

        // Verify the extension is critical (01 01 FF after OID)
        let pos = crl
            .der
            .windows(cert_issuer_oid.len())
            .position(|w| w == cert_issuer_oid)
            .expect("Certificate Issuer OID must be present");
        let critical_marker =
            &crl.der[pos + cert_issuer_oid.len()..pos + cert_issuer_oid.len() + 3];
        assert_eq!(
            critical_marker,
            &[0x01, 0x01, 0xFF],
            "Certificate Issuer extension must be marked critical (RFC 5280 §5.3.3)"
        );

        // Verify the "Other Issuing CA" DN is somewhere in the CRL
        assert!(
            crl.der
                .windows(b"Other Issuing CA".len())
                .any(|w| w == b"Other Issuing CA"),
            "CRL should contain the certificate issuer DN"
        );
    }

    #[test]
    fn test_revoked_certificate_with_certificate_issuer() {
        let issuer_dn = DistinguishedName::simple("External CA");
        let revoked = RevokedCertificate::new(vec![0xAB, 0xCD], Utc::now())
            .with_certificate_issuer(issuer_dn);

        assert!(revoked.certificate_issuer.is_some());
        let dn = revoked.certificate_issuer.unwrap();
        assert_eq!(dn.common_name, "External CA");
    }

    // ── RFC 5280 §5.2.3: CRL number monotonicity enforcement ────────────

    #[test]
    fn test_crl_builder_rejects_non_monotonic_number() {
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_dn = DistinguishedName::simple("Monotonicity Test CA");

        // CRL number 5 with previous 10 — should fail
        let result = CrlBuilder::new(ca_dn.clone())
            .crl_number(5)
            .previous_crl_number(10)
            .next_update_hours(24)
            .build_and_sign(&ca_key);

        assert!(result.is_err(), "CRL number 5 after 10 should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("must be greater than previous"),
            "Error should mention monotonicity: {err}"
        );

        // CRL number 10 with previous 10 (equal) — should also fail
        let result = CrlBuilder::new(ca_dn.clone())
            .crl_number(10)
            .previous_crl_number(10)
            .next_update_hours(24)
            .build_and_sign(&ca_key);

        assert!(
            result.is_err(),
            "Equal CRL numbers should be rejected (must be strictly greater)"
        );
    }

    #[test]
    fn test_crl_builder_accepts_monotonic_number() {
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_dn = DistinguishedName::simple("Monotonicity Test CA");

        // CRL number 11 with previous 10 — should succeed
        let result = CrlBuilder::new(ca_dn)
            .crl_number(11)
            .previous_crl_number(10)
            .next_update_hours(24)
            .build_and_sign(&ca_key);

        assert!(result.is_ok(), "CRL number 11 after 10 should be accepted");
        assert_eq!(result.unwrap().crl_number, 11);
    }

    #[test]
    fn test_crl_builder_no_previous_allows_any_number() {
        let ca_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let ca_dn = DistinguishedName::simple("First CRL Test CA");

        // No previous_crl_number set — any number should work
        let result = CrlBuilder::new(ca_dn)
            .crl_number(1)
            .next_update_hours(24)
            .build_and_sign(&ca_key);

        assert!(
            result.is_ok(),
            "First CRL without previous should always succeed"
        );
    }
}
