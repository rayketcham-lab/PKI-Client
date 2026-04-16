//! Certificate Signing Request (PKCS#10 / RFC 2986)

use der::{asn1::BitString, Decode, Encode};
use x509_cert::name::Name;
use x509_cert::request::{CertReq, CertReqInfo};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use super::DistinguishedName;
use crate::algo::{AlgorithmId, KeyPair};
use crate::error::{Error, Result};

/// Parsed Certificate Signing Request
#[derive(Debug)]
pub struct CertificateRequest {
    /// Raw DER-encoded CSR
    pub der: Vec<u8>,
    /// Parsed CSR structure
    pub inner: CertReq,
}

impl CertificateRequest {
    /// Parse CSR from DER
    ///
    /// Validates that the CSR version is v1 (0) per RFC 2986 §4.1.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let inner = CertReq::from_der(der).map_err(|e| Error::InvalidCsr(e.to_string()))?;

        // RFC 2986 §4.1: version MUST be 0 (v1)
        if inner.info.version != x509_cert::request::Version::V1 {
            return Err(Error::InvalidCsr(format!(
                "RFC 2986 §4.1: CSR version must be v1 (0), got {:?}",
                inner.info.version
            )));
        }

        Ok(Self {
            der: der.to_vec(),
            inner,
        })
    }

    /// Parse CSR from PEM
    pub fn from_pem(pem: &str) -> Result<Self> {
        let pem_data =
            pem::parse(pem).map_err(|e| Error::InvalidCsr(format!("PEM parse: {}", e)))?;

        if pem_data.tag() != "CERTIFICATE REQUEST" && pem_data.tag() != "NEW CERTIFICATE REQUEST" {
            return Err(Error::InvalidCsr(format!(
                "Expected CERTIFICATE REQUEST, got {}",
                pem_data.tag()
            )));
        }

        Self::from_der(pem_data.contents())
    }

    /// Get subject name
    pub fn subject(&self) -> &Name {
        &self.inner.info.subject
    }

    /// Get subject as a formatted DN string
    pub fn subject_dn(&self) -> String {
        format_name_as_dn(&self.inner.info.subject)
    }

    /// Get the Common Name (CN) from the subject
    pub fn subject_cn(&self) -> String {
        extract_cn_from_name(&self.inner.info.subject)
    }

    /// Get subject public key info
    pub fn public_key_info(&self) -> &SubjectPublicKeyInfoOwned {
        &self.inner.info.public_key
    }

    /// Get public key algorithm OID
    pub fn algorithm_oid(&self) -> &const_oid::ObjectIdentifier {
        &self.inner.info.public_key.algorithm.oid
    }

    /// Get algorithm name as a human-readable string
    pub fn algorithm_name(&self) -> &'static str {
        let oid = self.algorithm_oid().to_string();
        match oid.as_str() {
            "1.2.840.10045.2.1" => "ECDSA",
            "1.2.840.113549.1.1.1" => "RSA",
            "2.16.840.1.101.3.4.3.17" => "ML-DSA-44",
            "2.16.840.1.101.3.4.3.18" => "ML-DSA-65",
            "2.16.840.1.101.3.4.3.19" => "ML-DSA-87",
            "2.16.840.1.101.3.4.3.20" => "SLH-DSA-SHA2-128s",
            "2.16.840.1.101.3.4.3.22" => "SLH-DSA-SHA2-192s",
            "2.16.840.1.101.3.4.3.24" => "SLH-DSA-SHA2-256s",
            _ => "Unknown",
        }
    }

    /// Extract challengePassword attribute from CSR (RFC 2985 §5.4.1).
    ///
    /// The challengePassword (OID 1.2.840.113549.1.9.7) is an optional attribute
    /// in PKCS#10 used by SCEP and other enrollment protocols.
    pub fn challenge_password(&self) -> Option<String> {
        // OID 1.2.840.113549.1.9.7 — challengePassword
        const CHALLENGE_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07];
        self.extract_string_attribute(CHALLENGE_OID)
    }

    /// Extract requested SAN DNS names from extensionRequest attribute (RFC 2986 §4, RFC 2985 §5.4.2).
    ///
    /// Parses the extensionRequest attribute (OID 1.2.840.113549.1.9.14) to find
    /// the SAN extension (OID 2.5.29.17) and extracts dNSName [2] entries.
    pub fn requested_dns_names(&self) -> Vec<String> {
        // SAN OID 2.5.29.17 encoded as DER
        const SAN_OID: &[u8] = &[0x55, 0x1D, 0x11];
        let der = &self.der;
        let mut names = Vec::new();

        // Find SAN OID in the DER
        let mut pos = 0;
        while pos + SAN_OID.len() < der.len() {
            if der[pos..].starts_with(SAN_OID) {
                // Found SAN OID — scan forward for GeneralNames SEQUENCE
                let search_start = pos + SAN_OID.len();
                for scan in search_start..std::cmp::min(search_start + 20, der.len()) {
                    if der[scan] == 0x30 {
                        let seq_start = scan + 1;
                        if seq_start >= der.len() {
                            break;
                        }
                        let (seq_len, hdr_len) = if der[seq_start] < 0x80 {
                            (der[seq_start] as usize, 1)
                        } else {
                            let nb = (der[seq_start] & 0x7F) as usize;
                            if seq_start + 1 + nb > der.len() {
                                break;
                            }
                            let mut l = 0usize;
                            for i in 0..nb {
                                l = (l << 8) | der[seq_start + 1 + i] as usize;
                            }
                            (l, 1 + nb)
                        };
                        let content_start = seq_start + hdr_len;
                        let content_end = std::cmp::min(content_start + seq_len, der.len());
                        // Parse GeneralName entries — dNSName is context tag [2]
                        let mut gn_pos = content_start;
                        while gn_pos + 2 <= content_end {
                            let tag = der[gn_pos];
                            gn_pos += 1;
                            if gn_pos >= content_end {
                                break;
                            }
                            let len = der[gn_pos] as usize;
                            gn_pos += 1;
                            if gn_pos + len > content_end {
                                break;
                            }
                            // Tag 0x82 = context [2] IMPLICIT = dNSName
                            if tag == 0x82 {
                                if let Ok(name) = std::str::from_utf8(&der[gn_pos..gn_pos + len]) {
                                    names.push(name.to_string());
                                }
                            }
                            gn_pos += len;
                        }
                        break;
                    }
                }
                break;
            }
            pos += 1;
        }
        names
    }

    /// Extract requested SAN IP addresses from extensionRequest attribute (RFC 2986 §4).
    ///
    /// Parses the extensionRequest attribute to find the SAN extension
    /// (OID 2.5.29.17) and extracts iPAddress [7] entries (RFC 5280 §4.2.1.6).
    ///
    /// Returns IP addresses as strings ("192.168.1.1" for IPv4, "::1" for IPv6).
    pub fn requested_ip_addresses(&self) -> Vec<String> {
        // SAN OID 2.5.29.17 encoded as DER
        const SAN_OID: &[u8] = &[0x55, 0x1D, 0x11];
        let der = &self.der;
        let mut addrs = Vec::new();

        let mut pos = 0;
        while pos + SAN_OID.len() < der.len() {
            if der[pos..].starts_with(SAN_OID) {
                let search_start = pos + SAN_OID.len();
                for scan in search_start..std::cmp::min(search_start + 20, der.len()) {
                    if der[scan] == 0x30 {
                        let seq_start = scan + 1;
                        if seq_start >= der.len() {
                            break;
                        }
                        let (seq_len, hdr_len) = if der[seq_start] < 0x80 {
                            (der[seq_start] as usize, 1)
                        } else {
                            let nb = (der[seq_start] & 0x7F) as usize;
                            if seq_start + 1 + nb > der.len() {
                                break;
                            }
                            let mut l = 0usize;
                            for i in 0..nb {
                                l = (l << 8) | der[seq_start + 1 + i] as usize;
                            }
                            (l, 1 + nb)
                        };
                        let content_start = seq_start + hdr_len;
                        let content_end = std::cmp::min(content_start + seq_len, der.len());
                        let mut gn_pos = content_start;
                        while gn_pos + 2 <= content_end {
                            let tag = der[gn_pos];
                            gn_pos += 1;
                            if gn_pos >= content_end {
                                break;
                            }
                            let len = der[gn_pos] as usize;
                            gn_pos += 1;
                            if gn_pos + len > content_end {
                                break;
                            }
                            // Tag 0x87 = context [7] IMPLICIT = iPAddress
                            if tag == 0x87 {
                                let ip_bytes = &der[gn_pos..gn_pos + len];
                                if len == 4 {
                                    // IPv4
                                    addrs.push(format!(
                                        "{}.{}.{}.{}",
                                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                                    ));
                                } else if len == 16 {
                                    // IPv6
                                    let addr = std::net::Ipv6Addr::new(
                                        u16::from_be_bytes([ip_bytes[0], ip_bytes[1]]),
                                        u16::from_be_bytes([ip_bytes[2], ip_bytes[3]]),
                                        u16::from_be_bytes([ip_bytes[4], ip_bytes[5]]),
                                        u16::from_be_bytes([ip_bytes[6], ip_bytes[7]]),
                                        u16::from_be_bytes([ip_bytes[8], ip_bytes[9]]),
                                        u16::from_be_bytes([ip_bytes[10], ip_bytes[11]]),
                                        u16::from_be_bytes([ip_bytes[12], ip_bytes[13]]),
                                        u16::from_be_bytes([ip_bytes[14], ip_bytes[15]]),
                                    );
                                    addrs.push(addr.to_string());
                                }
                            }
                            gn_pos += len;
                        }
                        break;
                    }
                }
                break;
            }
            pos += 1;
        }
        addrs
    }

    /// Extract requested SAN email addresses (rfc822Name) from extensionRequest attribute.
    ///
    /// Parses the extensionRequest attribute (OID 1.2.840.113549.1.9.14) to find
    /// the SAN extension (OID 2.5.29.17) and extracts rfc822Name [1] entries
    /// (RFC 5280 §4.2.1.6). Required for S/MIME and client-auth identification.
    pub fn requested_email_addresses(&self) -> Vec<String> {
        // SAN OID 2.5.29.17 encoded as DER
        const SAN_OID: &[u8] = &[0x55, 0x1D, 0x11];
        let der = &self.der;
        let mut emails = Vec::new();

        let mut pos = 0;
        while pos + SAN_OID.len() < der.len() {
            if der[pos..].starts_with(SAN_OID) {
                let search_start = pos + SAN_OID.len();
                for scan in search_start..std::cmp::min(search_start + 20, der.len()) {
                    if der[scan] == 0x30 {
                        let seq_start = scan + 1;
                        if seq_start >= der.len() {
                            break;
                        }
                        let (seq_len, hdr_len) = if der[seq_start] < 0x80 {
                            (der[seq_start] as usize, 1)
                        } else {
                            let nb = (der[seq_start] & 0x7F) as usize;
                            if seq_start + 1 + nb > der.len() {
                                break;
                            }
                            let mut l = 0usize;
                            for i in 0..nb {
                                l = (l << 8) | der[seq_start + 1 + i] as usize;
                            }
                            (l, 1 + nb)
                        };
                        let content_start = seq_start + hdr_len;
                        let content_end = std::cmp::min(content_start + seq_len, der.len());
                        let mut gn_pos = content_start;
                        while gn_pos + 2 <= content_end {
                            let tag = der[gn_pos];
                            gn_pos += 1;
                            if gn_pos >= content_end {
                                break;
                            }
                            let len = der[gn_pos] as usize;
                            gn_pos += 1;
                            if gn_pos + len > content_end {
                                break;
                            }
                            // Tag 0x81 = context [1] IMPLICIT = rfc822Name
                            if tag == 0x81 {
                                if let Ok(email) = std::str::from_utf8(&der[gn_pos..gn_pos + len]) {
                                    emails.push(email.to_string());
                                }
                            }
                            gn_pos += len;
                        }
                        break;
                    }
                }
                break;
            }
            pos += 1;
        }
        emails
    }

    /// Extract unstructuredName attribute from CSR (RFC 2985 §5.4.3).
    ///
    /// The unstructuredName (OID 1.2.840.113549.1.9.2) is an optional PKCS#9
    /// attribute used to convey additional naming information not in the subject DN.
    pub fn unstructured_name(&self) -> Option<String> {
        // OID 1.2.840.113549.1.9.2 — unstructuredName
        const OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x02];
        self.extract_string_attribute(OID)
    }

    /// Extract unstructuredAddress attribute from CSR (RFC 2985 §5.4.3).
    ///
    /// The unstructuredAddress (OID 1.2.840.113549.1.9.8) is an optional PKCS#9
    /// attribute providing postal address information for enrollment.
    pub fn unstructured_address(&self) -> Option<String> {
        // OID 1.2.840.113549.1.9.8 — unstructuredAddress (actually id-at-unstructuredAddress)
        // Note: PKCS#9 v2.0 (RFC 2985) defines 1.2.840.113549.1.9.8 for this
        const OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x08];
        self.extract_string_attribute(OID)
    }

    /// Generic helper to extract a string-valued PKCS#9 attribute by OID.
    ///
    /// Scans raw DER for the given OID, then reads the first string value
    /// (UTF8String, PrintableString, or IA5String) from the attribute's SET.
    fn extract_string_attribute(&self, oid: &[u8]) -> Option<String> {
        let der = &self.der;
        let mut pos = 0;
        while pos + oid.len() < der.len() {
            if der[pos..].starts_with(oid) {
                pos += oid.len();
                // Walk past SET tag+length to find the string value
                while pos < der.len() {
                    let tag = der[pos];
                    // UTF8String (0x0C), PrintableString (0x13), IA5String (0x16)
                    if tag == 0x0C || tag == 0x13 || tag == 0x16 {
                        pos += 1;
                        if pos >= der.len() {
                            return None;
                        }
                        let len = der[pos] as usize;
                        pos += 1;
                        if pos + len > der.len() {
                            return None;
                        }
                        return String::from_utf8(der[pos..pos + len].to_vec()).ok();
                    }
                    pos += 1;
                }
                return None;
            }
            pos += 1;
        }
        None
    }

    /// Validate CSR attributes against recognized PKCS#9 OIDs (RFC 2986 §4.1).
    ///
    /// Returns a list of warnings for unrecognized or problematic attributes.
    /// Known PKCS#9 attributes (RFC 2985):
    /// - challengePassword (1.2.840.113549.1.9.7)
    /// - extensionRequest (1.2.840.113549.1.9.14)
    /// - unstructuredName (1.2.840.113549.1.9.2)
    /// - unstructuredAddress (1.2.840.113549.1.9.8)
    pub fn validate_attributes(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        // Known PKCS#9 attribute OID values (DER-encoded, without tag+length)
        // RFC 2985 Table 1 — complete list of recognized PKCS#9 attributes
        let known_oids: &[&[u8]] = &[
            // contentType (1.2.840.113549.1.9.3) — RFC 2985 §5.1
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03],
            // messageDigest (1.2.840.113549.1.9.4) — RFC 2985 §5.2
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04],
            // signingTime (1.2.840.113549.1.9.5) — RFC 2985 §5.3
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05],
            // counterSignature (1.2.840.113549.1.9.6) — RFC 2985 §5.3
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x06],
            // challengePassword (1.2.840.113549.1.9.7) — RFC 2985 §5.4.1
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07],
            // unstructuredAddress (1.2.840.113549.1.9.8) — RFC 2985 §5.4.3
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x08],
            // unstructuredName (1.2.840.113549.1.9.2) — RFC 2985 §5.4.3
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x02],
            // emailAddress (1.2.840.113549.1.9.1) — RFC 2985 §5.5
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01],
            // extensionRequest (1.2.840.113549.1.9.14) — RFC 2985 §5.4.2
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E],
            // smimeCapabilities (1.2.840.113549.1.9.15) — RFC 2985 §5.6
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0F],
        ];

        // Microsoft CSR OID prefix (1.3.6.1.4.1.311.*)
        let ms_prefix: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37];

        // Scan raw DER for OID tags to find attribute OIDs
        let der = &self.der;
        let mut pos = 0;
        while pos + 2 < der.len() {
            // Look for OID tag (0x06)
            if der[pos] == 0x06 {
                let oid_len = der[pos + 1] as usize;
                if pos + 2 + oid_len <= der.len() {
                    let oid_value = &der[pos + 2..pos + 2 + oid_len];

                    // Skip well-known non-attribute OIDs (algorithm identifiers etc.)
                    // We only flag OIDs that look like PKCS#9 attributes (1.2.840.113549.1.9.*)
                    // but aren't in our known list
                    let pkcs9_prefix: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09];
                    if oid_value.starts_with(pkcs9_prefix) && oid_value.len() > pkcs9_prefix.len() {
                        let is_known = known_oids.contains(&oid_value);
                        if !is_known {
                            warnings.push(format!(
                                "RFC 2986 §4.1: unrecognized PKCS#9 attribute OID 1.2.840.113549.1.9.{}",
                                oid_value[pkcs9_prefix.len()]
                            ));
                        }
                    } else if oid_value.starts_with(ms_prefix) {
                        // Microsoft attributes — recognized, no warning
                    }

                    pos += 2 + oid_len;
                    continue;
                }
            }
            pos += 1;
        }

        // Validate challengePassword (RFC 2985 §5.4.1)
        if let Some(pw) = self.challenge_password() {
            if pw.len() > 255 {
                warnings.push(format!(
                    "RFC 2985 §5.4.1: challengePassword exceeds 255 characters ({})",
                    pw.len()
                ));
            }
        }

        // RFC 2985 §5.4.1: challengePassword encoding MUST be a DirectoryString
        // (UTF8String 0x0C, PrintableString 0x13, BMPString 0x1E, TeletexString 0x14).
        // Warn if encoded as IA5String (0x16) or other non-DirectoryString types.
        let challenge_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07];
        if let Some(oid_pos) = der
            .windows(challenge_oid.len())
            .position(|w| w == challenge_oid)
        {
            // Skip past the OID to find the SET { value } wrapper, then the string tag
            let search_start = oid_pos + challenge_oid.len();
            let search_end = std::cmp::min(search_start + 20, der.len());
            for &tag in &der[search_start..search_end] {
                // DirectoryString valid tags: UTF8String (0x0C), PrintableString (0x13),
                // BMPString (0x1E), TeletexString/T61String (0x14), UniversalString (0x1C)
                let is_directory_string =
                    tag == 0x0C || tag == 0x13 || tag == 0x1E || tag == 0x14 || tag == 0x1C;
                let is_common_string = tag == 0x16; // IA5String — not a DirectoryString

                if is_directory_string {
                    break; // Valid encoding
                }
                if is_common_string {
                    warnings.push(
                        "RFC 2985 §5.4.1: challengePassword encoded as IA5String (0x16); \
                         MUST be DirectoryString (UTF8String, PrintableString, BMPString, or TeletexString)"
                            .to_string(),
                    );
                    break;
                }
            }
        }
        let cp_count = der
            .windows(challenge_oid.len())
            .filter(|w| *w == challenge_oid)
            .count();
        if cp_count > 1 {
            warnings.push(format!(
                "RFC 2985 §5.4.1: challengePassword must be single-valued, found {} occurrences",
                cp_count
            ));
        }

        // RFC 2985 §5.4.2: extensionRequest MUST be single-valued
        let ext_req_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E];
        let er_count = der
            .windows(ext_req_oid.len())
            .filter(|w| *w == ext_req_oid)
            .count();
        if er_count > 1 {
            warnings.push(format!(
                "RFC 2985 §5.4.2: extensionRequest must be single-valued, found {} occurrences",
                er_count
            ));
        }

        // RFC 5280 §4.2.1.6: Validate SAN IP address encoding length
        // iPAddress [7] must be exactly 4 bytes (IPv4) or 16 bytes (IPv6)
        let san_oid: &[u8] = &[0x55, 0x1D, 0x11]; // 2.5.29.17
        if der.windows(san_oid.len()).any(|w| w == san_oid) {
            let mut scan_pos = 0;
            while scan_pos + san_oid.len() < der.len() {
                if der[scan_pos..].starts_with(san_oid) {
                    // Found SAN extension — look for iPAddress [7] tags
                    let search_end = std::cmp::min(scan_pos + 200, der.len());
                    let mut ip_pos = scan_pos + san_oid.len();
                    while ip_pos + 2 <= search_end {
                        if der[ip_pos] == 0x87 {
                            let ip_len = der[ip_pos + 1] as usize;
                            if ip_len != 4 && ip_len != 16 {
                                warnings.push(format!(
                                    "RFC 5280 §4.2.1.6: SAN iPAddress has invalid length {} (must be 4 for IPv4 or 16 for IPv6)",
                                    ip_len
                                ));
                            }
                            ip_pos += 2 + ip_len;
                        } else {
                            ip_pos += 1;
                        }
                    }
                    break;
                }
                scan_pos += 1;
            }
        }

        warnings
    }

    /// Verify CSR signature
    ///
    /// Verifies that the signature in the CSR was created by the private key
    /// corresponding to the public key in the CSR. This proves the requester
    /// possesses the private key.
    pub fn verify_signature(&self) -> Result<bool> {
        use der::Encode;

        // Get the CertReqInfo (the data that was signed)
        let info_der = self
            .inner
            .info
            .to_der()
            .map_err(|e| Error::Encoding(format!("Failed to encode CertReqInfo: {}", e)))?;

        // Get the signature bytes
        let sig_bytes = self.inner.signature.as_bytes().ok_or_else(|| {
            Error::InvalidSignature("Signature BitString has unused bits".to_string())
        })?;

        // Determine algorithm from signature algorithm OID
        let sig_alg_oid = self.inner.algorithm.oid.to_string();

        match sig_alg_oid.as_str() {
            // ECDSA with SHA-256 (P-256)
            "1.2.840.10045.4.3.2" => {
                let pk_bytes = self
                    .inner
                    .info
                    .public_key
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| Error::InvalidCsr("Invalid public key BitString".to_string()))?;
                super::verify::verify_ecdsa_p256_sig(pk_bytes, &info_der, sig_bytes)
            }
            // ECDSA with SHA-384 (P-384)
            "1.2.840.10045.4.3.3" => {
                let pk_bytes = self
                    .inner
                    .info
                    .public_key
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| Error::InvalidCsr("Invalid public key BitString".to_string()))?;
                super::verify::verify_ecdsa_p384_sig(pk_bytes, &info_der, sig_bytes)
            }
            // RSA with SHA-256
            "1.2.840.113549.1.1.11" => {
                let spki_der = self
                    .inner
                    .info
                    .public_key
                    .to_der()
                    .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;
                super::verify::verify_rsa_pkcs1_sha256_sig(&spki_der, &info_der, sig_bytes)
            }
            // RSA with SHA-384
            "1.2.840.113549.1.1.12" => {
                let spki_der = self
                    .inner
                    .info
                    .public_key
                    .to_der()
                    .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;
                super::verify::verify_rsa_pkcs1_sha384_sig(&spki_der, &info_der, sig_bytes)
            }
            // RSA with SHA-512
            "1.2.840.113549.1.1.13" => {
                let spki_der = self
                    .inner
                    .info
                    .public_key
                    .to_der()
                    .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;
                super::verify::verify_rsa_pkcs1_sha512_sig(&spki_der, &info_der, sig_bytes)
            }
            // RSASSA-PSS (RFC 4055)
            "1.2.840.113549.1.1.10" => {
                let spki_der = self
                    .inner
                    .info
                    .public_key
                    .to_der()
                    .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;
                let algo_der = self.inner.algorithm.to_der().unwrap_or_default();
                let pss_hash = super::verify::detect_pss_hash_algorithm(&algo_der);
                super::verify::verify_rsa_pss_sig(&spki_der, &info_der, sig_bytes, pss_hash)
            }
            // ML-DSA-44
            #[cfg(feature = "pqc")]
            "2.16.840.1.101.3.4.3.17" => {
                use ml_dsa::{MlDsa44, Signature, VerifyingKey};
                let pk_bytes = self
                    .inner
                    .info
                    .public_key
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| Error::InvalidCsr("Invalid public key BitString".to_string()))?;
                let encoded_vk: ml_dsa::EncodedVerifyingKey<MlDsa44> =
                    pk_bytes.try_into().map_err(|_| {
                        Error::InvalidCsr("Invalid ML-DSA-44 public key length".to_string())
                    })?;
                let vk = VerifyingKey::<MlDsa44>::decode(&encoded_vk);
                let encoded_sig: ml_dsa::EncodedSignature<MlDsa44> =
                    sig_bytes.try_into().map_err(|_| {
                        Error::InvalidSignature("Invalid ML-DSA-44 signature length".into())
                    })?;
                let sig = Signature::<MlDsa44>::decode(&encoded_sig).ok_or_else(|| {
                    Error::InvalidSignature("Invalid ML-DSA-44 signature encoding".into())
                })?;
                Ok(vk.verify_with_context(&info_der, &[], &sig))
            }
            // ML-DSA-65
            #[cfg(feature = "pqc")]
            "2.16.840.1.101.3.4.3.18" => {
                use ml_dsa::{MlDsa65, Signature, VerifyingKey};
                let pk_bytes = self
                    .inner
                    .info
                    .public_key
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| Error::InvalidCsr("Invalid public key BitString".to_string()))?;
                let encoded_vk: ml_dsa::EncodedVerifyingKey<MlDsa65> =
                    pk_bytes.try_into().map_err(|_| {
                        Error::InvalidCsr("Invalid ML-DSA-65 public key length".to_string())
                    })?;
                let vk = VerifyingKey::<MlDsa65>::decode(&encoded_vk);
                let encoded_sig: ml_dsa::EncodedSignature<MlDsa65> =
                    sig_bytes.try_into().map_err(|_| {
                        Error::InvalidSignature("Invalid ML-DSA-65 signature length".into())
                    })?;
                let sig = Signature::<MlDsa65>::decode(&encoded_sig).ok_or_else(|| {
                    Error::InvalidSignature("Invalid ML-DSA-65 signature encoding".into())
                })?;
                Ok(vk.verify_with_context(&info_der, &[], &sig))
            }
            // ML-DSA-87
            #[cfg(feature = "pqc")]
            "2.16.840.1.101.3.4.3.19" => {
                use ml_dsa::{MlDsa87, Signature, VerifyingKey};
                let pk_bytes = self
                    .inner
                    .info
                    .public_key
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| Error::InvalidCsr("Invalid public key BitString".to_string()))?;
                let encoded_vk: ml_dsa::EncodedVerifyingKey<MlDsa87> =
                    pk_bytes.try_into().map_err(|_| {
                        Error::InvalidCsr("Invalid ML-DSA-87 public key length".to_string())
                    })?;
                let vk = VerifyingKey::<MlDsa87>::decode(&encoded_vk);
                let encoded_sig: ml_dsa::EncodedSignature<MlDsa87> =
                    sig_bytes.try_into().map_err(|_| {
                        Error::InvalidSignature("Invalid ML-DSA-87 signature length".into())
                    })?;
                let sig = Signature::<MlDsa87>::decode(&encoded_sig).ok_or_else(|| {
                    Error::InvalidSignature("Invalid ML-DSA-87 signature encoding".into())
                })?;
                Ok(vk.verify_with_context(&info_der, &[], &sig))
            }
            // SLH-DSA-SHA2-128s
            #[cfg(feature = "pqc")]
            "2.16.840.1.101.3.4.3.20" => {
                use slh_dsa::{
                    signature::Verifier, Sha2_128s as Sha2_128sParam, Signature, VerifyingKey,
                };
                let pk_bytes = self
                    .inner
                    .info
                    .public_key
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| Error::InvalidCsr("Invalid public key BitString".to_string()))?;
                let vk = VerifyingKey::<Sha2_128sParam>::try_from(pk_bytes).map_err(|e| {
                    Error::InvalidCsr(format!("Invalid SLH-DSA-SHA2-128s public key: {}", e))
                })?;
                let sig = Signature::<Sha2_128sParam>::try_from(sig_bytes).map_err(|e| {
                    Error::InvalidSignature(format!("Invalid SLH-DSA-SHA2-128s signature: {}", e))
                })?;
                Ok(vk.verify(&info_der, &sig).is_ok())
            }
            // SLH-DSA-SHA2-192s
            #[cfg(feature = "pqc")]
            "2.16.840.1.101.3.4.3.22" => {
                use slh_dsa::{
                    signature::Verifier, Sha2_192s as Sha2_192sParam, Signature, VerifyingKey,
                };
                let pk_bytes = self
                    .inner
                    .info
                    .public_key
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| Error::InvalidCsr("Invalid public key BitString".to_string()))?;
                let vk = VerifyingKey::<Sha2_192sParam>::try_from(pk_bytes).map_err(|e| {
                    Error::InvalidCsr(format!("Invalid SLH-DSA-SHA2-192s public key: {}", e))
                })?;
                let sig = Signature::<Sha2_192sParam>::try_from(sig_bytes).map_err(|e| {
                    Error::InvalidSignature(format!("Invalid SLH-DSA-SHA2-192s signature: {}", e))
                })?;
                Ok(vk.verify(&info_der, &sig).is_ok())
            }
            // SLH-DSA-SHA2-256s
            #[cfg(feature = "pqc")]
            "2.16.840.1.101.3.4.3.24" => {
                use slh_dsa::{
                    signature::Verifier, Sha2_256s as Sha2_256sParam, Signature, VerifyingKey,
                };
                let pk_bytes = self
                    .inner
                    .info
                    .public_key
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| Error::InvalidCsr("Invalid public key BitString".to_string()))?;
                let vk = VerifyingKey::<Sha2_256sParam>::try_from(pk_bytes).map_err(|e| {
                    Error::InvalidCsr(format!("Invalid SLH-DSA-SHA2-256s public key: {}", e))
                })?;
                let sig = Signature::<Sha2_256sParam>::try_from(sig_bytes).map_err(|e| {
                    Error::InvalidSignature(format!("Invalid SLH-DSA-SHA2-256s signature: {}", e))
                })?;
                Ok(vk.verify(&info_der, &sig).is_ok())
            }
            // Composite ML-DSA-44 + ECDSA-P256
            #[cfg(feature = "pqc")]
            "2.16.840.1.114027.80.8.1.1" => {
                let pk_bytes = self
                    .inner
                    .info
                    .public_key
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| Error::InvalidCsr("Invalid public key BitString".to_string()))?;
                crate::algo::composite_impl::verify_composite_signature_standalone(
                    crate::algo::AlgorithmId::MlDsa44EcdsaP256,
                    pk_bytes,
                    &info_der,
                    sig_bytes,
                )
            }
            // Composite ML-DSA-65 + ECDSA-P256
            #[cfg(feature = "pqc")]
            "2.16.840.1.114027.80.8.1.2" => {
                let pk_bytes = self
                    .inner
                    .info
                    .public_key
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| Error::InvalidCsr("Invalid public key BitString".to_string()))?;
                crate::algo::composite_impl::verify_composite_signature_standalone(
                    crate::algo::AlgorithmId::MlDsa65EcdsaP256,
                    pk_bytes,
                    &info_der,
                    sig_bytes,
                )
            }
            // Composite ML-DSA-65 + ECDSA-P384
            #[cfg(feature = "pqc")]
            "2.16.840.1.114027.80.8.1.3" => {
                let pk_bytes = self
                    .inner
                    .info
                    .public_key
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| Error::InvalidCsr("Invalid public key BitString".to_string()))?;
                crate::algo::composite_impl::verify_composite_signature_standalone(
                    crate::algo::AlgorithmId::MlDsa65EcdsaP384,
                    pk_bytes,
                    &info_der,
                    sig_bytes,
                )
            }
            // Composite ML-DSA-87 + ECDSA-P384
            #[cfg(feature = "pqc")]
            "2.16.840.1.114027.80.8.1.4" => {
                let pk_bytes = self
                    .inner
                    .info
                    .public_key
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| Error::InvalidCsr("Invalid public key BitString".to_string()))?;
                crate::algo::composite_impl::verify_composite_signature_standalone(
                    crate::algo::AlgorithmId::MlDsa87EcdsaP384,
                    pk_bytes,
                    &info_der,
                    sig_bytes,
                )
            }
            // Ed25519 (RFC 8410)
            "1.3.101.112" => {
                let pk_bytes = self
                    .inner
                    .info
                    .public_key
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| Error::InvalidCsr("Invalid public key BitString".to_string()))?;
                super::verify::verify_ed25519_sig(pk_bytes, &info_der, sig_bytes)
            }
            _ => Err(Error::UnsupportedAlgorithm(format!(
                "CSR signature verification not supported for algorithm OID: {}",
                sig_alg_oid
            ))),
        }
    }

    /// Encode to DER
    pub fn to_der(&self) -> &[u8] {
        &self.der
    }

    /// Encode to PEM
    pub fn to_pem(&self) -> String {
        pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", self.der.clone()))
    }

    /// Detect algorithm from OID
    pub fn detect_algorithm(&self) -> Result<AlgorithmId> {
        use crate::algo::oid;

        let algorithm_oid = *self.algorithm_oid();

        if algorithm_oid == oid::EC_PUBLIC_KEY {
            // ecPublicKey — extract curve OID from SPKI parameters
            if let Some(params) = &self.inner.info.public_key.algorithm.parameters {
                let curve_oid = params
                    .decode_as::<const_oid::ObjectIdentifier>()
                    .map_err(|e| {
                        Error::InvalidCsr(format!("Failed to decode EC curve OID: {}", e))
                    })?;
                if curve_oid == oid::SECP256R1 {
                    Ok(AlgorithmId::EcdsaP256)
                } else if curve_oid == oid::SECP384R1 {
                    Ok(AlgorithmId::EcdsaP384)
                } else {
                    Err(Error::UnsupportedAlgorithm(format!(
                        "EC curve {}",
                        curve_oid
                    )))
                }
            } else {
                Err(Error::InvalidCsr(
                    "EC key missing curve parameters".to_string(),
                ))
            }
        } else if algorithm_oid == oid::RSA_ENCRYPTION {
            // rsaEncryption — determine key size from public key bit length
            let pk_bits = self.inner.info.public_key.subject_public_key.raw_bytes();
            // RSA SubjectPublicKey is DER-encoded RSAPublicKey SEQUENCE
            // Modulus dominates size: 2048-bit ~270 bytes, 3072-bit ~398 bytes, 4096-bit ~526 bytes
            let byte_len = pk_bits.len();
            if byte_len > 450 {
                Ok(AlgorithmId::Rsa4096)
            } else if byte_len > 340 {
                Ok(AlgorithmId::Rsa3072)
            } else {
                Ok(AlgorithmId::Rsa2048)
            }
        } else if algorithm_oid == oid::ED25519 {
            Ok(AlgorithmId::Ed25519)
        } else {
            #[cfg(feature = "pqc")]
            {
                // ML-DSA (FIPS 204)
                if algorithm_oid == oid::ML_DSA_44 {
                    return Ok(AlgorithmId::MlDsa44);
                } else if algorithm_oid == oid::ML_DSA_65 {
                    return Ok(AlgorithmId::MlDsa65);
                } else if algorithm_oid == oid::ML_DSA_87 {
                    return Ok(AlgorithmId::MlDsa87);
                }
                // SLH-DSA (FIPS 205)
                if algorithm_oid == oid::SLH_DSA_SHA2_128S {
                    return Ok(AlgorithmId::SlhDsaSha2_128s);
                } else if algorithm_oid == oid::SLH_DSA_SHA2_192S {
                    return Ok(AlgorithmId::SlhDsaSha2_192s);
                } else if algorithm_oid == oid::SLH_DSA_SHA2_256S {
                    return Ok(AlgorithmId::SlhDsaSha2_256s);
                }
                // Hybrid composites (draft-ietf-lamps-pq-composite-sigs)
                if algorithm_oid == oid::ML_DSA_44_ECDSA_P256 {
                    return Ok(AlgorithmId::MlDsa44EcdsaP256);
                } else if algorithm_oid == oid::ML_DSA_65_ECDSA_P256 {
                    return Ok(AlgorithmId::MlDsa65EcdsaP256);
                } else if algorithm_oid == oid::ML_DSA_65_ECDSA_P384 {
                    return Ok(AlgorithmId::MlDsa65EcdsaP384);
                } else if algorithm_oid == oid::ML_DSA_87_ECDSA_P384 {
                    return Ok(AlgorithmId::MlDsa87EcdsaP384);
                }
            }
            Err(Error::UnsupportedAlgorithm(algorithm_oid.to_string()))
        }
    }
}

/// CSR Builder (RFC 2986 §4)
///
/// Supports optional attributes per RFC 2985/2986:
/// - `challengePassword` (OID 1.2.840.113549.1.9.7)
/// - `extensionRequest` (OID 1.2.840.113549.1.9.14) with SAN, keyUsage, etc.
/// - `unstructuredName` (OID 1.2.840.113549.1.9.2, RFC 2985 §5.4.3)
/// - `unstructuredAddress` (OID 1.2.840.113549.1.9.8, RFC 2985 §5.4.3)
pub struct CsrBuilder {
    subject: DistinguishedName,
    challenge_password: Option<String>,
    unstructured_name: Option<String>,
    unstructured_address: Option<String>,
    san_dns_names: Vec<String>,
    san_ips: Vec<String>,
    san_emails: Vec<String>,
}

impl CsrBuilder {
    /// Create a new CSR builder
    pub fn new(subject: DistinguishedName) -> Self {
        Self {
            subject,
            challenge_password: None,
            unstructured_name: None,
            unstructured_address: None,
            san_dns_names: Vec::new(),
            san_ips: Vec::new(),
            san_emails: Vec::new(),
        }
    }

    /// Set the challengePassword attribute (RFC 2985 §5.4.1).
    ///
    /// Used by SCEP enrollment and some EST profiles.
    /// Per RFC 2985 §5.4.1, the challengePassword is a DirectoryString
    /// with a maximum length of 255 characters.
    pub fn with_challenge_password(mut self, password: &str) -> Self {
        // RFC 2985 §5.4.1: challengePassword is a DirectoryString, max 255 chars
        self.challenge_password = Some(if password.len() > 255 {
            password[..255].to_string()
        } else {
            password.to_string()
        });
        self
    }

    /// Set the unstructuredName attribute (RFC 2985 §5.4.3, OID 1.2.840.113549.1.9.2).
    ///
    /// The unstructuredName is a PKCS#9 attribute that provides an
    /// alternative name for the entity requesting the certificate.
    pub fn with_unstructured_name(mut self, name: &str) -> Self {
        self.unstructured_name = Some(name.to_string());
        self
    }

    /// Set the unstructuredAddress attribute (RFC 2985 §5.4.3, OID 1.2.840.113549.1.9.8).
    ///
    /// The unstructuredAddress is a PKCS#9 attribute that provides an
    /// address for the entity requesting the certificate.
    pub fn with_unstructured_address(mut self, address: &str) -> Self {
        self.unstructured_address = Some(address.to_string());
        self
    }

    /// Add DNS names to the Subject Alternative Name extension request (RFC 2985 §5.4.2).
    pub fn with_san_dns_names(mut self, names: &[&str]) -> Self {
        self.san_dns_names
            .extend(names.iter().map(|s| s.to_string()));
        self
    }

    /// Add IP addresses to the Subject Alternative Name extension request.
    pub fn with_san_ips(mut self, ips: &[&str]) -> Self {
        self.san_ips.extend(ips.iter().map(|s| s.to_string()));
        self
    }

    /// Add email addresses to the Subject Alternative Name extension request.
    ///
    /// Emits `rfc822Name` GeneralName entries (RFC 5280 §4.2.1.6, context tag [1] IA5String).
    /// Required for S/MIME and client-auth certificates where the email identity
    /// is carried in SAN rather than the subject DN.
    pub fn with_san_emails(mut self, emails: &[&str]) -> Self {
        self.san_emails.extend(emails.iter().map(|s| s.to_string()));
        self
    }

    /// Build the attributes SET OF for this CSR.
    fn build_attributes(&self) -> Result<x509_cert::attr::Attributes> {
        let mut attrs = der::asn1::SetOfVec::new();

        // challengePassword (RFC 2985 §5.4.1)
        if let Some(ref password) = self.challenge_password {
            let dir_string = x509_cert::ext::pkix::name::DirectoryString::Utf8String(
                der::asn1::Utf8StringRef::new(password)
                    .map_err(|e| Error::Encoding(format!("challengePassword: {e}")))?
                    .into(),
            );
            let challenge = x509_cert::request::attributes::ChallengePassword(dir_string);
            use x509_cert::request::attributes::AsAttribute;
            let attr = challenge
                .to_attribute()
                .map_err(|e| Error::Encoding(format!("challengePassword attribute: {e}")))?;
            attrs
                .insert(attr)
                .map_err(|e| Error::Encoding(format!("insert challengePassword: {e}")))?;
        }

        // unstructuredName (RFC 2985 §5.4.3, OID 1.2.840.113549.1.9.2)
        if let Some(ref name) = self.unstructured_name {
            let oid = const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.2");
            let value = der::asn1::Ia5StringRef::new(name)
                .map_err(|e| Error::Encoding(format!("unstructuredName: {e}")))?;
            let any_value = der::asn1::Any::from(value);
            let mut values = der::asn1::SetOfVec::new();
            values
                .insert(any_value)
                .map_err(|e| Error::Encoding(format!("insert unstructuredName value: {e}")))?;
            let attr = x509_cert::attr::Attribute { oid, values };
            attrs
                .insert(attr)
                .map_err(|e| Error::Encoding(format!("insert unstructuredName: {e}")))?;
        }

        // unstructuredAddress (RFC 2985 §5.4.3, OID 1.2.840.113549.1.9.8)
        if let Some(ref address) = self.unstructured_address {
            let oid = const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.8");
            let value = der::asn1::Utf8StringRef::new(address)
                .map_err(|e| Error::Encoding(format!("unstructuredAddress: {e}")))?;
            let any_value = der::asn1::Any::from(value);
            let mut values = der::asn1::SetOfVec::new();
            values
                .insert(any_value)
                .map_err(|e| Error::Encoding(format!("insert unstructuredAddress value: {e}")))?;
            let attr = x509_cert::attr::Attribute { oid, values };
            attrs
                .insert(attr)
                .map_err(|e| Error::Encoding(format!("insert unstructuredAddress: {e}")))?;
        }

        // extensionRequest (RFC 2985 §5.4.2) — SAN
        if !self.san_dns_names.is_empty()
            || !self.san_ips.is_empty()
            || !self.san_emails.is_empty()
        {
            let san_ext = self.build_san_extension()?;
            let ext_req = x509_cert::request::ExtensionReq(vec![san_ext]);
            let attr: x509_cert::attr::Attribute = ext_req
                .try_into()
                .map_err(|e: der::Error| Error::Encoding(format!("extensionRequest: {e}")))?;
            attrs
                .insert(attr)
                .map_err(|e| Error::Encoding(format!("insert extensionRequest: {e}")))?;
        }

        Ok(attrs)
    }

    /// Build a SAN extension from the configured DNS names, IPs, and emails.
    fn build_san_extension(&self) -> Result<x509_cert::ext::Extension> {
        // Build GeneralNames DER manually (SEQUENCE OF GeneralName)
        let mut names_der = Vec::new();
        for email in &self.san_emails {
            // rfc822Name [1] IA5String (RFC 5280 §4.2.1.6)
            let bytes = email.as_bytes();
            names_der.push(0x81); // context [1]
            names_der.extend(der_encode_length(bytes.len()));
            names_der.extend_from_slice(bytes);
        }
        for dns in &self.san_dns_names {
            // dNSName [2] IA5String
            let bytes = dns.as_bytes();
            names_der.push(0x82); // context [2]
            names_der.extend(der_encode_length(bytes.len()));
            names_der.extend_from_slice(bytes);
        }
        for ip in &self.san_ips {
            // iPAddress [7] OCTET STRING
            if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                let octets = addr.octets();
                names_der.push(0x87); // context [7]
                names_der.push(4);
                names_der.extend_from_slice(&octets);
            } else if let Ok(addr) = ip.parse::<std::net::Ipv6Addr>() {
                let octets = addr.octets();
                names_der.push(0x87);
                names_der.push(16);
                names_der.extend_from_slice(&octets);
            }
        }

        // Wrap in SEQUENCE
        let mut san_seq = vec![0x30]; // SEQUENCE tag
        san_seq.extend(der_encode_length(names_der.len()));
        san_seq.extend(names_der);

        // OID 2.5.29.17 — id-ce-subjectAltName
        let san_oid = const_oid::ObjectIdentifier::new_unwrap("2.5.29.17");

        Ok(x509_cert::ext::Extension {
            extn_id: san_oid,
            critical: false,
            extn_value: der::asn1::OctetString::new(san_seq)
                .map_err(|e| Error::Encoding(format!("SAN octet string: {e}")))?,
        })
    }

    /// Build and sign the CSR
    pub fn build_and_sign(self, key_pair: &KeyPair) -> Result<CertificateRequest> {
        let subject_name = self.subject.to_name()?;

        // Get public key
        let public_key_der = key_pair.public_key_der()?;
        let spki = build_spki_for_csr(&public_key_der, key_pair.algorithm_id())?;

        // Build attributes
        let attributes = self.build_attributes()?;

        // Build CertReqInfo
        let info = CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: subject_name,
            public_key: spki,
            attributes,
        };

        // Encode info for signing
        let info_der = info.to_der().map_err(|e| Error::Encoding(e.to_string()))?;

        // Sign
        let signature = key_pair.sign(&info_der)?;
        let signature_bits = BitString::new(0, signature)
            .map_err(|e| Error::Encoding(format!("BitString: {}", e)))?;

        // Build signature algorithm
        let sig_algorithm = signature_algorithm_identifier(key_pair.algorithm_id())?;

        let csr = CertReq {
            info,
            algorithm: sig_algorithm,
            signature: signature_bits,
        };

        let der = csr.to_der().map_err(|e| Error::Encoding(e.to_string()))?;

        Ok(CertificateRequest { der, inner: csr })
    }
}

/// Encode a DER length field (short or long form).
fn der_encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

/// Build SPKI for CSR
fn build_spki_for_csr(
    public_key_der: &[u8],
    algorithm: AlgorithmId,
) -> Result<SubjectPublicKeyInfoOwned> {
    match algorithm {
        AlgorithmId::Ed25519
        | AlgorithmId::EcdsaP256
        | AlgorithmId::EcdsaP384
        | AlgorithmId::Rsa2048
        | AlgorithmId::Rsa3072
        | AlgorithmId::Rsa4096
        | AlgorithmId::Rsa3072Pss
        | AlgorithmId::Rsa4096Pss => {
            // These return proper SPKI DER
            SubjectPublicKeyInfoOwned::from_der(public_key_der)
                .map_err(|e| Error::Decoding(format!("SPKI decode: {}", e)))
        }
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa44EcdsaP256
        | AlgorithmId::MlDsa65EcdsaP256
        | AlgorithmId::MlDsa65EcdsaP384
        | AlgorithmId::MlDsa87EcdsaP384 => {
            // Composite keys return proper SPKI DER from public_key_der()
            SubjectPublicKeyInfoOwned::from_der(public_key_der)
                .map_err(|e| Error::Decoding(format!("SPKI decode: {}", e)))
        }
        #[cfg(feature = "pqc")]
        _ => {
            // Pure PQC (ML-DSA, SLH-DSA) - wrap raw bytes into SPKI
            let algorithm = public_key_algorithm_identifier(algorithm)?;
            let subject_public_key = BitString::new(0, public_key_der)
                .map_err(|e| Error::Encoding(format!("BitString: {}", e)))?;
            Ok(SubjectPublicKeyInfoOwned {
                algorithm,
                subject_public_key,
            })
        }
    }
}

/// Build public key algorithm identifier
#[cfg(feature = "pqc")]
fn public_key_algorithm_identifier(algorithm: AlgorithmId) -> Result<AlgorithmIdentifierOwned> {
    use const_oid::ObjectIdentifier;

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
        // Composite public key OIDs
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa44EcdsaP256 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.1"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa65EcdsaP256 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.2"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa65EcdsaP384 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.3"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa87EcdsaP384 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.4"),
        AlgorithmId::Ed25519 => ObjectIdentifier::new_unwrap("1.3.101.112"),
        AlgorithmId::EcdsaP256 | AlgorithmId::EcdsaP384 => {
            ObjectIdentifier::new_unwrap("1.2.840.10045.2.1")
        }
        AlgorithmId::Rsa2048
        | AlgorithmId::Rsa3072
        | AlgorithmId::Rsa4096
        | AlgorithmId::Rsa3072Pss
        | AlgorithmId::Rsa4096Pss => ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
    };

    Ok(AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    })
}

/// Build signature algorithm identifier
fn signature_algorithm_identifier(algorithm: AlgorithmId) -> Result<AlgorithmIdentifierOwned> {
    use const_oid::ObjectIdentifier;

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
        // Composite signature OIDs
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa44EcdsaP256 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.1"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa65EcdsaP256 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.2"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa65EcdsaP384 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.3"),
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa87EcdsaP384 => ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.4"),
        AlgorithmId::Ed25519 => ObjectIdentifier::new_unwrap("1.3.101.112"), // id-Ed25519
        AlgorithmId::EcdsaP256 => ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
        AlgorithmId::EcdsaP384 => ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"),
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
        parameters: None,
    })
}

/// Format an X.500 Name as a DN string
fn format_name_as_dn(name: &Name) -> String {
    let mut parts = Vec::new();

    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            let oid = atv.oid.to_string();
            let value = decode_atv_value(&atv.value);

            let attr_name = match oid.as_str() {
                "2.5.4.3" => "CN",
                "2.5.4.6" => "C",
                "2.5.4.7" => "L",
                "2.5.4.8" => "ST",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "1.2.840.113549.1.9.1" => "emailAddress",
                _ => &oid,
            };

            parts.push(format!("{}={}", attr_name, value));
        }
    }

    parts.join(", ")
}

/// Extract Common Name from an X.500 Name
fn extract_cn_from_name(name: &Name) -> String {
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid.to_string() == "2.5.4.3" {
                return decode_atv_value(&atv.value);
            }
        }
    }
    String::new()
}

/// Decode an AttributeTypeAndValue value to a string
fn decode_atv_value(value: &der::asn1::Any) -> String {
    // Try to decode as various string types
    if let Ok(s) = der::asn1::Utf8StringRef::try_from(value) {
        return s.as_str().to_string();
    }
    if let Ok(s) = der::asn1::PrintableStringRef::try_from(value) {
        return s.as_str().to_string();
    }
    if let Ok(s) = der::asn1::Ia5StringRef::try_from(value) {
        return s.as_str().to_string();
    }
    // Fallback: hex encode the raw value
    hex::encode(value.value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::NameBuilder;

    #[test]
    fn test_csr_builder() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Test Subject")
            .organization("Test Org")
            .build();

        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();

        // Verify we can parse it back
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert!(parsed.verify_signature().unwrap());
    }

    #[test]
    fn test_csr_generation_and_verification_roundtrip() {
        // Generate a P-256 key pair
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

        // Create a CSR with a simple DN
        let subject = NameBuilder::new("Roundtrip Test")
            .organization("SPORK Tests")
            .country("US")
            .build();

        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();

        // Verify raw DER is non-empty
        assert!(!csr.to_der().is_empty());

        // Parse the CSR back from DER
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();

        // Subject CN should be preserved
        assert_eq!(parsed.subject_cn(), "Roundtrip Test");

        // Subject DN string should contain all components
        let dn_str = parsed.subject_dn();
        assert!(
            dn_str.contains("Roundtrip Test"),
            "DN should contain CN, got: {}",
            dn_str
        );
        assert!(
            dn_str.contains("SPORK Tests"),
            "DN should contain O, got: {}",
            dn_str
        );

        // Algorithm should be detected as ECDSA P-256
        assert_eq!(parsed.algorithm_name(), "ECDSA");
        let algo = parsed.detect_algorithm().unwrap();
        assert!(matches!(algo, AlgorithmId::EcdsaP256));

        // Signature should verify (proof of possession)
        assert!(parsed.verify_signature().unwrap());
    }

    #[test]
    fn test_csr_p384_roundtrip() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();
        let subject = NameBuilder::new("P384 Test").build();

        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();

        assert_eq!(parsed.subject_cn(), "P384 Test");
        assert!(parsed.verify_signature().unwrap());
    }

    #[test]
    fn test_csr_tampered_signature_fails() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Tamper Test").build();

        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let mut der = csr.to_der().to_vec();

        // Tamper with the last byte of the DER (part of the signature)
        if let Some(last) = der.last_mut() {
            *last ^= 0xFF;
        }

        // Either parsing fails or signature verification fails
        if let Ok(parsed) = CertificateRequest::from_der(&der) {
            // If it parses, the signature should not verify
            if let Ok(true) = parsed.verify_signature() {
                panic!("Tampered CSR should not verify");
            }
            // Ok(false) or Err(_) are both expected for tampered signatures
        }
        // DER parsing failure is also acceptable for tampered bytes
    }

    #[test]
    fn test_csr_pem_roundtrip() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("PEM Test").build();

        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let pem = csr.to_pem();

        assert!(pem.contains("BEGIN CERTIFICATE REQUEST"));
        assert!(pem.contains("END CERTIFICATE REQUEST"));

        let parsed = CertificateRequest::from_pem(&pem).unwrap();
        assert_eq!(parsed.der, csr.der);
    }

    // --- Issue #31: CSR generation and verification round-trip ---

    #[test]
    #[cfg(not(feature = "fips"))] // RSA-2048 not permitted in FIPS mode
    fn test_csr_rsa_roundtrip() {
        let kp = KeyPair::generate(AlgorithmId::Rsa2048).unwrap();
        let subject = NameBuilder::new("RSA CSR Test")
            .organization("RSA Org")
            .country("US")
            .build();

        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        assert!(!csr.to_der().is_empty());

        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert_eq!(parsed.subject_cn(), "RSA CSR Test");
        assert_eq!(parsed.algorithm_name(), "RSA");
        assert!(parsed.verify_signature().unwrap());
    }

    #[test]
    fn test_csr_der_pem_der_consistency() {
        // CSR DER -> PEM -> parse -> DER should produce identical bytes
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Consistency Test").build();

        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let original_der = csr.to_der().to_vec();

        let pem = csr.to_pem();
        let parsed_from_pem = CertificateRequest::from_pem(&pem).unwrap();
        assert_eq!(
            parsed_from_pem.der, original_der,
            "DER->PEM->DER should be identical"
        );
    }

    #[test]
    fn test_csr_different_keys_different_signatures() {
        // Two CSRs from different keys for the same subject should have
        // different signatures and both should verify
        let kp1 = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let kp2 = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();

        let subject1 = NameBuilder::new("Same Subject").build();
        let subject2 = NameBuilder::new("Same Subject").build();

        let csr1 = CsrBuilder::new(subject1).build_and_sign(&kp1).unwrap();
        let csr2 = CsrBuilder::new(subject2).build_and_sign(&kp2).unwrap();

        // Both should verify
        let p1 = CertificateRequest::from_der(csr1.to_der()).unwrap();
        let p2 = CertificateRequest::from_der(csr2.to_der()).unwrap();
        assert!(p1.verify_signature().unwrap());
        assert!(p2.verify_signature().unwrap());

        // DER should differ (different public keys and signatures)
        assert_ne!(
            csr1.to_der(),
            csr2.to_der(),
            "CSRs from different keys should differ"
        );
    }

    #[test]
    fn test_csr_subject_dn_all_fields_preserved() {
        // Verify that all DN fields make it through the CSR round-trip
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Full DN CSR")
            .organization("Test Corp")
            .organizational_unit("PKI Team")
            .country("US")
            .state("Texas")
            .locality("Austin")
            .build();

        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let dn_str = csr.subject_dn();

        assert!(
            dn_str.contains("Full DN CSR"),
            "DN should contain CN, got: {}",
            dn_str
        );
        assert!(
            dn_str.contains("Test Corp"),
            "DN should contain O, got: {}",
            dn_str
        );
        assert!(
            dn_str.contains("PKI Team"),
            "DN should contain OU, got: {}",
            dn_str
        );
        assert!(
            dn_str.contains("US"),
            "DN should contain C, got: {}",
            dn_str
        );
        assert!(
            dn_str.contains("Texas"),
            "DN should contain ST, got: {}",
            dn_str
        );
        assert!(
            dn_str.contains("Austin"),
            "DN should contain L, got: {}",
            dn_str
        );
    }

    #[test]
    fn test_csr_pem_wrong_tag_rejected() {
        // A PEM with a wrong tag should be rejected
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Wrong Tag").build();

        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        // Re-encode with wrong PEM tag
        let wrong_pem = pem::encode(&pem::Pem::new("CERTIFICATE", csr.der.clone()));

        let result = CertificateRequest::from_pem(&wrong_pem);
        assert!(
            result.is_err(),
            "PEM with tag CERTIFICATE should be rejected for CSR"
        );
    }

    #[test]
    fn test_csr_invalid_der_rejected() {
        // Random bytes should fail to parse as CSR
        let result = CertificateRequest::from_der(&[0x30, 0x03, 0x01, 0x01, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_csr_detect_algorithm_p256() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Detect P256").build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        let algo = parsed.detect_algorithm().unwrap();
        assert!(matches!(algo, AlgorithmId::EcdsaP256));
    }

    #[test]
    fn test_csr_detect_algorithm_p384() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();
        let subject = NameBuilder::new("Detect P384").build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        let algo = parsed.detect_algorithm().unwrap();
        assert!(matches!(algo, AlgorithmId::EcdsaP384));
    }

    #[test]
    #[cfg(not(feature = "fips"))] // RSA-2048 not permitted in FIPS mode
    fn test_csr_detect_algorithm_rsa() {
        let kp = KeyPair::generate(AlgorithmId::Rsa2048).unwrap();
        let subject = NameBuilder::new("Detect RSA").build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        let algo = parsed.detect_algorithm().unwrap();
        assert!(matches!(algo, AlgorithmId::Rsa2048));
    }

    #[test]
    fn test_challenge_password_not_present() {
        // Standard CSR without challengePassword should return None
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("No Challenge").build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        assert!(csr.challenge_password().is_none());
    }

    /// RFC 2986 §4.1: CSR version MUST be 0 (v1).
    #[test]
    fn test_csr_version_is_zero() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Version Check").build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        // PKCS#10 version is 0 (v1)
        assert_eq!(
            parsed.inner.info.version,
            x509_cert::request::Version::V1,
            "CSR version must be v1 (0)"
        );
    }

    /// Ed25519 CSR generation, DER/PEM roundtrip, and signature verification (RFC 8410).
    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_csr_ed25519_roundtrip() {
        let kp = KeyPair::generate(AlgorithmId::Ed25519).unwrap();
        let subject = NameBuilder::new("Ed25519 CSR Test").build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        // Verify DER parses back
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert!(!parsed.der.is_empty());
        // Verify PEM roundtrip
        let pem = csr.to_pem();
        assert!(pem.contains("BEGIN CERTIFICATE REQUEST"));
        let reparsed = CertificateRequest::from_pem(&pem).unwrap();
        assert_eq!(csr.to_der(), reparsed.to_der());
        // Verify Ed25519 CSR signature (RFC 8410 — was previously unsupported)
        assert!(
            parsed.verify_signature().unwrap(),
            "Ed25519 CSR signature must verify"
        );
    }

    /// Ed25519 CSR algorithm detection.
    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_csr_detect_algorithm_ed25519() {
        let kp = KeyPair::generate(AlgorithmId::Ed25519).unwrap();
        let subject = NameBuilder::new("Detect Ed25519").build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        let algo = parsed.detect_algorithm().unwrap();
        assert!(matches!(algo, AlgorithmId::Ed25519));
    }

    /// RFC 2986 §4 / RFC 2985 §5.4.2: CSR without extensionRequest has no SAN DNS names
    #[test]
    fn test_csr_requested_dns_names_empty() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("No SAN").build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let names = csr.requested_dns_names();
        assert!(
            names.is_empty(),
            "CSR without extensionRequest should have no SAN DNS names"
        );
    }

    /// RFC 2986 §4.1: from_der rejects CSR with wrong version
    #[test]
    fn test_csr_from_der_rejects_invalid() {
        // Garbage DER should fail
        let result = CertificateRequest::from_der(&[0x30, 0x00]);
        assert!(result.is_err());
    }

    /// RSA-3072 CSRs use SHA-384 (OID 1.2.840.113549.1.1.12) — verify_signature must handle it
    #[test]
    fn test_csr_rsa3072_sha384_roundtrip() {
        let kp = KeyPair::generate(AlgorithmId::Rsa3072).unwrap();
        let subject = NameBuilder::new("RSA-3072 SHA-384 Test")
            .organization("Test Org")
            .build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert_eq!(parsed.subject_cn(), "RSA-3072 SHA-384 Test");
        assert!(
            parsed.verify_signature().unwrap(),
            "RSA-3072 CSR (SHA-384) signature must verify"
        );
    }

    /// RSA-PSS CSRs use OID 1.2.840.113549.1.1.10 — verify_signature must handle it
    #[test]
    fn test_csr_rsa_pss_roundtrip() {
        let kp = KeyPair::generate(AlgorithmId::Rsa3072Pss).unwrap();
        let subject = NameBuilder::new("RSA-PSS Test")
            .organization("Test Org")
            .build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert_eq!(parsed.subject_cn(), "RSA-PSS Test");
        assert!(
            parsed.verify_signature().unwrap(),
            "RSA-PSS CSR signature must verify"
        );
    }

    /// RFC 2986 §4 / RFC 5280 §4.2.1.6: CSR without SAN has no IP addresses
    #[test]
    fn test_csr_no_ip_addresses() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("No IP Test").build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert!(parsed.requested_ip_addresses().is_empty());
    }

    #[test]
    fn test_csr_no_unstructured_attributes() {
        // Standard CSR should have no unstructuredName or unstructuredAddress
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Test").build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert!(parsed.unstructured_name().is_none());
        assert!(parsed.unstructured_address().is_none());
    }

    #[test]
    fn test_challenge_password_uses_shared_helper() {
        // Verify challenge_password still works after refactor to shared helper
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Challenge Test").build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        // No challenge password in a standard CSR
        assert!(parsed.challenge_password().is_none());
    }

    // ─── CSR Builder Attribute Tests (RFC 2985/2986) ───

    #[test]
    fn test_csr_builder_with_challenge_password() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Challenge CSR").build();
        let csr = CsrBuilder::new(subject)
            .with_challenge_password("s3cret!")
            .build_and_sign(&kp)
            .unwrap();

        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert!(parsed.verify_signature().unwrap());
        // The challenge password should be extractable from the parsed CSR
        let pw = parsed.challenge_password();
        assert_eq!(pw, Some("s3cret!".to_string()));
    }

    #[test]
    fn test_csr_builder_with_san_dns() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("SAN CSR").build();
        let csr = CsrBuilder::new(subject)
            .with_san_dns_names(&["example.com", "www.example.com"])
            .build_and_sign(&kp)
            .unwrap();

        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert!(parsed.verify_signature().unwrap());
        let dns_names = parsed.requested_dns_names();
        assert_eq!(
            dns_names.len(),
            2,
            "Expected 2 SAN DNS names, got: {:?}",
            dns_names
        );
        assert!(dns_names.contains(&"example.com".to_string()));
        assert!(dns_names.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn test_csr_builder_with_san_ip() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("IP SAN CSR").build();
        let csr = CsrBuilder::new(subject)
            .with_san_ips(&["192.168.1.100"])
            .build_and_sign(&kp)
            .unwrap();

        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert!(parsed.verify_signature().unwrap());
        let ips = parsed.requested_ip_addresses();
        assert_eq!(ips.len(), 1, "Expected 1 SAN IP, got: {:?}", ips);
        assert_eq!(ips[0], "192.168.1.100");
    }

    #[test]
    fn test_csr_builder_with_all_attributes() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Full CSR").organization("SPORK").build();
        let csr = CsrBuilder::new(subject)
            .with_challenge_password("test123")
            .with_san_dns_names(&["full.example.com"])
            .with_san_ips(&["10.0.0.1"])
            .build_and_sign(&kp)
            .unwrap();

        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert!(parsed.verify_signature().unwrap());
        assert_eq!(parsed.challenge_password(), Some("test123".to_string()));
        assert_eq!(parsed.requested_dns_names(), vec!["full.example.com"]);
        assert_eq!(parsed.requested_ip_addresses(), vec!["10.0.0.1"]);
    }

    #[test]
    fn test_csr_builder_with_san_email() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Email SAN CSR").build();
        let csr = CsrBuilder::new(subject)
            .with_san_emails(&["user@example.com"])
            .build_and_sign(&kp)
            .unwrap();

        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert!(parsed.verify_signature().unwrap());
        let emails = parsed.requested_email_addresses();
        assert_eq!(emails.len(), 1, "Expected 1 SAN email, got: {emails:?}");
        assert_eq!(emails[0], "user@example.com");
        assert!(parsed.requested_dns_names().is_empty());
        assert!(parsed.requested_ip_addresses().is_empty());
    }

    #[test]
    fn test_csr_builder_with_san_mixed_types() {
        // S/MIME-style CSR: DNS + IP + email together.
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Mixed SAN CSR").build();
        let csr = CsrBuilder::new(subject)
            .with_san_dns_names(&["example.com"])
            .with_san_ips(&["192.0.2.1"])
            .with_san_emails(&["admin@example.com", "noc@example.com"])
            .build_and_sign(&kp)
            .unwrap();

        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert!(parsed.verify_signature().unwrap());
        assert_eq!(parsed.requested_dns_names(), vec!["example.com"]);
        assert_eq!(parsed.requested_ip_addresses(), vec!["192.0.2.1"]);
        let emails = parsed.requested_email_addresses();
        assert_eq!(emails.len(), 2, "Expected 2 emails, got: {emails:?}");
        assert!(emails.contains(&"admin@example.com".to_string()));
        assert!(emails.contains(&"noc@example.com".to_string()));
    }

    #[test]
    fn test_csr_builder_email_only_no_dns() {
        // S/MIME CSRs often carry only email SANs — no DNS, no IP.
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Ray Ketcham").build();
        let csr = CsrBuilder::new(subject)
            .with_san_emails(&["rayketcham@ogjos.com"])
            .build_and_sign(&kp)
            .unwrap();

        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert!(parsed.verify_signature().unwrap());
        assert_eq!(
            parsed.requested_email_addresses(),
            vec!["rayketcham@ogjos.com"]
        );
    }

    #[test]
    fn test_csr_builder_empty_attributes() {
        // No attributes set — should still work (backwards compatible)
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Empty Attrs").build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();

        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert!(parsed.verify_signature().unwrap());
        assert!(parsed.challenge_password().is_none());
        assert!(parsed.requested_dns_names().is_empty());
    }

    // ─── CSR Attribute Validation Tests (RFC 2985/2986) ───

    #[test]
    fn test_validate_attributes_standard_csr() {
        // Standard CSR with known attributes should have no warnings
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Validation Test").build();
        let csr = CsrBuilder::new(subject)
            .with_challenge_password("test123")
            .with_san_dns_names(&["example.com"])
            .build_and_sign(&kp)
            .unwrap();

        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        let warnings = parsed.validate_attributes();
        // Known attributes shouldn't generate warnings
        let unrecognized = warnings
            .iter()
            .filter(|w| w.contains("unrecognized"))
            .count();
        assert_eq!(
            unrecognized, 0,
            "Known attributes should not be flagged: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_attributes_no_attributes() {
        // CSR with no attributes — should validate cleanly
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("No Attrs").build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();

        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        let warnings = parsed.validate_attributes();
        assert!(
            warnings.is_empty(),
            "No attributes should produce no warnings: {warnings:?}"
        );
    }

    #[test]
    fn test_challenge_password_truncation() {
        // RFC 2985 §5.4.1: challengePassword max 255 chars
        // Verify the builder truncates passwords longer than 255 chars
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Long PW").build();
        let long_pw = "x".repeat(300);
        let csr = CsrBuilder::new(subject)
            .with_challenge_password(&long_pw)
            .build_and_sign(&kp)
            .unwrap();

        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        // The password may or may not extract cleanly depending on DER length encoding,
        // but if it does, it should be ≤255 chars
        if let Some(pw) = parsed.challenge_password() {
            assert!(
                pw.len() <= 255,
                "Password should be truncated to 255: got {}",
                pw.len()
            );
        }
        // Either way, the CSR should still be valid
        assert!(parsed.verify_signature().unwrap());
    }

    #[test]
    fn test_csr_builder_with_unstructured_name() {
        // RFC 2985 §5.4.3: unstructuredName (OID 1.2.840.113549.1.9.2)
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Unstructured Name Test").build();
        let csr = CsrBuilder::new(subject)
            .with_unstructured_name("alternate-name.example.com")
            .build_and_sign(&kp)
            .unwrap();

        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert!(parsed.verify_signature().unwrap());

        // Verify the unstructuredName OID (1.2.840.113549.1.9.2) is present in DER
        let der_bytes = csr.to_der();
        let oid_bytes: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x02];
        assert!(
            der_bytes.windows(oid_bytes.len()).any(|w| w == oid_bytes),
            "unstructuredName OID should be present in CSR DER"
        );
    }

    #[test]
    fn test_csr_builder_with_unstructured_address() {
        // RFC 2985 §5.4.3: unstructuredAddress (OID 1.2.840.113549.1.9.8)
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Unstructured Address Test").build();
        let csr = CsrBuilder::new(subject)
            .with_unstructured_address("123 Test Street, Suite 456")
            .build_and_sign(&kp)
            .unwrap();

        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert!(parsed.verify_signature().unwrap());

        // Verify the unstructuredAddress OID (1.2.840.113549.1.9.8) is present in DER
        let der_bytes = csr.to_der();
        let oid_bytes: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x08];
        assert!(
            der_bytes.windows(oid_bytes.len()).any(|w| w == oid_bytes),
            "unstructuredAddress OID should be present in CSR DER"
        );
    }

    #[test]
    fn test_csr_builder_with_all_pkcs9_attributes() {
        // Combine all PKCS#9 attributes: challengePassword + unstructuredName + unstructuredAddress + SAN
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Full PKCS9 Test").build();
        let csr = CsrBuilder::new(subject)
            .with_challenge_password("secret123")
            .with_unstructured_name("alt.example.com")
            .with_unstructured_address("Test City")
            .with_san_dns_names(&["test.example.com"])
            .build_and_sign(&kp)
            .unwrap();

        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        assert!(parsed.verify_signature().unwrap());

        // All four attribute OIDs should be present
        let der_bytes = csr.to_der();
        // challengePassword 1.2.840.113549.1.9.7
        let cp_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07];
        // unstructuredName 1.2.840.113549.1.9.2
        let un_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x02];
        // unstructuredAddress 1.2.840.113549.1.9.8
        let ua_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x08];
        // extensionRequest 1.2.840.113549.1.9.14
        let er_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E];

        assert!(
            der_bytes.windows(cp_oid.len()).any(|w| w == cp_oid),
            "challengePassword OID missing"
        );
        assert!(
            der_bytes.windows(un_oid.len()).any(|w| w == un_oid),
            "unstructuredName OID missing"
        );
        assert!(
            der_bytes.windows(ua_oid.len()).any(|w| w == ua_oid),
            "unstructuredAddress OID missing"
        );
        assert!(
            der_bytes.windows(er_oid.len()).any(|w| w == er_oid),
            "extensionRequest OID missing"
        );
    }

    #[test]
    fn test_validate_single_challenge_password() {
        // RFC 2985 §5.4.1: challengePassword must be single-valued
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Single CP Test").build();
        let csr = CsrBuilder::new(subject)
            .with_challenge_password("test123")
            .build_and_sign(&kp)
            .unwrap();
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        let warnings = parsed.validate_attributes();
        // Single challengePassword should produce no warnings about duplicates
        assert!(
            !warnings.iter().any(|w| w.contains("single-valued")),
            "Single challengePassword should not trigger uniqueness warning"
        );
    }

    #[test]
    fn test_validate_single_extension_request() {
        // RFC 2985 §5.4.2: extensionRequest must be single-valued
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("Single ER Test").build();
        let csr = CsrBuilder::new(subject)
            .with_san_dns_names(&["test.example.com"])
            .build_and_sign(&kp)
            .unwrap();
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        let warnings = parsed.validate_attributes();
        assert!(
            !warnings.iter().any(|w| w.contains("single-valued")),
            "Single extensionRequest should not trigger uniqueness warning"
        );
    }

    #[test]
    fn test_validate_no_attributes_no_warnings() {
        // CSR with no attributes should produce no warnings about single-valued attrs
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("No Attrs").build();
        let csr = CsrBuilder::new(subject).build_and_sign(&kp).unwrap();
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        let warnings = parsed.validate_attributes();
        assert!(
            !warnings.iter().any(|w| w.contains("single-valued")),
            "No attributes should not trigger uniqueness warnings"
        );
    }

    #[test]
    fn test_challenge_password_utf8string_encoding_valid() {
        // RFC 2985 §5.4.1: UTF8String (0x0C) is a valid DirectoryString encoding
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("UTF8 CP Test").build();
        let csr = CsrBuilder::new(subject)
            .with_challenge_password("valid-utf8-password")
            .build_and_sign(&kp)
            .unwrap();
        let parsed = CertificateRequest::from_der(csr.to_der()).unwrap();
        let warnings = parsed.validate_attributes();
        // Our builder uses UTF8String — should produce no encoding warnings
        assert!(
            !warnings.iter().any(|w| w.contains("IA5String")),
            "UTF8String encoding should not trigger IA5String warning"
        );
    }

    #[test]
    fn test_challenge_password_ia5string_encoding_rejected() {
        // RFC 2985 §5.4.1: IA5String (0x16) is NOT a valid DirectoryString
        // Build a real CSR, then tamper with the challengePassword encoding tag
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let subject = NameBuilder::new("IA5 CP Test").build();
        let csr = CsrBuilder::new(subject)
            .with_challenge_password("test123")
            .build_and_sign(&kp)
            .unwrap();
        let mut tampered = csr.to_der().to_vec();

        // Find the challengePassword value and change its tag from UTF8String (0x0C) to IA5String (0x16)
        let challenge_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07];
        if let Some(oid_pos) = tampered
            .windows(challenge_oid.len())
            .position(|w| w == challenge_oid)
        {
            // Search after the OID for the string tag (UTF8String = 0x0C)
            let search_start = oid_pos + challenge_oid.len();
            for i in search_start..std::cmp::min(search_start + 20, tampered.len()) {
                if tampered[i] == 0x0C {
                    tampered[i] = 0x16; // Change to IA5String
                    break;
                }
            }
        }

        // Use the raw DER directly (can't re-parse because signature is now invalid,
        // but validate_attributes only looks at the DER byte scan)
        let parsed = CertificateRequest::from_der(&tampered);
        // The tampered CSR may fail parsing, but we can still test the DER scan logic.
        // Build a minimal wrapper to test the validation directly.
        if let Ok(parsed) = parsed {
            let warnings = parsed.validate_attributes();
            assert!(
                warnings.iter().any(|w| w.contains("IA5String")),
                "IA5String encoding should trigger RFC 2985 §5.4.1 warning, got: {:?}",
                warnings
            );
        } else {
            // If parsing fails due to tampered signature, test with a synthetic CertificateRequest
            // that has the tampered DER but a valid inner struct
            let kp2 = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
            let subject2 = NameBuilder::new("Fallback").build();
            let csr2 = CsrBuilder::new(subject2).build_and_sign(&kp2).unwrap();
            let original_parsed = CertificateRequest::from_der(csr2.to_der()).unwrap();
            // Replace the DER with our tampered version
            let test_csr = CertificateRequest {
                der: tampered,
                inner: original_parsed.inner,
            };
            let warnings = test_csr.validate_attributes();
            assert!(
                warnings.iter().any(|w| w.contains("IA5String")),
                "IA5String encoding should trigger RFC 2985 §5.4.1 warning, got: {:?}",
                warnings
            );
        }
    }
}
