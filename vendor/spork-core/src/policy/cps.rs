//! CP/CPS Document Generator (RFC 3647)
//!
//! Generates a skeleton Certificate Policy / Certification Practice Statement
//! from a SecurityLevel configuration. The output follows the RFC 3647 section
//! structure and maps each section to the requirements defined in LevelRequirements.
//!
//! ## Output Format
//!
//! Generates Markdown suitable for review, editing, and conversion to PDF.
//! All sections from RFC 3647 are included with guidance text populated from
//! the security level requirements.
//!
//! ## References
//!
//! - RFC 3647: Internet X.509 PKI Certificate Policy and Certification
//!   Practices Framework
//! - NIST SP 800-57 Part 1 Rev 5
//! - FIPS 140-3

use super::security_level::{KeyProtection, LevelRequirements, SecurityLevel};

/// Configuration for CP/CPS document generation.
#[derive(Debug, Clone)]
pub struct CpsConfig {
    /// Security level for this CP/CPS.
    pub level: SecurityLevel,
    /// Organization name.
    pub org_name: String,
    /// CA common name.
    pub ca_name: String,
    /// Document version.
    pub version: String,
}

impl CpsConfig {
    pub fn new(
        level: SecurityLevel,
        org_name: impl Into<String>,
        ca_name: impl Into<String>,
    ) -> Self {
        Self {
            level,
            org_name: org_name.into(),
            ca_name: ca_name.into(),
            version: "1.0".into(),
        }
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }
}

/// Generate a CP/CPS document in Markdown format following RFC 3647 structure.
pub fn generate_cps(config: &CpsConfig) -> String {
    let req = LevelRequirements::for_level(config.level);
    let mut doc = String::with_capacity(16384);

    // Title
    doc.push_str("# Certificate Policy / Certification Practice Statement\n\n");
    doc.push_str(&format!("**Organization:** {}  \n", config.org_name));
    doc.push_str(&format!("**CA Name:** {}  \n", config.ca_name));
    doc.push_str(&format!(
        "**Security Level:** {} ({})  \n",
        config.level,
        config.level.name()
    ));
    doc.push_str(&format!("**Version:** {}  \n", config.version));
    doc.push_str(&format!("**Document OID:** {}  \n", req.ogjos_policy_oid));
    doc.push_str("**Status:** DRAFT — Requires review before deployment  \n\n");
    doc.push_str("---\n\n");

    // Section 1: Introduction
    section_1_introduction(&mut doc, config, &req);
    // Section 2: Publication and Repository Responsibilities
    section_2_publication(&mut doc, config);
    // Section 3: Identification and Authentication
    section_3_identification(&mut doc, config, &req);
    // Section 4: Certificate Life-Cycle Operational Requirements
    section_4_lifecycle(&mut doc, config, &req);
    // Section 5: Facility, Management, and Operational Controls
    section_5_controls(&mut doc, config, &req);
    // Section 6: Technical Security Controls
    section_6_technical(&mut doc, config, &req);
    // Section 7: Certificate, CRL, and OCSP Profiles
    section_7_profiles(&mut doc, config, &req);
    // Section 8: Compliance Audit and Other Assessments
    section_8_audit(&mut doc, config, &req);
    // Section 9: Other Business and Legal Matters
    section_9_legal(&mut doc, config);

    doc
}

fn section_1_introduction(doc: &mut String, config: &CpsConfig, req: &LevelRequirements) {
    doc.push_str("## 1. Introduction\n\n");

    doc.push_str("### 1.1 Overview\n\n");
    doc.push_str(&format!(
        "This document defines the Certificate Policy (CP) and Certification Practice \
         Statement (CPS) for the **{}** certificate authority operated by **{}**. \
         This CA operates at **{} ({})** as defined by the SPORK security level framework.\n\n",
        config.ca_name,
        config.org_name,
        config.level,
        config.level.name(),
    ));

    doc.push_str("### 1.2 Document Name and Identification\n\n");
    doc.push_str(&format!(
        "- **Document Title:** CP/CPS for {}\n",
        config.ca_name
    ));
    doc.push_str(&format!("- **Version:** {}\n", config.version));
    doc.push_str(&format!("- **Policy OID:** {}\n", req.ogjos_policy_oid));
    doc.push_str(&format!(
        "- **FPKI Equivalent:** {}\n\n",
        req.fpki_policy_oid
    ));

    doc.push_str("### 1.3 PKI Participants\n\n");
    doc.push_str("#### 1.3.1 Certification Authorities\n\n");
    doc.push_str(&format!(
        "The **{}** is the issuing CA under this policy.\n\n",
        config.ca_name
    ));
    doc.push_str("#### 1.3.2 Registration Authorities\n\n");
    doc.push_str("*[Specify any RAs authorized to approve certificate requests]*\n\n");
    doc.push_str("#### 1.3.3 Subscribers\n\n");
    doc.push_str(
        "*[Specify the types of entities eligible for certificates under this policy]*\n\n",
    );
    doc.push_str("#### 1.3.4 Relying Parties\n\n");
    doc.push_str("*[Specify who may rely on certificates issued under this policy]*\n\n");

    doc.push_str("### 1.4 Certificate Usage\n\n");
    doc.push_str("#### 1.4.1 Appropriate Certificate Uses\n\n");
    doc.push_str("Certificates issued under this policy may be used for:\n\n");
    doc.push_str("- TLS server authentication\n");
    doc.push_str("- TLS client authentication\n");
    doc.push_str("- Code signing\n");
    doc.push_str("- Document signing\n\n");
    doc.push_str("#### 1.4.2 Prohibited Certificate Uses\n\n");
    doc.push_str("Certificates SHALL NOT be used for any purpose not listed in §1.4.1.\n\n");

    doc.push_str("### 1.5 Policy Administration\n\n");
    doc.push_str(&format!("**Organization:** {}  \n", config.org_name));
    doc.push_str("**Contact:** *[Policy administration contact]*  \n\n");
}

fn section_2_publication(doc: &mut String, _config: &CpsConfig) {
    doc.push_str("## 2. Publication and Repository Responsibilities\n\n");

    doc.push_str("### 2.1 Repositories\n\n");
    doc.push_str("The CA SHALL maintain an online repository for:\n\n");
    doc.push_str("- This CP/CPS document\n");
    doc.push_str("- CA certificates\n");
    doc.push_str("- Certificate Revocation Lists (CRLs)\n");
    doc.push_str("- OCSP responder endpoints (if applicable)\n\n");

    doc.push_str("### 2.2 Publication of Certification Information\n\n");
    doc.push_str(
        "CA certificates and CRLs SHALL be published via HTTP at the \
                  AIA and CDP URLs embedded in issued certificates.\n\n",
    );

    doc.push_str("### 2.3 Time or Frequency of Publication\n\n");
    doc.push_str(
        "CRLs SHALL be published per the schedule defined in §4.9.7. \
                  CA certificates SHALL be published within 24 hours of issuance.\n\n",
    );

    doc.push_str("### 2.4 Access Controls on Repositories\n\n");
    doc.push_str(
        "Repository access for published information (certificates, CRLs) \
                  SHALL be publicly available. Administrative access to the repository \
                  SHALL require authentication.\n\n",
    );
}

fn section_3_identification(doc: &mut String, config: &CpsConfig, _req: &LevelRequirements) {
    doc.push_str("## 3. Identification and Authentication\n\n");

    doc.push_str("### 3.1 Naming\n\n");
    doc.push_str("#### 3.1.1 Types of Names\n\n");
    doc.push_str(
        "All certificates SHALL contain an X.500 Distinguished Name in the Subject field. \
                  End-entity certificates SHALL include Subject Alternative Names.\n\n",
    );

    doc.push_str("### 3.2 Initial Identity Validation\n\n");
    let ial = config.level.nist_ial();
    doc.push_str(&format!(
        "Identity validation SHALL conform to **NIST SP 800-63 IAL{}** requirements.\n\n",
        ial,
    ));
    match config.level {
        SecurityLevel::Level1 => {
            doc.push_str(
                "Domain control validation is sufficient at this level. \
                         No in-person identity proofing is required.\n\n",
            );
        }
        SecurityLevel::Level2 => {
            doc.push_str(
                "Subscribers SHALL be authenticated through organizational \
                         verification. Domain control validation SHALL be performed \
                         for all DNS names.\n\n",
            );
        }
        SecurityLevel::Level3 | SecurityLevel::Level4 => {
            doc.push_str(
                "Subscribers SHALL undergo identity proofing at the appropriate \
                         NIST IAL level. For CA certificates, in-person verification \
                         may be required.\n\n",
            );
        }
    }

    doc.push_str("### 3.3 Identification and Authentication for Re-key Requests\n\n");
    doc.push_str("Re-keying SHALL follow the same authentication requirements as initial issuance \
                  unless the subscriber can demonstrate proof of possession of the previous key.\n\n");

    doc.push_str("### 3.4 Identification and Authentication for Revocation Request\n\n");
    doc.push_str(
        "Revocation requests SHALL be authenticated. The following parties may \
                  request revocation:\n\n",
    );
    doc.push_str("- The certificate subscriber (via signed request or authenticated session)\n");
    doc.push_str("- A CA administrator\n");
    doc.push_str("- A Registration Authority\n\n");
}

fn section_4_lifecycle(doc: &mut String, _config: &CpsConfig, req: &LevelRequirements) {
    doc.push_str("## 4. Certificate Life-Cycle Operational Requirements\n\n");

    doc.push_str("### 4.1 Certificate Application\n\n");
    doc.push_str("Certificate requests SHALL be submitted via one of the following protocols:\n\n");
    doc.push_str("- ACME (RFC 8555)\n");
    doc.push_str("- EST (RFC 7030)\n");
    doc.push_str("- SCEP (RFC 8894)\n");
    doc.push_str("- CMP (RFC 9810)\n");
    doc.push_str("- Manual CSR submission\n\n");

    doc.push_str("### 4.2 Certificate Application Processing\n\n");
    doc.push_str(
        "The CA SHALL validate all certificate requests against the applicable \
                  issuance policy before signing.\n\n",
    );

    doc.push_str("### 4.3 Certificate Issuance\n\n");
    doc.push_str(&format!(
        "The CA signing key is protected at **{}** level",
        req.key_protection,
    ));
    if req.fips_algorithms_required {
        doc.push_str(" using FIPS-approved algorithms only");
    }
    doc.push_str(".\n\n");

    doc.push_str("### 4.4 Certificate Acceptance\n\n");
    doc.push_str("The subscriber SHALL verify the certificate contents before deploying it.\n\n");

    doc.push_str("### 4.5 Key Pair and Certificate Usage\n\n");
    doc.push_str(&format!(
        "- **Maximum CA certificate validity:** {} days ({:.0} years)\n",
        req.max_ca_validity_days,
        req.max_ca_validity_days as f64 / 365.25,
    ));
    doc.push_str(&format!(
        "- **Maximum end-entity certificate validity:** {} days\n\n",
        req.max_ee_validity_days,
    ));

    doc.push_str("### 4.6 Certificate Renewal\n\n");
    doc.push_str("Certificate renewal SHALL follow the same procedures as initial issuance.\n\n");

    doc.push_str("### 4.7 Certificate Re-key\n\n");
    doc.push_str(
        "Re-keying generates a new key pair and issues a new certificate. \
                  The previous certificate remains valid until its expiration or revocation.\n\n",
    );

    doc.push_str("### 4.8 Certificate Modification\n\n");
    doc.push_str(
        "Certificate modification is not supported. A new certificate SHALL be issued.\n\n",
    );

    doc.push_str("### 4.9 Certificate Revocation and Suspension\n\n");

    doc.push_str("#### 4.9.1 Circumstances for Revocation\n\n");
    doc.push_str("A certificate SHALL be revoked when:\n\n");
    doc.push_str("- The private key is compromised or suspected compromised\n");
    doc.push_str("- The subscriber's affiliation changes\n");
    doc.push_str("- The certificate was issued in error\n");
    doc.push_str("- The CA's private key is compromised\n\n");

    doc.push_str("#### 4.9.7 CRL Issuance Frequency\n\n");
    if req.automated_crl_required {
        doc.push_str(&format!(
            "CRLs SHALL be issued automatically at intervals not exceeding \
             **{} hours**.\n\n",
            req.max_crl_interval_hours,
        ));
    } else {
        doc.push_str(
            "CRLs SHALL be issued as needed. Automated CRL generation is recommended.\n\n",
        );
    }

    doc.push_str("#### 4.9.9 On-Line Revocation/Status Checking Availability\n\n");
    if req.ocsp_required {
        doc.push_str(
            "An OCSP responder SHALL be operated and available for real-time \
                     certificate status checking per RFC 6960.\n\n",
        );
    } else {
        doc.push_str(
            "OCSP is optional at this security level. CRL-based revocation \
                     checking is sufficient.\n\n",
        );
    }

    doc.push_str("### 4.10 Certificate Status Services\n\n");
    doc.push_str(
        "Certificate status is available via CRL distribution points and, \
                  where applicable, OCSP responders as specified in the AIA extension.\n\n",
    );

    doc.push_str("### 4.11 End of Subscription\n\n");
    doc.push_str(
        "Upon end of subscription, the subscriber SHALL cease using the certificate \
                  and its associated private key.\n\n",
    );

    doc.push_str("### 4.12 Key Escrow and Recovery\n\n");
    doc.push_str(
        "Key escrow is not performed for signing keys. Encryption key escrow \
                  may be offered as an optional service.\n\n",
    );
}

fn section_5_controls(doc: &mut String, config: &CpsConfig, req: &LevelRequirements) {
    doc.push_str("## 5. Facility, Management, and Operational Controls\n\n");

    doc.push_str("### 5.1 Physical Controls\n\n");
    match config.level {
        SecurityLevel::Level1 => {
            doc.push_str("Standard office security is acceptable at this level.\n\n");
        }
        SecurityLevel::Level2 => {
            doc.push_str("The CA system SHALL be housed in a controlled-access environment.\n\n");
        }
        SecurityLevel::Level3 | SecurityLevel::Level4 => {
            doc.push_str(
                "The CA system SHALL be housed in a physically secured facility \
                         with access controls, surveillance, and environmental protections.\n\n",
            );
        }
    }

    doc.push_str("### 5.2 Procedural Controls\n\n");

    doc.push_str("#### 5.2.1 Trusted Roles\n\n");
    doc.push_str("The following trusted roles are defined:\n\n");
    doc.push_str("- **SuperAdmin:** Full system access, key ceremony authority\n");
    doc.push_str("- **Admin:** Certificate management, policy configuration\n");
    doc.push_str("- **Operator:** Day-to-day operations, monitoring\n");
    doc.push_str("- **Viewer:** Read-only access to status and reports\n\n");

    if req.dual_control_required {
        doc.push_str("#### 5.2.2 Dual Control\n\n");
        doc.push_str(
            "**Dual control is REQUIRED** for all CA key operations. \
                     No single individual SHALL have the ability to activate \
                     the CA signing key unilaterally.\n\n",
        );
    }

    doc.push_str("### 5.3 Personnel Controls\n\n");
    doc.push_str(
        "*[Specify background check, training, and separation-of-duties requirements]*\n\n",
    );

    doc.push_str("### 5.4 Audit Logging Procedures\n\n");
    if req.crypto_audit_required {
        doc.push_str(
            "All cryptographic operations SHALL be logged in an audit trail. \
                     Audit records SHALL include:\n\n",
        );
        doc.push_str("- Timestamp\n");
        doc.push_str("- Operator identity\n");
        doc.push_str("- Operation type\n");
        doc.push_str("- Target certificate/key\n");
        doc.push_str("- Result (success/failure)\n\n");
        doc.push_str(
            "Audit logs SHALL be integrity-protected (hash-chained) and \
                     retained for a minimum of 7 years.\n\n",
        );
    } else {
        doc.push_str("Audit logging is recommended but not mandatory at this level.\n\n");
    }

    doc.push_str("### 5.5 Records Archival\n\n");
    doc.push_str(
        "The CA SHALL archive all issued certificates and revocation records \
                  for the lifetime of the CA plus 5 years.\n\n",
    );

    doc.push_str("### 5.6 Key Changeover\n\n");
    doc.push_str(
        "Key changeover SHALL be planned and executed before the CA signing key's \
                  originator usage period expires per NIST SP 800-57 Part 1.\n\n",
    );

    doc.push_str("### 5.7 Compromise and Disaster Recovery\n\n");
    doc.push_str(
        "*[Specify incident response, key compromise, and disaster recovery procedures]*\n\n",
    );

    doc.push_str("### 5.8 CA or RA Termination\n\n");
    doc.push_str("Upon termination, the CA SHALL:\n\n");
    doc.push_str("1. Revoke all outstanding certificates\n");
    doc.push_str("2. Publish a final CRL\n");
    doc.push_str("3. Securely destroy all CA private keys\n");
    doc.push_str("4. Archive all records per §5.5\n\n");
}

fn section_6_technical(doc: &mut String, config: &CpsConfig, req: &LevelRequirements) {
    doc.push_str("## 6. Technical Security Controls\n\n");

    doc.push_str("### 6.1 Key Pair Generation and Installation\n\n");

    doc.push_str("#### 6.1.1 Key Pair Generation\n\n");
    doc.push_str(&format!(
        "CA key pairs SHALL be generated using {} key storage ",
        match req.key_protection {
            KeyProtection::Software => "software",
            KeyProtection::Hardware => "FIPS 140-3 Level 2+ hardware (TPM or HSM)",
            KeyProtection::HardwareLevel3 => "FIPS 140-3 Level 3+ HSM",
        }
    ));
    if req.fips_algorithms_required {
        doc.push_str("with FIPS-approved algorithms only");
    }
    doc.push_str(".\n\n");

    doc.push_str("#### 6.1.2 Permitted Algorithms\n\n");
    let algos = config.level.permitted_algorithms();
    doc.push_str("| Algorithm | Minimum Key Size |\n");
    doc.push_str("|-----------|------------------|\n");
    for algo in &algos {
        let size = match algo.to_string().as_str() {
            s if s.contains("P-256") => "256 bits (128-bit security)",
            s if s.contains("P-384") => "384 bits (192-bit security)",
            s if s.contains("2048") => "2048 bits (112-bit security)",
            s if s.contains("3072") => "3072 bits (128-bit security)",
            s if s.contains("4096") => "4096 bits (152-bit security)",
            s if s.contains("ML-DSA") => "NIST PQC standard",
            s if s.contains("SLH-DSA") => "NIST PQC standard",
            _ => "See specification",
        };
        doc.push_str(&format!("| {} | {} |\n", algo, size));
    }
    doc.push('\n');

    doc.push_str(&format!(
        "- **Minimum RSA key size:** {} bits\n",
        req.min_rsa_bits,
    ));
    doc.push_str(&format!(
        "- **Minimum EC security:** {} bits\n\n",
        req.min_ec_security_bits,
    ));

    doc.push_str("#### 6.1.3 Key Protection\n\n");
    doc.push_str(&format!(
        "CA private keys SHALL be protected at **{}** level.\n\n",
        req.key_protection,
    ));
    if req.key_attestation_required {
        doc.push_str(
            "**Key attestation is REQUIRED.** The HSM SHALL provide cryptographic \
                     proof that the key was generated within the module boundary.\n\n",
        );
    }

    doc.push_str(
        "### 6.2 Private Key Protection and Cryptographic Module Engineering Controls\n\n",
    );
    doc.push_str(&format!(
        "The cryptographic module SHALL meet FIPS 140-3 Level {} requirements.\n\n",
        config.level.fips_module_level(),
    ));

    doc.push_str("### 6.3 Other Aspects of Key Pair Management\n\n");
    doc.push_str(
        "Key lifecycle management SHALL conform to NIST SP 800-57 Part 1. \
                  Key state transitions (Pre-Activation → Active → Deactivated → Destroyed) \
                  SHALL be tracked and enforced.\n\n",
    );

    doc.push_str("### 6.4 Activation Data\n\n");
    doc.push_str("*[Specify PIN/passphrase requirements for key activation]*\n\n");

    doc.push_str("### 6.5 Computer Security Controls\n\n");
    doc.push_str("The CA system SHALL implement:\n\n");
    doc.push_str("- Role-based access control\n");
    doc.push_str("- Separation of duties\n");
    doc.push_str("- Integrity verification of CA software\n");
    doc.push_str("- Secure configuration management\n\n");

    doc.push_str("### 6.6 Life Cycle Technical Controls\n\n");
    doc.push_str(
        "The CA system SHALL be maintained with current security patches. \
                  Changes to the CA system SHALL be tested before deployment.\n\n",
    );

    doc.push_str("### 6.7 Network Security Controls\n\n");
    doc.push_str(
        "The CA system SHALL be deployed on a segmented network. \
                  Administrative access SHALL require mTLS with admin certificates.\n\n",
    );

    doc.push_str("### 6.8 Time-Stamping\n\n");
    doc.push_str("The CA system clock SHALL be synchronized to a reliable time source.\n\n");
}

fn section_7_profiles(doc: &mut String, _config: &CpsConfig, req: &LevelRequirements) {
    doc.push_str("## 7. Certificate, CRL, and OCSP Profiles\n\n");

    doc.push_str("### 7.1 Certificate Profile\n\n");
    doc.push_str("Certificates SHALL conform to RFC 5280. All certificates SHALL include:\n\n");
    doc.push_str("- **Version:** v3 (2)\n");
    doc.push_str("- **Serial Number:** Cryptographically random, minimum 64 bits\n");
    doc.push_str("- **Signature Algorithm:** As permitted in §6.1.2\n");
    doc.push_str("- **Issuer:** CA Distinguished Name\n");
    doc.push_str(&format!(
        "- **Validity:** Not exceeding {} days (CA) or {} days (end-entity)\n",
        req.max_ca_validity_days, req.max_ee_validity_days,
    ));
    doc.push_str("- **Subject:** Per subscriber registration\n");
    doc.push_str("- **Subject Public Key Info:** Per subscriber's key pair\n\n");

    doc.push_str("#### 7.1.1 Required Extensions\n\n");
    doc.push_str("| Extension | Critical | Description |\n");
    doc.push_str("|-----------|----------|-------------|\n");
    doc.push_str("| Authority Key Identifier | No | SHA-256 of issuer public key |\n");
    doc.push_str("| Subject Key Identifier | No | SHA-256 of subject public key |\n");
    doc.push_str("| Key Usage | Yes | Per certificate type |\n");
    doc.push_str("| Basic Constraints | Yes (CA) | pathLenConstraint per hierarchy |\n");
    doc.push_str(&format!(
        "| Certificate Policies | No | OID: {} |\n",
        req.ogjos_policy_oid,
    ));
    doc.push_str("| CRL Distribution Points | No | HTTP URL for CRL |\n");
    doc.push_str("| Authority Information Access | No | OCSP + CA Issuer URLs |\n");
    doc.push_str("| Subject Alternative Name | No | DNS names, IPs, emails |\n\n");

    doc.push_str("### 7.2 CRL Profile\n\n");
    doc.push_str("CRLs SHALL conform to RFC 5280 §5. Each CRL SHALL include:\n\n");
    doc.push_str("- **Version:** v2 (1)\n");
    doc.push_str("- **Signature Algorithm:** Same as CA certificate\n");
    doc.push_str("- **thisUpdate / nextUpdate:** Per issuance schedule (§4.9.7)\n");
    doc.push_str("- **Authority Key Identifier:** Matching CA SKI\n\n");

    doc.push_str("### 7.3 OCSP Profile\n\n");
    if req.ocsp_required {
        doc.push_str("OCSP responses SHALL conform to RFC 6960. The OCSP responder SHALL:\n\n");
        doc.push_str("- Sign responses with a delegated OCSP signing key\n");
        doc.push_str("- Include the OCSP Signing EKU in the responder certificate\n");
        doc.push_str("- Support HTTP GET and POST methods\n\n");
    } else {
        doc.push_str("OCSP is not required at this security level.\n\n");
    }
}

fn section_8_audit(doc: &mut String, config: &CpsConfig, req: &LevelRequirements) {
    doc.push_str("## 8. Compliance Audit and Other Assessments\n\n");

    doc.push_str("### 8.1 Frequency or Circumstances of Assessment\n\n");
    match config.level {
        SecurityLevel::Level1 => {
            doc.push_str("Self-assessment is acceptable at this level.\n\n");
        }
        SecurityLevel::Level2 => {
            doc.push_str("Annual self-assessment with documented findings and remediation.\n\n");
        }
        SecurityLevel::Level3 => {
            doc.push_str(
                "Annual compliance assessment by qualified personnel. \
                         Independent audit every 3 years.\n\n",
            );
        }
        SecurityLevel::Level4 => {
            doc.push_str("Annual independent audit by a qualified third-party assessor.\n\n");
        }
    }

    doc.push_str("### 8.2 Identity/Qualifications of Assessor\n\n");
    doc.push_str("*[Specify assessor qualifications]*\n\n");

    doc.push_str("### 8.3 Assessor's Relationship to Assessed Entity\n\n");
    if config.level >= SecurityLevel::Level3 {
        doc.push_str("The assessor SHALL be independent of the CA operator.\n\n");
    } else {
        doc.push_str("Self-assessment is permitted at this level.\n\n");
    }

    doc.push_str("### 8.4 Topics Covered by Assessment\n\n");
    doc.push_str("The assessment SHALL cover all sections of this CP/CPS, including:\n\n");
    doc.push_str("- Physical and logical access controls\n");
    doc.push_str("- Key management procedures\n");
    doc.push_str("- Certificate lifecycle operations\n");
    doc.push_str("- Audit logging and monitoring\n");
    if req.fips_algorithms_required {
        doc.push_str("- FIPS 140-3 module validation status\n");
    }
    doc.push('\n');

    doc.push_str("### 8.5 Actions Taken as a Result of Deficiency\n\n");
    doc.push_str(
        "Deficiencies identified during assessment SHALL be documented and \
                  remediated within 90 days. Critical deficiencies SHALL require \
                  immediate corrective action.\n\n",
    );

    doc.push_str("### 8.6 Communication of Results\n\n");
    doc.push_str(
        "Assessment results SHALL be communicated to the CA policy authority \
                  and any cross-certified CAs.\n\n",
    );
}

fn section_9_legal(doc: &mut String, config: &CpsConfig) {
    doc.push_str("## 9. Other Business and Legal Matters\n\n");

    doc.push_str("### 9.1 Fees\n\n");
    doc.push_str("*[Specify any fee schedule for certificate services]*\n\n");

    doc.push_str("### 9.2 Financial Responsibility\n\n");
    doc.push_str("*[Specify insurance or financial responsibility requirements]*\n\n");

    doc.push_str("### 9.3 Confidentiality of Business Information\n\n");
    doc.push_str(
        "Private keys and activation data SHALL be treated as confidential. \
                  Audit logs SHALL be restricted to authorized personnel.\n\n",
    );

    doc.push_str("### 9.4 Privacy of Personal Information\n\n");
    doc.push_str(
        "Personal information collected during identity validation SHALL \
                  be protected in accordance with applicable privacy regulations.\n\n",
    );

    doc.push_str("### 9.5 Intellectual Property Rights\n\n");
    doc.push_str("*[Specify IP rights related to certificates and this document]*\n\n");

    doc.push_str("### 9.6 Representations and Warranties\n\n");
    doc.push_str("*[Specify CA, subscriber, and relying party warranties]*\n\n");

    doc.push_str("### 9.7 Disclaimers of Warranties\n\n");
    doc.push_str("*[Specify any disclaimers]*\n\n");

    doc.push_str("### 9.8 Limitations of Liability\n\n");
    doc.push_str("*[Specify liability limitations]*\n\n");

    doc.push_str("### 9.9 Indemnities\n\n");
    doc.push_str("*[Specify indemnification terms]*\n\n");

    doc.push_str("### 9.10 Term and Termination\n\n");
    doc.push_str(
        "This CP/CPS is effective upon publication and remains in effect \
                  until superseded or the CA is terminated.\n\n",
    );

    doc.push_str("### 9.11 Individual Notices and Communications with Participants\n\n");
    doc.push_str("*[Specify communication procedures]*\n\n");

    doc.push_str("### 9.12 Amendments\n\n");
    doc.push_str(
        "Amendments to this CP/CPS SHALL be published with a new version number. \
                  Material changes SHALL be communicated to all subscribers.\n\n",
    );

    doc.push_str("### 9.13 Dispute Resolution Provisions\n\n");
    doc.push_str("*[Specify dispute resolution procedures]*\n\n");

    doc.push_str("### 9.14 Governing Law\n\n");
    doc.push_str("*[Specify governing jurisdiction]*\n\n");

    doc.push_str("### 9.15 Compliance with Applicable Law\n\n");
    doc.push_str(
        "Operations under this CP/CPS SHALL comply with all applicable laws \
                  and regulations.\n\n",
    );

    doc.push_str("### 9.16 Miscellaneous Provisions\n\n");
    doc.push_str("*[Entire agreement, severability, survival clauses]*\n\n");

    doc.push_str("---\n\n");
    doc.push_str(&format!(
        "*Generated by SPORK CA for {} — {}. This document is a \
         skeleton and requires review, customization, and legal approval before use.*\n",
        config.org_name,
        config.level.name(),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_cps_level1() {
        let config = CpsConfig::new(SecurityLevel::Level1, "Test Org", "Test CA");
        let doc = generate_cps(&config);
        assert!(doc.contains("Certificate Policy / Certification Practice Statement"));
        assert!(doc.contains("Test Org"));
        assert!(doc.contains("Test CA"));
        assert!(doc.contains("Level 1"));
        assert!(doc.contains("## 1. Introduction"));
        assert!(doc.contains("## 9. Other Business and Legal Matters"));
    }

    #[test]
    fn test_generate_cps_level2_fips_required() {
        let config = CpsConfig::new(SecurityLevel::Level2, "Acme Corp", "Acme CA");
        let doc = generate_cps(&config);
        assert!(doc.contains("FIPS-approved algorithms only"));
        assert!(doc.contains("OCSP responder SHALL be operated"));
        assert!(doc.contains("automatically"));
    }

    #[test]
    fn test_generate_cps_level3_hardware() {
        let config = CpsConfig::new(SecurityLevel::Level3, "Gov Agency", "Gov CA");
        let doc = generate_cps(&config);
        assert!(doc.contains("FIPS 140-3 Level 2+ hardware"));
        assert!(doc.contains("physically secured facility"));
    }

    #[test]
    fn test_generate_cps_level4_dual_control() {
        let config = CpsConfig::new(SecurityLevel::Level4, "Fed Agency", "Fed CA");
        let doc = generate_cps(&config);
        assert!(doc.contains("Dual control is REQUIRED"));
        assert!(doc.contains("Key attestation is REQUIRED"));
        assert!(doc.contains("FIPS 140-3 Level 3+ HSM"));
        assert!(doc.contains("Annual independent audit"));
    }

    #[test]
    fn test_generate_cps_contains_all_sections() {
        let config = CpsConfig::new(SecurityLevel::Level2, "Org", "CA");
        let doc = generate_cps(&config);
        for section in 1..=9 {
            assert!(
                doc.contains(&format!("## {}.", section)),
                "Missing section {}",
                section
            );
        }
    }

    #[test]
    fn test_generate_cps_contains_policy_oid() {
        let config = CpsConfig::new(SecurityLevel::Level3, "Org", "CA");
        let doc = generate_cps(&config);
        let req = LevelRequirements::for_level(SecurityLevel::Level3);
        assert!(doc.contains(&req.ogjos_policy_oid));
        assert!(doc.contains(&req.fpki_policy_oid));
    }

    #[test]
    fn test_generate_cps_algorithm_table() {
        let config = CpsConfig::new(SecurityLevel::Level4, "Org", "CA");
        let doc = generate_cps(&config);
        assert!(doc.contains("| Algorithm | Minimum Key Size |"));
        assert!(doc.contains("P-384"));
    }

    #[test]
    fn test_cps_config_with_version() {
        let config = CpsConfig::new(SecurityLevel::Level2, "Org", "CA").with_version("2.1");
        let doc = generate_cps(&config);
        assert!(doc.contains("**Version:** 2.1"));
    }

    #[test]
    fn test_cps_config_default_version() {
        let config = CpsConfig::new(SecurityLevel::Level1, "Org", "CA");
        assert_eq!(config.version, "1.0");
    }
}
