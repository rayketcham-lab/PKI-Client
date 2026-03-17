//! NIST SP 800-57 Part 1 key lifecycle management and cryptoperiod enforcement
//!
//! Implements key state tracking per SP 800-57 Section 8.2 and cryptoperiod
//! policies per Section 5.3. Integrates with the FIPS module to enforce
//! algorithm deprecation schedules from SP 800-131A Rev 2.
//!
//! ## Key States (SP 800-57 Section 8.2)
//!
//! ```text
//! PreActivation -> Active -> Deactivated -> Destroyed
//!                    |   \       |
//!                    v    v      v
//!                Suspended  Compromised -> Destroyed
//!                    |   \
//!                    v    v
//!                 Active  Deactivated/Compromised
//! ```
//!
//! ## Cryptoperiod Policies
//!
//! Each algorithm/use-case combination has two periods:
//! - **Originator usage period**: How long the key may create new signatures
//! - **Recipient usage period**: How long existing signatures remain valid

use chrono::{DateTime, Datelike, Duration, Utc};

use crate::algo::AlgorithmId;
use crate::error::{Error, Result};

/// Key states per NIST SP 800-57 Part 1 Section 8.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum KeyState {
    /// Key has been generated but is not yet authorized for use
    PreActivation,
    /// Key is available for cryptographic operations
    Active,
    /// Key is temporarily unavailable (administrative hold)
    Suspended,
    /// Key is no longer used for applying protection but may still be used
    /// for processing (e.g., verifying existing signatures)
    Deactivated,
    /// Key's integrity or confidentiality is suspect or known compromised
    Compromised,
    /// Key material has been destroyed and is no longer available
    Destroyed,
}

impl std::fmt::Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PreActivation => write!(f, "Pre-Activation"),
            Self::Active => write!(f, "Active"),
            Self::Suspended => write!(f, "Suspended"),
            Self::Deactivated => write!(f, "Deactivated"),
            Self::Compromised => write!(f, "Compromised"),
            Self::Destroyed => write!(f, "Destroyed"),
        }
    }
}

impl KeyState {
    /// Returns the set of states this state can transition to (SP 800-57 Section 8.2)
    pub fn allowed_transitions(&self) -> &'static [KeyState] {
        match self {
            Self::PreActivation => &[Self::Active],
            Self::Active => &[Self::Suspended, Self::Deactivated, Self::Compromised],
            Self::Suspended => &[Self::Active, Self::Deactivated, Self::Compromised],
            Self::Deactivated => &[Self::Compromised, Self::Destroyed],
            Self::Compromised => &[Self::Destroyed],
            Self::Destroyed => &[],
        }
    }

    /// Check whether transitioning to `target` is allowed
    pub fn can_transition_to(&self, target: KeyState) -> bool {
        self.allowed_transitions().contains(&target)
    }
}

/// Cryptoperiod policy defining how long a key may be used
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CryptoperiodPolicy {
    /// How long the key can create new signatures/encryptions
    pub originator_usage_period: Duration,
    /// How long existing signatures/encryptions remain valid for verification
    pub recipient_usage_period: Duration,
}

impl CryptoperiodPolicy {
    /// Create a new policy with the given durations
    pub fn new(originator_usage_period: Duration, recipient_usage_period: Duration) -> Self {
        Self {
            originator_usage_period,
            recipient_usage_period,
        }
    }
}

/// Key usage context for selecting the appropriate default cryptoperiod
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsage {
    /// Root CA signing key
    RootCa,
    /// Intermediate/subordinate CA signing key
    IntermediateCa,
    /// TLS server authentication
    TlsServer,
    /// Code signing
    CodeSigning,
    /// OCSP responder signing
    OcspResponder,
}

/// Returns the default cryptoperiod policy for a given algorithm and usage context.
///
/// Values are based on NIST SP 800-57 Part 1 Table 1 recommendations,
/// adjusted for CA-specific use cases.
pub fn default_policy(algorithm: &AlgorithmId, usage: KeyUsage) -> CryptoperiodPolicy {
    match usage {
        KeyUsage::RootCa => match algorithm {
            AlgorithmId::EcdsaP384 => CryptoperiodPolicy::new(
                Duration::days(365 * 20), // 20 years originator
                Duration::days(365 * 30), // 30 years recipient
            ),
            AlgorithmId::EcdsaP256 => {
                CryptoperiodPolicy::new(Duration::days(365 * 15), Duration::days(365 * 25))
            }
            AlgorithmId::Rsa4096 | AlgorithmId::Rsa4096Pss => {
                CryptoperiodPolicy::new(Duration::days(365 * 20), Duration::days(365 * 30))
            }
            AlgorithmId::Rsa3072 | AlgorithmId::Rsa3072Pss => {
                CryptoperiodPolicy::new(Duration::days(365 * 15), Duration::days(365 * 25))
            }
            #[cfg(feature = "pqc")]
            AlgorithmId::MlDsa44 | AlgorithmId::MlDsa65 | AlgorithmId::MlDsa87 => {
                CryptoperiodPolicy::new(
                    Duration::days(365 * 5),  // conservative for PQC
                    Duration::days(365 * 10), // conservative for PQC
                )
            }
            _ => CryptoperiodPolicy::new(Duration::days(365 * 10), Duration::days(365 * 20)),
        },
        KeyUsage::IntermediateCa => match algorithm {
            AlgorithmId::EcdsaP256 => {
                CryptoperiodPolicy::new(Duration::days(365 * 7), Duration::days(365 * 15))
            }
            AlgorithmId::EcdsaP384 => {
                CryptoperiodPolicy::new(Duration::days(365 * 10), Duration::days(365 * 20))
            }
            AlgorithmId::Rsa3072
            | AlgorithmId::Rsa4096
            | AlgorithmId::Rsa3072Pss
            | AlgorithmId::Rsa4096Pss => {
                CryptoperiodPolicy::new(Duration::days(365 * 7), Duration::days(365 * 15))
            }
            #[cfg(feature = "pqc")]
            AlgorithmId::MlDsa44 | AlgorithmId::MlDsa65 | AlgorithmId::MlDsa87 => {
                CryptoperiodPolicy::new(Duration::days(365 * 5), Duration::days(365 * 10))
            }
            _ => CryptoperiodPolicy::new(Duration::days(365 * 5), Duration::days(365 * 10)),
        },
        KeyUsage::TlsServer => CryptoperiodPolicy::new(
            Duration::days(365),     // 1 year originator
            Duration::days(365 * 2), // 2 years recipient
        ),
        KeyUsage::CodeSigning => CryptoperiodPolicy::new(
            Duration::days(365 * 3),  // 3 years originator
            Duration::days(365 * 10), // 10 years recipient
        ),
        KeyUsage::OcspResponder => CryptoperiodPolicy::new(
            Duration::days(365 * 3), // 3 years originator
            Duration::days(365 * 5), // 5 years recipient
        ),
    }
}

/// A recorded key state transition for SP 800-57 §8.2 audit trail.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyStateTransition {
    /// Previous state
    pub from_state: KeyState,
    /// New state after transition
    pub to_state: KeyState,
    /// When the transition occurred
    pub timestamp: DateTime<Utc>,
    /// Why the transition was made (e.g., "scheduled_rotation", "compromise_detected")
    pub reason: String,
    /// Who initiated the transition (operator name, system process, etc.)
    pub actor: Option<String>,
    /// Reference to authorization evidence (ticket ID, ceremony log, etc.)
    pub evidence_ref: Option<String>,
}

/// Tracks the lifecycle of a single cryptographic key
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyLifecycleTracker {
    algorithm: AlgorithmId,
    state: KeyState,
    activation_time: DateTime<Utc>,
    policy: CryptoperiodPolicy,
    /// When the key entered its current state
    state_changed_at: DateTime<Utc>,
    /// When the key was deactivated (if applicable)
    deactivation_time: Option<DateTime<Utc>>,
    /// When the key was compromised (if applicable)
    compromise_time: Option<DateTime<Utc>>,
    /// Full audit trail of state transitions (SP 800-57 §8.2)
    #[serde(default)]
    transition_history: Vec<KeyStateTransition>,
}

impl KeyLifecycleTracker {
    /// Create a new tracker starting in PreActivation state
    pub fn new(
        algorithm: AlgorithmId,
        activation_time: DateTime<Utc>,
        policy: CryptoperiodPolicy,
    ) -> Self {
        Self {
            algorithm,
            state: KeyState::PreActivation,
            activation_time,
            policy,
            state_changed_at: Utc::now(),
            deactivation_time: None,
            compromise_time: None,
            transition_history: Vec::new(),
        }
    }

    /// Create a new tracker with default policy for the given usage context
    pub fn with_default_policy(
        algorithm: AlgorithmId,
        activation_time: DateTime<Utc>,
        usage: KeyUsage,
    ) -> Self {
        let policy = default_policy(&algorithm, usage);
        Self::new(algorithm, activation_time, policy)
    }

    /// Current key state
    pub fn state(&self) -> KeyState {
        self.state
    }

    /// Algorithm this key uses
    pub fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }

    /// The configured cryptoperiod policy
    pub fn policy(&self) -> &CryptoperiodPolicy {
        &self.policy
    }

    /// When the key was (or will be) activated
    pub fn activation_time(&self) -> DateTime<Utc> {
        self.activation_time
    }

    /// Transition the key to a new state, validating per SP 800-57 rules
    pub fn transition(&mut self, new_state: KeyState) -> Result<()> {
        if !self.state.can_transition_to(new_state) {
            return Err(Error::PolicyViolation(format!(
                "Invalid key state transition: {} -> {} (allowed: {:?})",
                self.state,
                new_state,
                self.state.allowed_transitions()
            )));
        }

        let now = Utc::now();

        if new_state == KeyState::Deactivated {
            self.deactivation_time = Some(now);
        }
        if new_state == KeyState::Compromised {
            self.compromise_time = Some(now);
        }

        self.state = new_state;
        self.state_changed_at = now;
        Ok(())
    }

    /// Transition the key to a new state with a recorded reason and actor.
    ///
    /// Per SP 800-57 §8.2, all key state transitions should be recorded
    /// with justification and attribution for the audit trail.
    pub fn transition_with_reason(
        &mut self,
        new_state: KeyState,
        reason: &str,
        actor: Option<&str>,
        evidence_ref: Option<&str>,
    ) -> Result<()> {
        if !self.state.can_transition_to(new_state) {
            return Err(Error::PolicyViolation(format!(
                "Invalid key state transition: {} -> {} (allowed: {:?})",
                self.state,
                new_state,
                self.state.allowed_transitions()
            )));
        }

        let now = Utc::now();

        // Record the transition in the audit trail
        self.transition_history.push(KeyStateTransition {
            from_state: self.state,
            to_state: new_state,
            timestamp: now,
            reason: reason.to_string(),
            actor: actor.map(|s| s.to_string()),
            evidence_ref: evidence_ref.map(|s| s.to_string()),
        });

        if new_state == KeyState::Deactivated {
            self.deactivation_time = Some(now);
        }
        if new_state == KeyState::Compromised {
            self.compromise_time = Some(now);
        }

        self.state = new_state;
        self.state_changed_at = now;
        Ok(())
    }

    /// Return the full audit trail of state transitions.
    pub fn transition_history(&self) -> &[KeyStateTransition] {
        &self.transition_history
    }

    /// Verify that the audit trail is internally consistent.
    ///
    /// Checks that each recorded transition follows valid SP 800-57 state
    /// machine rules and that from_state matches the previous to_state.
    pub fn verify_audit_trail(&self) -> bool {
        let mut current = KeyState::PreActivation;
        for event in &self.transition_history {
            if event.from_state != current {
                return false;
            }
            if !event.from_state.can_transition_to(event.to_state) {
                return false;
            }
            current = event.to_state;
        }
        current == self.state
    }

    /// Time remaining in the originator usage period from now.
    /// Returns None if the key is not Active or the period has expired.
    pub fn time_remaining(&self) -> Option<Duration> {
        if self.state != KeyState::Active {
            return None;
        }
        let expiry = self.activation_time + self.policy.originator_usage_period;
        let remaining = expiry - Utc::now();
        if remaining <= Duration::zero() {
            None
        } else {
            Some(remaining)
        }
    }

    /// Number of days remaining until the originator cryptoperiod expires.
    ///
    /// Returns `None` if the key is not Active or the period has already expired.
    /// SP 800-57 Pt.1 §5.3: keys nearing end of cryptoperiod should be flagged
    /// for rotation planning.
    pub fn days_until_expiry(&self) -> Option<i64> {
        self.time_remaining().map(|d| d.num_days())
    }

    /// Whether the key is within its originator usage cryptoperiod
    pub fn is_within_cryptoperiod(&self) -> bool {
        if self.state != KeyState::Active {
            return false;
        }
        let now = Utc::now();
        now >= self.activation_time
            && now < self.activation_time + self.policy.originator_usage_period
    }

    /// Whether existing signatures from this key are still within the recipient usage period
    pub fn is_within_recipient_period(&self) -> bool {
        let now = Utc::now();
        now < self.activation_time + self.policy.recipient_usage_period
    }
}

/// Validate that a certificate's validity period does not exceed the key's cryptoperiod.
///
/// Per SP 800-57, a certificate's notAfter MUST NOT extend beyond the key's
/// recipient usage period. This catches configurations where a certificate
/// would outlive the key it was signed with.
pub fn validate_cert_validity(
    key_activation: DateTime<Utc>,
    cert_not_after: DateTime<Utc>,
    policy: &CryptoperiodPolicy,
) -> Result<()> {
    let recipient_end = key_activation + policy.recipient_usage_period;

    if cert_not_after > recipient_end {
        let overshoot = cert_not_after - recipient_end;
        return Err(Error::PolicyViolation(format!(
            "Certificate validity (notAfter) exceeds key recipient usage period by {} days; \
             key activated at {}, recipient period ends at {}, cert expires at {}",
            overshoot.num_days(),
            key_activation.format("%Y-%m-%d"),
            recipient_end.format("%Y-%m-%d"),
            cert_not_after.format("%Y-%m-%d"),
        )));
    }

    // Warn-level: cert outlives originator period (key can't sign new certs but existing ones valid)
    let originator_end = key_activation + policy.originator_usage_period;
    if cert_not_after > originator_end {
        // This is acceptable per SP 800-57 (recipient period exists for this reason)
        // but worth noting in audit logs. We return Ok here.
    }

    Ok(())
}

/// Enforce that a signing key is within its cryptoperiod at certificate issuance time.
///
/// Per SP 800-57 Pt.1 §5.3, keys MUST NOT be used to apply protection
/// (create signatures) after their originator usage period expires. This
/// function should be called during certificate issuance to gate signing.
///
/// Unlike `is_within_cryptoperiod()` which returns bool, this returns a
/// descriptive error suitable for audit logging and user-facing messages.
pub fn enforce_cryptoperiod_at_signing(tracker: &KeyLifecycleTracker) -> Result<()> {
    if tracker.state() != KeyState::Active {
        return Err(Error::PolicyViolation(format!(
            "Key is in state '{}'; only Active keys may sign certificates (SP 800-57 §8.2)",
            tracker.state()
        )));
    }

    let now = Utc::now();
    let activation = tracker.activation_time();
    let expiry = activation + tracker.policy().originator_usage_period;

    if now < activation {
        return Err(Error::PolicyViolation(format!(
            "Key not yet activated; activation time is {} (SP 800-57 §8.2)",
            activation.format("%Y-%m-%d %H:%M:%S UTC")
        )));
    }

    if now >= expiry {
        let days_past = (now - expiry).num_days();
        return Err(Error::PolicyViolation(format!(
            "Key originator cryptoperiod expired {} days ago on {} (SP 800-57 §5.3); \
             key activated {}, {} algorithm, {}-day originator period",
            days_past,
            expiry.format("%Y-%m-%d"),
            activation.format("%Y-%m-%d"),
            tracker.algorithm(),
            tracker.policy().originator_usage_period.num_days()
        )));
    }

    Ok(())
}

/// Validate algorithm strength at runtime using the current year.
///
/// Convenience wrapper around `validate_algorithm_strength` that uses the
/// current calendar year as the target. Call this during CSR processing and
/// certificate issuance to enforce SP 800-131A Rev 2 deprecation schedule
/// at runtime, not just build time.
pub fn validate_algorithm_strength_runtime(algorithm: &AlgorithmId) -> Result<()> {
    let current_year = Utc::now().date_naive().year_ce().1;
    validate_algorithm_strength(algorithm, current_year)
}

/// Key protection level for destruction policy validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProtection {
    /// Key stored in software (file, database, memory)
    Software,
    /// Key stored in hardware security module
    Hardware,
    /// Key stored in TPM 2.0
    Tpm,
}

impl std::fmt::Display for KeyProtection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Software => write!(f, "Software"),
            Self::Hardware => write!(f, "Hardware (HSM)"),
            Self::Tpm => write!(f, "TPM 2.0"),
        }
    }
}

/// Key destruction method per SP 800-152 §6.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDestructionMethod {
    /// Cryptographic erasure (overwrite key material with random data)
    Zeroize,
    /// Physical destruction of the storage medium
    Physical,
    /// Vendor-specific secure erase command (HSM/TPM)
    VendorSecureErase,
}

impl std::fmt::Display for KeyDestructionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Zeroize => write!(f, "Cryptographic erasure (zeroize)"),
            Self::Physical => write!(f, "Physical destruction"),
            Self::VendorSecureErase => write!(f, "Vendor secure erase"),
        }
    }
}

/// Key destruction policy per SP 800-152 §6.7 and FIPS 140-3 AS.10.
#[derive(Debug, Clone)]
pub struct KeyDestructionPolicy {
    /// How the key material will be/was destroyed
    pub method: KeyDestructionMethod,
    /// Whether destruction was verified (e.g., read-back check, attestation)
    pub verified: bool,
    /// Timestamp of destruction (required for audit trail)
    pub timestamp: Option<DateTime<Utc>>,
}

/// A finding from destruction policy validation.
#[derive(Debug, Clone)]
pub struct DestructionFinding {
    pub code: &'static str,
    pub pass: bool,
    pub description: String,
    pub reference: &'static str,
}

/// Validate a key destruction policy for a given protection level.
///
/// Per SP 800-152 §6.7, key destruction requirements vary based on key protection:
/// - Software keys: zeroize is sufficient
/// - Hardware keys: vendor secure erase or physical destruction required
/// - All: destruction must be timestamped for audit
/// - All: verification is required for hardware protection
pub fn validate_destruction_policy(
    protection: KeyProtection,
    policy: &KeyDestructionPolicy,
) -> Vec<DestructionFinding> {
    let mut findings = Vec::new();

    // KD-001: Destruction method is appropriate for key protection level
    let method_ok = match protection {
        KeyProtection::Software => true, // Any method works for software keys
        KeyProtection::Hardware | KeyProtection::Tpm => {
            // Hardware keys need vendor erase or physical destruction
            matches!(
                policy.method,
                KeyDestructionMethod::VendorSecureErase | KeyDestructionMethod::Physical
            )
        }
    };
    findings.push(DestructionFinding {
        code: "KD-001",
        pass: method_ok,
        description: if method_ok {
            format!(
                "Destruction method '{}' is appropriate for {} key protection",
                policy.method, protection
            )
        } else {
            format!(
                "Destruction method '{}' is NOT appropriate for {} key protection; \
                 hardware keys require vendor secure erase or physical destruction",
                policy.method, protection
            )
        },
        reference: "SP 800-152 §6.7; FIPS 140-3 AS.10",
    });

    // KD-002: Destruction timestamp exists (audit trail)
    let has_timestamp = policy.timestamp.is_some();
    findings.push(DestructionFinding {
        code: "KD-002",
        pass: has_timestamp,
        description: if has_timestamp {
            format!(
                "Destruction timestamp recorded: {}",
                policy.timestamp.unwrap().format("%Y-%m-%d %H:%M:%S UTC")
            )
        } else {
            "Missing destruction timestamp — required for audit trail".to_string()
        },
        reference: "SP 800-152 §6.7; SP 800-57 Pt.2 §6.7",
    });

    // KD-003: Verification for hardware keys
    let verification_ok = match protection {
        KeyProtection::Hardware | KeyProtection::Tpm => policy.verified,
        KeyProtection::Software => true, // Verification optional for software
    };
    findings.push(DestructionFinding {
        code: "KD-003",
        pass: verification_ok,
        description: if verification_ok {
            format!(
                "Destruction verification {} for {} protection",
                if policy.verified {
                    "confirmed"
                } else {
                    "not required"
                },
                protection
            )
        } else {
            format!(
                "Destruction verification REQUIRED for {} keys but not confirmed",
                protection
            )
        },
        reference: "FIPS 140-3 AS.10.02",
    });

    findings
}

/// Maximum recommended certificate validity period per SP 800-57 Pt.1 Table 1.
///
/// Returns the maximum validity in days for a given key usage role.
/// These are recommendations, not hard limits — but exceeding them should
/// generate a warning.
pub fn max_validity_days_for_role(usage: KeyUsage) -> u32 {
    match usage {
        // Root CAs: up to 25 years
        KeyUsage::RootCa => 365 * 25,
        // Intermediate CAs: up to 10 years
        KeyUsage::IntermediateCa => 365 * 10,
        // TLS server: 1 year (browser requirement, stricter than SP 800-57)
        KeyUsage::TlsServer => 398, // CA/Browser Forum max
        // Code signing: 3 years
        KeyUsage::CodeSigning => 365 * 3,
        // OCSP responder: 3 years
        KeyUsage::OcspResponder => 365 * 3,
    }
}

/// Validate a certificate's requested validity period against SP 800-57 recommendations.
///
/// Checks that the certificate's validity does not exceed the maximum
/// recommended period for its intended role. Also validates that the
/// certificate would not outlive the issuing key's originator cryptoperiod.
///
/// Returns a list of findings (pass/fail with descriptions).
pub fn validate_cert_validity_for_role(
    validity_days: u32,
    role: KeyUsage,
    issuer_tracker: Option<&KeyLifecycleTracker>,
) -> Vec<DestructionFinding> {
    let mut findings = Vec::new();

    // CV-001: Validity period within SP 800-57 recommendation
    let max_days = max_validity_days_for_role(role);
    let within_max = validity_days <= max_days;
    findings.push(DestructionFinding {
        code: "CV-001",
        pass: within_max,
        description: if within_max {
            format!(
                "Certificate validity {} days is within {}-day maximum for {:?} role",
                validity_days, max_days, role
            )
        } else {
            format!(
                "Certificate validity {} days exceeds {}-day maximum for {:?} role \
                 (SP 800-57 Pt.1 Table 1)",
                validity_days, max_days, role
            )
        },
        reference: "SP 800-57 Pt.1 Rev 5 §5.3 Table 1",
    });

    // CV-002: Certificate would not outlive issuer's originator cryptoperiod
    if let Some(tracker) = issuer_tracker {
        let issuer_remaining = tracker.days_until_expiry().unwrap_or(0);
        let outlives_issuer = (validity_days as i64) > issuer_remaining;
        findings.push(DestructionFinding {
            code: "CV-002",
            pass: !outlives_issuer,
            description: if outlives_issuer {
                format!(
                    "Certificate validity {} days would outlive issuer key's remaining \
                     originator period ({} days); reduce validity or rotate issuer key",
                    validity_days, issuer_remaining
                )
            } else {
                format!(
                    "Certificate validity {} days is within issuer key's remaining \
                     originator period ({} days)",
                    validity_days, issuer_remaining
                )
            },
            reference: "SP 800-57 Pt.1 §5.3",
        });
    }

    findings
}

/// Validate algorithm strength against SP 800-131A Rev 2 deprecation schedule.
///
/// Checks whether the given algorithm provides adequate security strength
/// for the target year. Per SP 800-131A Rev 2:
/// - RSA-2048 / 112-bit: disallowed for signing after 2030
/// - RSA < 2048: already disallowed
/// - ECDSA P-256 / 128-bit: acceptable through 2030+
/// - ECDSA P-384 / 192-bit: acceptable indefinitely
pub fn validate_algorithm_strength(algorithm: &AlgorithmId, target_year: u32) -> Result<()> {
    match algorithm {
        AlgorithmId::Rsa2048 if target_year > 2030 => Err(Error::PolicyViolation(format!(
            "RSA-2048 (112-bit security) is disallowed for new signatures after 2030 \
                 per SP 800-131A Rev 2; target year is {}",
            target_year
        ))),
        // RSA-3072+ provides 128-bit security, acceptable through foreseeable future
        AlgorithmId::Rsa3072 | AlgorithmId::Rsa3072Pss => Ok(()),
        AlgorithmId::Rsa4096 | AlgorithmId::Rsa4096Pss => Ok(()),
        // ECDSA P-256 provides 128-bit security
        AlgorithmId::EcdsaP256 => Ok(()),
        // ECDSA P-384 provides 192-bit security
        AlgorithmId::EcdsaP384 => Ok(()),
        // RSA-2048 before 2031 is still allowed (matched by the guard above)
        AlgorithmId::Rsa2048 => Ok(()),
        // Ed25519 provides ~128-bit security (comparable to P-256)
        AlgorithmId::Ed25519 => Ok(()),
        // PQC algorithms are future-proof by design
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa44
        | AlgorithmId::MlDsa65
        | AlgorithmId::MlDsa87
        | AlgorithmId::SlhDsaSha2_128s
        | AlgorithmId::SlhDsaSha2_192s
        | AlgorithmId::SlhDsaSha2_256s
        | AlgorithmId::MlDsa44EcdsaP256
        | AlgorithmId::MlDsa65EcdsaP256
        | AlgorithmId::MlDsa65EcdsaP384
        | AlgorithmId::MlDsa87EcdsaP384 => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- KeyState transition tests ----

    #[test]
    fn test_preactivation_to_active() {
        let state = KeyState::PreActivation;
        assert!(state.can_transition_to(KeyState::Active));
    }

    #[test]
    fn test_preactivation_invalid_transitions() {
        let state = KeyState::PreActivation;
        assert!(!state.can_transition_to(KeyState::Suspended));
        assert!(!state.can_transition_to(KeyState::Deactivated));
        assert!(!state.can_transition_to(KeyState::Compromised));
        assert!(!state.can_transition_to(KeyState::Destroyed));
    }

    #[test]
    fn test_active_valid_transitions() {
        let state = KeyState::Active;
        assert!(state.can_transition_to(KeyState::Suspended));
        assert!(state.can_transition_to(KeyState::Deactivated));
        assert!(state.can_transition_to(KeyState::Compromised));
    }

    #[test]
    fn test_active_invalid_transitions() {
        let state = KeyState::Active;
        assert!(!state.can_transition_to(KeyState::PreActivation));
        assert!(!state.can_transition_to(KeyState::Destroyed));
    }

    #[test]
    fn test_suspended_valid_transitions() {
        let state = KeyState::Suspended;
        assert!(state.can_transition_to(KeyState::Active));
        assert!(state.can_transition_to(KeyState::Deactivated));
        assert!(state.can_transition_to(KeyState::Compromised));
    }

    #[test]
    fn test_suspended_invalid_transitions() {
        let state = KeyState::Suspended;
        assert!(!state.can_transition_to(KeyState::PreActivation));
        assert!(!state.can_transition_to(KeyState::Destroyed));
    }

    #[test]
    fn test_deactivated_valid_transitions() {
        let state = KeyState::Deactivated;
        assert!(state.can_transition_to(KeyState::Compromised));
        assert!(state.can_transition_to(KeyState::Destroyed));
    }

    #[test]
    fn test_deactivated_invalid_transitions() {
        let state = KeyState::Deactivated;
        assert!(!state.can_transition_to(KeyState::PreActivation));
        assert!(!state.can_transition_to(KeyState::Active));
        assert!(!state.can_transition_to(KeyState::Suspended));
    }

    #[test]
    fn test_compromised_to_destroyed() {
        let state = KeyState::Compromised;
        assert!(state.can_transition_to(KeyState::Destroyed));
    }

    #[test]
    fn test_compromised_invalid_transitions() {
        let state = KeyState::Compromised;
        assert!(!state.can_transition_to(KeyState::PreActivation));
        assert!(!state.can_transition_to(KeyState::Active));
        assert!(!state.can_transition_to(KeyState::Suspended));
        assert!(!state.can_transition_to(KeyState::Deactivated));
    }

    #[test]
    fn test_destroyed_no_transitions() {
        let state = KeyState::Destroyed;
        assert!(state.allowed_transitions().is_empty());
        assert!(!state.can_transition_to(KeyState::PreActivation));
        assert!(!state.can_transition_to(KeyState::Active));
    }

    #[test]
    fn test_state_display() {
        assert_eq!(KeyState::PreActivation.to_string(), "Pre-Activation");
        assert_eq!(KeyState::Active.to_string(), "Active");
        assert_eq!(KeyState::Suspended.to_string(), "Suspended");
        assert_eq!(KeyState::Deactivated.to_string(), "Deactivated");
        assert_eq!(KeyState::Compromised.to_string(), "Compromised");
        assert_eq!(KeyState::Destroyed.to_string(), "Destroyed");
    }

    // ---- KeyLifecycleTracker tests ----

    #[test]
    fn test_tracker_starts_preactivation() {
        let tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        assert_eq!(tracker.state(), KeyState::PreActivation);
    }

    #[test]
    fn test_tracker_activate() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        assert!(tracker.transition(KeyState::Active).is_ok());
        assert_eq!(tracker.state(), KeyState::Active);
    }

    #[test]
    fn test_tracker_invalid_transition() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        let result = tracker.transition(KeyState::Destroyed);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Invalid key state transition"));
    }

    #[test]
    fn test_tracker_full_lifecycle() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP384,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365 * 20), Duration::days(365 * 30)),
        );
        assert!(tracker.transition(KeyState::Active).is_ok());
        assert!(tracker.transition(KeyState::Deactivated).is_ok());
        assert!(tracker.transition(KeyState::Destroyed).is_ok());
        assert_eq!(tracker.state(), KeyState::Destroyed);
    }

    #[test]
    fn test_tracker_compromise_path() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        assert!(tracker.transition(KeyState::Active).is_ok());
        assert!(tracker.transition(KeyState::Compromised).is_ok());
        assert!(tracker.compromise_time.is_some());
        assert!(tracker.transition(KeyState::Destroyed).is_ok());
    }

    #[test]
    fn test_tracker_suspend_resume() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        assert!(tracker.transition(KeyState::Active).is_ok());
        assert!(tracker.transition(KeyState::Suspended).is_ok());
        assert!(tracker.transition(KeyState::Active).is_ok());
        assert_eq!(tracker.state(), KeyState::Active);
    }

    #[test]
    fn test_tracker_is_within_cryptoperiod_active() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now() - Duration::hours(1),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker.transition(KeyState::Active).unwrap();
        assert!(tracker.is_within_cryptoperiod());
    }

    #[test]
    fn test_tracker_is_within_cryptoperiod_expired() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now() - Duration::days(400),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker.transition(KeyState::Active).unwrap();
        assert!(!tracker.is_within_cryptoperiod());
    }

    #[test]
    fn test_tracker_is_within_cryptoperiod_not_active() {
        let tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        // Still in PreActivation
        assert!(!tracker.is_within_cryptoperiod());
    }

    #[test]
    fn test_tracker_time_remaining() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker.transition(KeyState::Active).unwrap();
        let remaining = tracker.time_remaining();
        assert!(remaining.is_some());
        // Should be approximately 365 days
        let days = remaining.unwrap().num_days();
        assert!((364..=365).contains(&days));
    }

    #[test]
    fn test_tracker_time_remaining_expired() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now() - Duration::days(400),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker.transition(KeyState::Active).unwrap();
        assert!(tracker.time_remaining().is_none());
    }

    #[test]
    fn test_tracker_time_remaining_not_active() {
        let tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        assert!(tracker.time_remaining().is_none());
    }

    #[test]
    fn test_tracker_recipient_period() {
        let tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now() - Duration::days(400),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        // Originator expired at 365 days, but recipient valid until 730 days
        assert!(tracker.is_within_recipient_period());
    }

    #[test]
    fn test_tracker_recipient_period_expired() {
        let tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now() - Duration::days(800),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        assert!(!tracker.is_within_recipient_period());
    }

    #[test]
    fn test_tracker_with_default_policy() {
        let tracker = KeyLifecycleTracker::with_default_policy(
            AlgorithmId::EcdsaP384,
            Utc::now(),
            KeyUsage::RootCa,
        );
        assert_eq!(
            tracker.policy().originator_usage_period.num_days(),
            365 * 20
        );
        assert_eq!(tracker.policy().recipient_usage_period.num_days(), 365 * 30);
    }

    #[test]
    fn test_tracker_deactivation_timestamp() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker.transition(KeyState::Active).unwrap();
        assert!(tracker.deactivation_time.is_none());
        tracker.transition(KeyState::Deactivated).unwrap();
        assert!(tracker.deactivation_time.is_some());
    }

    // ---- Default policy tests ----

    #[test]
    fn test_default_policy_root_p384() {
        let policy = default_policy(&AlgorithmId::EcdsaP384, KeyUsage::RootCa);
        assert_eq!(policy.originator_usage_period.num_days(), 365 * 20);
        assert_eq!(policy.recipient_usage_period.num_days(), 365 * 30);
    }

    #[test]
    fn test_default_policy_intermediate_p256() {
        let policy = default_policy(&AlgorithmId::EcdsaP256, KeyUsage::IntermediateCa);
        assert_eq!(policy.originator_usage_period.num_days(), 365 * 7);
        assert_eq!(policy.recipient_usage_period.num_days(), 365 * 15);
    }

    #[test]
    fn test_default_policy_tls_server() {
        let policy = default_policy(&AlgorithmId::EcdsaP256, KeyUsage::TlsServer);
        assert_eq!(policy.originator_usage_period.num_days(), 365);
        assert_eq!(policy.recipient_usage_period.num_days(), 365 * 2);
    }

    #[test]
    fn test_default_policy_code_signing() {
        let policy = default_policy(&AlgorithmId::EcdsaP256, KeyUsage::CodeSigning);
        assert_eq!(policy.originator_usage_period.num_days(), 365 * 3);
        assert_eq!(policy.recipient_usage_period.num_days(), 365 * 10);
    }

    #[test]
    fn test_default_policy_ocsp_responder() {
        let policy = default_policy(&AlgorithmId::EcdsaP256, KeyUsage::OcspResponder);
        assert_eq!(policy.originator_usage_period.num_days(), 365 * 3);
        assert_eq!(policy.recipient_usage_period.num_days(), 365 * 5);
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn test_default_policy_mldsa_root() {
        let policy = default_policy(&AlgorithmId::MlDsa65, KeyUsage::RootCa);
        assert_eq!(policy.originator_usage_period.num_days(), 365 * 5);
        assert_eq!(policy.recipient_usage_period.num_days(), 365 * 10);
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn test_default_policy_mldsa_intermediate() {
        let policy = default_policy(&AlgorithmId::MlDsa44, KeyUsage::IntermediateCa);
        assert_eq!(policy.originator_usage_period.num_days(), 365 * 5);
        assert_eq!(policy.recipient_usage_period.num_days(), 365 * 10);
    }

    // ---- Certificate validity validation tests ----

    #[test]
    fn test_validate_cert_validity_within_period() {
        let activation = Utc::now();
        let not_after = activation + Duration::days(365);
        let policy = CryptoperiodPolicy::new(Duration::days(365), Duration::days(730));
        assert!(validate_cert_validity(activation, not_after, &policy).is_ok());
    }

    #[test]
    fn test_validate_cert_validity_exceeds_recipient() {
        let activation = Utc::now();
        let not_after = activation + Duration::days(800); // exceeds 730-day recipient period
        let policy = CryptoperiodPolicy::new(Duration::days(365), Duration::days(730));
        let result = validate_cert_validity(activation, not_after, &policy);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("exceeds key recipient usage period"));
    }

    #[test]
    fn test_validate_cert_validity_at_recipient_boundary() {
        let activation = Utc::now();
        let not_after = activation + Duration::days(730); // exactly at boundary
        let policy = CryptoperiodPolicy::new(Duration::days(365), Duration::days(730));
        assert!(validate_cert_validity(activation, not_after, &policy).is_ok());
    }

    #[test]
    fn test_validate_cert_validity_between_originator_and_recipient() {
        let activation = Utc::now();
        let not_after = activation + Duration::days(500); // past 365 originator, within 730 recipient
        let policy = CryptoperiodPolicy::new(Duration::days(365), Duration::days(730));
        assert!(validate_cert_validity(activation, not_after, &policy).is_ok());
    }

    // ---- Algorithm strength validation tests ----

    #[test]
    fn test_validate_strength_rsa2048_before_2031() {
        assert!(validate_algorithm_strength(&AlgorithmId::Rsa2048, 2026).is_ok());
        assert!(validate_algorithm_strength(&AlgorithmId::Rsa2048, 2030).is_ok());
    }

    #[test]
    fn test_validate_strength_rsa2048_after_2030() {
        let result = validate_algorithm_strength(&AlgorithmId::Rsa2048, 2031);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("RSA-2048"));
        assert!(err_msg.contains("2031"));
    }

    #[test]
    fn test_validate_strength_rsa3072_future_proof() {
        assert!(validate_algorithm_strength(&AlgorithmId::Rsa3072, 2040).is_ok());
        assert!(validate_algorithm_strength(&AlgorithmId::Rsa3072Pss, 2040).is_ok());
    }

    #[test]
    fn test_validate_strength_rsa4096_future_proof() {
        assert!(validate_algorithm_strength(&AlgorithmId::Rsa4096, 2050).is_ok());
        assert!(validate_algorithm_strength(&AlgorithmId::Rsa4096Pss, 2050).is_ok());
    }

    #[test]
    fn test_validate_strength_ecdsa_future_proof() {
        assert!(validate_algorithm_strength(&AlgorithmId::EcdsaP256, 2040).is_ok());
        assert!(validate_algorithm_strength(&AlgorithmId::EcdsaP384, 2050).is_ok());
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn test_validate_strength_pqc_future_proof() {
        assert!(validate_algorithm_strength(&AlgorithmId::MlDsa44, 2050).is_ok());
        assert!(validate_algorithm_strength(&AlgorithmId::MlDsa65, 2050).is_ok());
        assert!(validate_algorithm_strength(&AlgorithmId::MlDsa87, 2050).is_ok());
    }

    // ---- Cryptoperiod enforcement tests (SP 800-57 §5.3) ----

    #[test]
    fn test_enforce_cryptoperiod_active_within_period() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now() - Duration::hours(1),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker.transition(KeyState::Active).unwrap();
        assert!(enforce_cryptoperiod_at_signing(&tracker).is_ok());
    }

    #[test]
    fn test_enforce_cryptoperiod_expired() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now() - Duration::days(400),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker.transition(KeyState::Active).unwrap();
        let result = enforce_cryptoperiod_at_signing(&tracker);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("cryptoperiod expired"));
    }

    #[test]
    fn test_enforce_cryptoperiod_not_yet_activated() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now() + Duration::days(10),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker.transition(KeyState::Active).unwrap();
        let result = enforce_cryptoperiod_at_signing(&tracker);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("not yet activated"));
    }

    #[test]
    fn test_enforce_cryptoperiod_wrong_state() {
        let tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        // Still in PreActivation
        let result = enforce_cryptoperiod_at_signing(&tracker);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("Pre-Activation"));
    }

    // ---- Key destruction policy tests (SP 800-152 §6.7) ----

    #[test]
    fn test_destruction_software_zeroize_ok() {
        let policy = KeyDestructionPolicy {
            method: KeyDestructionMethod::Zeroize,
            verified: false,
            timestamp: Some(Utc::now()),
        };
        let findings = validate_destruction_policy(KeyProtection::Software, &policy);
        assert!(findings.iter().all(|f| f.pass));
    }

    #[test]
    fn test_destruction_hardware_zeroize_rejected() {
        let policy = KeyDestructionPolicy {
            method: KeyDestructionMethod::Zeroize,
            verified: true,
            timestamp: Some(Utc::now()),
        };
        let findings = validate_destruction_policy(KeyProtection::Hardware, &policy);
        let kd001 = findings.iter().find(|f| f.code == "KD-001").unwrap();
        assert!(!kd001.pass);
    }

    #[test]
    fn test_destruction_hardware_vendor_erase_ok() {
        let policy = KeyDestructionPolicy {
            method: KeyDestructionMethod::VendorSecureErase,
            verified: true,
            timestamp: Some(Utc::now()),
        };
        let findings = validate_destruction_policy(KeyProtection::Hardware, &policy);
        assert!(findings.iter().all(|f| f.pass));
    }

    #[test]
    fn test_destruction_tpm_physical_ok() {
        let policy = KeyDestructionPolicy {
            method: KeyDestructionMethod::Physical,
            verified: true,
            timestamp: Some(Utc::now()),
        };
        let findings = validate_destruction_policy(KeyProtection::Tpm, &policy);
        assert!(findings.iter().all(|f| f.pass));
    }

    #[test]
    fn test_destruction_missing_timestamp() {
        let policy = KeyDestructionPolicy {
            method: KeyDestructionMethod::Zeroize,
            verified: false,
            timestamp: None,
        };
        let findings = validate_destruction_policy(KeyProtection::Software, &policy);
        let kd002 = findings.iter().find(|f| f.code == "KD-002").unwrap();
        assert!(!kd002.pass);
    }

    #[test]
    fn test_destruction_hardware_unverified() {
        let policy = KeyDestructionPolicy {
            method: KeyDestructionMethod::VendorSecureErase,
            verified: false,
            timestamp: Some(Utc::now()),
        };
        let findings = validate_destruction_policy(KeyProtection::Hardware, &policy);
        let kd003 = findings.iter().find(|f| f.code == "KD-003").unwrap();
        assert!(!kd003.pass);
    }

    #[test]
    fn test_destruction_software_unverified_ok() {
        // Verification is optional for software keys
        let policy = KeyDestructionPolicy {
            method: KeyDestructionMethod::Zeroize,
            verified: false,
            timestamp: Some(Utc::now()),
        };
        let findings = validate_destruction_policy(KeyProtection::Software, &policy);
        let kd003 = findings.iter().find(|f| f.code == "KD-003").unwrap();
        assert!(kd003.pass);
    }

    #[test]
    fn test_destruction_tpm_zeroize_rejected() {
        let policy = KeyDestructionPolicy {
            method: KeyDestructionMethod::Zeroize,
            verified: true,
            timestamp: Some(Utc::now()),
        };
        let findings = validate_destruction_policy(KeyProtection::Tpm, &policy);
        let kd001 = findings.iter().find(|f| f.code == "KD-001").unwrap();
        assert!(!kd001.pass);
    }

    // ---- Certificate validity per role tests (SP 800-57) ----

    #[test]
    fn test_max_validity_tls_server() {
        assert_eq!(max_validity_days_for_role(KeyUsage::TlsServer), 398);
    }

    #[test]
    fn test_max_validity_root_ca() {
        assert_eq!(max_validity_days_for_role(KeyUsage::RootCa), 365 * 25);
    }

    #[test]
    fn test_max_validity_intermediate_ca() {
        assert_eq!(
            max_validity_days_for_role(KeyUsage::IntermediateCa),
            365 * 10
        );
    }

    #[test]
    fn test_cert_validity_tls_within_limit() {
        let findings = validate_cert_validity_for_role(365, KeyUsage::TlsServer, None);
        assert!(findings.iter().all(|f| f.pass));
    }

    #[test]
    fn test_cert_validity_tls_exceeds_limit() {
        let findings = validate_cert_validity_for_role(730, KeyUsage::TlsServer, None);
        let cv001 = findings.iter().find(|f| f.code == "CV-001").unwrap();
        assert!(!cv001.pass);
    }

    #[test]
    fn test_cert_validity_root_ca_25yr() {
        let findings = validate_cert_validity_for_role(365 * 25, KeyUsage::RootCa, None);
        assert!(findings.iter().all(|f| f.pass));
    }

    #[test]
    fn test_cert_validity_root_ca_exceeds() {
        let findings = validate_cert_validity_for_role(365 * 26, KeyUsage::RootCa, None);
        let cv001 = findings.iter().find(|f| f.code == "CV-001").unwrap();
        assert!(!cv001.pass);
    }

    #[test]
    fn test_cert_validity_with_issuer_tracker() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365 * 7), Duration::days(365 * 15)),
        );
        tracker.transition(KeyState::Active).unwrap();

        // 365 days is within 7-year originator period
        let findings = validate_cert_validity_for_role(365, KeyUsage::TlsServer, Some(&tracker));
        assert!(findings.iter().all(|f| f.pass));
    }

    #[test]
    fn test_cert_validity_outlives_issuer() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now() - Duration::days(365 * 6), // 6 years into 7-year period
            CryptoperiodPolicy::new(Duration::days(365 * 7), Duration::days(365 * 15)),
        );
        tracker.transition(KeyState::Active).unwrap();

        // 730 days > remaining ~365 days of originator period
        let findings = validate_cert_validity_for_role(730, KeyUsage::TlsServer, Some(&tracker));
        let cv002 = findings.iter().find(|f| f.code == "CV-002").unwrap();
        assert!(!cv002.pass);
    }

    #[test]
    fn test_key_protection_display() {
        assert_eq!(KeyProtection::Software.to_string(), "Software");
        assert_eq!(KeyProtection::Hardware.to_string(), "Hardware (HSM)");
        assert_eq!(KeyProtection::Tpm.to_string(), "TPM 2.0");
    }

    #[test]
    fn test_destruction_method_display() {
        assert_eq!(
            KeyDestructionMethod::Zeroize.to_string(),
            "Cryptographic erasure (zeroize)"
        );
        assert_eq!(
            KeyDestructionMethod::Physical.to_string(),
            "Physical destruction"
        );
        assert_eq!(
            KeyDestructionMethod::VendorSecureErase.to_string(),
            "Vendor secure erase"
        );
    }

    #[test]
    fn test_validate_algorithm_strength_runtime() {
        // P-256 should pass for current year (2026)
        assert!(validate_algorithm_strength_runtime(&AlgorithmId::EcdsaP256).is_ok());
        assert!(validate_algorithm_strength_runtime(&AlgorithmId::EcdsaP384).is_ok());
        // RSA-2048 should pass for 2026
        assert!(validate_algorithm_strength_runtime(&AlgorithmId::Rsa2048).is_ok());
    }

    // ---- Key state transition audit trail tests (SP 800-57 §8.2) ----

    #[test]
    fn test_transition_with_reason_recorded() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker
            .transition_with_reason(
                KeyState::Active,
                "scheduled_activation",
                Some("admin@spork.local"),
                Some("CEREMONY-001"),
            )
            .unwrap();
        assert_eq!(tracker.state(), KeyState::Active);
        assert_eq!(tracker.transition_history().len(), 1);

        let event = &tracker.transition_history()[0];
        assert_eq!(event.from_state, KeyState::PreActivation);
        assert_eq!(event.to_state, KeyState::Active);
        assert_eq!(event.reason, "scheduled_activation");
        assert_eq!(event.actor.as_deref(), Some("admin@spork.local"));
        assert_eq!(event.evidence_ref.as_deref(), Some("CEREMONY-001"));
    }

    #[test]
    fn test_transition_with_reason_invalid_rejected() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        let result = tracker.transition_with_reason(KeyState::Destroyed, "invalid", None, None);
        assert!(result.is_err());
        assert!(tracker.transition_history().is_empty());
    }

    #[test]
    fn test_transition_with_reason_full_lifecycle() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP384,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365 * 20), Duration::days(365 * 30)),
        );
        tracker
            .transition_with_reason(
                KeyState::Active,
                "ceremony_complete",
                Some("operator1"),
                None,
            )
            .unwrap();
        tracker
            .transition_with_reason(
                KeyState::Deactivated,
                "cryptoperiod_expired",
                Some("scheduler"),
                None,
            )
            .unwrap();
        tracker
            .transition_with_reason(
                KeyState::Destroyed,
                "key_material_zeroized",
                Some("hsm_daemon"),
                Some("DESTRUCTION-042"),
            )
            .unwrap();

        assert_eq!(tracker.state(), KeyState::Destroyed);
        assert_eq!(tracker.transition_history().len(), 3);
        assert!(tracker.deactivation_time.is_some());
    }

    #[test]
    fn test_verify_audit_trail_valid() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker
            .transition_with_reason(KeyState::Active, "activation", None, None)
            .unwrap();
        tracker
            .transition_with_reason(KeyState::Suspended, "admin_hold", None, None)
            .unwrap();
        tracker
            .transition_with_reason(KeyState::Active, "admin_release", None, None)
            .unwrap();
        assert!(tracker.verify_audit_trail());
    }

    #[test]
    fn test_verify_audit_trail_empty() {
        let tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        assert!(tracker.verify_audit_trail());
    }

    #[test]
    fn test_verify_audit_trail_detects_tamper() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker
            .transition_with_reason(KeyState::Active, "activation", None, None)
            .unwrap();

        // Tamper with the audit trail — inject a fake transition
        tracker.transition_history.push(KeyStateTransition {
            from_state: KeyState::Destroyed, // Wrong: current is Active
            to_state: KeyState::PreActivation,
            timestamp: Utc::now(),
            reason: "tampered".to_string(),
            actor: None,
            evidence_ref: None,
        });

        assert!(!tracker.verify_audit_trail());
    }

    #[test]
    fn test_transition_with_reason_compromise() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker
            .transition_with_reason(KeyState::Active, "activation", None, None)
            .unwrap();
        tracker
            .transition_with_reason(
                KeyState::Compromised,
                "key_material_leaked",
                Some("secops"),
                Some("INCIDENT-2026-001"),
            )
            .unwrap();
        assert!(tracker.compromise_time.is_some());
        let event = &tracker.transition_history()[1];
        assert_eq!(event.reason, "key_material_leaked");
    }

    #[test]
    fn test_transition_history_timestamps_ordered() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker
            .transition_with_reason(KeyState::Active, "step1", None, None)
            .unwrap();
        tracker
            .transition_with_reason(KeyState::Deactivated, "step2", None, None)
            .unwrap();

        let history = tracker.transition_history();
        assert!(history[1].timestamp >= history[0].timestamp);
    }

    #[test]
    fn test_audit_trail_serde_roundtrip() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker
            .transition_with_reason(
                KeyState::Active,
                "test_activation",
                Some("test_actor"),
                Some("REF-001"),
            )
            .unwrap();

        let json = serde_json::to_string(&tracker).unwrap();
        let restored: KeyLifecycleTracker = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.transition_history().len(), 1);
        assert_eq!(restored.transition_history()[0].reason, "test_activation");
    }

    #[test]
    fn test_mixed_transition_methods() {
        // Old transition() and new transition_with_reason() can coexist
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        // Old method — no audit trail entry
        tracker.transition(KeyState::Active).unwrap();
        assert!(tracker.transition_history().is_empty());

        // New method — audit trail entry
        tracker
            .transition_with_reason(KeyState::Deactivated, "rotation", None, None)
            .unwrap();
        assert_eq!(tracker.transition_history().len(), 1);
    }

    // ---- Serde roundtrip test ----

    #[test]
    fn test_key_state_serde_roundtrip() {
        let states = [
            KeyState::PreActivation,
            KeyState::Active,
            KeyState::Suspended,
            KeyState::Deactivated,
            KeyState::Compromised,
            KeyState::Destroyed,
        ];
        for state in states {
            let json = serde_json::to_string(&state).unwrap();
            let restored: KeyState = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, state);
        }
    }

    #[test]
    fn test_policy_serde_roundtrip() {
        let policy = CryptoperiodPolicy::new(Duration::days(365), Duration::days(730));
        let json = serde_json::to_string(&policy).unwrap();
        let restored: CryptoperiodPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.originator_usage_period.num_days(),
            policy.originator_usage_period.num_days()
        );
    }

    // ---- FIPS interaction test ----

    #[test]
    fn test_fips_approved_algorithms_have_policies() {
        for algo in crate::fips::FIPS_APPROVED_ALGORITHMS {
            let policy = default_policy(algo, KeyUsage::IntermediateCa);
            assert!(
                policy.originator_usage_period.num_days() > 0,
                "FIPS-approved algorithm {:?} should have a positive originator period",
                algo
            );
            assert!(
                policy.recipient_usage_period > policy.originator_usage_period,
                "Recipient period should exceed originator period for {:?}",
                algo
            );
        }
    }

    #[test]
    fn test_algorithm_accessor() {
        let tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP384,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365 * 20), Duration::days(365 * 30)),
        );
        assert_eq!(tracker.algorithm(), AlgorithmId::EcdsaP384);
    }

    #[test]
    fn test_days_until_expiry_active() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now(),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker.transition(KeyState::Active).unwrap();
        let days = tracker.days_until_expiry();
        assert!(days.is_some());
        assert!((364..=365).contains(&days.unwrap()));
    }

    #[test]
    fn test_days_until_expiry_expired() {
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP256,
            Utc::now() - Duration::days(400),
            CryptoperiodPolicy::new(Duration::days(365), Duration::days(730)),
        );
        tracker.transition(KeyState::Active).unwrap();
        assert!(tracker.days_until_expiry().is_none());
    }
}
