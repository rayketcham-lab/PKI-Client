//! Audit Log Module with Hash Chain Integrity
//!
//! This module provides tamper-evident audit logging with hash chain verification.
//! Each log entry includes a hash of the previous entry, creating an immutable chain.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
//! │  Entry 1    │───▶│  Entry 2    │───▶│  Entry 3    │
//! │  Hash: H1   │    │  Prev: H1   │    │  Prev: H2   │
//! │             │    │  Hash: H2   │    │  Hash: H3   │
//! └─────────────┘    └─────────────┘    └─────────────┘
//! ```
//!
//! # Security Properties
//!
//! - **Append-only**: Entries cannot be modified after creation
//! - **Tamper-evident**: Any modification breaks the hash chain
//! - **Verifiable**: Chain integrity can be verified at any time
//! - **Non-repudiable**: Entries can be signed for accountability

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::digest;

/// Audit log errors
#[derive(Error, Debug)]
pub enum AuditError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Hash chain verification failed
    #[error("Hash chain verification failed at entry {index}: expected {expected}, got {actual}")]
    HashChainBroken {
        index: u64,
        expected: String,
        actual: String,
    },

    /// Invalid log format
    #[error("Invalid log format: {0}")]
    InvalidFormat(String),

    /// Log is empty
    #[error("Log is empty")]
    EmptyLog,
}

/// Audit result type
pub type AuditResult<T> = Result<T, AuditError>;

/// Audit action types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // Certificate operations
    CertificateIssued,
    CertificateRevoked,
    CertificateRenewed,

    // CRL operations
    CrlGenerated,
    CrlPublished,

    // Key operations
    KeyGenerated,
    KeyImported,
    KeyDestroyed,
    KeyCeremonyStarted,
    KeyCeremonyCompleted,

    // CA operations
    CaCreated,
    CaConfigChanged,
    CaDisabled,
    CaEnabled,

    // Authentication
    AuthenticationSuccess,
    AuthenticationFailure,
    SessionCreated,
    SessionDestroyed,

    // System events
    SystemStartup,
    SystemShutdown,
    ConfigChanged,
    BackupCreated,
    BackupRestored,

    // Custom action
    Custom(String),
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Entry sequence number
    pub sequence: u64,

    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Action type
    pub action: AuditAction,

    /// Actor (user, service, or system)
    pub actor: String,

    /// Target resource (e.g., certificate serial, CA ID)
    pub target: Option<String>,

    /// Action result
    pub result: AuditResult_,

    /// Additional details
    pub details: serde_json::Value,

    /// Hash of previous entry (empty for first entry)
    pub previous_hash: String,

    /// Hash of this entry
    pub hash: String,

    /// Optional signature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Action result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditResult_ {
    Success,
    Failure,
    Partial,
}

impl AuditEntry {
    /// Create a new audit entry
    pub fn new(
        sequence: u64,
        action: AuditAction,
        actor: impl Into<String>,
        target: Option<String>,
        result: AuditResult_,
        details: serde_json::Value,
        previous_hash: String,
    ) -> Self {
        let mut entry = Self {
            sequence,
            timestamp: Utc::now(),
            action,
            actor: actor.into(),
            target,
            result,
            details,
            previous_hash,
            hash: String::new(),
            signature: None,
        };
        entry.hash = entry.calculate_hash();
        entry
    }

    /// Calculate the hash of this entry
    pub fn calculate_hash(&self) -> String {
        let mut hasher = digest::Sha256Hasher::new();

        // Hash all fields except 'hash' and 'signature'
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(format!("{:?}", self.action).as_bytes());
        hasher.update(self.actor.as_bytes());
        if let Some(ref target) = self.target {
            hasher.update(target.as_bytes());
        }
        hasher.update(format!("{:?}", self.result).as_bytes());
        hasher.update(self.details.to_string().as_bytes());
        hasher.update(self.previous_hash.as_bytes());

        hex::encode(hasher.finalize())
    }

    /// Verify the hash of this entry
    pub fn verify_hash(&self) -> bool {
        self.hash == self.calculate_hash()
    }
}

/// Audit logger with hash chain integrity
pub struct AuditLogger {
    /// Log file path
    log_path: PathBuf,

    /// Current sequence number
    sequence: Arc<RwLock<u64>>,

    /// Last entry hash
    last_hash: Arc<RwLock<String>>,

    /// File handle
    file: Arc<RwLock<File>>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(log_path: impl AsRef<Path>) -> AuditResult<Self> {
        let log_path = log_path.as_ref().to_path_buf();

        // Open or create log file
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&log_path)?;

        // Read existing entries to get sequence and last hash
        let (sequence, last_hash) = Self::read_last_entry(&log_path)?;

        Ok(Self {
            log_path,
            sequence: Arc::new(RwLock::new(sequence)),
            last_hash: Arc::new(RwLock::new(last_hash)),
            file: Arc::new(RwLock::new(file)),
        })
    }

    /// Read the last entry from the log file
    fn read_last_entry(path: &Path) -> AuditResult<(u64, String)> {
        if !path.exists() {
            return Ok((0, String::new()));
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut last_sequence = 0u64;
        let mut last_hash = String::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let entry: AuditEntry = serde_json::from_str(&line)?;
            last_sequence = entry.sequence;
            last_hash = entry.hash.clone();
        }

        Ok((last_sequence, last_hash))
    }

    /// Log an action
    pub fn log(
        &self,
        action: AuditAction,
        actor: impl Into<String>,
        target: Option<String>,
        result: AuditResult_,
        details: serde_json::Value,
    ) -> AuditResult<AuditEntry> {
        let mut sequence = self
            .sequence
            .write()
            .map_err(|_| AuditError::InvalidFormat("Lock poisoned".into()))?;
        let mut last_hash = self
            .last_hash
            .write()
            .map_err(|_| AuditError::InvalidFormat("Lock poisoned".into()))?;
        let mut file = self
            .file
            .write()
            .map_err(|_| AuditError::InvalidFormat("Lock poisoned".into()))?;

        *sequence += 1;
        let entry = AuditEntry::new(
            *sequence,
            action,
            actor,
            target,
            result,
            details,
            last_hash.clone(),
        );

        // Write entry
        let json = serde_json::to_string(&entry)?;
        writeln!(file, "{}", json)?;
        file.flush()?;

        // Update last hash
        *last_hash = entry.hash.clone();

        Ok(entry)
    }

    /// Log a success action
    pub fn log_success(
        &self,
        action: AuditAction,
        actor: impl Into<String>,
        target: Option<String>,
        details: serde_json::Value,
    ) -> AuditResult<AuditEntry> {
        self.log(action, actor, target, AuditResult_::Success, details)
    }

    /// Log a failure action
    pub fn log_failure(
        &self,
        action: AuditAction,
        actor: impl Into<String>,
        target: Option<String>,
        details: serde_json::Value,
    ) -> AuditResult<AuditEntry> {
        self.log(action, actor, target, AuditResult_::Failure, details)
    }

    /// Verify the integrity of the audit log
    pub fn verify_integrity(&self) -> AuditResult<VerificationResult> {
        let file = File::open(&self.log_path)?;
        let reader = BufReader::new(file);

        let mut entries_checked = 0u64;
        let mut previous_hash = String::new();

        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| AuditError::InvalidFormat(format!("Line {}: {}", line_num + 1, e)))?;

            // Verify hash chain
            if entry.previous_hash != previous_hash {
                return Err(AuditError::HashChainBroken {
                    index: entry.sequence,
                    expected: previous_hash,
                    actual: entry.previous_hash,
                });
            }

            // Verify entry hash
            if !entry.verify_hash() {
                return Err(AuditError::HashChainBroken {
                    index: entry.sequence,
                    expected: entry.hash.clone(),
                    actual: entry.calculate_hash(),
                });
            }

            previous_hash = entry.hash;
            entries_checked += 1;
        }

        Ok(VerificationResult {
            entries_checked,
            first_entry_time: None, // Could be enhanced to track this
            last_entry_time: None,
            is_valid: true,
        })
    }

    /// Export logs in a specific format
    pub fn export(&self, format: ExportFormat) -> AuditResult<Vec<u8>> {
        let file = File::open(&self.log_path)?;
        let reader = BufReader::new(file);

        let mut entries: Vec<AuditEntry> = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            entries.push(serde_json::from_str(&line)?);
        }

        match format {
            ExportFormat::Json => Ok(serde_json::to_vec_pretty(&entries)?),
            ExportFormat::JsonLines => {
                let mut output = Vec::new();
                for entry in entries {
                    output.extend_from_slice(serde_json::to_string(&entry)?.as_bytes());
                    output.push(b'\n');
                }
                Ok(output)
            }
            ExportFormat::Csv => {
                let mut output = String::new();
                output.push_str("sequence,timestamp,action,actor,target,result,hash\n");
                for entry in entries {
                    output.push_str(&format!(
                        "{},{},{:?},{},{},{:?},{}\n",
                        entry.sequence,
                        entry.timestamp.to_rfc3339(),
                        entry.action,
                        entry.actor,
                        entry.target.unwrap_or_default(),
                        entry.result,
                        entry.hash,
                    ));
                }
                Ok(output.into_bytes())
            }
        }
    }

    /// Get log file path
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }
}

/// Verification result
#[derive(Debug)]
pub struct VerificationResult {
    /// Number of entries checked
    pub entries_checked: u64,
    /// Timestamp of first entry
    pub first_entry_time: Option<DateTime<Utc>>,
    /// Timestamp of last entry
    pub last_entry_time: Option<DateTime<Utc>>,
    /// Whether the log is valid
    pub is_valid: bool,
}

/// Export format options
#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    /// Pretty-printed JSON array
    Json,
    /// JSON lines (one entry per line)
    JsonLines,
    /// CSV format
    Csv,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_audit_entry_hash() {
        let entry = AuditEntry::new(
            1,
            AuditAction::CertificateIssued,
            "admin",
            Some("cert-123".into()),
            AuditResult_::Success,
            serde_json::json!({"cn": "example.com"}),
            String::new(),
        );

        assert!(!entry.hash.is_empty());
        assert!(entry.verify_hash());
    }

    #[test]
    fn test_audit_logger_chain() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path()).unwrap();

        // Log several entries
        let entry1 = logger
            .log_success(
                AuditAction::SystemStartup,
                "system",
                None,
                serde_json::json!({}),
            )
            .unwrap();

        let entry2 = logger
            .log_success(
                AuditAction::CertificateIssued,
                "admin",
                Some("cert-123".into()),
                serde_json::json!({"cn": "example.com"}),
            )
            .unwrap();

        let entry3 = logger
            .log_success(
                AuditAction::CrlGenerated,
                "system",
                Some("ca-1".into()),
                serde_json::json!({"entries": 10}),
            )
            .unwrap();

        // Verify chain
        assert_eq!(entry1.previous_hash, "");
        assert_eq!(entry2.previous_hash, entry1.hash);
        assert_eq!(entry3.previous_hash, entry2.hash);

        // Verify integrity
        let result = logger.verify_integrity().unwrap();
        assert!(result.is_valid);
        assert_eq!(result.entries_checked, 3);
    }

    #[test]
    fn test_audit_export() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path()).unwrap();

        logger
            .log_success(
                AuditAction::CertificateIssued,
                "admin",
                Some("cert-123".into()),
                serde_json::json!({}),
            )
            .unwrap();

        // Export as JSON
        let json_export = logger.export(ExportFormat::Json).unwrap();
        assert!(!json_export.is_empty());

        // Export as CSV
        let csv_export = logger.export(ExportFormat::Csv).unwrap();
        let csv_str = String::from_utf8(csv_export).unwrap();
        assert!(csv_str.contains("sequence,timestamp,action"));
    }

    #[test]
    fn test_audit_action_serde_roundtrip() {
        let actions = vec![
            AuditAction::CertificateIssued,
            AuditAction::CertificateRevoked,
            AuditAction::CertificateRenewed,
            AuditAction::CrlGenerated,
            AuditAction::CrlPublished,
            AuditAction::KeyGenerated,
            AuditAction::KeyImported,
            AuditAction::KeyDestroyed,
            AuditAction::KeyCeremonyStarted,
            AuditAction::KeyCeremonyCompleted,
            AuditAction::CaCreated,
            AuditAction::CaConfigChanged,
            AuditAction::CaDisabled,
            AuditAction::CaEnabled,
            AuditAction::AuthenticationSuccess,
            AuditAction::AuthenticationFailure,
            AuditAction::SessionCreated,
            AuditAction::SessionDestroyed,
            AuditAction::SystemStartup,
            AuditAction::SystemShutdown,
            AuditAction::ConfigChanged,
            AuditAction::BackupCreated,
            AuditAction::BackupRestored,
            AuditAction::Custom("test_action".into()),
        ];
        for action in &actions {
            let json = serde_json::to_string(action).unwrap();
            let restored: AuditAction = serde_json::from_str(&json).unwrap();
            assert_eq!(&restored, action);
        }
        assert_eq!(actions.len(), 24);
    }

    #[test]
    fn test_audit_result_serde() {
        for result in [
            AuditResult_::Success,
            AuditResult_::Failure,
            AuditResult_::Partial,
        ] {
            let json = serde_json::to_string(&result).unwrap();
            let restored: AuditResult_ = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, result);
        }
        assert_eq!(
            serde_json::to_string(&AuditResult_::Success).unwrap(),
            "\"success\""
        );
        assert_eq!(
            serde_json::to_string(&AuditResult_::Failure).unwrap(),
            "\"failure\""
        );
        assert_eq!(
            serde_json::to_string(&AuditResult_::Partial).unwrap(),
            "\"partial\""
        );
    }

    #[test]
    fn test_audit_entry_hash_changes_with_modification() {
        let entry = AuditEntry::new(
            1,
            AuditAction::CaCreated,
            "admin",
            Some("ca-root".into()),
            AuditResult_::Success,
            serde_json::json!({"algo": "ecdsa-p256"}),
            String::new(),
        );
        let original_hash = entry.hash.clone();
        assert!(entry.verify_hash());

        // Changing a field should invalidate the hash
        let mut modified = entry.clone();
        modified.actor = "attacker".to_string();
        assert_ne!(modified.calculate_hash(), original_hash);
        assert!(!modified.verify_hash());
    }

    #[test]
    fn test_audit_action_custom_variant() {
        let action = AuditAction::Custom("my_custom_action".into());
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("my_custom_action"));
        let restored: AuditAction = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, action);
    }

    #[test]
    fn test_audit_logger_log_failure() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path()).unwrap();

        let entry = logger
            .log_failure(
                AuditAction::AuthenticationFailure,
                "unknown_user",
                None,
                serde_json::json!({"reason": "bad password"}),
            )
            .unwrap();

        assert_eq!(entry.result, AuditResult_::Failure);
        assert_eq!(entry.actor, "unknown_user");
        assert!(entry.target.is_none());
        assert!(entry.verify_hash());
    }

    #[test]
    fn test_audit_logger_empty_log_verify() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path()).unwrap();

        let result = logger.verify_integrity().unwrap();
        assert!(result.is_valid);
        assert_eq!(result.entries_checked, 0);
    }

    #[test]
    fn test_audit_export_json_lines() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path()).unwrap();

        logger
            .log_success(
                AuditAction::SystemStartup,
                "system",
                None,
                serde_json::json!({}),
            )
            .unwrap();
        logger
            .log_success(
                AuditAction::CertificateIssued,
                "admin",
                Some("cert-456".into()),
                serde_json::json!({}),
            )
            .unwrap();

        let jsonl = logger.export(ExportFormat::JsonLines).unwrap();
        let jsonl_str = String::from_utf8(jsonl).unwrap();
        let lines: Vec<&str> = jsonl_str.trim().split('\n').collect();
        assert_eq!(lines.len(), 2);
        // Each line should be valid JSON
        for line in &lines {
            let _: AuditEntry = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn test_audit_export_csv_columns() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path()).unwrap();

        logger
            .log_success(
                AuditAction::KeyGenerated,
                "admin",
                Some("key-001".into()),
                serde_json::json!({"algo": "ecdsa-p256"}),
            )
            .unwrap();

        let csv = logger.export(ExportFormat::Csv).unwrap();
        let csv_str = String::from_utf8(csv).unwrap();
        let lines: Vec<&str> = csv_str.trim().split('\n').collect();
        assert_eq!(lines.len(), 2); // header + 1 entry
        assert!(lines[0].starts_with("sequence,timestamp,action"));
        assert!(lines[1].contains("admin"));
        assert!(lines[1].contains("key-001"));
    }

    #[test]
    fn test_audit_entry_sequence_and_target() {
        let entry = AuditEntry::new(
            42,
            AuditAction::CrlPublished,
            "scheduler",
            None,
            AuditResult_::Success,
            serde_json::json!(null),
            "prev_hash_abc".to_string(),
        );
        assert_eq!(entry.sequence, 42);
        assert_eq!(entry.previous_hash, "prev_hash_abc");
        assert!(entry.target.is_none());
        assert!(entry.signature.is_none());
        assert!(!entry.hash.is_empty());
    }

    #[test]
    fn test_audit_action_serde_snake_case() {
        let json = serde_json::to_string(&AuditAction::CertificateIssued).unwrap();
        assert_eq!(json, "\"certificate_issued\"");
        let json = serde_json::to_string(&AuditAction::KeyCeremonyStarted).unwrap();
        assert_eq!(json, "\"key_ceremony_started\"");
        let json = serde_json::to_string(&AuditAction::BackupRestored).unwrap();
        assert_eq!(json, "\"backup_restored\"");
    }

    #[test]
    fn test_audit_logger_log_path() {
        let temp_file = NamedTempFile::new().unwrap();
        let expected_path = temp_file.path().to_path_buf();
        let logger = AuditLogger::new(temp_file.path()).unwrap();
        assert_eq!(logger.log_path(), expected_path);
    }
}
