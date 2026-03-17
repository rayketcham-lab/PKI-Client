//! In-Memory Certificate Store
//!
//! Thread-safe in-memory storage for testing and single-process deployments.

use std::collections::HashMap;
use std::sync::RwLock;

use super::{
    CaStateRecord, CertificateRecord, CertificateStore, RevocationReason, RevocationRecord,
};
use crate::error::{Error, Result};
use chrono::Utc;

/// Thread-safe in-memory certificate store
pub struct MemoryStore {
    certificates: RwLock<HashMap<String, CertificateRecord>>,
    revocations: RwLock<HashMap<String, RevocationRecord>>,
    ca_states: RwLock<HashMap<String, CaStateRecord>>,
}

impl MemoryStore {
    /// Create a new empty memory store
    pub fn new() -> Self {
        Self {
            certificates: RwLock::new(HashMap::new()),
            revocations: RwLock::new(HashMap::new()),
            ca_states: RwLock::new(HashMap::new()),
        }
    }

    /// Get number of stored certificates
    pub fn certificate_count(&self) -> usize {
        self.certificates
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Get number of revocations
    pub fn revocation_count(&self) -> usize {
        self.revocations
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Clear all data
    pub fn clear(&self) {
        self.certificates
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.revocations
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.ca_states
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificateStore for MemoryStore {
    fn store_certificate(&self, record: CertificateRecord) -> Result<()> {
        let mut certs = self.certificates.write().map_err(|_| {
            Error::Storage("Failed to acquire write lock on certificates".to_string())
        })?;

        if certs.contains_key(&record.serial) {
            return Err(Error::Storage(format!(
                "Certificate with serial {} already exists",
                record.serial
            )));
        }

        certs.insert(record.serial.clone(), record);
        Ok(())
    }

    fn get_certificate(&self, serial: &str) -> Result<Option<CertificateRecord>> {
        let certs = self.certificates.read().map_err(|_| {
            Error::Storage("Failed to acquire read lock on certificates".to_string())
        })?;

        Ok(certs.get(serial).cloned())
    }

    fn get_certificate_by_cn(&self, cn: &str) -> Result<Vec<CertificateRecord>> {
        let certs = self.certificates.read().map_err(|_| {
            Error::Storage("Failed to acquire read lock on certificates".to_string())
        })?;

        Ok(certs
            .values()
            .filter(|c| c.subject_cn == cn)
            .cloned()
            .collect())
    }

    fn list_certificates(&self) -> Result<Vec<CertificateRecord>> {
        let certs = self.certificates.read().map_err(|_| {
            Error::Storage("Failed to acquire read lock on certificates".to_string())
        })?;

        Ok(certs.values().cloned().collect())
    }

    fn revoke_certificate(&self, serial: &str, reason: RevocationReason) -> Result<()> {
        // Update certificate record
        {
            let mut certs = self.certificates.write().map_err(|_| {
                Error::Storage("Failed to acquire write lock on certificates".to_string())
            })?;

            if let Some(cert) = certs.get_mut(serial) {
                cert.revoked = true;
            } else {
                return Err(Error::Storage(format!(
                    "Certificate with serial {} not found",
                    serial
                )));
            }
        }

        // Create revocation record
        let cert = self
            .get_certificate(serial)?
            .expect("certificate exists — verified by status check above");
        let revocation = RevocationRecord {
            serial: serial.to_string(),
            reason,
            revoked_at: Utc::now(),
            invalidity_date: None,
            issuer_id: cert.issuer_id,
            revoked_by: None,
            comment: None,
        };

        let mut revocations = self.revocations.write().map_err(|_| {
            Error::Storage("Failed to acquire write lock on revocations".to_string())
        })?;

        revocations.insert(serial.to_string(), revocation);
        Ok(())
    }

    fn get_revocation(&self, serial: &str) -> Result<Option<RevocationRecord>> {
        let revocations = self.revocations.read().map_err(|_| {
            Error::Storage("Failed to acquire read lock on revocations".to_string())
        })?;

        Ok(revocations.get(serial).cloned())
    }

    fn list_revocations(&self) -> Result<Vec<RevocationRecord>> {
        let revocations = self.revocations.read().map_err(|_| {
            Error::Storage("Failed to acquire read lock on revocations".to_string())
        })?;

        Ok(revocations.values().cloned().collect())
    }

    fn store_ca_state(&self, state: CaStateRecord) -> Result<()> {
        let mut states = self
            .ca_states
            .write()
            .map_err(|_| Error::Storage("Failed to acquire write lock on CA states".to_string()))?;

        states.insert(state.ca_id.clone(), state);
        Ok(())
    }

    fn get_ca_state(&self, ca_id: &str) -> Result<Option<CaStateRecord>> {
        let states = self
            .ca_states
            .read()
            .map_err(|_| Error::Storage("Failed to acquire read lock on CA states".to_string()))?;

        Ok(states.get(ca_id).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algo::AlgorithmId;
    use crate::ca::{CaType, CertificateProfile};
    use chrono::Duration;

    fn make_test_ca_state(ca_id: &str) -> CaStateRecord {
        CaStateRecord {
            ca_id: ca_id.to_string(),
            ca_type: CaType::Root,
            common_name: format!("Test CA {}", ca_id),
            certificate_der_b64: String::new(),
            encrypted_private_key_b64: String::new(),
            key_nonce_b64: String::new(),
            algorithm: AlgorithmId::EcdsaP256,
            serial_counter: 1,
            parent_ca_id: None,
            created_at: Utc::now(),
            active: true,
            last_used_at: Utc::now(),
        }
    }

    fn make_test_cert(serial: &str) -> CertificateRecord {
        CertificateRecord {
            serial: serial.to_string(),
            subject_cn: format!("test-{}", serial),
            subject_dn: format!("CN=test-{}", serial),
            issuer_cn: "Test CA".to_string(),
            issuer_id: "ca-1".to_string(),
            certificate_der_b64: String::new(),
            algorithm: AlgorithmId::EcdsaP256,
            profile: CertificateProfile::TlsServer,
            not_before: Utc::now(),
            not_after: Utc::now() + Duration::days(365),
            created_at: Utc::now(),
            san_json: None,
            revoked: false,
            metadata: None,
        }
    }

    #[test]
    fn test_store_and_retrieve() {
        let store = MemoryStore::new();
        let cert = make_test_cert("01");

        store.store_certificate(cert.clone()).unwrap();

        let retrieved = store.get_certificate("01").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().serial, "01");
    }

    #[test]
    fn test_duplicate_serial_rejected() {
        let store = MemoryStore::new();
        let cert = make_test_cert("01");

        store.store_certificate(cert.clone()).unwrap();
        let result = store.store_certificate(cert);
        assert!(result.is_err());
    }

    #[test]
    fn test_revocation() {
        let store = MemoryStore::new();
        let cert = make_test_cert("01");

        store.store_certificate(cert).unwrap();
        store
            .revoke_certificate("01", RevocationReason::KeyCompromise)
            .unwrap();

        let cert = store.get_certificate("01").unwrap().unwrap();
        assert!(cert.revoked);

        let revocation = store.get_revocation("01").unwrap();
        assert!(revocation.is_some());
        assert_eq!(revocation.unwrap().reason, RevocationReason::KeyCompromise);
    }

    #[test]
    fn test_list_operations() {
        let store = MemoryStore::new();

        for i in 1..=5 {
            store
                .store_certificate(make_test_cert(&format!("{:02}", i)))
                .unwrap();
        }

        let certs = store.list_certificates().unwrap();
        assert_eq!(certs.len(), 5);
    }

    #[test]
    fn test_get_certificate_not_found() {
        let store = MemoryStore::new();
        let result = store.get_certificate("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_get_certificate_by_cn() {
        let store = MemoryStore::new();

        let mut cert1 = make_test_cert("01");
        cert1.subject_cn = "web.example.com".to_string();
        let mut cert2 = make_test_cert("02");
        cert2.subject_cn = "web.example.com".to_string();
        let mut cert3 = make_test_cert("03");
        cert3.subject_cn = "other.example.com".to_string();

        store.store_certificate(cert1).unwrap();
        store.store_certificate(cert2).unwrap();
        store.store_certificate(cert3).unwrap();

        let results = store.get_certificate_by_cn("web.example.com").unwrap();
        assert_eq!(results.len(), 2);

        let results = store.get_certificate_by_cn("other.example.com").unwrap();
        assert_eq!(results.len(), 1);

        let results = store.get_certificate_by_cn("missing.example.com").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_revoke_nonexistent_certificate() {
        let store = MemoryStore::new();
        let result = store.revoke_certificate("nonexistent", RevocationReason::Unspecified);
        assert!(result.is_err());
    }

    #[test]
    fn test_clear_all_data() {
        let store = MemoryStore::new();

        store.store_certificate(make_test_cert("01")).unwrap();
        store.store_certificate(make_test_cert("02")).unwrap();
        store
            .revoke_certificate("01", RevocationReason::Superseded)
            .unwrap();
        store.store_ca_state(make_test_ca_state("ca-1")).unwrap();

        assert_eq!(store.certificate_count(), 2);
        assert_eq!(store.revocation_count(), 1);

        store.clear();

        assert_eq!(store.certificate_count(), 0);
        assert_eq!(store.revocation_count(), 0);
    }

    #[test]
    fn test_certificate_and_revocation_counts() {
        let store = MemoryStore::new();
        assert_eq!(store.certificate_count(), 0);
        assert_eq!(store.revocation_count(), 0);

        store.store_certificate(make_test_cert("01")).unwrap();
        store.store_certificate(make_test_cert("02")).unwrap();
        store.store_certificate(make_test_cert("03")).unwrap();
        assert_eq!(store.certificate_count(), 3);

        store
            .revoke_certificate("01", RevocationReason::KeyCompromise)
            .unwrap();
        store
            .revoke_certificate("02", RevocationReason::CaCompromise)
            .unwrap();
        assert_eq!(store.revocation_count(), 2);
    }

    #[test]
    fn test_ca_state_store_and_retrieve() {
        let store = MemoryStore::new();

        let state = make_test_ca_state("root-ca");
        store.store_ca_state(state).unwrap();

        let retrieved = store.get_ca_state("root-ca").unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.ca_id, "root-ca");
        assert_eq!(retrieved.common_name, "Test CA root-ca");
        assert_eq!(retrieved.serial_counter, 1);

        // Non-existent CA state
        let missing = store.get_ca_state("nonexistent").unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_ca_state_overwrite() {
        let store = MemoryStore::new();

        let state1 = make_test_ca_state("ca-1");
        store.store_ca_state(state1).unwrap();

        let mut state2 = make_test_ca_state("ca-1");
        state2.serial_counter = 42;
        store.store_ca_state(state2).unwrap();

        let retrieved = store.get_ca_state("ca-1").unwrap().unwrap();
        assert_eq!(retrieved.serial_counter, 42);
    }

    #[test]
    fn test_default_impl() {
        let store = MemoryStore::default();
        assert_eq!(store.certificate_count(), 0);
        assert_eq!(store.revocation_count(), 0);
    }

    #[test]
    fn test_list_revocations() {
        let store = MemoryStore::new();

        store.store_certificate(make_test_cert("01")).unwrap();
        store.store_certificate(make_test_cert("02")).unwrap();
        store
            .revoke_certificate("01", RevocationReason::KeyCompromise)
            .unwrap();
        store
            .revoke_certificate("02", RevocationReason::Superseded)
            .unwrap();

        let revocations = store.list_revocations().unwrap();
        assert_eq!(revocations.len(), 2);
    }

    #[test]
    fn test_get_revocation_not_found() {
        let store = MemoryStore::new();
        let result = store.get_revocation("nonexistent").unwrap();
        assert!(result.is_none());
    }
}
