//! Certificate Authority Core Operations
//!
//! CA initialization, certificate issuance, and management

#[cfg(feature = "ceremony")]
mod ceremony;
mod issuer;
mod signer;

/// CA ceremony operations (key generation, root CA init, subordinate CSR).
///
/// Gated behind the `ceremony` feature flag. Network-facing crates like
/// `spork-api` MUST NOT enable this feature — CA creation is a local-only
/// ceremony operation, never exposed over a network API.
#[cfg(feature = "ceremony")]
pub use ceremony::{CaCeremony, CaConfig, InitializedCa, SubordinateCsr};

/// CA type is always available (needed for loading existing CAs)
#[cfg(feature = "ceremony")]
pub use ceremony::CaType;
#[cfg(not(feature = "ceremony"))]
mod ca_type {
    /// CA Type (available without ceremony feature for loading existing CAs)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub enum CaType {
        /// Root CA (self-signed)
        Root,
        /// Intermediate CA (signed by parent)
        Intermediate,
    }
}
#[cfg(not(feature = "ceremony"))]
pub use ca_type::CaType;

pub use issuer::{CertificateProfile, IssuanceRequest, IssuedCertificate};
pub use signer::Signer;

#[allow(unused_imports)]
use der::Encode;
use x509_cert::Certificate;

use crate::algo::{AlgorithmId, KeyPair};
use crate::cert::SerialNumber;
use crate::error::{Error, Result};

/// CA state
#[derive(Debug)]
pub struct CertificateAuthority {
    /// CA type (Root or Intermediate)
    pub ca_type: CaType,
    /// CA certificate
    pub certificate: Certificate,
    /// CA certificate DER
    pub certificate_der: Vec<u8>,
    /// CA certificate PEM
    pub certificate_pem: String,
    /// Subject key identifier
    pub subject_key_id: Vec<u8>,
    /// Signing backend (in-memory key or external key store)
    signer: Signer,
    /// Algorithm
    pub algorithm: AlgorithmId,
    /// Next serial number
    serial_counter: u64,
    /// CRL Distribution Point URL (included in issued certificates)
    pub cdp_url: Option<String>,
    /// Authority Information Access base URL (for OCSP and CA Issuer)
    pub aia_base_url: Option<String>,
}

impl CertificateAuthority {
    /// Load CA from stored components (creates an in-memory signer)
    pub fn load(
        ca_type: CaType,
        certificate_der: Vec<u8>,
        private_key_der: Vec<u8>,
        algorithm: AlgorithmId,
        serial_counter: u64,
    ) -> Result<Self> {
        use crate::cert::extensions::SubjectKeyIdentifier;
        use crate::cert::{encode_certificate_pem, parse_certificate_der};

        let certificate = parse_certificate_der(&certificate_der)?;
        let certificate_pem = encode_certificate_pem(&certificate)?;

        // Compute subject key identifier
        let spki_der = certificate
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| Error::Encoding(e.to_string()))?;
        let ski = SubjectKeyIdentifier::from_public_key(&spki_der);

        Ok(Self {
            ca_type,
            certificate,
            certificate_der,
            certificate_pem,
            subject_key_id: ski.0,
            signer: Signer::in_memory(private_key_der, algorithm),
            algorithm,
            serial_counter,
            cdp_url: None,
            aia_base_url: None,
        })
    }

    /// Load CA with an external signer (TPM, HSM, software keystore)
    pub fn load_with_signer(
        ca_type: CaType,
        certificate_der: Vec<u8>,
        signer: Signer,
        serial_counter: u64,
    ) -> Result<Self> {
        use crate::cert::extensions::SubjectKeyIdentifier;
        use crate::cert::{encode_certificate_pem, parse_certificate_der};

        let certificate = parse_certificate_der(&certificate_der)?;
        let certificate_pem = encode_certificate_pem(&certificate)?;

        let spki_der = certificate
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| Error::Encoding(e.to_string()))?;
        let ski = SubjectKeyIdentifier::from_public_key(&spki_der);

        let algorithm = signer.algorithm();

        Ok(Self {
            ca_type,
            certificate,
            certificate_der,
            certificate_pem,
            subject_key_id: ski.0,
            signer,
            algorithm,
            serial_counter,
            cdp_url: None,
            aia_base_url: None,
        })
    }

    /// Set CRL Distribution Point URL for issued certificates
    pub fn set_cdp_url(&mut self, url: impl Into<String>) {
        self.cdp_url = Some(url.into());
    }

    /// Set Authority Information Access base URL for issued certificates
    /// OCSP URL will be: {base_url}/ocsp
    /// CA Issuer URL will be: {base_url}/ca/{ca_name}.crt
    pub fn set_aia_base_url(&mut self, url: impl Into<String>) {
        self.aia_base_url = Some(url.into());
    }

    /// Get next serial number (random, unpredictable)
    /// Counter is incremented for tracking but not used in serial
    pub fn next_serial(&mut self) -> SerialNumber {
        self.serial_counter += 1;
        SerialNumber::random()
    }

    /// Get CA's key pair for signing
    ///
    /// For in-memory signers, returns the `KeyPair` directly.
    /// For external signers, returns an error — callers should use
    /// `signer()` and call `sign()` on it instead.
    pub fn signing_key(&self) -> Result<KeyPair> {
        self.signer.signing_key()
    }

    /// Get a reference to the CA's signer
    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    /// Get CA's distinguished name
    pub fn subject(&self) -> &x509_cert::name::Name {
        &self.certificate.tbs_certificate.subject
    }

    /// Export private key DER (for secure storage)
    ///
    /// Returns an error for CAs backed by an external signer.
    pub fn export_private_key_der(&self) -> Result<&[u8]> {
        self.signer.export_private_key_der()
    }

    /// Get current serial counter
    pub fn serial_counter(&self) -> u64 {
        self.serial_counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serial_generation() {
        // Test that serial numbers increment correctly
        let serial1 = SerialNumber::sequential(1);
        let serial2 = SerialNumber::sequential(2);
        assert_ne!(serial1.0, serial2.0);
    }

    #[test]
    #[cfg(feature = "ceremony")]
    fn test_load_creates_in_memory_signer() {
        use crate::ca::{CaCeremony, CaConfig};

        let config = CaConfig::root("Signer Test CA", AlgorithmId::EcdsaP256);
        let result = CaCeremony::init_root(config).unwrap();

        // signing_key() should work for in-memory signer
        let key = result.ca.signing_key();
        assert!(key.is_ok());

        // export should work for in-memory signer
        let exported = result.ca.export_private_key_der();
        assert!(exported.is_ok());
    }

    #[test]
    #[cfg(feature = "ceremony")]
    fn test_load_with_external_signer() {
        use crate::ca::{CaCeremony, CaConfig};
        use crate::hsm::{KeySpec, KeyStore, SoftwareKeyStore};
        use std::sync::Arc;

        // Create a CA to get a valid certificate
        let config = CaConfig::root("External Signer Test", AlgorithmId::EcdsaP256);
        let result = CaCeremony::init_root(config).unwrap();

        // Create an external signer
        let store = Arc::new(SoftwareKeyStore::new());
        let key_id = store.generate_key("ca-key", KeySpec::EcdsaP256).unwrap();
        let signer = Signer::external(store, key_id, AlgorithmId::EcdsaP256);

        // Load CA with external signer
        let ca =
            CertificateAuthority::load_with_signer(CaType::Root, result.certificate_der, signer, 0)
                .unwrap();

        // signing_key() should error for external signer
        assert!(ca.signing_key().is_err());

        // export should error for external signer
        assert!(ca.export_private_key_der().is_err());

        // But we can access the signer directly
        assert_eq!(ca.signer().algorithm(), AlgorithmId::EcdsaP256);
    }
}
