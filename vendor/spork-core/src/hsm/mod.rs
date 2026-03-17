//! Hardware Security Module (HSM) Integration
//!
//! This module provides an abstraction layer for key storage backends,
//! supporting both software-based storage and hardware HSMs via PKCS#11.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │           KeyStore Trait                │
//! │  (generate, sign, verify, export)       │
//! └─────────────┬───────────────────────────┘
//!               │
//!     ┌─────────┼─────────┐
//!     ▼         ▼         ▼
//! ┌───────┐ ┌───────┐ ┌───────┐
//! │Software│ │ TPM2  │ │PKCS#11│
//! │(memory)│ │(chip) │ │ (HSM) │
//! └───────┘ └───────┘ └───────┘
//! ```
//!
//! # Example
//!
//! ```rust
//! use spork_core::hsm::{KeyStore, SoftwareKeyStore, KeySpec};
//!
//! let store = SoftwareKeyStore::new();
//! let key_id = store.generate_key("my-ca-key", KeySpec::EcdsaP256).unwrap();
//! let signature = store.sign(&key_id, b"data to sign").unwrap();
//! ```

mod software;
#[cfg(feature = "tpm")]
pub mod tpm;
mod traits;

pub use software::SoftwareKeyStore;
#[cfg(feature = "tpm")]
pub use tpm::TpmKeyStore;
pub use traits::{
    KeyAttestation, KeyId, KeySpec, KeyStore, KeyStoreError, KeyStoreResult, KeyUsage,
    StoredKeyInfo,
};
