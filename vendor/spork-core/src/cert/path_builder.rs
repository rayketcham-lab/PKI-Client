//! RFC 4158 Certification Path Building
//!
//! Implements forward path building from a target certificate toward a trust anchor.
//! Handles bridge PKI topologies where cross-certificates create a web of trust.
//!
//! RFC 4158 §2: The path building algorithm starts with the target certificate
//! and works forward toward a trust anchor, discovering candidate issuers at each step.

use der::{Decode, Encode};
use std::collections::{HashMap, HashSet};

use crate::digest;
use x509_cert::Certificate;

use crate::error::{Error, Result};

// OID arc constants for AKI and SKI
const OID_AKI: &[u32] = &[2, 5, 29, 35];
const OID_SKI: &[u32] = &[2, 5, 29, 14];

/// A local store of certificates used for path building.
///
/// Contains trust anchors (explicitly trusted roots) and a set of known
/// intermediates/cross-certificates indexed by their subject DN for fast lookup.
pub struct CertificateStore {
    /// Trust anchor certificates in DER encoding (self-signed roots).
    trust_anchors: Vec<Vec<u8>>,
    /// Known intermediates and cross-certs, indexed by raw subject Name bytes.
    /// Multiple certs can share the same subject DN (e.g. renewed CAs, cross-certs).
    intermediates: HashMap<Vec<u8>, Vec<Vec<u8>>>,
}

impl CertificateStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            trust_anchors: Vec::new(),
            intermediates: HashMap::new(),
        }
    }

    /// Add a trust anchor (DER-encoded). Trust anchors are always checked as
    /// potential issuers and mark the end of a valid path.
    pub fn add_trust_anchor(&mut self, cert_der: Vec<u8>) -> Result<()> {
        // Index trust anchors as intermediates too so they can be found as issuers
        let subject = extract_subject_dn(&cert_der)?;
        self.intermediates
            .entry(subject)
            .or_default()
            .push(cert_der.clone());
        self.trust_anchors.push(cert_der);
        Ok(())
    }

    /// Add an intermediate or cross-certificate (DER-encoded).
    pub fn add_intermediate(&mut self, cert_der: Vec<u8>) -> Result<()> {
        let subject = extract_subject_dn(&cert_der)?;
        self.intermediates
            .entry(subject)
            .or_default()
            .push(cert_der);
        Ok(())
    }

    /// Check whether a DER-encoded cert is a trust anchor.
    fn is_trust_anchor(&self, cert_der: &[u8]) -> bool {
        self.trust_anchors
            .iter()
            .any(|ta| ta.as_slice() == cert_der)
    }

    /// Find all candidate issuers for the given target cert.
    ///
    /// Matches on:
    /// 1. Subject DN == target's issuer DN (required)
    /// 2. SKI == target's AKI key ID (preferred, used to disambiguate)
    fn find_candidate_issuers(&self, target_der: &[u8]) -> Vec<Vec<u8>> {
        let issuer_dn = match extract_issuer_dn(target_der) {
            Ok(dn) => dn,
            Err(_) => return Vec::new(),
        };
        let target_aki = extract_aki_key_id(target_der);

        let candidates = match self.intermediates.get(&issuer_dn) {
            Some(certs) => certs.clone(),
            None => return Vec::new(),
        };

        if let Some(aki) = target_aki {
            // Prefer certs whose SKI matches the AKI
            let mut matched: Vec<Vec<u8>> = candidates
                .iter()
                .filter(|c| extract_ski(c).as_ref() == Some(&aki))
                .cloned()
                .collect();
            // Fall back to all DN-matched candidates if no SKI match found
            if matched.is_empty() {
                matched = candidates;
            }
            matched
        } else {
            candidates
        }
    }
}

impl Default for CertificateStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for path building.
#[derive(Debug, Clone)]
pub struct PathBuildConfig {
    /// Maximum chain length to attempt (including target and trust anchor).
    pub max_path_length: usize,
    /// Maximum number of candidate paths to explore before giving up.
    pub max_paths_to_try: usize,
    /// Timeout in milliseconds (0 = no timeout).
    pub timeout_ms: u64,
}

impl Default for PathBuildConfig {
    fn default() -> Self {
        Self {
            max_path_length: 10,
            max_paths_to_try: 25,
            timeout_ms: 5000,
        }
    }
}

/// An ordered certificate path from target to trust anchor.
#[derive(Debug, Clone)]
pub struct CertificatePath {
    /// Certificates in order: `[target, intermediate..., trust_anchor]`
    pub certificates: Vec<Vec<u8>>,
    /// Path length (number of certificates).
    pub length: usize,
}

/// Result of a path building operation.
#[derive(Debug, Clone)]
pub struct PathBuildResult {
    /// All valid paths found, sorted by length (shortest first).
    pub paths: Vec<CertificatePath>,
    /// Errors or informational messages accumulated during building.
    pub errors: Vec<String>,
}

impl PathBuildResult {
    /// Whether at least one valid path was found.
    pub fn success(&self) -> bool {
        !self.paths.is_empty()
    }
}

/// RFC 4158 forward path builder.
///
/// Builds certificate paths from a target certificate to a trust anchor by
/// searching a local store of known certificates.
pub struct PathBuilder {
    store: CertificateStore,
    config: PathBuildConfig,
}

impl PathBuilder {
    /// Create a new path builder with the given store and default config.
    pub fn new(store: CertificateStore) -> Self {
        Self {
            store,
            config: PathBuildConfig::default(),
        }
    }

    /// Create a new path builder with the given store and custom config.
    pub fn with_config(store: CertificateStore, config: PathBuildConfig) -> Self {
        Self { store, config }
    }

    /// Build all certification paths from `target_der` to a trust anchor.
    ///
    /// Returns all paths found, sorted shortest first. If no path reaches a
    /// trust anchor, the paths list will be empty and errors will describe
    /// why building failed.
    pub fn build_paths(&self, target_der: &[u8]) -> PathBuildResult {
        let mut all_paths = Vec::new();
        let mut errors = Vec::new();
        let mut paths_tried = 0usize;

        // Start time for timeout enforcement
        let start = std::time::Instant::now();

        // The initial chain is just the target cert
        let initial_chain = vec![target_der.to_vec()];
        // Visited set tracks fingerprints to prevent loops
        let mut visited = HashSet::new();
        visited.insert(cert_fingerprint(target_der));

        self.build_recursive(
            &initial_chain,
            &visited,
            &mut all_paths,
            &mut errors,
            &mut paths_tried,
            start,
        );

        // Sort paths by length (shortest first)
        all_paths.sort_by_key(|p| p.length);

        PathBuildResult {
            paths: all_paths,
            errors,
        }
    }

    /// Recursive inner function for path building.
    fn build_recursive(
        &self,
        current_chain: &[Vec<u8>],
        visited: &HashSet<[u8; 32]>,
        all_paths: &mut Vec<CertificatePath>,
        errors: &mut Vec<String>,
        paths_tried: &mut usize,
        start: std::time::Instant,
    ) {
        // Enforce limits
        if *paths_tried >= self.config.max_paths_to_try {
            errors.push(format!(
                "Path building limit reached ({} paths tried)",
                self.config.max_paths_to_try
            ));
            return;
        }
        if self.config.timeout_ms > 0
            && start.elapsed().as_millis() as u64 >= self.config.timeout_ms
        {
            errors.push("Path building timeout exceeded".to_string());
            return;
        }
        if current_chain.len() > self.config.max_path_length {
            errors.push(format!(
                "Max path length {} exceeded",
                self.config.max_path_length
            ));
            return;
        }

        let tip = current_chain.last().expect("chain is never empty");

        // If the current tip is a trust anchor, we found a complete path
        if self.store.is_trust_anchor(tip) {
            *paths_tried += 1;
            let path = CertificatePath {
                length: current_chain.len(),
                certificates: current_chain.to_vec(),
            };
            all_paths.push(path);
            return;
        }

        // Find candidate issuers for the current tip
        let candidates = self.store.find_candidate_issuers(tip);

        if candidates.is_empty() {
            errors
                .push("No issuers found for certificate with issuer DN matching store".to_string());
            return;
        }

        for candidate in candidates {
            let fp = cert_fingerprint(&candidate);

            // Loop detection: skip if we've already visited this cert
            if visited.contains(&fp) {
                errors.push("Loop detected in candidate chain — skipping".to_string());
                continue;
            }

            let mut next_chain = current_chain.to_vec();
            next_chain.push(candidate.clone());

            let mut next_visited = visited.clone();
            next_visited.insert(fp);

            self.build_recursive(
                &next_chain,
                &next_visited,
                all_paths,
                errors,
                paths_tried,
                start,
            );
        }
    }
}

// --------------------------------------------------------------------------
// Helper functions
// --------------------------------------------------------------------------

/// Extract the raw DER bytes of the Subject Name from a DER-encoded certificate.
pub fn extract_subject_dn(cert_der: &[u8]) -> Result<Vec<u8>> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::Decoding(format!("Subject DN: {}", e)))?;
    cert.tbs_certificate
        .subject
        .to_der()
        .map_err(|e| Error::Encoding(format!("Subject DN encode: {}", e)))
}

/// Extract the raw DER bytes of the Issuer Name from a DER-encoded certificate.
pub fn extract_issuer_dn(cert_der: &[u8]) -> Result<Vec<u8>> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::Decoding(format!("Issuer DN: {}", e)))?;
    cert.tbs_certificate
        .issuer
        .to_der()
        .map_err(|e| Error::Encoding(format!("Issuer DN encode: {}", e)))
}

/// Extract the SubjectKeyIdentifier value from a DER-encoded certificate.
///
/// Returns `None` if the extension is absent or malformed.
pub fn extract_ski(cert_der: &[u8]) -> Option<Vec<u8>> {
    let cert = Certificate::from_der(cert_der).ok()?;
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    for ext in extensions.iter() {
        let arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if arcs == OID_SKI {
            // SKI value is an OCTET STRING wrapping a KeyIdentifier OCTET STRING
            // The extension value bytes: OCTET STRING { KeyIdentifier }
            return parse_ski_value(ext.extn_value.as_bytes());
        }
    }
    None
}

/// Extract the AKI keyIdentifier value from a DER-encoded certificate.
///
/// Returns `None` if the extension is absent, has no keyIdentifier, or is malformed.
pub fn extract_aki_key_id(cert_der: &[u8]) -> Option<Vec<u8>> {
    let cert = Certificate::from_der(cert_der).ok()?;
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    for ext in extensions.iter() {
        let arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if arcs == OID_AKI {
            return parse_aki_key_id(ext.extn_value.as_bytes());
        }
    }
    None
}

/// Compute the SHA-256 fingerprint of a DER-encoded certificate.
pub fn cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    digest::sha256(cert_der).try_into().unwrap()
}

/// Parse a SubjectKeyIdentifier extension value.
///
/// The extension value bytes as stored by SPORK's builder are the raw bytes from
/// `SubjectKeyIdentifier::to_der()`, which produces:
///   OCTET STRING { key_id_bytes }  →  04 <len> <key_id_bytes>
///
/// `ext.extn_value.as_bytes()` returns those raw bytes, so we parse an OCTET STRING.
fn parse_ski_value(data: &[u8]) -> Option<Vec<u8>> {
    // data = 04 <len> <key_id_bytes>
    if data.len() < 2 || data[0] != 0x04 {
        return None;
    }
    let (content_len, hdr_len) = read_der_length_bytes(&data[1..])?;
    let content = data.get(1 + hdr_len..1 + hdr_len + content_len)?;
    Some(content.to_vec())
}

/// Parse an AuthorityKeyIdentifier extension value to extract the keyIdentifier field.
///
/// The extension value bytes as stored by SPORK's builder are the raw bytes from
/// `AuthorityKeyIdentifier::to_der()`, which produces:
///   SEQUENCE { [0] IMPLICIT OCTET STRING <key_id_bytes> }
///   →  30 <len> 80 <len> <key_id_bytes>
///
/// AKI ::= SEQUENCE {
///   keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL,
///   ...
/// }
fn parse_aki_key_id(data: &[u8]) -> Option<Vec<u8>> {
    // data = 30 <len> 80 <len> <key_id_bytes>
    if data.len() < 2 || data[0] != 0x30 {
        return None;
    }
    let (seq_content_len, hdr_len) = read_der_length_bytes(&data[1..])?;
    let seq_content = data.get(1 + hdr_len..1 + hdr_len + seq_content_len)?;

    // Scan the SEQUENCE content for [0] IMPLICIT OCTET STRING (tag = 0x80)
    let mut pos = 0;
    while pos < seq_content.len() {
        let tag = *seq_content.get(pos)?;
        pos += 1;
        let (val_len, l_hdr) = read_der_length_bytes(seq_content.get(pos..)?)?;
        pos += l_hdr;
        let value = seq_content.get(pos..pos + val_len)?;
        pos += val_len;

        if tag == 0x80 {
            // [0] IMPLICIT OCTET STRING — this is the keyIdentifier
            return Some(value.to_vec());
        }
        // Skip [1] authorityCertIssuer and [2] authorityCertSerialNumber if present
    }
    None
}

/// Read a DER length field, returning `(length, bytes_consumed)`.
fn read_der_length_bytes(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()? as usize;
    if first < 0x80 {
        Some((first, 1))
    } else if first == 0x81 {
        let len = *data.get(1)? as usize;
        Some((len, 2))
    } else if first == 0x82 {
        let b1 = *data.get(1)? as usize;
        let b2 = *data.get(2)? as usize;
        Some(((b1 << 8) | b2, 3))
    } else {
        None
    }
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[cfg(all(test, feature = "ceremony"))]
mod tests {
    use super::*;
    use crate::algo::AlgorithmId;
    use crate::ca::{CaCeremony, CaConfig, CertificateProfile};
    use crate::cert::{NameBuilder, Validity};

    // ---- Certificate factory helpers ----

    fn make_root(name: &str) -> (Vec<u8>, crate::ca::CertificateAuthority) {
        let config = CaConfig::root(name, AlgorithmId::EcdsaP256).with_subject(
            NameBuilder::new(name)
                .organization("Path Builder Test")
                .country("US")
                .build(),
        );
        let result = CaCeremony::init_root(config).unwrap();
        let der = result.ca.certificate.to_der().unwrap();
        (der, result.ca)
    }

    fn make_intermediate(
        name: &str,
        root_ca: &mut crate::ca::CertificateAuthority,
    ) -> (Vec<u8>, crate::ca::CertificateAuthority) {
        let config = CaConfig::intermediate(name, AlgorithmId::EcdsaP256).with_subject(
            NameBuilder::new(name)
                .organization("Path Builder Test")
                .country("US")
                .build(),
        );
        let result = CaCeremony::init_intermediate(config, root_ca).unwrap();
        let der = result.ca.certificate.to_der().unwrap();
        (der, result.ca)
    }

    fn issue_leaf(ca: &mut crate::ca::CertificateAuthority, cn: &str) -> Vec<u8> {
        let subject = NameBuilder::new(cn).build();
        let (issued, _key) = ca
            .issue_direct(
                subject,
                AlgorithmId::EcdsaP256,
                CertificateProfile::TlsServer,
                Validity::days_from_now(365),
                None,
            )
            .unwrap();
        let cert = crate::cert::parse_certificate_pem(&issued.pem).unwrap();
        cert.to_der().unwrap()
    }

    // ---- Test: simple 3-tier chain ----

    #[test]
    fn test_build_simple_chain() {
        let (root_der, mut root_ca) = make_root("Test Root");
        let (int_der, mut int_ca) = make_intermediate("Test Intermediate", &mut root_ca);
        let leaf_der = issue_leaf(&mut int_ca, "leaf.example.com");

        let mut store = CertificateStore::new();
        store.add_trust_anchor(root_der.clone()).unwrap();
        store.add_intermediate(int_der.clone()).unwrap();

        let builder = PathBuilder::new(store);
        let result = builder.build_paths(&leaf_der);

        assert!(
            result.success(),
            "Expected path found; errors: {:?}",
            result.errors
        );
        assert_eq!(result.paths.len(), 1);
        let path = &result.paths[0];
        assert_eq!(path.length, 3, "Expected leaf + intermediate + root");
        assert_eq!(path.certificates[0], leaf_der);
        assert_eq!(path.certificates[1], int_der);
        assert_eq!(path.certificates[2], root_der);
    }

    // ---- Test: multiple intermediates ----

    #[test]
    fn test_build_chain_two_intermediates() {
        let (root_der, mut root_ca) = make_root("Deep Root");
        let (int1_der, mut int1_ca) = make_intermediate("Deep Intermediate 1", &mut root_ca);
        let (int2_der, mut int2_ca) = make_intermediate("Deep Intermediate 2", &mut int1_ca);
        let leaf_der = issue_leaf(&mut int2_ca, "deep.example.com");

        let mut store = CertificateStore::new();
        store.add_trust_anchor(root_der.clone()).unwrap();
        store.add_intermediate(int1_der.clone()).unwrap();
        store.add_intermediate(int2_der.clone()).unwrap();

        let builder = PathBuilder::new(store);
        let result = builder.build_paths(&leaf_der);

        assert!(
            result.success(),
            "Expected path; errors: {:?}",
            result.errors
        );
        let path = &result.paths[0];
        assert_eq!(path.length, 4, "Expected leaf + 2 intermediates + root");
        assert_eq!(path.certificates[0], leaf_der);
        assert_eq!(path.certificates[3], root_der);
    }

    // ---- Test: max depth enforcement ----

    #[test]
    fn test_max_depth_enforcement() {
        let (root_der, mut root_ca) = make_root("MaxDepth Root");
        let (int_der, mut int_ca) = make_intermediate("MaxDepth Int", &mut root_ca);
        let leaf_der = issue_leaf(&mut int_ca, "maxdepth.example.com");

        let mut store = CertificateStore::new();
        store.add_trust_anchor(root_der).unwrap();
        store.add_intermediate(int_der).unwrap();

        let config = PathBuildConfig {
            max_path_length: 2, // Only allows leaf + root (no intermediates)
            ..Default::default()
        };
        let builder = PathBuilder::with_config(store, config);
        let result = builder.build_paths(&leaf_der);

        // Path of length 3 exceeds max_path_length=2, so no path found
        assert!(
            !result.success(),
            "Should not find path exceeding max depth"
        );
        assert!(
            result.errors.iter().any(|e| e.contains("Max path length")),
            "Expected max depth error; got: {:?}",
            result.errors
        );
    }

    // ---- Test: no path found (missing intermediate) ----

    #[test]
    fn test_no_path_missing_intermediate() {
        let (root_der, mut root_ca) = make_root("Missing Int Root");
        let (_int_der, mut int_ca) = make_intermediate("Missing Int", &mut root_ca);
        let leaf_der = issue_leaf(&mut int_ca, "missing.example.com");

        // Store has the root but NOT the intermediate
        let mut store = CertificateStore::new();
        store.add_trust_anchor(root_der).unwrap();
        // deliberately omit int_der

        let builder = PathBuilder::new(store);
        let result = builder.build_paths(&leaf_der);

        assert!(
            !result.success(),
            "No path should be found without intermediate"
        );
    }

    // ---- Test: trust anchor is the target itself (self-signed root) ----

    #[test]
    fn test_trust_anchor_is_target() {
        let (root_der, _root_ca) = make_root("Self Trust Root");

        let mut store = CertificateStore::new();
        store.add_trust_anchor(root_der.clone()).unwrap();

        let builder = PathBuilder::new(store);
        let result = builder.build_paths(&root_der);

        assert!(
            result.success(),
            "Self-signed root should find path; errors: {:?}",
            result.errors
        );
        assert_eq!(result.paths[0].length, 1);
        assert_eq!(result.paths[0].certificates[0], root_der);
    }

    // ---- Test: cross-certificate path ----

    #[test]
    fn test_cross_certificate_path() {
        // Two roots: Root A cross-certifies Root B's intermediate
        // Path: leaf → int (issued by Root A) → Root A (trust anchor)
        // Alternative: leaf → int2 (issued by Root B) → Root B (trust anchor)
        let (root_a_der, mut root_a_ca) = make_root("Cross Root A");
        let (root_b_der, mut root_b_ca) = make_root("Cross Root B");

        // Intermediate issued by Root A
        let (int_a_der, mut int_a_ca) = make_intermediate("Cross Int A", &mut root_a_ca);
        // Intermediate issued by Root B
        let (int_b_der, mut int_b_ca) = make_intermediate("Cross Int B", &mut root_b_ca);

        let leaf_a = issue_leaf(&mut int_a_ca, "cross-a.example.com");
        let leaf_b = issue_leaf(&mut int_b_ca, "cross-b.example.com");

        // Build a store that has both trust anchors and both intermediates
        let mut store = CertificateStore::new();
        store.add_trust_anchor(root_a_der.clone()).unwrap();
        store.add_trust_anchor(root_b_der.clone()).unwrap();
        store.add_intermediate(int_a_der).unwrap();
        store.add_intermediate(int_b_der).unwrap();

        let builder = PathBuilder::new(store);

        // Leaf A should reach Root A
        let result_a = builder.build_paths(&leaf_a);
        assert!(
            result_a.success(),
            "Leaf A should find path; errors: {:?}",
            result_a.errors
        );
        assert!(
            result_a.paths[0].certificates.last().unwrap() == &root_a_der,
            "Leaf A path should terminate at Root A"
        );

        // Leaf B should reach Root B
        let result_b = builder.build_paths(&leaf_b);
        assert!(
            result_b.success(),
            "Leaf B should find path; errors: {:?}",
            result_b.errors
        );
        assert!(
            result_b.paths[0].certificates.last().unwrap() == &root_b_der,
            "Leaf B path should terminate at Root B"
        );
    }

    // ---- Test: loop detection ----
    // We cannot easily create actual X.509 loops (certs would need to be
    // mutually signed, which is impossible without circularity), so we test
    // the fingerprint deduplication mechanism directly.

    #[test]
    fn test_loop_detection_via_fingerprint() {
        // Build a valid chain first, then verify the same cert can't appear twice
        let (root_der, mut root_ca) = make_root("Loop Root");
        let (int_der, mut int_ca) = make_intermediate("Loop Int", &mut root_ca);
        let leaf_der = issue_leaf(&mut int_ca, "loop.example.com");

        let mut store = CertificateStore::new();
        store.add_trust_anchor(root_der.clone()).unwrap();
        // Add the intermediate twice — path builder should still find only 1 path
        // (not loop through it twice)
        store.add_intermediate(int_der.clone()).unwrap();
        // The HashMap deduplicates — adding again puts a 2nd copy in the vec
        store.add_intermediate(int_der.clone()).unwrap();

        let builder = PathBuilder::new(store);
        let result = builder.build_paths(&leaf_der);

        // With loop detection, even though int_der appears twice in the candidate
        // list, it should only be traversed once per path
        assert!(
            result.success(),
            "Should find path; errors: {:?}",
            result.errors
        );
        for path in &result.paths {
            // Verify no cert appears twice in any path
            let fps: Vec<_> = path
                .certificates
                .iter()
                .map(|c| cert_fingerprint(c))
                .collect();
            let unique: HashSet<_> = fps.iter().collect();
            assert_eq!(
                fps.len(),
                unique.len(),
                "Loop detected in path: cert appears twice"
            );
        }
    }

    // ---- Unit tests for helper functions ----

    #[test]
    fn test_cert_fingerprint_deterministic() {
        let (root_der, _) = make_root("FP Root");
        let fp1 = cert_fingerprint(&root_der);
        let fp2 = cert_fingerprint(&root_der);
        assert_eq!(fp1, fp2, "Fingerprint must be deterministic");
    }

    #[test]
    fn test_cert_fingerprint_distinct() {
        let (root_a, _) = make_root("FP Root A");
        let (root_b, _) = make_root("FP Root B");
        assert_ne!(
            cert_fingerprint(&root_a),
            cert_fingerprint(&root_b),
            "Different certs must have different fingerprints"
        );
    }

    #[test]
    fn test_extract_subject_issuer_dn() {
        let (root_der, mut root_ca) = make_root("DN Root");
        let (int_der, _) = make_intermediate("DN Intermediate", &mut root_ca);

        let root_subject = extract_subject_dn(&root_der).unwrap();
        let int_issuer = extract_issuer_dn(&int_der).unwrap();

        // Intermediate's issuer DN should match root's subject DN
        assert_eq!(
            root_subject, int_issuer,
            "Intermediate issuer DN should match root subject DN"
        );
    }

    #[test]
    fn test_extract_ski_present() {
        let (root_der, _) = make_root("SKI Root");
        // SPORK CAs always have SKI
        let ski = extract_ski(&root_der);
        assert!(ski.is_some(), "Root CA should have SKI");
        assert!(!ski.unwrap().is_empty(), "SKI should not be empty");
    }

    #[test]
    fn test_extract_aki_present_on_intermediate() {
        let (root_der, mut root_ca) = make_root("AKI Root");
        let (int_der, _) = make_intermediate("AKI Int", &mut root_ca);

        let root_ski = extract_ski(&root_der).expect("Root should have SKI");
        let int_aki = extract_aki_key_id(&int_der).expect("Intermediate should have AKI");

        assert_eq!(root_ski, int_aki, "Intermediate AKI should match Root SKI");
    }
}

// Non-ceremony unit tests for helper parsing functions (no actual certs needed)
#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_read_der_length_short_form() {
        assert_eq!(read_der_length_bytes(&[0x05]), Some((5, 1)));
        assert_eq!(read_der_length_bytes(&[0x7F]), Some((127, 1)));
    }

    #[test]
    fn test_read_der_length_one_byte_long_form() {
        assert_eq!(read_der_length_bytes(&[0x81, 0x80]), Some((128, 2)));
        assert_eq!(read_der_length_bytes(&[0x81, 0xFF]), Some((255, 2)));
    }

    #[test]
    fn test_read_der_length_two_byte_long_form() {
        assert_eq!(read_der_length_bytes(&[0x82, 0x01, 0x00]), Some((256, 3)));
        assert_eq!(read_der_length_bytes(&[0x82, 0x01, 0xFF]), Some((511, 3)));
    }

    #[test]
    fn test_read_der_length_empty() {
        assert_eq!(read_der_length_bytes(&[]), None);
    }

    #[test]
    fn test_parse_ski_value_valid() {
        // SKI format: OCTET STRING { key_id_bytes }
        // tag=0x04, len=3, content=[0xAA, 0xBB, 0xCC]
        let data = vec![0x04, 0x03, 0xAA, 0xBB, 0xCC];
        let result = parse_ski_value(&data);
        assert_eq!(result, Some(vec![0xAA, 0xBB, 0xCC]));
    }

    #[test]
    fn test_parse_ski_value_wrong_tag() {
        // SEQUENCE tag is wrong for SKI
        let data = vec![0x30, 0x03, 0xAA, 0xBB, 0xCC];
        assert_eq!(parse_ski_value(&data), None);
    }

    #[test]
    fn test_parse_ski_value_empty() {
        assert_eq!(parse_ski_value(&[]), None);
    }

    #[test]
    fn test_parse_aki_key_id_valid() {
        // AKI format: SEQUENCE { [0] IMPLICIT OCTET STRING { key_id_bytes } }
        // 30 05 80 03 AA BB CC
        let data = vec![0x30, 0x05, 0x80, 0x03, 0xAA, 0xBB, 0xCC];
        let result = parse_aki_key_id(&data);
        assert_eq!(result, Some(vec![0xAA, 0xBB, 0xCC]));
    }

    #[test]
    fn test_parse_aki_key_id_wrong_outer_tag() {
        // OCTET STRING tag instead of SEQUENCE
        let data = vec![0x04, 0x05, 0x80, 0x03, 0xAA, 0xBB, 0xCC];
        assert_eq!(parse_aki_key_id(&data), None);
    }

    #[test]
    fn test_parse_aki_key_id_empty() {
        assert_eq!(parse_aki_key_id(&[]), None);
    }

    #[test]
    fn test_cert_store_default() {
        let store = CertificateStore::default();
        assert!(store.trust_anchors.is_empty());
        assert!(store.intermediates.is_empty());
    }
}
