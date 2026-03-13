//! Hierarchy validation

use crate::config::HierarchyConfig;
use crate::error::{HierarchyError, Result};
use crate::topology::{build_tree, HierarchyTree};

/// Validation warning (non-fatal)
#[derive(Debug)]
pub struct ValidationWarning {
    pub ca_id: String,
    pub message: String,
}

/// Validation result
#[derive(Debug)]
pub struct ValidationResult {
    pub tree: HierarchyTree,
    pub warnings: Vec<ValidationWarning>,
}

/// Known algorithm names
const KNOWN_ALGORITHMS: &[&str] = &[
    "ecdsa-p256",
    "ecdsa-p384",
    "rsa-2048",
    "rsa-4096",
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    "slh-dsa-sha2-128s",
    "slh-dsa-sha2-192s",
    "slh-dsa-sha2-256s",
    "ml-dsa-44-ecdsa-p256",
    "ml-dsa-65-ecdsa-p256",
    "ml-dsa-65-ecdsa-p384",
    "ml-dsa-87-ecdsa-p384",
];

/// Validate a hierarchy configuration
pub fn validate_hierarchy(config: &HierarchyConfig) -> Result<ValidationResult> {
    // Build tree first (catches topology errors)
    let tree = build_tree(config)?;
    let mut warnings = Vec::new();

    for id in &tree.build_order {
        let node = &tree.nodes[id];
        let entry = &node.entry;

        // Check algorithm is recognized
        if !KNOWN_ALGORITHMS.contains(&entry.algorithm.as_str()) {
            return Err(HierarchyError::Validation(format!(
                "CA '{}': unknown algorithm '{}'. Known: {}",
                id,
                entry.algorithm,
                KNOWN_ALGORITHMS.join(", ")
            )));
        }

        // Check path length consistency against all ancestors (RFC 5280 Section 4.2.1.9)
        // pathLenConstraint = max number of non-self-issued CA certs that may follow
        if let Some(first_parent) = &entry.parent {
            // Walk up to each ancestor and check its path_length allows this depth
            let mut ancestor_id = first_parent.clone();
            loop {
                let ancestor = &tree.nodes[&ancestor_id];
                if let Some(ancestor_pl) = ancestor.entry.path_length {
                    // Number of CA levels between ancestor and this node
                    let levels_below = node.depth - ancestor.depth;
                    if (ancestor_pl as usize) < levels_below {
                        return Err(HierarchyError::Validation(format!(
                            "CA '{}': ancestor '{}' has path_length={} but CA is {} level(s) below",
                            id, ancestor_id, ancestor_pl, levels_below
                        )));
                    }
                }
                match &ancestor.entry.parent {
                    Some(next) => ancestor_id = next.clone(),
                    None => break,
                }
            }
        }

        if let Some(parent_id) = &entry.parent {
            let parent = &tree.nodes[parent_id];

            // Child validity must not exceed parent validity
            if entry.validity_years > parent.entry.validity_years {
                return Err(HierarchyError::Validation(format!(
                    "CA '{}': validity ({} years) exceeds parent '{}' validity ({} years)",
                    id, entry.validity_years, parent_id, parent.entry.validity_years
                )));
            }

            // Warn if child validity is close to parent
            if entry.validity_years > parent.entry.validity_years * 3 / 4 {
                warnings.push(ValidationWarning {
                    ca_id: id.clone(),
                    message: format!(
                        "validity ({} years) is >75% of parent '{}' validity ({} years)",
                        entry.validity_years, parent_id, parent.entry.validity_years
                    ),
                });
            }
        }

        // Validate URL formats
        if let Some(ref cdp) = entry.cdp {
            for url in &cdp.urls {
                if !url.starts_with("http://") && !url.starts_with("https://") {
                    return Err(HierarchyError::Validation(format!(
                        "CA '{}': CDP URL must start with http:// or https://: '{}'",
                        id, url
                    )));
                }
            }
        }

        if let Some(ref aia) = entry.aia {
            for url in aia.ocsp_urls.iter().chain(aia.ca_issuer_urls.iter()) {
                if !url.starts_with("http://") && !url.starts_with("https://") {
                    return Err(HierarchyError::Validation(format!(
                        "CA '{}': AIA URL must start with http:// or https://: '{}'",
                        id, url
                    )));
                }
            }
        }

        // Warn about root with no path length (unlimited)
        if entry.ca_type == "root" && entry.path_length.is_none() {
            warnings.push(ValidationWarning {
                ca_id: id.clone(),
                message: "root CA has no path_length constraint (unlimited)".to_string(),
            });
        }

        // Intermediate with path_length=0 must not have children
        if entry.path_length == Some(0) && !node.children.is_empty() {
            return Err(HierarchyError::Validation(format!(
                "CA '{}': has path_length=0 but has child CAs: {}",
                id,
                node.children.join(", ")
            )));
        }
    }

    Ok(ValidationResult { tree, warnings })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    fn make_config(cas: Vec<CaEntry>) -> HierarchyConfig {
        HierarchyConfig {
            hierarchy: HierarchyMeta {
                name: "test".to_string(),
                output_dir: "./test".to_string(),
                distribution: None,
                defaults: None,
            },
            ca: cas,
        }
    }

    fn root_entry(id: &str, validity: u32, path_length: Option<u8>) -> CaEntry {
        CaEntry {
            id: id.to_string(),
            ca_type: "root".to_string(),
            parent: None,
            algorithm: "ecdsa-p256".to_string(),
            common_name: format!("{} CA", id),
            ou: None,
            validity_years: validity,
            path_length,
            cdp: None,
            aia: None,
            policies: None,
            eku: None,
        }
    }

    fn int_entry(id: &str, parent: &str, validity: u32, path_length: Option<u8>) -> CaEntry {
        CaEntry {
            id: id.to_string(),
            ca_type: "intermediate".to_string(),
            parent: Some(parent.to_string()),
            algorithm: "ecdsa-p256".to_string(),
            common_name: format!("{} CA", id),
            ou: None,
            validity_years: validity,
            path_length,
            cdp: None,
            aia: None,
            policies: None,
            eku: None,
        }
    }

    #[test]
    fn test_valid_hierarchy() {
        let config = make_config(vec![
            root_entry("root", 20, Some(2)),
            int_entry("policy", "root", 15, Some(1)),
            int_entry("issuing", "policy", 10, Some(0)),
        ]);
        let result = validate_hierarchy(&config).unwrap();
        assert_eq!(result.tree.build_order.len(), 3);
    }

    #[test]
    fn test_child_exceeds_parent_validity() {
        let config = make_config(vec![
            root_entry("root", 10, None),
            int_entry("child", "root", 15, Some(0)),
        ]);
        assert!(validate_hierarchy(&config).is_err());
    }

    #[test]
    fn test_path_length_violation() {
        let config = make_config(vec![
            root_entry("root", 20, Some(1)),
            int_entry("policy", "root", 15, Some(1)),
            int_entry("issuing", "policy", 10, Some(0)),
        ]);
        // root path_length=1, but issuing is 2 levels below root
        assert!(validate_hierarchy(&config).is_err());
    }

    #[test]
    fn test_unknown_algorithm() {
        let mut entry = root_entry("root", 20, None);
        entry.algorithm = "quantum-magic".to_string();
        let config = make_config(vec![entry]);
        assert!(validate_hierarchy(&config).is_err());
    }

    #[test]
    fn test_zero_path_length_with_children() {
        let config = make_config(vec![
            root_entry("root", 20, Some(2)),
            int_entry("mid", "root", 15, Some(0)),
            int_entry("leaf", "mid", 10, Some(0)),
        ]);
        assert!(validate_hierarchy(&config).is_err());
    }

    #[test]
    fn test_bad_cdp_url() {
        let mut entry = root_entry("root", 20, None);
        entry.cdp = Some(CdpConfig {
            urls: vec!["ftp://bad.com/crl".into()],
        });
        let config = make_config(vec![entry]);
        assert!(validate_hierarchy(&config).is_err());
    }

    #[test]
    fn test_bad_aia_ocsp_url() {
        let mut entry = root_entry("root", 20, None);
        entry.aia = Some(AiaConfig {
            ocsp_urls: vec!["ldap://bad.com/ocsp".into()],
            ca_issuer_urls: vec![],
        });
        let config = make_config(vec![entry]);
        assert!(validate_hierarchy(&config).is_err());
    }

    #[test]
    fn test_bad_aia_ca_issuer_url() {
        let mut entry = root_entry("root", 20, None);
        entry.aia = Some(AiaConfig {
            ocsp_urls: vec![],
            ca_issuer_urls: vec!["file:///local/cert".into()],
        });
        let config = make_config(vec![entry]);
        assert!(validate_hierarchy(&config).is_err());
    }

    #[test]
    fn test_valid_http_and_https_urls() {
        let mut entry = root_entry("root", 20, None);
        entry.cdp = Some(CdpConfig {
            urls: vec![
                "http://crl.example.com/root.crl".into(),
                "https://crl.example.com/root.crl".into(),
            ],
        });
        entry.aia = Some(AiaConfig {
            ocsp_urls: vec!["http://ocsp.example.com".into()],
            ca_issuer_urls: vec!["https://pki.example.com/root.crt".into()],
        });
        let config = make_config(vec![entry]);
        assert!(validate_hierarchy(&config).is_ok());
    }

    #[test]
    fn test_root_no_path_length_warning() {
        let config = make_config(vec![root_entry("root", 20, None)]);
        let result = validate_hierarchy(&config).unwrap();
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.message.contains("no path_length")),
            "Expected warning about root with no path_length constraint"
        );
    }

    #[test]
    fn test_root_with_path_length_no_warning() {
        let config = make_config(vec![root_entry("root", 20, Some(2))]);
        let result = validate_hierarchy(&config).unwrap();
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.message.contains("no path_length")),
            "Root with path_length should not generate path_length warning"
        );
    }

    #[test]
    fn test_validity_close_to_parent_warning() {
        let config = make_config(vec![
            root_entry("root", 20, Some(1)),
            int_entry("child", "root", 16, Some(0)), // 16/20 = 80% > 75%
        ]);
        let result = validate_hierarchy(&config).unwrap();
        assert!(
            result.warnings.iter().any(|w| w.message.contains(">75%")),
            "Expected warning about child validity being >75% of parent"
        );
    }

    #[test]
    fn test_validity_not_close_to_parent_no_warning() {
        let config = make_config(vec![
            root_entry("root", 20, Some(1)),
            int_entry("child", "root", 10, Some(0)), // 10/20 = 50% < 75%
        ]);
        let result = validate_hierarchy(&config).unwrap();
        assert!(
            !result.warnings.iter().any(|w| w.message.contains(">75%")),
            "50% validity ratio should not generate warning"
        );
    }

    #[test]
    fn test_equal_parent_child_validity_is_error() {
        // Equal validity should be caught as child > parent*3/4, so it's a warning
        // but NOT an error (child <= parent)
        let config = make_config(vec![
            root_entry("root", 20, Some(1)),
            int_entry("child", "root", 20, Some(0)),
        ]);
        // Equal validity is allowed (not greater)
        assert!(validate_hierarchy(&config).is_ok());
    }

    #[test]
    fn test_all_known_algorithms() {
        for algo in KNOWN_ALGORITHMS {
            let mut entry = root_entry("root", 20, None);
            entry.algorithm = algo.to_string();
            let config = make_config(vec![entry]);
            assert!(
                validate_hierarchy(&config).is_ok(),
                "Algorithm '{}' should be recognized",
                algo
            );
        }
    }

    #[test]
    fn test_deep_path_length_violation() {
        // root(pl=2) -> L1(pl=1) -> L2(pl=0) -> L3 should fail
        // L3 is 3 levels below root, but root has pl=2
        let config = make_config(vec![
            root_entry("root", 30, Some(2)),
            int_entry("L1", "root", 25, Some(1)),
            int_entry("L2", "L1", 20, Some(1)),
            int_entry("L3", "L2", 15, Some(0)),
        ]);
        assert!(validate_hierarchy(&config).is_err());
    }

    #[test]
    fn test_deep_hierarchy_valid() {
        // root(pl=3) -> L1(pl=2) -> L2(pl=1) -> L3(pl=0)
        let config = make_config(vec![
            root_entry("root", 30, Some(3)),
            int_entry("L1", "root", 25, Some(2)),
            int_entry("L2", "L1", 20, Some(1)),
            int_entry("L3", "L2", 15, Some(0)),
        ]);
        assert!(validate_hierarchy(&config).is_ok());
    }
}
