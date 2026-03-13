//! Hierarchy builder — orchestrate CA ceremony in topological order

use std::collections::HashMap;

use spork_core::algo::AlgorithmId;
use spork_core::ca::{CaCeremony, CaConfig, InitializedCa};
use spork_core::cert::extensions::{CertificatePolicies, ExtendedKeyUsage};
use spork_core::cert::{NameBuilder, Validity};
use zeroize::Zeroizing;

use crate::config::HierarchyConfig;
use crate::error::{HierarchyError, Result};
use crate::validate::validate_hierarchy;

/// Result of building a hierarchy
#[derive(Debug)]
pub struct BuildResult {
    /// Built CAs indexed by ID
    pub cas: HashMap<String, BuiltCa>,
    /// Build order (root first)
    pub build_order: Vec<String>,
}

/// A successfully built CA
#[derive(Debug)]
pub struct BuiltCa {
    /// CA ID from config
    pub id: String,
    /// Certificate in PEM format
    pub certificate_pem: String,
    /// Certificate in DER format
    pub certificate_der: Vec<u8>,
    /// Private key in PEM format
    pub private_key_pem: Zeroizing<String>,
    /// Full chain PEM (this cert + all parents up to root)
    pub chain_pem: String,
}

/// Build a complete CA hierarchy from config
pub fn build_hierarchy(config: &HierarchyConfig) -> Result<BuildResult> {
    let validation = validate_hierarchy(config)?;
    let tree = validation.tree;

    let mut cas: HashMap<String, BuiltCa> = HashMap::new();
    let mut initialized: HashMap<String, InitializedCa> = HashMap::new();
    let build_order = tree.build_order.clone();

    for id in &build_order {
        let node = &tree.nodes[id];
        let entry = &node.entry;

        // Parse algorithm
        let algorithm = parse_algorithm(&entry.algorithm)?;

        // Build DN with defaults
        let mut name_builder = NameBuilder::new(&entry.common_name);
        if let Some(ref defaults) = config.hierarchy.defaults {
            // Domain components (DC) — from explicit list or parsed from domain name
            if !defaults.domain_components.is_empty() {
                for dc in &defaults.domain_components {
                    name_builder = name_builder.domain_component(dc);
                }
            } else if let Some(ref domain) = defaults.domain {
                name_builder = name_builder.domain(domain);
            }
            if let Some(ref country) = defaults.country {
                name_builder = name_builder.country(country);
            }
            if let Some(ref state) = defaults.state {
                name_builder = name_builder.state(state);
            }
            if let Some(ref org) = defaults.organization {
                name_builder = name_builder.organization(org);
            }
        }
        if let Some(ref ou) = entry.ou {
            name_builder = name_builder.organizational_unit(ou);
        }
        let subject = name_builder.build();

        // Build CaConfig
        let validity = Validity::years_from_now(entry.validity_years);

        let ca_config = if entry.ca_type == "root" {
            CaConfig::root(&entry.common_name, algorithm)
                .with_subject(subject)
                .with_validity(validity)
                .with_path_length(entry.path_length)
        } else {
            CaConfig::intermediate(&entry.common_name, algorithm)
                .with_subject(subject)
                .with_validity(validity)
                .with_path_length(entry.path_length)
        };

        // Apply extensions
        let ca_config = apply_extensions(ca_config, entry, config)?;

        // Build the CA
        let init_result = if entry.ca_type == "root" {
            CaCeremony::init_root(ca_config)?
        } else {
            let parent_id = entry.parent.as_ref().ok_or_else(|| {
                HierarchyError::Build(format!("intermediate CA '{}' missing parent", entry.id))
            })?;
            let parent_init = initialized.get_mut(parent_id).ok_or_else(|| {
                HierarchyError::Build(format!("parent CA '{}' not yet initialized", parent_id))
            })?;
            CaCeremony::init_intermediate(ca_config, &mut parent_init.ca)?
        };

        // Build chain PEM
        let mut chain = init_result.certificate_pem.clone();
        if let Some(ref parent_id) = entry.parent {
            if let Some(parent_built) = cas.get(parent_id) {
                chain.push('\n');
                chain.push_str(&parent_built.chain_pem);
            }
        }

        cas.insert(
            id.clone(),
            BuiltCa {
                id: id.clone(),
                certificate_pem: init_result.certificate_pem.clone(),
                certificate_der: init_result.certificate_der.clone(),
                private_key_pem: init_result.private_key_pem.clone(),
                chain_pem: chain,
            },
        );

        initialized.insert(id.clone(), init_result);
    }

    Ok(BuildResult { cas, build_order })
}

/// Parse algorithm string to AlgorithmId
fn parse_algorithm(name: &str) -> Result<AlgorithmId> {
    match name {
        "ecdsa-p256" => Ok(AlgorithmId::EcdsaP256),
        "ecdsa-p384" => Ok(AlgorithmId::EcdsaP384),
        "rsa-2048" => Ok(AlgorithmId::Rsa2048),
        "rsa-3072" => Ok(AlgorithmId::Rsa3072),
        "rsa-4096" => Ok(AlgorithmId::Rsa4096),
        #[cfg(feature = "pqc")]
        "ml-dsa-44" => Ok(AlgorithmId::MlDsa44),
        #[cfg(feature = "pqc")]
        "ml-dsa-65" => Ok(AlgorithmId::MlDsa65),
        #[cfg(feature = "pqc")]
        "ml-dsa-87" => Ok(AlgorithmId::MlDsa87),
        #[cfg(feature = "pqc")]
        "slh-dsa-sha2-128s" => Ok(AlgorithmId::SlhDsaSha2_128s),
        #[cfg(feature = "pqc")]
        "slh-dsa-sha2-192s" => Ok(AlgorithmId::SlhDsaSha2_192s),
        #[cfg(feature = "pqc")]
        "slh-dsa-sha2-256s" => Ok(AlgorithmId::SlhDsaSha2_256s),
        #[cfg(feature = "pqc")]
        "ml-dsa-44-ecdsa-p256" => Ok(AlgorithmId::MlDsa44EcdsaP256),
        #[cfg(feature = "pqc")]
        "ml-dsa-65-ecdsa-p256" => Ok(AlgorithmId::MlDsa65EcdsaP256),
        #[cfg(feature = "pqc")]
        "ml-dsa-65-ecdsa-p384" => Ok(AlgorithmId::MlDsa65EcdsaP384),
        #[cfg(feature = "pqc")]
        "ml-dsa-87-ecdsa-p384" => Ok(AlgorithmId::MlDsa87EcdsaP384),
        _ => Err(HierarchyError::Config(format!(
            "unknown algorithm: '{}'",
            name
        ))),
    }
}

/// Apply extension fields from CaEntry to CaConfig
fn apply_extensions(
    mut ca_config: CaConfig,
    entry: &crate::config::CaEntry,
    config: &HierarchyConfig,
) -> Result<CaConfig> {
    // CDP URLs -- from entry config or auto-generate from distribution base_url
    let mut cdp_urls = Vec::new();
    if let Some(ref cdp) = entry.cdp {
        cdp_urls.clone_from(&cdp.urls);
    } else if let Some(ref dist) = config.hierarchy.distribution {
        cdp_urls.push(format!(
            "{}/{}.crl",
            dist.base_url.trim_end_matches('/'),
            entry.id
        ));
    }
    if !cdp_urls.is_empty() {
        ca_config = ca_config.with_cdp_urls(cdp_urls);
    }

    // AIA URLs -- from entry config or auto-generate
    let mut ocsp_urls = Vec::new();
    let mut ca_issuer_urls = Vec::new();
    if let Some(ref aia) = entry.aia {
        ocsp_urls.clone_from(&aia.ocsp_urls);
        ca_issuer_urls.clone_from(&aia.ca_issuer_urls);
    } else if let Some(ref dist) = config.hierarchy.distribution {
        if let Some(ref ocsp) = dist.ocsp_url {
            ocsp_urls.push(ocsp.clone());
        }
        if let Some(ref parent_id) = entry.parent {
            ca_issuer_urls.push(format!(
                "{}/{}.cer",
                dist.base_url.trim_end_matches('/'),
                parent_id
            ));
        }
    }
    if !ocsp_urls.is_empty() || !ca_issuer_urls.is_empty() {
        ca_config = ca_config.with_aia(ocsp_urls, ca_issuer_urls);
    }

    // Certificate policies
    if let Some(ref policy_oids) = entry.policies {
        let oids: std::result::Result<Vec<_>, _> = policy_oids
            .iter()
            .map(|s| {
                const_oid::ObjectIdentifier::new(s).map_err(|e| {
                    HierarchyError::Config(format!("invalid policy OID '{}': {}", s, e))
                })
            })
            .collect();
        ca_config = ca_config.with_certificate_policies(CertificatePolicies::new(oids?));
    }

    // Extended Key Usage
    if let Some(ref eku_oids) = entry.eku {
        let oids: std::result::Result<Vec<_>, _> = eku_oids
            .iter()
            .map(|s| {
                const_oid::ObjectIdentifier::new(s)
                    .map_err(|e| HierarchyError::Config(format!("invalid EKU OID '{}': {}", s, e)))
            })
            .collect();
        ca_config = ca_config.with_extended_key_usage(ExtendedKeyUsage::new(oids?));
    }

    Ok(ca_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_algorithm_ecdsa_p256() {
        let algo = parse_algorithm("ecdsa-p256").unwrap();
        assert_eq!(algo, AlgorithmId::EcdsaP256);
    }

    #[test]
    fn test_parse_algorithm_ecdsa_p384() {
        let algo = parse_algorithm("ecdsa-p384").unwrap();
        assert_eq!(algo, AlgorithmId::EcdsaP384);
    }

    #[test]
    fn test_parse_algorithm_rsa_2048() {
        let algo = parse_algorithm("rsa-2048").unwrap();
        assert_eq!(algo, AlgorithmId::Rsa2048);
    }

    #[test]
    fn test_parse_algorithm_rsa_3072() {
        let algo = parse_algorithm("rsa-3072").unwrap();
        assert_eq!(algo, AlgorithmId::Rsa3072);
    }

    #[test]
    fn test_parse_algorithm_rsa_4096() {
        let algo = parse_algorithm("rsa-4096").unwrap();
        assert_eq!(algo, AlgorithmId::Rsa4096);
    }

    #[test]
    fn test_parse_algorithm_unknown() {
        let result = parse_algorithm("ed25519");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown algorithm"));
    }

    #[test]
    fn test_parse_algorithm_empty() {
        assert!(parse_algorithm("").is_err());
    }

    #[test]
    fn test_parse_algorithm_case_sensitive() {
        // Algorithms should be lowercase
        assert!(parse_algorithm("ECDSA-P256").is_err());
        assert!(parse_algorithm("RSA-4096").is_err());
    }
}
