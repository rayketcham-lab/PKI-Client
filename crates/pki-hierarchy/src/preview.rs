//! Hierarchy preview — terminal tree visualization

use std::fmt::Write;

use crate::config::HierarchyConfig;
use crate::error::Result;
use crate::topology::HierarchyTree;
use crate::validate::validate_hierarchy;

/// Preview a hierarchy as a formatted tree string
pub fn preview_hierarchy(config: &HierarchyConfig) -> Result<String> {
    let result = validate_hierarchy(config)?;
    let tree = &result.tree;
    let mut output = String::new();

    writeln!(output, "PKI Hierarchy: {}", config.hierarchy.name).unwrap();
    writeln!(output, "{}", "=".repeat(60)).unwrap();

    if let Some(ref dist) = config.hierarchy.distribution {
        writeln!(output, "Distribution: {}", dist.base_url).unwrap();
        if let Some(ref ocsp) = dist.ocsp_url {
            writeln!(output, "OCSP:         {}", ocsp).unwrap();
        }
    }
    writeln!(output).unwrap();

    // Print tree recursively
    print_node(&mut output, tree, &tree.root_id, "", true);

    // Print warnings
    if !result.warnings.is_empty() {
        writeln!(output).unwrap();
        writeln!(output, "Warnings:").unwrap();
        for w in &result.warnings {
            writeln!(output, "  [{}] {}", w.ca_id, w.message).unwrap();
        }
    }

    Ok(output)
}

fn print_node(
    output: &mut String,
    tree: &HierarchyTree,
    node_id: &str,
    prefix: &str,
    is_last: bool,
) {
    let node = &tree.nodes[node_id];
    let entry = &node.entry;

    // Tree connector
    let connector = if node.depth == 0 {
        ""
    } else if is_last {
        "`-- "
    } else {
        "|-- "
    };

    // CA info line
    let type_label = match entry.ca_type.as_str() {
        "root" => "[ROOT]",
        "intermediate" => "[INT]",
        _ => "[???]",
    };

    writeln!(
        output,
        "{}{}{} {} ({})",
        prefix, connector, type_label, entry.common_name, entry.algorithm
    )
    .unwrap();

    // Detail lines
    let detail_prefix = if node.depth == 0 {
        "     ".to_string()
    } else if is_last {
        format!("{}     ", prefix)
    } else {
        format!("{}|    ", prefix)
    };

    writeln!(
        output,
        "{}validity: {} years, path_length: {}",
        detail_prefix,
        entry.validity_years,
        entry
            .path_length
            .map_or("unlimited".to_string(), |p| p.to_string())
    )
    .unwrap();

    if let Some(ref cdp) = entry.cdp {
        for url in &cdp.urls {
            writeln!(output, "{}CDP: {}", detail_prefix, url).unwrap();
        }
    }

    if let Some(ref aia) = entry.aia {
        for url in &aia.ocsp_urls {
            writeln!(output, "{}OCSP: {}", detail_prefix, url).unwrap();
        }
        for url in &aia.ca_issuer_urls {
            writeln!(output, "{}CA Issuer: {}", detail_prefix, url).unwrap();
        }
    }

    // Recurse into children
    let children = &node.children;
    for (i, child_id) in children.iter().enumerate() {
        let child_is_last = i == children.len() - 1;
        let child_prefix = if node.depth == 0 {
            String::new()
        } else if is_last {
            format!("{}     ", prefix)
        } else {
            format!("{}|    ", prefix)
        };
        print_node(output, tree, child_id, &child_prefix, child_is_last);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_config() -> HierarchyConfig {
        toml::from_str(
            r#"
[hierarchy]
name = "Test PKI"

[[ca]]
id = "root"
type = "root"
algorithm = "ecdsa-p256"
common_name = "Test Root CA"
validity_years = 20

[[ca]]
id = "issuing"
type = "intermediate"
parent = "root"
algorithm = "ecdsa-p256"
common_name = "Test Issuing CA"
validity_years = 10
path_length = 0
"#,
        )
        .unwrap()
    }

    #[test]
    fn test_preview_contains_hierarchy_name() {
        let config = simple_config();
        let output = preview_hierarchy(&config).unwrap();
        assert!(output.contains("PKI Hierarchy: Test PKI"));
    }

    #[test]
    fn test_preview_contains_root_label() {
        let config = simple_config();
        let output = preview_hierarchy(&config).unwrap();
        assert!(output.contains("[ROOT]"));
        assert!(output.contains("Test Root CA"));
    }

    #[test]
    fn test_preview_contains_intermediate_label() {
        let config = simple_config();
        let output = preview_hierarchy(&config).unwrap();
        assert!(output.contains("[INT]"));
        assert!(output.contains("Test Issuing CA"));
    }

    #[test]
    fn test_preview_contains_validity() {
        let config = simple_config();
        let output = preview_hierarchy(&config).unwrap();
        assert!(output.contains("validity: 20 years"));
        assert!(output.contains("validity: 10 years"));
    }

    #[test]
    fn test_preview_contains_path_length() {
        let config = simple_config();
        let output = preview_hierarchy(&config).unwrap();
        assert!(output.contains("path_length: unlimited")); // root
        assert!(output.contains("path_length: 0")); // issuing
    }

    #[test]
    fn test_preview_with_distribution() {
        let config: HierarchyConfig = toml::from_str(
            r#"
[hierarchy]
name = "Dist PKI"

[hierarchy.distribution]
base_url = "https://pki.example.com"
ocsp_url = "https://ocsp.example.com"

[[ca]]
id = "root"
type = "root"
algorithm = "ecdsa-p256"
common_name = "Root"
validity_years = 20
"#,
        )
        .unwrap();

        let output = preview_hierarchy(&config).unwrap();
        assert!(output.contains("Distribution: https://pki.example.com"));
        assert!(output.contains("OCSP:         https://ocsp.example.com"));
    }

    #[test]
    fn test_preview_with_cdp_aia() {
        let config: HierarchyConfig = toml::from_str(
            r#"
[hierarchy]
name = "Extensions PKI"

[[ca]]
id = "root"
type = "root"
algorithm = "ecdsa-p256"
common_name = "Root"
validity_years = 20

[[ca]]
id = "issuing"
type = "intermediate"
parent = "root"
algorithm = "ecdsa-p256"
common_name = "Issuing"
validity_years = 10
path_length = 0

[ca.cdp]
urls = ["http://crl.example.com/issuing.crl"]

[ca.aia]
ocsp_urls = ["http://ocsp.example.com"]
ca_issuer_urls = ["http://ca.example.com/root.cer"]
"#,
        )
        .unwrap();

        let output = preview_hierarchy(&config).unwrap();
        assert!(output.contains("CDP: http://crl.example.com/issuing.crl"));
        assert!(output.contains("OCSP: http://ocsp.example.com"));
        assert!(output.contains("CA Issuer: http://ca.example.com/root.cer"));
    }

    #[test]
    fn test_preview_3_tier_hierarchy() {
        let config: HierarchyConfig = toml::from_str(
            r#"
[hierarchy]
name = "3-Tier PKI"

[[ca]]
id = "root"
type = "root"
algorithm = "ecdsa-p384"
common_name = "Root CA"
validity_years = 25

[[ca]]
id = "policy"
type = "intermediate"
parent = "root"
algorithm = "ecdsa-p384"
common_name = "Policy CA"
validity_years = 15
path_length = 1

[[ca]]
id = "issuing"
type = "intermediate"
parent = "policy"
algorithm = "ecdsa-p256"
common_name = "Issuing CA"
validity_years = 5
path_length = 0
"#,
        )
        .unwrap();

        let output = preview_hierarchy(&config).unwrap();
        assert!(output.contains("[ROOT]"));
        assert!(output.contains("Root CA"));
        assert!(output.contains("Policy CA"));
        assert!(output.contains("Issuing CA"));
        // Verify tree connector exists
        assert!(output.contains("`-- "));
    }

    #[test]
    fn test_preview_invalid_hierarchy_returns_error() {
        let config: HierarchyConfig = toml::from_str(
            r#"
[hierarchy]
name = "Invalid"

[[ca]]
id = "orphan"
type = "intermediate"
parent = "nonexistent"
algorithm = "ecdsa-p256"
common_name = "Orphan"
validity_years = 10
"#,
        )
        .unwrap();

        let result = preview_hierarchy(&config);
        assert!(result.is_err());
    }
}
