//! Hierarchy topology — tree building and topological sort

use std::collections::{HashMap, HashSet, VecDeque};

use crate::config::{CaEntry, HierarchyConfig};
use crate::error::{HierarchyError, Result};

/// A node in the hierarchy tree
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// The CA entry from config
    pub entry: CaEntry,
    /// Child CA IDs
    pub children: Vec<String>,
    /// Depth in the tree (root = 0)
    pub depth: usize,
}

/// The resolved hierarchy tree
#[derive(Debug)]
pub struct HierarchyTree {
    /// Root CA ID
    pub root_id: String,
    /// All nodes indexed by ID
    pub nodes: HashMap<String, TreeNode>,
    /// Topological build order (root first, then breadth-first)
    pub build_order: Vec<String>,
}

/// Build a hierarchy tree from config
pub fn build_tree(config: &HierarchyConfig) -> Result<HierarchyTree> {
    let entries = &config.ca;

    if entries.is_empty() {
        return Err(HierarchyError::Topology("no CA entries defined".into()));
    }

    // Check for duplicate IDs
    let mut seen = HashMap::new();
    for entry in entries {
        if seen.insert(entry.id.clone(), ()).is_some() {
            return Err(HierarchyError::Topology(format!(
                "duplicate CA id: '{}'",
                entry.id
            )));
        }
    }

    // Find roots
    let roots: Vec<&CaEntry> = entries.iter().filter(|e| e.ca_type == "root").collect();
    if roots.is_empty() {
        return Err(HierarchyError::Topology("no root CA defined".into()));
    }
    if roots.len() > 1 {
        return Err(HierarchyError::Topology(format!(
            "multiple root CAs defined: {}",
            roots
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    let root_id = roots[0].id.clone();

    // Verify root has no parent
    if roots[0].parent.is_some() {
        return Err(HierarchyError::Topology(
            "root CA must not have a parent".into(),
        ));
    }

    // Build initial nodes
    let mut nodes: HashMap<String, TreeNode> = HashMap::new();
    for entry in entries {
        nodes.insert(
            entry.id.clone(),
            TreeNode {
                entry: entry.clone(),
                children: Vec::new(),
                depth: 0,
            },
        );
    }

    // Resolve parent-child relationships
    for entry in entries {
        if let Some(ref parent_id) = entry.parent {
            if !nodes.contains_key(parent_id) {
                return Err(HierarchyError::Topology(format!(
                    "CA '{}' references unknown parent '{}'",
                    entry.id, parent_id
                )));
            }
            nodes
                .get_mut(parent_id)
                .expect("parent verified by contains_key above")
                .children
                .push(entry.id.clone());
        } else if entry.ca_type != "root" {
            return Err(HierarchyError::Topology(format!(
                "intermediate CA '{}' must have a parent",
                entry.id
            )));
        }
    }

    // Compute depths via BFS and produce build order
    let mut build_order = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back((root_id.clone(), 0usize));

    while let Some((id, depth)) = queue.pop_front() {
        nodes
            .get_mut(&id)
            .expect("BFS only visits known nodes")
            .depth = depth;
        build_order.push(id.clone());
        let children = nodes[&id].children.clone();
        for child_id in children {
            queue.push_back((child_id, depth + 1));
        }
    }

    // Verify all nodes were visited (detect orphans/cycles)
    if build_order.len() != entries.len() {
        let visited: HashSet<_> = build_order.iter().collect();
        let orphans: Vec<_> = entries
            .iter()
            .filter(|e| !visited.contains(&e.id))
            .map(|e| e.id.as_str())
            .collect();
        return Err(HierarchyError::Topology(format!(
            "orphaned CAs not reachable from root: {}",
            orphans.join(", ")
        )));
    }

    Ok(HierarchyTree {
        root_id,
        nodes,
        build_order,
    })
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

    fn root_entry(id: &str) -> CaEntry {
        CaEntry {
            id: id.to_string(),
            ca_type: "root".to_string(),
            parent: None,
            algorithm: "ecdsa-p256".to_string(),
            common_name: format!("{} CA", id),
            ou: None,
            validity_years: 20,
            path_length: None,
            cdp: None,
            aia: None,
            policies: None,
            eku: None,
        }
    }

    fn intermediate_entry(id: &str, parent: &str) -> CaEntry {
        CaEntry {
            id: id.to_string(),
            ca_type: "intermediate".to_string(),
            parent: Some(parent.to_string()),
            algorithm: "ecdsa-p256".to_string(),
            common_name: format!("{} CA", id),
            ou: None,
            validity_years: 10,
            path_length: Some(0),
            cdp: None,
            aia: None,
            policies: None,
            eku: None,
        }
    }

    #[test]
    fn test_simple_hierarchy() {
        let config = make_config(vec![
            root_entry("root"),
            intermediate_entry("policy", "root"),
            intermediate_entry("issuing", "policy"),
        ]);
        let tree = build_tree(&config).unwrap();
        assert_eq!(tree.root_id, "root");
        assert_eq!(tree.build_order, vec!["root", "policy", "issuing"]);
        assert_eq!(tree.nodes["root"].depth, 0);
        assert_eq!(tree.nodes["policy"].depth, 1);
        assert_eq!(tree.nodes["issuing"].depth, 2);
    }

    #[test]
    fn test_wide_hierarchy() {
        let config = make_config(vec![
            root_entry("root"),
            intermediate_entry("tls", "root"),
            intermediate_entry("signing", "root"),
            intermediate_entry("email", "root"),
        ]);
        let tree = build_tree(&config).unwrap();
        assert_eq!(tree.build_order[0], "root");
        assert_eq!(tree.build_order.len(), 4);
        // All children at depth 1
        assert_eq!(tree.nodes["tls"].depth, 1);
        assert_eq!(tree.nodes["signing"].depth, 1);
        assert_eq!(tree.nodes["email"].depth, 1);
    }

    #[test]
    fn test_duplicate_ids() {
        let config = make_config(vec![
            root_entry("root"),
            intermediate_entry("dup", "root"),
            intermediate_entry("dup", "root"),
        ]);
        assert!(build_tree(&config).is_err());
    }

    #[test]
    fn test_no_root() {
        let config = make_config(vec![intermediate_entry("orphan", "missing")]);
        assert!(build_tree(&config).is_err());
    }

    #[test]
    fn test_multiple_roots() {
        let config = make_config(vec![root_entry("root1"), root_entry("root2")]);
        assert!(build_tree(&config).is_err());
    }

    #[test]
    fn test_missing_parent() {
        let config = make_config(vec![
            root_entry("root"),
            intermediate_entry("child", "nonexistent"),
        ]);
        assert!(build_tree(&config).is_err());
    }
}
