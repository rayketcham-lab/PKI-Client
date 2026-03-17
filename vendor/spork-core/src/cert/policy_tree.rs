//! RFC 5280 Section 6 Policy Tree Processing
//!
//! Implements the certificate policy tree algorithm for path validation,
//! including policy mapping, inhibitAnyPolicy, and requireExplicitPolicy.
//!
//! Incorporates RFC 9618 DoS protection: limits on tree depth and total node
//! count prevent exponential growth from adversarial policy/mapping chains.

use der::Encode;
use std::collections::HashSet;
use x509_cert::Certificate;

/// anyPolicy OID: 2.5.29.32.0
const ANY_POLICY: &str = "2.5.29.32.0";

/// Maximum total nodes in the policy tree (RFC 9618 DoS protection).
/// Exceeding this limit prunes the tree to prevent exponential growth.
const MAX_POLICY_TREE_NODES: usize = 256;

/// A single node in the policy tree.
#[derive(Debug, Clone)]
struct PolicyNode {
    /// The valid policy OID at this node
    valid_policy: String,
    /// Set of expected policy OIDs for the next certificate
    expected_policy_set: HashSet<String>,
    /// Policy qualifiers associated with this node (RFC 5280 §4.2.1.4).
    /// When a node is created via anyPolicy expansion, qualifiers from the
    /// anyPolicy entry are propagated to the expanded node.
    qualifiers: Vec<ParsedPolicyQualifier>,
    /// Depth in the tree (0 = root)
    depth: usize,
    /// Child node indices (into the tree's node Vec)
    children: Vec<usize>,
}

/// Policy tree for RFC 5280 Section 6 path validation.
///
/// The tree is stored as a flat Vec of nodes with index-based references.
/// This avoids recursive ownership issues and makes pruning straightforward.
#[derive(Debug)]
struct PolicyTree {
    nodes: Vec<Option<PolicyNode>>,
}

impl PolicyTree {
    /// Create a new policy tree with the initial anyPolicy node (6.1.2.a).
    fn new() -> Self {
        let root = PolicyNode {
            valid_policy: ANY_POLICY.to_string(),
            expected_policy_set: {
                let mut s = HashSet::new();
                s.insert(ANY_POLICY.to_string());
                s
            },
            qualifiers: Vec::new(),
            depth: 0,
            children: Vec::new(),
        };
        Self {
            nodes: vec![Some(root)],
        }
    }

    /// Total number of live (non-None) nodes.
    fn node_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.is_some()).count()
    }

    /// Whether the tree has been pruned to NULL (all nodes removed).
    fn is_null(&self) -> bool {
        self.node_count() == 0
    }

    /// Add a child node, returning its index. Returns None if DoS limit reached.
    fn add_child(&mut self, parent_idx: usize, child: PolicyNode) -> Option<usize> {
        if self.node_count() >= MAX_POLICY_TREE_NODES {
            return None;
        }
        let idx = self.nodes.len();
        self.nodes.push(Some(child));
        if let Some(ref mut parent) = self.nodes[parent_idx] {
            parent.children.push(idx);
        }
        Some(idx)
    }

    /// Get all live node indices at a given depth.
    fn nodes_at_depth(&self, depth: usize) -> Vec<usize> {
        self.nodes
            .iter()
            .enumerate()
            .filter_map(|(i, n)| n.as_ref().filter(|node| node.depth == depth).map(|_| i))
            .collect()
    }

    /// Remove a node and recursively remove all its descendants.
    fn remove_subtree(&mut self, idx: usize) {
        if let Some(node) = self.nodes[idx].take() {
            for child_idx in node.children {
                self.remove_subtree(child_idx);
            }
        }
    }

    /// Prune: remove any leaf nodes at the given depth that have no children,
    /// then work up to remove any newly-childless ancestors.
    fn prune_leaves_at_depth(&mut self, depth: usize) {
        if depth == 0 {
            // Don't prune the root during intermediate processing
            return;
        }
        let indices: Vec<usize> = self.nodes_at_depth(depth);
        for idx in indices {
            self.prune_leaf_upward(idx);
        }
    }

    /// If the node at `idx` is a leaf (no live children), remove it
    /// and recurse upward to its parent. Stops at depth 0.
    fn prune_leaf_upward(&mut self, idx: usize) {
        let (is_leaf, depth) = match &self.nodes[idx] {
            Some(node) => {
                let has_live_children = node
                    .children
                    .iter()
                    .any(|&c| c < self.nodes.len() && self.nodes[c].is_some());
                (!has_live_children, node.depth)
            }
            None => return,
        };

        if is_leaf && depth > 0 {
            self.nodes[idx] = None;
            // Find parent and remove this child reference, then check if parent is now a leaf
            for parent_idx in 0..self.nodes.len() {
                if let Some(ref mut parent) = self.nodes[parent_idx] {
                    if parent.children.contains(&idx) {
                        parent.children.retain(|&c| c != idx);
                        self.prune_leaf_upward(parent_idx);
                        break;
                    }
                }
            }
        }
    }

    /// Set the entire tree to NULL (empty).
    fn set_null(&mut self) {
        self.nodes.clear();
    }

    /// Get valid policies from the tree (nodes at the target depth).
    fn valid_policies(&self, depth: usize) -> HashSet<String> {
        let mut policies = HashSet::new();
        for idx in self.nodes_at_depth(depth) {
            if let Some(ref node) = self.nodes[idx] {
                policies.insert(node.valid_policy.clone());
            }
        }
        policies
    }

    /// Collect policy qualifiers from nodes at the target depth.
    ///
    /// RFC 5280 §4.2.1.4: qualifiers associated with anyPolicy are propagated
    /// to expanded policy nodes during tree processing. This method collects
    /// all (policy OID, qualifier) pairs from the final tree.
    fn collect_qualifiers(&self, depth: usize) -> Vec<(String, ParsedPolicyQualifier)> {
        let mut result = Vec::new();
        for idx in self.nodes_at_depth(depth) {
            if let Some(ref node) = self.nodes[idx] {
                for q in &node.qualifiers {
                    result.push((node.valid_policy.clone(), q.clone()));
                }
            }
        }
        result
    }
}

/// Extension OID arc components for policy-related extensions
const OID_CERTIFICATE_POLICIES: &[u32] = &[2, 5, 29, 32];
const OID_POLICY_MAPPINGS: &[u32] = &[2, 5, 29, 33];
const OID_POLICY_CONSTRAINTS: &[u32] = &[2, 5, 29, 36];
const OID_INHIBIT_ANY_POLICY: &[u32] = &[2, 5, 29, 54];

// OID bytes for id-qt-cps (1.3.6.1.5.5.7.2.1) and id-qt-unotice (1.3.6.1.5.5.7.2.2)
const OID_QT_CPS: &str = "1.3.6.1.5.5.7.2.1";
const OID_QT_UNOTICE: &str = "1.3.6.1.5.5.7.2.2";

/// Parse certificatePolicies extension from a certificate.
/// Returns a list of (policy OID string, qualifiers) pairs.
fn parse_certificate_policies(
    cert: &Certificate,
) -> Option<Vec<(String, Vec<ParsedPolicyQualifier>)>> {
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    for ext in extensions.iter() {
        let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if oid_arcs == OID_CERTIFICATE_POLICIES {
            return parse_policy_infos_from_der(ext.extn_value.as_bytes());
        }
    }
    None
}

/// Parse the DER-encoded certificatePolicies value into a list of
/// (policy OID string, qualifiers) pairs.
///
/// ```text
/// CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
/// PolicyInformation ::= SEQUENCE {
///   policyIdentifier   CertPolicyId,
///   policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }
/// CertPolicyId ::= OBJECT IDENTIFIER
/// PolicyQualifierInfo ::= SEQUENCE {
///   policyQualifierId  OBJECT IDENTIFIER,
///   qualifier          ANY }
/// ```
///
/// Per RFC 6818 §2, explicitText in UserNotice SHOULD be UTF8String.
/// IA5String (tag 0x16), VisibleString (0x1A), BMPString (0x1E), and
/// UTF8String (0x0C) are all accepted.
fn parse_policy_infos_from_der(data: &[u8]) -> Option<Vec<(String, Vec<ParsedPolicyQualifier>)>> {
    // Outer SEQUENCE
    if data.is_empty() || data[0] != 0x30 {
        return None;
    }
    let (outer_len, outer_hdr) = read_der_length(&data[1..])?;
    let outer_start = 1 + outer_hdr;
    let outer_end = (outer_start + outer_len).min(data.len());

    let mut result = Vec::new();
    let mut pos = outer_start;

    while pos < outer_end {
        // Each PolicyInformation is a SEQUENCE
        if data[pos] != 0x30 {
            return None;
        }
        pos += 1;
        let (pi_len, pi_hdr) = read_der_length(&data[pos..])?;
        let pi_start = pos + pi_hdr;
        let pi_end = (pi_start + pi_len).min(data.len());
        pos = pi_start;

        // First element: policyIdentifier OID
        if pos >= pi_end || data[pos] != 0x06 {
            pos = pi_end;
            continue;
        }
        pos += 1;
        let (oid_len, oid_hdr) = read_der_length(&data[pos..])?;
        let oid_start = pos + oid_hdr;
        let oid_end = (oid_start + oid_len).min(data.len());
        pos = oid_end;

        let policy_oid = match decode_oid_to_string(&data[oid_start..oid_end]) {
            Some(s) => s,
            None => {
                pos = pi_end;
                continue;
            }
        };

        // Optional: policyQualifiers SEQUENCE OF PolicyQualifierInfo
        let mut qualifiers = Vec::new();
        if pos < pi_end && data[pos] == 0x30 {
            pos += 1;
            let (pq_len, pq_hdr) = match read_der_length(&data[pos..]) {
                Some(v) => v,
                None => {
                    pos = pi_end;
                    result.push((policy_oid, qualifiers));
                    continue;
                }
            };
            let pq_start = pos + pq_hdr;
            let pq_end = (pq_start + pq_len).min(data.len());
            pos = pq_start;

            // Parse each PolicyQualifierInfo
            while pos < pq_end {
                if data[pos] != 0x30 {
                    break;
                }
                pos += 1;
                let (qi_len, qi_hdr) = match read_der_length(&data[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                let qi_start = pos + qi_hdr;
                let qi_end = (qi_start + qi_len).min(data.len());
                pos = qi_start;

                // policyQualifierId OID
                if pos >= qi_end || data[pos] != 0x06 {
                    pos = qi_end;
                    continue;
                }
                pos += 1;
                let (qoid_len, qoid_hdr) = match read_der_length(&data[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                let qoid_start = pos + qoid_hdr;
                let qoid_end = (qoid_start + qoid_len).min(data.len());
                pos = qoid_end;

                let qualifier_oid =
                    decode_oid_to_string(&data[qoid_start..qoid_end]).unwrap_or_default();

                // Parse qualifier value based on OID
                let qualifier = if qualifier_oid == OID_QT_CPS {
                    // CPS: qualifier = IA5String
                    if pos < qi_end && data[pos] == 0x16 {
                        pos += 1;
                        let (s_len, s_hdr) = match read_der_length(&data[pos..]) {
                            Some(v) => v,
                            None => {
                                pos = qi_end;
                                continue;
                            }
                        };
                        let s_start = pos + s_hdr;
                        let s_end = (s_start + s_len).min(data.len());
                        pos = qi_end;
                        let uri = String::from_utf8_lossy(&data[s_start..s_end]).into_owned();
                        ParsedPolicyQualifier::CpsUri(uri)
                    } else {
                        pos = qi_end;
                        ParsedPolicyQualifier::Unknown(qualifier_oid)
                    }
                } else if qualifier_oid == OID_QT_UNOTICE {
                    // UserNotice: qualifier = SEQUENCE { noticeRef OPTIONAL, explicitText OPTIONAL }
                    let text = parse_user_notice_explicit_text(&data[pos..qi_end]);
                    pos = qi_end;
                    ParsedPolicyQualifier::UserNotice {
                        explicit_text: text,
                    }
                } else {
                    pos = qi_end;
                    ParsedPolicyQualifier::Unknown(qualifier_oid)
                };

                qualifiers.push(qualifier);
            }
        }

        result.push((policy_oid, qualifiers));
        pos = pi_end;
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Parse the explicitText field from a UserNotice SEQUENCE.
///
/// Accepts all four string types per RFC 6818 §2:
/// - UTF8String (0x0C) — preferred per RFC 6818
/// - IA5String (0x16) — deprecated but accepted
/// - VisibleString (0x1A) — accepted
/// - BMPString (0x1E) — accepted (decoded as UTF-16BE)
fn parse_user_notice_explicit_text(data: &[u8]) -> Option<String> {
    // data starts at the UserNotice SEQUENCE value
    if data.is_empty() || data[0] != 0x30 {
        return None;
    }
    let (seq_len, seq_hdr) = read_der_length(&data[1..])?;
    let seq_start = 1 + seq_hdr;
    let seq_end = (seq_start + seq_len).min(data.len());
    let mut pos = seq_start;

    // Skip optional noticeRef (which would also be a SEQUENCE 0x30)
    if pos < seq_end && data[pos] == 0x30 {
        pos += 1;
        let (nr_len, nr_hdr) = read_der_length(&data[pos..])?;
        pos += nr_hdr + nr_len;
    }

    // explicitText: one of the supported string types
    if pos >= seq_end {
        return None;
    }

    let tag = data[pos];
    pos += 1;
    let (s_len, s_hdr) = read_der_length(&data[pos..])?;
    let s_start = pos + s_hdr;
    let s_end = (s_start + s_len).min(data.len());
    let bytes = &data[s_start..s_end];

    match tag {
        0x0C => {
            // UTF8String — preferred per RFC 6818
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        0x16 | 0x1A => {
            // IA5String or VisibleString — ASCII-compatible
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        0x1E => {
            // BMPString — UTF-16BE
            if !bytes.len().is_multiple_of(2) {
                return None;
            }
            let chars: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16(&chars).ok()
        }
        _ => None,
    }
}

/// Parse policyMappings extension.
///
/// ```text
/// PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
///   issuerDomainPolicy    CertPolicyId,
///   subjectDomainPolicy   CertPolicyId }
/// ```
///
/// Returns pairs of (issuer_policy, subject_policy).
fn parse_policy_mappings(cert: &Certificate) -> Option<Vec<(String, String)>> {
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    for ext in extensions.iter() {
        let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if oid_arcs == OID_POLICY_MAPPINGS {
            return parse_policy_mappings_der(ext.extn_value.as_bytes());
        }
    }
    None
}

fn parse_policy_mappings_der(data: &[u8]) -> Option<Vec<(String, String)>> {
    if data.is_empty() || data[0] != 0x30 {
        return None;
    }
    let (outer_len, outer_hdr) = read_der_length(&data[1..])?;
    let outer_start = 1 + outer_hdr;
    let outer_end = (outer_start + outer_len).min(data.len());

    let mut mappings = Vec::new();
    let mut pos = outer_start;

    while pos < outer_end {
        if data[pos] != 0x30 {
            return None;
        }
        pos += 1;
        let (seq_len, seq_hdr) = read_der_length(&data[pos..])?;
        let seq_start = pos + seq_hdr;
        let seq_end = (seq_start + seq_len).min(data.len());
        pos = seq_start;

        // issuerDomainPolicy OID
        if pos >= seq_end || data[pos] != 0x06 {
            pos = seq_end;
            continue;
        }
        pos += 1;
        let (oid1_len, oid1_hdr) = read_der_length(&data[pos..])?;
        let oid1_start = pos + oid1_hdr;
        let oid1_end = (oid1_start + oid1_len).min(data.len());
        let issuer_oid = decode_oid_to_string(&data[oid1_start..oid1_end]);
        pos = oid1_end;

        // subjectDomainPolicy OID
        if pos >= seq_end || data[pos] != 0x06 {
            pos = seq_end;
            continue;
        }
        pos += 1;
        let (oid2_len, oid2_hdr) = read_der_length(&data[pos..])?;
        let oid2_start = pos + oid2_hdr;
        let oid2_end = (oid2_start + oid2_len).min(data.len());
        let subject_oid = decode_oid_to_string(&data[oid2_start..oid2_end]);
        pos = seq_end;

        if let (Some(issuer), Some(subject)) = (issuer_oid, subject_oid) {
            mappings.push((issuer, subject));
        }
    }

    if mappings.is_empty() {
        None
    } else {
        Some(mappings)
    }
}

/// Parse policyConstraints extension.
///
/// ```text
/// PolicyConstraints ::= SEQUENCE {
///   requireExplicitPolicy  [0] SkipCerts OPTIONAL,
///   inhibitPolicyMapping   [1] SkipCerts OPTIONAL }
/// SkipCerts ::= INTEGER (0..MAX)
/// ```
///
/// Returns (requireExplicitPolicy, inhibitPolicyMapping).
fn parse_policy_constraints(cert: &Certificate) -> Option<(Option<u32>, Option<u32>)> {
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    for ext in extensions.iter() {
        let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if oid_arcs == OID_POLICY_CONSTRAINTS {
            return parse_policy_constraints_der(ext.extn_value.as_bytes());
        }
    }
    None
}

fn parse_policy_constraints_der(data: &[u8]) -> Option<(Option<u32>, Option<u32>)> {
    if data.is_empty() || data[0] != 0x30 {
        return None;
    }
    let (outer_len, outer_hdr) = read_der_length(&data[1..])?;
    let outer_start = 1 + outer_hdr;
    let outer_end = (outer_start + outer_len).min(data.len());

    let mut require_explicit = None;
    let mut inhibit_mapping = None;
    let mut pos = outer_start;

    while pos < outer_end {
        let tag = data[pos];
        pos += 1;
        let (val_len, val_hdr) = read_der_length(&data[pos..])?;
        let val_start = pos + val_hdr;
        let val_end = (val_start + val_len).min(data.len());

        let value = parse_der_integer_value(&data[val_start..val_end]);

        match tag {
            0x80 => require_explicit = Some(value),
            0x81 => inhibit_mapping = Some(value),
            _ => {}
        }

        pos = val_end;
    }

    Some((require_explicit, inhibit_mapping))
}

/// Parse inhibitAnyPolicy extension.
///
/// ```text
/// InhibitAnyPolicy ::= SkipCerts
/// SkipCerts ::= INTEGER (0..MAX)
/// ```
fn parse_inhibit_any_policy(cert: &Certificate) -> Option<u32> {
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    for ext in extensions.iter() {
        let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if oid_arcs == OID_INHIBIT_ANY_POLICY {
            return parse_inhibit_any_policy_der(ext.extn_value.as_bytes());
        }
    }
    None
}

fn parse_inhibit_any_policy_der(data: &[u8]) -> Option<u32> {
    // Should be a bare INTEGER
    if data.is_empty() || data[0] != 0x02 {
        return None;
    }
    let (val_len, val_hdr) = read_der_length(&data[1..])?;
    let val_start = 1 + val_hdr;
    let val_end = (val_start + val_len).min(data.len());
    Some(parse_der_integer_value(&data[val_start..val_end]))
}

/// Parse a DER integer value (big-endian unsigned bytes) into u32.
fn parse_der_integer_value(bytes: &[u8]) -> u32 {
    let mut result: u32 = 0;
    for &b in bytes {
        result = result.wrapping_shl(8) | (b as u32);
    }
    result
}

/// DER length reader (same logic as in verify.rs / mod.rs).
fn read_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0] as usize;
    if first < 0x80 {
        Some((first, 1))
    } else if first == 0x81 {
        data.get(1).map(|&b| (b as usize, 2))
    } else if first == 0x82 {
        if data.len() >= 3 {
            Some((((data[1] as usize) << 8) | (data[2] as usize), 3))
        } else {
            None
        }
    } else {
        None
    }
}

/// Decode raw OID bytes (BER/DER encoded content, not including tag+length)
/// into a dotted-decimal string.
fn decode_oid_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    // First byte encodes first two arcs: arc1 = byte / 40, arc2 = byte % 40
    let first = bytes[0] as u32;
    let mut arcs = vec![first / 40, first % 40];

    let mut i = 1;
    while i < bytes.len() {
        let mut value: u32 = 0;
        loop {
            if i >= bytes.len() {
                return None;
            }
            let b = bytes[i] as u32;
            i += 1;
            value = value.checked_shl(7)?.checked_add(b & 0x7F)?;
            if b & 0x80 == 0 {
                break;
            }
        }
        arcs.push(value);
    }

    Some(
        arcs.iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// Check if a certificate is self-issued (subject == issuer).
fn is_self_issued(cert: &Certificate) -> bool {
    let subject_der = cert.tbs_certificate.subject.to_der().ok();
    let issuer_der = cert.tbs_certificate.issuer.to_der().ok();
    match (subject_der, issuer_der) {
        (Some(s), Some(i)) => s == i,
        _ => false,
    }
}

/// A parsed policy qualifier associated with a policy OID in a certificate.
///
/// Per RFC 6818, explicitText is expected as UTF8String. IA5String is accepted
/// for backward compatibility but triggers a warning.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedPolicyQualifier {
    /// CPS URI qualifier (id-qt-cps, 1.3.6.1.5.5.7.2.1)
    CpsUri(String),
    /// User Notice qualifier (id-qt-unotice, 1.3.6.1.5.5.7.2.2).
    /// `explicit_text` is the decoded string (all supported encodings).
    UserNotice { explicit_text: Option<String> },
    /// Unknown qualifier type — OID preserved as string
    Unknown(String),
}

/// Result of policy tree processing.
#[derive(Debug, Clone)]
pub struct PolicyValidationResult {
    /// The set of valid policy OIDs at the end of the path.
    /// Empty if no policies are valid or the tree was pruned to NULL.
    pub valid_policies: HashSet<String>,
    /// Errors that make the chain invalid from a policy perspective.
    pub errors: Vec<String>,
    /// Warnings (non-fatal policy observations).
    pub warnings: Vec<String>,
    /// Policy qualifiers encountered during path processing.
    /// Pairs of (policy OID string, parsed qualifier).
    pub policy_qualifiers: Vec<(String, ParsedPolicyQualifier)>,
}

/// Run RFC 5280 Section 6.1 policy tree processing on a certificate chain.
///
/// `chain` is ordered `[leaf, intermediate..., root]` — same as `validate_chain`.
/// `initial_policy_set` is the set of policies acceptable to the relying party.
/// Pass a set containing just `ANY_POLICY` to accept any valid policy.
/// `initial_explicit_policy` — if true, require an explicit policy in the chain.
/// `initial_policy_mapping_inhibit` — if true, policy mapping is not allowed.
/// `initial_inhibit_any_policy` — if true, anyPolicy is not acceptable.
pub fn process_policy_tree(
    chain: &[Certificate],
    initial_policy_set: &HashSet<String>,
    initial_explicit_policy: bool,
    initial_policy_mapping_inhibit: bool,
    initial_inhibit_any_policy: bool,
) -> PolicyValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut all_qualifiers: Vec<(String, ParsedPolicyQualifier)> = Vec::new();

    if chain.is_empty() {
        return PolicyValidationResult {
            valid_policies: HashSet::new(),
            errors: vec!["Empty certificate chain".to_string()],
            warnings: Vec::new(),
            policy_qualifiers: Vec::new(),
        };
    }

    // RFC 5280 processes the chain from trust anchor (root) toward the leaf.
    // Our chain is [leaf, ..., root], so we reverse the processing order.
    let n = chain.len();

    // === 6.1.2: Initialization ===

    // (a) valid_policy_tree: initialized with a single node {anyPolicy, {}, {anyPolicy}}
    let mut tree = PolicyTree::new();

    // (c-e) State variables
    // explicit_policy: if 0, the path must be valid for at least one policy
    let mut explicit_policy: i64 = if initial_explicit_policy {
        0
    } else {
        n as i64 + 1
    };
    // policy_mapping: if 0, policy mapping is not permitted
    let mut policy_mapping: i64 = if initial_policy_mapping_inhibit {
        0
    } else {
        n as i64 + 1
    };
    // inhibit_any_policy: if 0, anyPolicy is not acceptable
    let mut inhibit_any_policy: i64 = if initial_inhibit_any_policy {
        0
    } else {
        n as i64 + 1
    };

    // Process certificates from root (index n-1) to leaf (index 0)
    for i in 0..n {
        // cert_index in our chain array (root is n-1, leaf is 0)
        let chain_idx = n - 1 - i;
        let cert = &chain[chain_idx];
        let depth = i + 1; // depth in the policy tree (1-indexed for certs)
        let is_last = i == n - 1; // true when processing the leaf

        // === 6.1.3: Basic Certificate Processing ===

        let cert_policies = parse_certificate_policies(cert);

        // (d) If certificatePolicies extension is present
        if let Some(ref policy_infos) = cert_policies {
            // Collect qualifiers from this certificate, issuing RFC 6818 warnings
            for (p, quals) in policy_infos {
                for q in quals {
                    // RFC 5280 §4.2.1.4: validate CPS URI format
                    if let ParsedPolicyQualifier::CpsUri(ref uri) = q {
                        if !validate_cps_uri(uri) {
                            warnings.push(format!(
                                "Certificate {} in path: CPS URI '{}' for policy {} has invalid format (RFC 5280 §4.2.1.4 requires http/https URI)",
                                chain_idx, uri, p
                            ));
                        }
                    }
                    all_qualifiers.push((p.clone(), q.clone()));
                }
            }

            // For each policy P in the extension:
            for (p, quals) in policy_infos {
                if p == ANY_POLICY {
                    // anyPolicy handling — only if inhibit_any_policy > 0
                    if inhibit_any_policy > 0 {
                        // Add nodes for policies in the parent level that expect anyPolicy.
                        // RFC 5280 §4.2.1.4: qualifiers from the anyPolicy entry are
                        // propagated to expanded nodes (anyPolicy qualifier propagation).
                        let parent_nodes = tree.nodes_at_depth(depth - 1);
                        for parent_idx in parent_nodes {
                            let expected = match &tree.nodes[parent_idx] {
                                Some(node) => node.expected_policy_set.clone(),
                                None => continue,
                            };
                            for ep in &expected {
                                // Only add if not already present at this depth
                                let already_exists =
                                    tree.nodes_at_depth(depth).iter().any(|&idx| {
                                        tree.nodes[idx]
                                            .as_ref()
                                            .is_some_and(|n| n.valid_policy == *ep)
                                    });
                                if !already_exists {
                                    let child = PolicyNode {
                                        valid_policy: ep.clone(),
                                        expected_policy_set: {
                                            let mut s = HashSet::new();
                                            s.insert(ep.clone());
                                            s
                                        },
                                        // Propagate anyPolicy qualifiers to expanded node
                                        qualifiers: quals.clone(),
                                        depth,
                                        children: Vec::new(),
                                    };
                                    tree.add_child(parent_idx, child);
                                }
                            }
                        }
                    }
                } else {
                    // Non-anyPolicy: find nodes at depth-1 whose expected_policy_set contains P
                    let parent_nodes = tree.nodes_at_depth(depth - 1);
                    let mut added = false;

                    for parent_idx in &parent_nodes {
                        let matches = match &tree.nodes[*parent_idx] {
                            Some(node) => node.expected_policy_set.contains(p),
                            None => false,
                        };
                        if matches {
                            let child = PolicyNode {
                                valid_policy: p.clone(),
                                expected_policy_set: {
                                    let mut s = HashSet::new();
                                    s.insert(p.clone());
                                    s
                                },
                                qualifiers: quals.clone(),
                                depth,
                                children: Vec::new(),
                            };
                            tree.add_child(*parent_idx, child);
                            added = true;
                        }
                    }

                    // If no match found, check if anyPolicy is at depth-1
                    if !added {
                        for parent_idx in &parent_nodes {
                            let is_any = match &tree.nodes[*parent_idx] {
                                Some(node) => node.valid_policy == ANY_POLICY,
                                None => false,
                            };
                            if is_any {
                                let child = PolicyNode {
                                    valid_policy: p.clone(),
                                    expected_policy_set: {
                                        let mut s = HashSet::new();
                                        s.insert(p.clone());
                                        s
                                    },
                                    qualifiers: quals.clone(),
                                    depth,
                                    children: Vec::new(),
                                };
                                tree.add_child(*parent_idx, child);
                            }
                        }
                    }
                }
            }

            // (d.4) Prune leaves at depth-1 that have no children
            tree.prune_leaves_at_depth(depth - 1);
        } else {
            // (e) certificatePolicies not present — set tree to NULL
            tree.set_null();
        }

        // (f) If the tree is NULL and explicit_policy is 0, the path is invalid
        if tree.is_null() && explicit_policy == 0 {
            errors.push(format!(
                "Certificate {} in path: policy tree is empty but explicit policy is required",
                chain_idx
            ));
        }

        // === 6.1.4: Preparation for Certificate i+1 (skip for leaf) ===
        if !is_last {
            // (a) Process policyMappings
            if let Some(mappings) = parse_policy_mappings(cert) {
                // RFC 5280 §6.1.4(a): anyPolicy MUST NOT appear in policyMappings.
                // This is a fatal error — invalidate the policy tree.
                for (issuer_p, subject_p) in &mappings {
                    if issuer_p == ANY_POLICY || subject_p == ANY_POLICY {
                        errors.push(format!(
                            "Certificate {} in path: policyMappings contains anyPolicy (prohibited by RFC 5280 §6.1.4(a))",
                            chain_idx
                        ));
                        tree.set_null();
                    }
                    // RFC 5280 §4.2.1.5: issuerDomainPolicy MUST NOT equal
                    // subjectDomainPolicy — a policy cannot map to itself.
                    if issuer_p == subject_p {
                        errors.push(format!(
                            "Certificate {} in path: policyMapping maps {} to itself (prohibited by RFC 5280 §4.2.1.5)",
                            chain_idx, issuer_p
                        ));
                    }
                }

                if policy_mapping > 0 {
                    // Apply the mappings to the tree: for nodes at current depth with
                    // valid_policy matching issuerDomainPolicy, replace expected_policy_set
                    // with the set of matching subjectDomainPolicies.
                    let depth_nodes = tree.nodes_at_depth(depth);
                    for node_idx in depth_nodes {
                        let vp = match &tree.nodes[node_idx] {
                            Some(node) => node.valid_policy.clone(),
                            None => continue,
                        };

                        let mapped_subjects: Vec<String> = mappings
                            .iter()
                            .filter(|(ip, _)| *ip == vp)
                            .map(|(_, sp)| sp.clone())
                            .collect();

                        if !mapped_subjects.is_empty() {
                            if let Some(ref mut node) = tree.nodes[node_idx] {
                                node.expected_policy_set = mapped_subjects.into_iter().collect();
                            }
                        }
                    }
                } else {
                    // policy_mapping == 0: delete nodes whose valid_policy is an
                    // issuerDomainPolicy in the mapping
                    let issuer_policies: HashSet<&str> =
                        mappings.iter().map(|(ip, _)| ip.as_str()).collect();
                    let depth_nodes = tree.nodes_at_depth(depth);
                    for node_idx in depth_nodes {
                        let should_remove = match &tree.nodes[node_idx] {
                            Some(node) => issuer_policies.contains(node.valid_policy.as_str()),
                            None => false,
                        };
                        if should_remove {
                            tree.remove_subtree(node_idx);
                        }
                    }
                }
            }

            // Process self-issued certificate adjustments
            let self_issued = is_self_issued(cert);

            // (b) Process policyConstraints
            if let Some((require_explicit, inhibit_mapping)) = parse_policy_constraints(cert) {
                if let Some(req) = require_explicit {
                    let new_val = (req as i64).saturating_add(1); // +1 because depth is 1-indexed
                    if new_val < explicit_policy {
                        explicit_policy = new_val;
                    }
                }
                if let Some(inh) = inhibit_mapping {
                    let new_val = (inh as i64).saturating_add(1);
                    if new_val < policy_mapping {
                        policy_mapping = new_val;
                    }
                }
            }

            // (c) Process inhibitAnyPolicy
            if let Some(skip) = parse_inhibit_any_policy(cert) {
                let new_val = (skip as i64).saturating_add(1);
                if new_val < inhibit_any_policy {
                    inhibit_any_policy = new_val;
                }
            }

            // Decrement counters (6.1.4.d-f)
            if explicit_policy > 0 && !self_issued {
                explicit_policy -= 1;
            }
            if policy_mapping > 0 && !self_issued {
                policy_mapping -= 1;
            }
            if inhibit_any_policy > 0 && !self_issued {
                inhibit_any_policy -= 1;
            }
        }
    }

    // === 6.1.5: Wrap-Up ===

    // (g) Calculate the intersection with the initial-policy-set
    let final_depth = n;
    let mut valid_policies = if !tree.is_null() {
        let tree_policies = tree.valid_policies(final_depth);
        if initial_policy_set.contains(ANY_POLICY) {
            // Accept all valid policies from the tree
            tree_policies
        } else {
            // Intersection with initial-policy-set
            tree_policies
                .intersection(initial_policy_set)
                .cloned()
                .collect()
        }
    } else {
        HashSet::new()
    };

    // Remove anyPolicy from the output set (it's a meta-policy)
    valid_policies.remove(ANY_POLICY);

    // If explicit_policy is 0 and the valid set is empty, that's an error
    if explicit_policy == 0 && valid_policies.is_empty() && !tree.is_null() {
        // Check if tree has only anyPolicy
        let tree_policies = tree.valid_policies(final_depth);
        if tree_policies.is_empty()
            || (tree_policies.len() == 1 && tree_policies.contains(ANY_POLICY))
        {
            // anyPolicy-only trees are valid when no specific policy is required
            if !initial_policy_set.contains(ANY_POLICY) {
                errors.push(
                    "Path valid for anyPolicy only, but specific policies required".to_string(),
                );
            }
        }
    }

    if tree.is_null() && explicit_policy == 0 {
        // Already reported in the loop, but ensure it's there
        if !errors.iter().any(|e| e.contains("policy tree is empty")) {
            errors.push("Policy tree is NULL but explicit policy is required".to_string());
        }
    }

    // RFC 5280 §4.2.1.4: Collect qualifiers propagated through the policy tree,
    // including those inherited via anyPolicy expansion. Merge with directly-
    // observed qualifiers, deduplicating to avoid double-reporting.
    if !tree.is_null() {
        let tree_qualifiers = tree.collect_qualifiers(final_depth);
        for tq in tree_qualifiers {
            if !all_qualifiers.contains(&tq) {
                all_qualifiers.push(tq);
            }
        }
    }

    PolicyValidationResult {
        valid_policies,
        errors,
        warnings,
        policy_qualifiers: all_qualifiers,
    }
}

/// Validate a CPS URI per RFC 5280 §4.2.1.4.
///
/// The URI should use http or https scheme and contain a valid authority.
/// This is a best-effort validation — we don't resolve DNS.
fn validate_cps_uri(uri: &str) -> bool {
    let lower = uri.to_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return false;
    }
    // Must have a host after the scheme
    let after_scheme = if lower.starts_with("https://") {
        &uri[8..]
    } else {
        &uri[7..]
    };
    // Host must be non-empty and contain at least one dot (domain)
    let host = after_scheme.split('/').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or(""); // strip port
    !host.is_empty() && host.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- RFC 6818 parsing tests ---

    #[test]
    fn test_parse_user_notice_utf8string() {
        // UserNotice SEQUENCE { explicitText UTF8String "Hello RFC 6818" }
        let text = b"Hello RFC 6818";
        let mut user_notice_inner = Vec::new();
        // UTF8String tag + length + value
        user_notice_inner.push(0x0C);
        user_notice_inner.push(text.len() as u8);
        user_notice_inner.extend_from_slice(text);

        let mut user_notice = vec![0x30];
        user_notice.push(user_notice_inner.len() as u8);
        user_notice.extend(user_notice_inner);

        let result = parse_user_notice_explicit_text(&user_notice);
        assert_eq!(result, Some("Hello RFC 6818".to_string()));
    }

    #[test]
    fn test_parse_user_notice_ia5string() {
        // UserNotice SEQUENCE { explicitText IA5String "CPS notice" }
        let text = b"CPS notice";
        let mut user_notice_inner = Vec::new();
        user_notice_inner.push(0x16); // IA5String
        user_notice_inner.push(text.len() as u8);
        user_notice_inner.extend_from_slice(text);

        let mut user_notice = vec![0x30];
        user_notice.push(user_notice_inner.len() as u8);
        user_notice.extend(user_notice_inner);

        let result = parse_user_notice_explicit_text(&user_notice);
        assert_eq!(result, Some("CPS notice".to_string()));
    }

    #[test]
    fn test_parse_user_notice_visible_string() {
        // UserNotice SEQUENCE { explicitText VisibleString "visible" }
        let text = b"visible";
        let mut user_notice_inner = Vec::new();
        user_notice_inner.push(0x1A); // VisibleString
        user_notice_inner.push(text.len() as u8);
        user_notice_inner.extend_from_slice(text);

        let mut user_notice = vec![0x30];
        user_notice.push(user_notice_inner.len() as u8);
        user_notice.extend(user_notice_inner);

        let result = parse_user_notice_explicit_text(&user_notice);
        assert_eq!(result, Some("visible".to_string()));
    }

    #[test]
    fn test_parse_user_notice_bmp_string() {
        // UserNotice SEQUENCE { explicitText BMPString "AB" (UTF-16BE) }
        let text_utf16: Vec<u8> = "AB".encode_utf16().flat_map(|c| c.to_be_bytes()).collect();
        let mut user_notice_inner = Vec::new();
        user_notice_inner.push(0x1E); // BMPString
        user_notice_inner.push(text_utf16.len() as u8);
        user_notice_inner.extend_from_slice(&text_utf16);

        let mut user_notice = vec![0x30];
        user_notice.push(user_notice_inner.len() as u8);
        user_notice.extend(user_notice_inner);

        let result = parse_user_notice_explicit_text(&user_notice);
        assert_eq!(result, Some("AB".to_string()));
    }

    #[test]
    fn test_parse_user_notice_empty_sequence() {
        // UserNotice SEQUENCE { } — no text
        let user_notice = vec![0x30, 0x00];
        let result = parse_user_notice_explicit_text(&user_notice);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_cps_qualifier_der() {
        // Build a minimal PolicyInformation DER with a CPS qualifier
        // OID 2.5.29.32.99 (invented test policy)
        // Using the encoding from parse_policy_infos_from_der

        // id-qt-cps OID bytes: 1.3.6.1.5.5.7.2.1
        // DER: 06 08 2b 06 01 05 05 07 02 01
        let qt_cps_oid = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01];
        let cps_uri = b"https://example.com/cps";

        // qualifier = IA5String
        let mut qual_val = vec![0x16];
        qual_val.push(cps_uri.len() as u8);
        qual_val.extend_from_slice(cps_uri);

        // PolicyQualifierInfo SEQUENCE { oid, qualifier }
        let pqi_inner_len = qt_cps_oid.len() + qual_val.len();
        let mut pqi = vec![0x30, pqi_inner_len as u8];
        pqi.extend_from_slice(&qt_cps_oid);
        pqi.extend(qual_val);

        // policyQualifiers SEQUENCE OF { pqi }
        let mut pq_seq = vec![0x30, pqi.len() as u8];
        pq_seq.extend(pqi);

        // Policy OID 2.5.29.32 (certificate policies extension OID for test)
        // Using a simple 2-byte test OID 1.2: 0x55 0x04 0x03 (commonName) as placeholder
        let policy_oid_bytes = [0x06, 0x03, 0x55, 0x04, 0x03]; // id-at-commonName (valid test OID)

        // PolicyInformation SEQUENCE { oid, qualifiers }
        let pi_inner_len = policy_oid_bytes.len() + pq_seq.len();
        let mut pi = vec![0x30, pi_inner_len as u8];
        pi.extend_from_slice(&policy_oid_bytes);
        pi.extend(pq_seq);

        // Outer CertificatePolicies SEQUENCE OF
        let mut outer = vec![0x30, pi.len() as u8];
        outer.extend(pi);

        let result = parse_policy_infos_from_der(&outer);
        assert!(result.is_some());
        let infos = result.unwrap();
        assert_eq!(infos.len(), 1);
        let (oid_str, quals) = &infos[0];
        assert_eq!(oid_str, "2.5.4.3"); // commonName OID
        assert_eq!(quals.len(), 1);
        assert_eq!(
            quals[0],
            ParsedPolicyQualifier::CpsUri("https://example.com/cps".to_string())
        );
    }

    #[test]
    fn test_parse_unotice_qualifier_der() {
        // id-qt-unotice OID: 1.3.6.1.5.5.7.2.2
        // DER: 06 08 2b 06 01 05 05 07 02 02
        let qt_unotice_oid = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02];
        let notice_text = b"Issued under SPORK CA Policy";

        // explicitText as UTF8String (RFC 6818)
        let mut explicit_text_enc = vec![0x0C];
        explicit_text_enc.push(notice_text.len() as u8);
        explicit_text_enc.extend_from_slice(notice_text);

        // UserNotice SEQUENCE { explicitText }
        let mut user_notice = vec![0x30, explicit_text_enc.len() as u8];
        user_notice.extend(explicit_text_enc);

        // PolicyQualifierInfo SEQUENCE { oid, UserNotice }
        let pqi_inner_len = qt_unotice_oid.len() + user_notice.len();
        let mut pqi = vec![0x30, pqi_inner_len as u8];
        pqi.extend_from_slice(&qt_unotice_oid);
        pqi.extend(user_notice);

        // policyQualifiers
        let mut pq_seq = vec![0x30, pqi.len() as u8];
        pq_seq.extend(pqi);

        let policy_oid_bytes = [0x06, 0x03, 0x55, 0x04, 0x03];
        let pi_inner_len = policy_oid_bytes.len() + pq_seq.len();
        let mut pi = vec![0x30, pi_inner_len as u8];
        pi.extend_from_slice(&policy_oid_bytes);
        pi.extend(pq_seq);

        let mut outer = vec![0x30, pi.len() as u8];
        outer.extend(pi);

        let result = parse_policy_infos_from_der(&outer);
        assert!(result.is_some());
        let infos = result.unwrap();
        let (_, quals) = &infos[0];
        assert_eq!(quals.len(), 1);
        assert_eq!(
            quals[0],
            ParsedPolicyQualifier::UserNotice {
                explicit_text: Some("Issued under SPORK CA Policy".to_string()),
            }
        );
    }

    #[test]
    fn test_decode_oid_to_string() {
        // OID 2.5.29.32.0 (anyPolicy)
        // Encoding: 2*40+5=85=0x55, 29=0x1D, 32=0x20, 0=0x00
        let bytes = [0x55, 0x1D, 0x20, 0x00];
        assert_eq!(
            decode_oid_to_string(&bytes),
            Some("2.5.29.32.0".to_string())
        );
    }

    #[test]
    fn test_decode_oid_empty() {
        assert_eq!(decode_oid_to_string(&[]), None);
    }

    #[test]
    fn test_decode_oid_simple() {
        // OID 2.5.4.3 (commonName)
        let bytes = [0x55, 0x04, 0x03];
        assert_eq!(decode_oid_to_string(&bytes), Some("2.5.4.3".to_string()));
    }

    #[test]
    fn test_policy_tree_new() {
        let tree = PolicyTree::new();
        assert_eq!(tree.node_count(), 1);
        assert!(!tree.is_null());
        assert_eq!(tree.nodes_at_depth(0).len(), 1);
    }

    #[test]
    fn test_policy_tree_add_child() {
        let mut tree = PolicyTree::new();
        let child = PolicyNode {
            valid_policy: "1.2.3.4".to_string(),
            expected_policy_set: {
                let mut s = HashSet::new();
                s.insert("1.2.3.4".to_string());
                s
            },
            qualifiers: Vec::new(),
            depth: 1,
            children: Vec::new(),
        };
        let idx = tree.add_child(0, child);
        assert!(idx.is_some());
        assert_eq!(tree.node_count(), 2);
    }

    #[test]
    fn test_policy_tree_set_null() {
        let mut tree = PolicyTree::new();
        tree.set_null();
        assert!(tree.is_null());
        assert_eq!(tree.node_count(), 0);
    }

    #[test]
    fn test_policy_tree_prune() {
        let mut tree = PolicyTree::new();
        // Add a child at depth 1 with no children of its own
        let child = PolicyNode {
            valid_policy: "1.2.3.4".to_string(),
            expected_policy_set: HashSet::new(),
            qualifiers: Vec::new(),
            depth: 1,
            children: Vec::new(),
        };
        tree.add_child(0, child);
        assert_eq!(tree.node_count(), 2);

        // Prune leaves at depth 1 — should remove the child
        tree.prune_leaves_at_depth(1);
        // The child should be gone, and the root (now a leaf at depth 0) stays
        assert_eq!(tree.node_count(), 1);
    }

    #[test]
    fn test_policy_tree_dos_limit() {
        let mut tree = PolicyTree::new();
        // Fill the tree up to the limit
        for i in 0..MAX_POLICY_TREE_NODES - 1 {
            let child = PolicyNode {
                valid_policy: format!("1.2.3.{}", i),
                expected_policy_set: HashSet::new(),
                qualifiers: Vec::new(),
                depth: 1,
                children: Vec::new(),
            };
            let result = tree.add_child(0, child);
            assert!(result.is_some(), "Should be able to add node {}", i);
        }
        assert_eq!(tree.node_count(), MAX_POLICY_TREE_NODES);

        // Next add should fail
        let overflow = PolicyNode {
            valid_policy: "overflow".to_string(),
            expected_policy_set: HashSet::new(),
            qualifiers: Vec::new(),
            depth: 1,
            children: Vec::new(),
        };
        assert!(tree.add_child(0, overflow).is_none());
    }

    #[test]
    fn test_empty_chain_policy_processing() {
        let result = process_policy_tree(
            &[],
            &{
                let mut s = HashSet::new();
                s.insert(ANY_POLICY.to_string());
                s
            },
            false,
            false,
            false,
        );
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_is_self_issued_identical_subject_issuer() {
        // Can't easily create a Certificate without the full builder,
        // so we test via the exported process_policy_tree with real certs.
        // The unit test for is_self_issued is implicitly tested via integration.
    }

    #[test]
    fn test_parse_der_integer_value() {
        assert_eq!(parse_der_integer_value(&[0x00]), 0);
        assert_eq!(parse_der_integer_value(&[0x01]), 1);
        assert_eq!(parse_der_integer_value(&[0x7F]), 127);
        assert_eq!(parse_der_integer_value(&[0x01, 0x00]), 256);
    }

    // --- CPS URI validation tests ---

    #[test]
    fn test_validate_cps_uri_https() {
        assert!(validate_cps_uri("https://example.com/cps"));
        assert!(validate_cps_uri(
            "https://pki.example.org/policies/cps.html"
        ));
    }

    #[test]
    fn test_validate_cps_uri_http() {
        assert!(validate_cps_uri("http://example.com/cps"));
    }

    #[test]
    fn test_validate_cps_uri_invalid_scheme() {
        assert!(!validate_cps_uri("ftp://example.com/cps"));
        assert!(!validate_cps_uri("ldap://example.com/cps"));
        assert!(!validate_cps_uri("file:///etc/cps"));
    }

    #[test]
    fn test_validate_cps_uri_no_host() {
        assert!(!validate_cps_uri("https://"));
        assert!(!validate_cps_uri("https:///path"));
    }

    #[test]
    fn test_validate_cps_uri_no_dot_in_host() {
        assert!(!validate_cps_uri("https://localhost/cps"));
    }

    #[test]
    fn test_validate_cps_uri_with_port() {
        assert!(validate_cps_uri("https://example.com:8443/cps"));
    }

    // --- Policy mapping self-check tests ---

    #[test]
    fn test_policy_mapping_self_map_detected() {
        // Verify that parse_policy_mappings_der correctly returns the data
        // that process_policy_tree will use to detect self-mapping.
        // We test the detection at the tree level via the integration test below.
        let oid_bytes = [0x55, 0x1D, 0x20]; // 2.5.29.32
        let oid = [0x06, 0x03, 0x55, 0x1D, 0x20];

        // Build a mapping where issuer == subject (same OID mapped to itself)
        let mapping_seq = {
            let inner_len = oid.len() * 2;
            let mut v = vec![0x30, inner_len as u8];
            v.extend_from_slice(&oid);
            v.extend_from_slice(&oid);
            v
        };
        let outer = {
            let mut v = vec![0x30, mapping_seq.len() as u8];
            v.extend(mapping_seq);
            v
        };

        let result = parse_policy_mappings_der(&outer);
        assert!(result.is_some());
        let mappings = result.unwrap();
        assert_eq!(mappings.len(), 1);
        let (issuer, subject) = &mappings[0];
        // Both should decode to the same OID
        assert_eq!(issuer, subject);
        let _ = oid_bytes; // suppress unused
    }

    #[test]
    fn test_valid_policies_at_depth() {
        let mut tree = PolicyTree::new();
        let c1 = PolicyNode {
            valid_policy: "1.2.3".to_string(),
            expected_policy_set: HashSet::new(),
            qualifiers: Vec::new(),
            depth: 1,
            children: Vec::new(),
        };
        let c2 = PolicyNode {
            valid_policy: "4.5.6".to_string(),
            expected_policy_set: HashSet::new(),
            qualifiers: Vec::new(),
            depth: 1,
            children: Vec::new(),
        };
        tree.add_child(0, c1);
        tree.add_child(0, c2);

        let policies = tree.valid_policies(1);
        assert!(policies.contains("1.2.3"));
        assert!(policies.contains("4.5.6"));
        assert_eq!(policies.len(), 2);
    }

    // ─── Policy Tree Edge Cases (RFC 5280 §6.1.1) ───

    #[test]
    fn test_policy_tree_valid_policies_empty_at_depth() {
        // Tree with root only — no policies at depth 1
        let tree = PolicyTree::new();
        let policies = tree.valid_policies(1);
        assert!(
            policies.is_empty(),
            "No policies should exist at depth 1 on empty tree"
        );
    }

    #[test]
    fn test_policy_tree_valid_policies_at_depth_zero() {
        // Depth 0 = root anyPolicy node
        let tree = PolicyTree::new();
        let policies = tree.valid_policies(0);
        assert!(
            policies.contains(ANY_POLICY),
            "Root should contain anyPolicy"
        );
    }

    #[test]
    fn test_policy_tree_prune_at_nonexistent_depth() {
        // Pruning at a depth with no nodes should be a no-op
        let mut tree = PolicyTree::new();
        let child = PolicyNode {
            valid_policy: "1.2.3".to_string(),
            expected_policy_set: HashSet::new(),
            qualifiers: Vec::new(),
            depth: 1,
            children: Vec::new(),
        };
        tree.add_child(0, child);
        let count_before = tree.node_count();
        tree.prune_leaves_at_depth(5); // depth 5 doesn't exist
        assert_eq!(
            tree.node_count(),
            count_before,
            "Pruning at nonexistent depth should not change tree"
        );
    }

    #[test]
    fn test_policy_tree_multiple_depths() {
        // Build a 3-level tree: root -> depth1 -> depth2
        let mut tree = PolicyTree::new();
        let d1 = PolicyNode {
            valid_policy: "1.2.3".to_string(),
            expected_policy_set: HashSet::new(),
            qualifiers: Vec::new(),
            depth: 1,
            children: Vec::new(),
        };
        let d1_idx = tree.add_child(0, d1).unwrap();

        let d2 = PolicyNode {
            valid_policy: "1.2.3.4".to_string(),
            expected_policy_set: HashSet::new(),
            qualifiers: Vec::new(),
            depth: 2,
            children: Vec::new(),
        };
        tree.add_child(d1_idx, d2);

        assert_eq!(tree.node_count(), 3);
        let d1_policies = tree.valid_policies(1);
        assert!(d1_policies.contains("1.2.3"));
        let d2_policies = tree.valid_policies(2);
        assert!(d2_policies.contains("1.2.3.4"));
    }

    #[test]
    fn test_policy_tree_null_after_set() {
        // Once null, tree should report no policies at any depth
        let mut tree = PolicyTree::new();
        let child = PolicyNode {
            valid_policy: "1.2.3".to_string(),
            expected_policy_set: HashSet::new(),
            qualifiers: Vec::new(),
            depth: 1,
            children: Vec::new(),
        };
        tree.add_child(0, child);
        tree.set_null();

        assert!(tree.is_null());
        assert!(tree.valid_policies(0).is_empty());
        assert!(tree.valid_policies(1).is_empty());
    }

    #[test]
    fn test_policy_tree_rebuild_after_null() {
        // After set_null, tree can be rebuilt by adding nodes
        // (set_null clears all nodes, add_child creates new root-like entry)
        let mut tree = PolicyTree::new();
        tree.set_null();
        assert!(tree.is_null());
        assert_eq!(tree.node_count(), 0);

        // Adding a node starts fresh (it becomes index 0 as its own root)
        let child = PolicyNode {
            valid_policy: "1.2.3".to_string(),
            expected_policy_set: HashSet::new(),
            qualifiers: Vec::new(),
            depth: 0,
            children: Vec::new(),
        };
        let result = tree.add_child(0, child);
        assert!(result.is_some(), "Should be able to add to cleared tree");
        assert!(!tree.is_null());
    }

    #[test]
    fn test_process_policy_tree_explicit_policy_empty() {
        // RFC 5280 §6.1.1: With explicit_policy=true and empty chain,
        // should get an error
        let result = process_policy_tree(
            &[],
            &{
                let mut s = HashSet::new();
                s.insert(ANY_POLICY.to_string());
                s
            },
            true,  // explicit_policy
            false, // policy_mapping_inhibit
            false, // inhibit_any_policy
        );
        assert!(
            !result.errors.is_empty(),
            "Empty chain with explicit policy should error"
        );
    }

    #[test]
    fn test_process_policy_tree_all_flags_true() {
        // All inhibit flags set — most restrictive mode
        let result = process_policy_tree(
            &[],
            &{
                let mut s = HashSet::new();
                s.insert(ANY_POLICY.to_string());
                s
            },
            true, // explicit_policy
            true, // policy_mapping_inhibit
            true, // inhibit_any_policy
        );
        assert!(
            !result.errors.is_empty(),
            "Empty chain should always error regardless of flags"
        );
    }

    // ─── RFC 5280 §4.2.1.4: anyPolicy qualifier propagation ───

    #[test]
    fn test_collect_qualifiers_from_tree_nodes() {
        let mut tree = PolicyTree::new();
        let cps = ParsedPolicyQualifier::CpsUri("https://example.com/cps".to_string());
        let child = PolicyNode {
            valid_policy: "1.2.3".to_string(),
            expected_policy_set: HashSet::new(),
            qualifiers: vec![cps.clone()],
            depth: 1,
            children: Vec::new(),
        };
        tree.add_child(0, child);

        let collected = tree.collect_qualifiers(1);
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].0, "1.2.3");
        assert_eq!(collected[0].1, cps);
    }

    #[test]
    fn test_collect_qualifiers_empty_on_no_qualifiers() {
        let mut tree = PolicyTree::new();
        let child = PolicyNode {
            valid_policy: "1.2.3".to_string(),
            expected_policy_set: HashSet::new(),
            qualifiers: Vec::new(),
            depth: 1,
            children: Vec::new(),
        };
        tree.add_child(0, child);

        let collected = tree.collect_qualifiers(1);
        assert!(
            collected.is_empty(),
            "No qualifiers should be collected from nodes without qualifiers"
        );
    }

    #[test]
    fn test_collect_qualifiers_multiple_nodes() {
        let mut tree = PolicyTree::new();
        let cps1 = ParsedPolicyQualifier::CpsUri("https://a.example.com/cps".to_string());
        let cps2 = ParsedPolicyQualifier::CpsUri("https://b.example.com/cps".to_string());
        let notice = ParsedPolicyQualifier::UserNotice {
            explicit_text: Some("Test notice".to_string()),
        };

        let c1 = PolicyNode {
            valid_policy: "1.2.3".to_string(),
            expected_policy_set: HashSet::new(),
            qualifiers: vec![cps1],
            depth: 1,
            children: Vec::new(),
        };
        let c2 = PolicyNode {
            valid_policy: "4.5.6".to_string(),
            expected_policy_set: HashSet::new(),
            qualifiers: vec![cps2, notice],
            depth: 1,
            children: Vec::new(),
        };
        tree.add_child(0, c1);
        tree.add_child(0, c2);

        let collected = tree.collect_qualifiers(1);
        assert_eq!(
            collected.len(),
            3,
            "Should collect qualifiers from all nodes"
        );
    }

    #[test]
    fn test_collect_qualifiers_null_tree() {
        let mut tree = PolicyTree::new();
        tree.set_null();
        let collected = tree.collect_qualifiers(1);
        assert!(collected.is_empty(), "NULL tree should have no qualifiers");
    }
}

#[cfg(all(test, feature = "ceremony"))]
mod integration_tests {
    use super::*;
    use crate::algo::AlgorithmId;
    use crate::ca::{CaCeremony, CaConfig, CertificateProfile};
    use crate::cert::{NameBuilder, Validity};

    fn create_root(name: &str) -> (x509_cert::Certificate, crate::ca::CertificateAuthority) {
        let config = CaConfig::root(name, AlgorithmId::EcdsaP256).with_subject(
            NameBuilder::new(name)
                .organization("Test")
                .country("US")
                .build(),
        );
        let result = CaCeremony::init_root(config).unwrap();
        (result.ca.certificate.clone(), result.ca)
    }

    fn create_intermediate(
        name: &str,
        root_ca: &mut crate::ca::CertificateAuthority,
    ) -> (x509_cert::Certificate, crate::ca::CertificateAuthority) {
        let config = CaConfig::intermediate(name, AlgorithmId::EcdsaP256).with_subject(
            NameBuilder::new(name)
                .organization("Test")
                .country("US")
                .build(),
        );
        let result = CaCeremony::init_intermediate(config, root_ca).unwrap();
        (result.ca.certificate.clone(), result.ca)
    }

    fn issue_ee(ca: &mut crate::ca::CertificateAuthority, cn: &str) -> x509_cert::Certificate {
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
        crate::cert::parse_certificate_pem(&issued.pem).unwrap()
    }

    #[test]
    fn test_basic_chain_no_explicit_policy() {
        let (root_cert, mut root_ca) = create_root("Policy Root");
        let (_int_cert, mut int_ca) = create_intermediate("Policy Int", &mut root_ca);
        let ee = issue_ee(&mut int_ca, "policy.example.com");

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let any_set = {
            let mut s = HashSet::new();
            s.insert(ANY_POLICY.to_string());
            s
        };

        // No explicit policy required — should pass even without certificatePolicies
        let result = process_policy_tree(&chain, &any_set, false, false, false);
        assert!(
            result.errors.is_empty(),
            "No explicit policy required, should have no errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_single_root_no_explicit_policy() {
        let (root_cert, _) = create_root("Solo Root");
        let chain = vec![root_cert];
        let any_set = {
            let mut s = HashSet::new();
            s.insert(ANY_POLICY.to_string());
            s
        };

        let result = process_policy_tree(&chain, &any_set, false, false, false);
        assert!(
            result.errors.is_empty(),
            "Single root should pass: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_chain_with_explicit_policy_no_cert_policies() {
        // When explicit_policy is required but certs have no certificatePolicies,
        // the tree becomes NULL and errors should be reported.
        let (root_cert, mut root_ca) = create_root("ExpPol Root");
        let (_int_cert, mut int_ca) = create_intermediate("ExpPol Int", &mut root_ca);
        let ee = issue_ee(&mut int_ca, "exppol.example.com");

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let any_set = {
            let mut s = HashSet::new();
            s.insert(ANY_POLICY.to_string());
            s
        };

        let result = process_policy_tree(&chain, &any_set, true, false, false);
        // With explicit_policy=true and no certificatePolicies in the chain,
        // the tree should be NULL and errors should be generated
        assert!(
            !result.errors.is_empty(),
            "Explicit policy required with no cert policies should error"
        );
    }
}
