//! RFC 6125 hostname matching and IDNA2008 basics for certificate identity verification.
//!
//! Implements:
//! - Hostname matching with wildcard support (RFC 6125 §6.4.3)
//! - SAN-based identity verification with CN fallback (RFC 6125 §6.4.4)
//! - IP address matching for iPAddress SAN entries
//! - IDNA2008 basic normalization (case folding, label validation, punycode awareness)

use std::net::IpAddr;

use crate::error::{Error, Result};

/// Subject Alternative Name entry types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanType {
    /// DNS name (dNSName, tag [2])
    DnsName(String),
    /// IP address (iPAddress, tag [7])
    IpAddress(String),
    /// Email address (rfc822Name, tag [1])
    Email(String),
    /// URI (uniformResourceIdentifier, tag [6])
    Uri(String),
    /// Internationalized email (RFC 9598 SmtpUTF8Mailbox, otherName [0])
    Utf8Email(String),
}

/// Match a certificate DNS name against a hostname per RFC 6125 §6.4.3.
///
/// Rules:
/// - Case-insensitive comparison (RFC 4343)
/// - Wildcard only in leftmost label (`*.example.com`)
/// - No partial wildcards (`f*o.example.com` -> reject)
/// - Wildcard must have at least 2 labels to the right (no `*.com`)
/// - Wildcard doesn't span multiple labels (`*.example.com` != `a.b.example.com`)
/// - No wildcards for IP addresses
pub fn matches_hostname(cert_name: &str, hostname: &str) -> bool {
    // Reject empty inputs
    if cert_name.is_empty() || hostname.is_empty() {
        return false;
    }

    // Normalize: strip trailing dots and lowercase
    let cert_lower = cert_name.trim_end_matches('.').to_ascii_lowercase();
    let host_lower = hostname.trim_end_matches('.').to_ascii_lowercase();

    // If hostname looks like an IP address, wildcards never match
    if host_lower.parse::<IpAddr>().is_ok() {
        return false;
    }

    // Split into labels
    let cert_labels: Vec<&str> = cert_lower.split('.').collect();
    let host_labels: Vec<&str> = host_lower.split('.').collect();

    // Check for wildcard in leftmost label
    if cert_labels[0].contains('*') {
        // RFC 6125 §6.4.3: wildcard must be the entire leftmost label
        if cert_labels[0] != "*" {
            // Partial wildcard like "f*o" or "w*" — reject per RFC 6125
            return false;
        }

        // Must have at least 2 labels after the wildcard (no `*.com` or `*`)
        if cert_labels.len() < 3 {
            return false;
        }

        // Label counts must match (wildcard matches exactly one label)
        if cert_labels.len() != host_labels.len() {
            return false;
        }

        // Compare all non-wildcard labels (index 1..n)
        for i in 1..cert_labels.len() {
            if cert_labels[i] != host_labels[i] {
                return false;
            }
        }

        return true;
    }

    // No wildcard: exact match (case-insensitive, already lowered)
    cert_lower == host_lower
}

/// Match an IP address from a SAN entry against a target IP.
///
/// Handles both IPv4 and IPv6 with normalization (IPv6 addresses are
/// compared in their canonical expanded form).
pub fn matches_ip(san_ip: &str, target_ip: &str) -> bool {
    let parsed_san: IpAddr = match san_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let parsed_target: IpAddr = match target_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    parsed_san == parsed_target
}

/// Verify a hostname against a set of SAN entries per RFC 6125 §6.4.4.
///
/// Priority:
/// 1. Check DNS SAN entries first — if any DNS SAN exists, CN is ignored
/// 2. Check IP address SAN entries for IP targets
/// 3. CN fallback only if NO DNS SAN entries are present (pass CN as a DnsName entry)
pub fn verify_hostname(san_entries: &[(SanType, String)], hostname: &str) -> bool {
    if hostname.is_empty() {
        return false;
    }

    let is_ip_target = hostname.parse::<IpAddr>().is_ok();

    // If target is an IP, only check IpAddress SAN entries
    if is_ip_target {
        return san_entries.iter().any(|(san_type, _)| {
            if let SanType::IpAddress(ip) = san_type {
                matches_ip(ip, hostname)
            } else {
                false
            }
        });
    }

    // For DNS targets: check DNS SAN entries
    let has_dns_san = san_entries
        .iter()
        .any(|(t, _)| matches!(t, SanType::DnsName(_)));

    if has_dns_san {
        // RFC 6125 §6.4.4: if SAN DNS names exist, use them exclusively
        return san_entries.iter().any(|(san_type, _)| {
            if let SanType::DnsName(name) = san_type {
                matches_hostname(name, hostname)
            } else {
                false
            }
        });
    }

    // CN fallback: only if no DNS SAN entries exist at all.
    // The CN value should be passed as the second element of a tuple with
    // a non-DNS SanType (typically Email or Uri) as a sentinel, OR the caller
    // should add the CN as a DnsName entry when building the list.
    //
    // Per convention, CN fallback entries are passed as DnsName entries by
    // the caller when no SAN DNS names are present. Since we checked above
    // and found no DNS SANs, there's nothing to match against.
    false
}

/// Verify hostname with explicit CN fallback support.
///
/// This is the preferred entry point. Pass the SAN entries from the certificate
/// and optionally the CN (common name) for fallback when no DNS SANs exist.
pub fn verify_hostname_with_cn(san_entries: &[SanType], cn: Option<&str>, hostname: &str) -> bool {
    if hostname.is_empty() {
        return false;
    }

    let is_ip_target = hostname.parse::<IpAddr>().is_ok();

    // For IP targets, only match iPAddress SANs
    if is_ip_target {
        return san_entries.iter().any(|san| {
            if let SanType::IpAddress(ip) = san {
                matches_ip(ip, hostname)
            } else {
                false
            }
        });
    }

    // Check DNS SANs
    let dns_sans: Vec<&str> = san_entries
        .iter()
        .filter_map(|san| {
            if let SanType::DnsName(name) = san {
                Some(name.as_str())
            } else {
                None
            }
        })
        .collect();

    if !dns_sans.is_empty() {
        // RFC 6125 §6.4.4: DNS SANs present — use them, ignore CN
        return dns_sans.iter().any(|name| matches_hostname(name, hostname));
    }

    // CN fallback: only when NO DNS SAN entries exist
    if let Some(cn_value) = cn {
        return matches_hostname(cn_value, hostname);
    }

    false
}

/// Normalize a hostname per RFC 9549 / IDNA2008 (RFC 5891).
///
/// Converts Unicode domain names to A-label (Punycode) form and validates
/// existing ASCII names. Performs case folding, label length validation,
/// and trailing dot normalization.
///
/// Supports wildcard prefixes (`*.example.com`) — the wildcard label is
/// preserved while the remaining labels are normalized.
pub fn normalize_hostname(hostname: &str) -> Result<String> {
    if hostname.is_empty() {
        return Err(Error::InvalidCertificate(
            "hostname must not be empty".into(),
        ));
    }

    // Strip trailing dot (FQDN notation)
    let trimmed = hostname.trim_end_matches('.');

    if trimmed.is_empty() {
        return Err(Error::InvalidCertificate(
            "hostname must not be only dots".into(),
        ));
    }

    // Handle wildcard prefix: strip, normalize remainder, re-attach
    let (wildcard, to_normalize) = if let Some(rest) = trimmed.strip_prefix("*.") {
        (true, rest)
    } else {
        (false, trimmed)
    };

    // RFC 9549: Use IDNA2008 to convert to A-label form
    let ascii_name = idna::domain_to_ascii(to_normalize).map_err(|e| {
        Error::InvalidCertificate(format!(
            "hostname fails IDNA2008 validation: {:?} — {}",
            hostname, e
        ))
    })?;

    if ascii_name.is_empty() {
        return Err(Error::InvalidCertificate(
            "hostname is empty after IDNA2008 normalization".into(),
        ));
    }

    let normalized = if wildcard {
        format!("*.{}", ascii_name)
    } else {
        ascii_name
    };

    // Validate total length (max 253 characters for a DNS name)
    if normalized.len() > 253 {
        return Err(Error::InvalidCertificate(format!(
            "hostname exceeds 253 characters: {} bytes",
            normalized.len()
        )));
    }

    // Defense-in-depth: validate individual labels per RFC 952/1123
    // (IDNA2008 may be more permissive than X.509 SAN requirements)
    let label_check = normalized.strip_prefix("*.").unwrap_or(&normalized);
    for label in label_check.split('.') {
        if label.is_empty() {
            return Err(Error::InvalidCertificate(
                "hostname contains empty label (consecutive dots)".into(),
            ));
        }
        if label.len() > 63 {
            return Err(Error::InvalidCertificate(format!(
                "label exceeds 63 bytes: '{}' ({} bytes)",
                label,
                label.len()
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(Error::InvalidCertificate(format!(
                "label must not start or end with hyphen: '{}'",
                label
            )));
        }
    }

    Ok(normalized)
}

/// Match an email address from a SAN entry against a target email.
///
/// Local part comparison is case-sensitive (RFC 5321 §2.3.11 — local parts
/// are technically case-sensitive, though many servers treat them as insensitive).
/// Domain part comparison is case-insensitive (RFC 5321 §2.3.5).
pub fn matches_email(cert_email: &str, target_email: &str) -> bool {
    if cert_email.is_empty() || target_email.is_empty() {
        return false;
    }

    let cert_parts: Vec<&str> = cert_email.splitn(2, '@').collect();
    let target_parts: Vec<&str> = target_email.splitn(2, '@').collect();

    if cert_parts.len() != 2 || target_parts.len() != 2 {
        return false;
    }

    // Local part: case-sensitive comparison per RFC 5321
    if cert_parts[0] != target_parts[0] {
        return false;
    }

    // Domain part: case-insensitive
    cert_parts[1].eq_ignore_ascii_case(target_parts[1])
}

/// Match an email address with IDNA2008 domain normalization (RFC 9598).
///
/// Both email domains are normalized to A-label form before comparison.
/// This handles internationalized domain names in email addresses.
/// Local parts with UTF-8 characters are compared byte-for-byte.
pub fn matches_email_idna(cert_email: &str, target_email: &str) -> bool {
    if cert_email.is_empty() || target_email.is_empty() {
        return false;
    }

    let cert_parts: Vec<&str> = cert_email.splitn(2, '@').collect();
    let target_parts: Vec<&str> = target_email.splitn(2, '@').collect();

    if cert_parts.len() != 2 || target_parts.len() != 2 {
        return false;
    }

    // Local part: byte-for-byte comparison (UTF-8 aware)
    if cert_parts[0] != target_parts[0] {
        return false;
    }

    // Domain part: normalize via IDNA2008 then compare
    let cert_domain = match idna::domain_to_ascii(cert_parts[1]) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let target_domain = match idna::domain_to_ascii(target_parts[1]) {
        Ok(d) => d,
        Err(_) => return false,
    };

    cert_domain.eq_ignore_ascii_case(&target_domain)
}

/// Match a hostname with IDNA2008 normalization per RFC 9549.
///
/// Both the certificate name and the hostname are normalized to A-label
/// form before comparison. This handles Unicode hostnames transparently.
pub fn matches_hostname_idna(cert_name: &str, hostname: &str) -> bool {
    let cert_norm = match normalize_hostname(cert_name) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let host_norm = match normalize_hostname(hostname) {
        Ok(n) => n,
        Err(_) => return false,
    };
    matches_hostname(&cert_norm, &host_norm)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- matches_hostname tests ----

    #[test]
    fn test_exact_match() {
        assert!(matches_hostname("example.com", "example.com"));
        assert!(matches_hostname("www.example.com", "www.example.com"));
        assert!(matches_hostname(
            "sub.domain.example.com",
            "sub.domain.example.com"
        ));
    }

    #[test]
    fn test_case_insensitive() {
        assert!(matches_hostname("Example.COM", "example.com"));
        assert!(matches_hostname("example.com", "EXAMPLE.COM"));
        assert!(matches_hostname("WWW.Example.Com", "www.example.com"));
    }

    #[test]
    fn test_trailing_dot_normalization() {
        assert!(matches_hostname("example.com.", "example.com"));
        assert!(matches_hostname("example.com", "example.com."));
        assert!(matches_hostname("example.com.", "example.com."));
    }

    #[test]
    fn test_wildcard_valid() {
        assert!(matches_hostname("*.example.com", "www.example.com"));
        assert!(matches_hostname("*.example.com", "mail.example.com"));
        assert!(matches_hostname("*.example.com", "anything.example.com"));
        assert!(matches_hostname(
            "*.sub.example.com",
            "host.sub.example.com"
        ));
    }

    #[test]
    fn test_wildcard_case_insensitive() {
        assert!(matches_hostname("*.Example.COM", "www.example.com"));
        assert!(matches_hostname("*.example.com", "WWW.EXAMPLE.COM"));
    }

    #[test]
    fn test_wildcard_no_multi_label() {
        // Wildcard must not match multiple labels
        assert!(!matches_hostname("*.example.com", "a.b.example.com"));
        assert!(!matches_hostname("*.example.com", "deep.sub.example.com"));
    }

    #[test]
    fn test_wildcard_no_bare_tld() {
        // *.com should be rejected (only 2 labels, need at least 3)
        assert!(!matches_hostname("*.com", "example.com"));
        assert!(!matches_hostname("*.org", "something.org"));
    }

    #[test]
    fn test_wildcard_single_star() {
        // Bare `*` with no other labels — reject
        assert!(!matches_hostname("*", "example.com"));
    }

    #[test]
    fn test_partial_wildcard_rejected() {
        // RFC 6125: partial wildcards are not allowed
        assert!(!matches_hostname("f*o.example.com", "foo.example.com"));
        assert!(!matches_hostname("w*.example.com", "www.example.com"));
        assert!(!matches_hostname("*w.example.com", "www.example.com"));
        assert!(!matches_hostname("ww*.example.com", "www.example.com"));
    }

    #[test]
    fn test_wildcard_no_ip() {
        // Wildcard must not match when hostname is an IP
        assert!(!matches_hostname("*.1.1.1", "0.1.1.1"));
        assert!(!matches_hostname("*.example.com", "192.168.1.1"));
    }

    #[test]
    fn test_no_match_different_domains() {
        assert!(!matches_hostname("example.com", "example.org"));
        assert!(!matches_hostname("www.example.com", "www.example.org"));
        assert!(!matches_hostname("*.example.com", "www.example.org"));
    }

    #[test]
    fn test_empty_inputs() {
        assert!(!matches_hostname("", "example.com"));
        assert!(!matches_hostname("example.com", ""));
        assert!(!matches_hostname("", ""));
    }

    #[test]
    fn test_wildcard_exact_base_no_match() {
        // *.example.com should NOT match bare "example.com"
        assert!(!matches_hostname("*.example.com", "example.com"));
    }

    // ---- matches_ip tests ----

    #[test]
    fn test_ipv4_exact_match() {
        assert!(matches_ip("192.168.1.1", "192.168.1.1"));
        assert!(matches_ip("10.0.0.1", "10.0.0.1"));
        assert!(matches_ip("127.0.0.1", "127.0.0.1"));
    }

    #[test]
    fn test_ipv4_no_match() {
        assert!(!matches_ip("192.168.1.1", "192.168.1.2"));
        assert!(!matches_ip("10.0.0.1", "10.0.0.2"));
    }

    #[test]
    fn test_ipv6_exact_match() {
        assert!(matches_ip("::1", "::1"));
        assert!(matches_ip("fe80::1", "fe80::1"));
        assert!(matches_ip("2001:db8::1", "2001:db8::1"));
    }

    #[test]
    fn test_ipv6_normalization() {
        // Different representations of the same IPv6 address
        assert!(matches_ip(
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "2001:db8::1"
        ));
        assert!(matches_ip("::1", "0:0:0:0:0:0:0:1"));
        assert!(matches_ip(
            "fe80:0000:0000:0000:0000:0000:0000:0001",
            "fe80::1"
        ));
    }

    #[test]
    fn test_ip_invalid_inputs() {
        assert!(!matches_ip("not-an-ip", "192.168.1.1"));
        assert!(!matches_ip("192.168.1.1", "not-an-ip"));
        assert!(!matches_ip("", "192.168.1.1"));
        assert!(!matches_ip("192.168.1.1", ""));
    }

    #[test]
    fn test_ip_v4_v6_mismatch() {
        // IPv4 and IPv6 are different address families
        assert!(!matches_ip("127.0.0.1", "::1"));
        assert!(!matches_ip("::ffff:192.168.1.1", "192.168.1.1"));
    }

    // ---- verify_hostname_with_cn tests ----

    #[test]
    fn test_verify_dns_san_match() {
        let sans = vec![
            SanType::DnsName("www.example.com".into()),
            SanType::DnsName("example.com".into()),
        ];
        assert!(verify_hostname_with_cn(&sans, None, "www.example.com"));
        assert!(verify_hostname_with_cn(&sans, None, "example.com"));
        assert!(!verify_hostname_with_cn(&sans, None, "other.example.com"));
    }

    #[test]
    fn test_verify_wildcard_san() {
        let sans = vec![SanType::DnsName("*.example.com".into())];
        assert!(verify_hostname_with_cn(&sans, None, "www.example.com"));
        assert!(verify_hostname_with_cn(&sans, None, "mail.example.com"));
        assert!(!verify_hostname_with_cn(&sans, None, "example.com"));
        assert!(!verify_hostname_with_cn(&sans, None, "a.b.example.com"));
    }

    #[test]
    fn test_verify_cn_fallback_when_no_dns_san() {
        // No DNS SANs present — CN should be used as fallback
        let sans = vec![SanType::IpAddress("192.168.1.1".into())];
        assert!(verify_hostname_with_cn(
            &sans,
            Some("www.example.com"),
            "www.example.com"
        ));
        assert!(!verify_hostname_with_cn(
            &sans,
            Some("www.example.com"),
            "other.example.com"
        ));
    }

    #[test]
    fn test_verify_cn_ignored_when_dns_san_present() {
        // RFC 6125 §6.4.4: CN must be ignored when DNS SANs exist
        let sans = vec![SanType::DnsName("www.example.com".into())];
        // Even though CN matches, it should only use SAN DNS names
        assert!(!verify_hostname_with_cn(
            &sans,
            Some("other.example.com"),
            "other.example.com"
        ));
        // SAN match still works
        assert!(verify_hostname_with_cn(
            &sans,
            Some("other.example.com"),
            "www.example.com"
        ));
    }

    #[test]
    fn test_verify_ip_san_match() {
        let sans = vec![
            SanType::DnsName("www.example.com".into()),
            SanType::IpAddress("192.168.1.1".into()),
        ];
        assert!(verify_hostname_with_cn(&sans, None, "192.168.1.1"));
        assert!(!verify_hostname_with_cn(&sans, None, "192.168.1.2"));
    }

    #[test]
    fn test_verify_ipv6_san() {
        let sans = vec![SanType::IpAddress("2001:db8::1".into())];
        assert!(verify_hostname_with_cn(&sans, None, "2001:db8::1"));
        assert!(verify_hostname_with_cn(
            &sans,
            None,
            "2001:0db8:0000:0000:0000:0000:0000:0001"
        ));
    }

    #[test]
    fn test_verify_empty_hostname() {
        let sans = vec![SanType::DnsName("example.com".into())];
        assert!(!verify_hostname_with_cn(&sans, None, ""));
    }

    #[test]
    fn test_verify_no_sans_no_cn() {
        let sans: Vec<SanType> = vec![];
        assert!(!verify_hostname_with_cn(&sans, None, "example.com"));
    }

    #[test]
    fn test_verify_cn_wildcard_fallback() {
        // CN fallback should also support wildcard matching
        let sans: Vec<SanType> = vec![];
        assert!(verify_hostname_with_cn(
            &sans,
            Some("*.example.com"),
            "www.example.com"
        ));
    }

    // ---- normalize_hostname tests ----

    #[test]
    fn test_normalize_ascii_passthrough() {
        assert_eq!(normalize_hostname("example.com").unwrap(), "example.com");
        assert_eq!(
            normalize_hostname("www.example.com").unwrap(),
            "www.example.com"
        );
    }

    #[test]
    fn test_normalize_case_folding() {
        assert_eq!(normalize_hostname("EXAMPLE.COM").unwrap(), "example.com");
        assert_eq!(
            normalize_hostname("Www.Example.Com").unwrap(),
            "www.example.com"
        );
    }

    #[test]
    fn test_normalize_trailing_dot() {
        assert_eq!(normalize_hostname("example.com.").unwrap(), "example.com");
    }

    #[test]
    fn test_normalize_punycode_passthrough() {
        // xn-- labels should pass through without modification (except case folding)
        assert_eq!(
            normalize_hostname("xn--nxasmq6b.example.com").unwrap(),
            "xn--nxasmq6b.example.com"
        );
    }

    #[test]
    fn test_normalize_empty_label_rejected() {
        assert!(normalize_hostname("example..com").is_err());
        assert!(normalize_hostname(".example.com").is_err());
    }

    #[test]
    fn test_normalize_empty_hostname() {
        assert!(normalize_hostname("").is_err());
    }

    #[test]
    fn test_normalize_label_too_long() {
        let long_label = "a".repeat(64);
        let hostname = format!("{}.example.com", long_label);
        assert!(normalize_hostname(&hostname).is_err());

        // 63 chars should be OK
        let ok_label = "a".repeat(63);
        let hostname = format!("{}.example.com", ok_label);
        assert!(normalize_hostname(&hostname).is_ok());
    }

    #[test]
    fn test_normalize_total_length_too_long() {
        // Build a hostname > 253 chars
        let label = "a".repeat(50);
        let parts: Vec<&str> = (0..6).map(|_| label.as_str()).collect();
        let hostname = parts.join(".");
        // 6 * 50 + 5 dots = 305 chars
        assert!(hostname.len() > 253);
        assert!(normalize_hostname(&hostname).is_err());
    }

    #[test]
    fn test_normalize_hyphen_start_end_rejected() {
        assert!(normalize_hostname("-example.com").is_err());
        assert!(normalize_hostname("example-.com").is_err());
        // Hyphens in the middle are fine
        assert!(normalize_hostname("my-example.com").is_ok());
    }

    #[test]
    fn test_normalize_invalid_punycode_prefix() {
        // xn-- with nothing after it
        assert!(normalize_hostname("xn--.example.com").is_err());
    }

    #[test]
    fn test_normalize_unicode_to_punycode() {
        // RFC 9549: Unicode domain names are converted to A-label (Punycode) form
        assert_eq!(
            normalize_hostname("münchen.de").unwrap(),
            "xn--mnchen-3ya.de"
        );
    }

    #[test]
    fn test_normalize_underscore_allowed() {
        // Underscores are used in SRV records (_dmarc.example.com)
        assert!(normalize_hostname("_dmarc.example.com").is_ok());
    }

    #[test]
    fn test_normalize_wildcard_label() {
        // Wildcard labels should pass normalization
        assert_eq!(
            normalize_hostname("*.example.com").unwrap(),
            "*.example.com"
        );
    }

    #[test]
    fn test_normalize_only_dots() {
        assert!(normalize_hostname(".").is_err());
        assert!(normalize_hostname("..").is_err());
    }

    // ---- RFC 9549 IDNA2008 tests ----

    #[test]
    fn test_normalize_unicode_japanese() {
        // Japanese domain → A-label
        let result = normalize_hostname("例え.jp").unwrap();
        assert!(result.starts_with("xn--"));
        assert!(result.ends_with(".jp"));
    }

    #[test]
    fn test_normalize_unicode_cyrillic() {
        // Cyrillic domain → A-label
        let result = normalize_hostname("пример.рф").unwrap();
        assert!(result.contains("xn--"));
    }

    #[test]
    fn test_normalize_unicode_wildcard() {
        // Wildcard with Unicode base domain
        let result = normalize_hostname("*.münchen.de").unwrap();
        assert_eq!(result, "*.xn--mnchen-3ya.de");
    }

    #[test]
    fn test_normalize_mixed_unicode_ascii() {
        // Mix of Unicode and ASCII labels
        let result = normalize_hostname("www.münchen.de").unwrap();
        assert_eq!(result, "www.xn--mnchen-3ya.de");
    }

    #[test]
    fn test_matches_hostname_idna_basic() {
        // IDNA-aware hostname matching
        assert!(matches_hostname_idna("example.com", "example.com"));
        assert!(matches_hostname_idna("EXAMPLE.COM", "example.com"));
        assert!(!matches_hostname_idna("example.com", "example.org"));
    }

    #[test]
    fn test_matches_hostname_idna_unicode() {
        // Unicode hostname matches its A-label equivalent
        assert!(matches_hostname_idna("xn--mnchen-3ya.de", "münchen.de"));
        assert!(matches_hostname_idna("münchen.de", "xn--mnchen-3ya.de"));
    }

    #[test]
    fn test_matches_hostname_idna_wildcard() {
        assert!(matches_hostname_idna("*.example.com", "www.example.com"));
        assert!(!matches_hostname_idna("*.example.com", "example.com"));
    }

    // ---- verify_hostname (tuple-based API) tests ----

    #[test]
    fn test_verify_hostname_tuple_api() {
        let entries = vec![
            (SanType::DnsName("www.example.com".into()), "san".into()),
            (SanType::IpAddress("10.0.0.1".into()), "san".into()),
        ];
        assert!(verify_hostname(&entries, "www.example.com"));
        assert!(!verify_hostname(&entries, "other.example.com"));
    }

    #[test]
    fn test_verify_hostname_ip_via_tuple() {
        let entries = vec![(SanType::IpAddress("10.0.0.1".into()), "san".into())];
        assert!(verify_hostname(&entries, "10.0.0.1"));
        assert!(!verify_hostname(&entries, "10.0.0.2"));
    }

    // ---- matches_email tests (RFC 9598) ----

    #[test]
    fn test_matches_email_exact() {
        assert!(matches_email("user@example.com", "user@example.com"));
    }

    #[test]
    fn test_matches_email_domain_case_insensitive() {
        assert!(matches_email("user@Example.COM", "user@example.com"));
        assert!(matches_email("user@example.com", "user@EXAMPLE.COM"));
    }

    #[test]
    fn test_matches_email_local_case_sensitive() {
        // RFC 5321 §2.3.11: local parts are technically case-sensitive
        assert!(!matches_email("User@example.com", "user@example.com"));
        assert!(!matches_email("USER@example.com", "user@example.com"));
    }

    #[test]
    fn test_matches_email_no_match() {
        assert!(!matches_email("alice@example.com", "bob@example.com"));
        assert!(!matches_email("user@example.com", "user@other.com"));
    }

    #[test]
    fn test_matches_email_empty() {
        assert!(!matches_email("", "user@example.com"));
        assert!(!matches_email("user@example.com", ""));
        assert!(!matches_email("", ""));
    }

    #[test]
    fn test_matches_email_no_at() {
        assert!(!matches_email("invalid", "user@example.com"));
        assert!(!matches_email("user@example.com", "invalid"));
    }

    // ---- matches_email_idna tests (RFC 9598) ----

    #[test]
    fn test_matches_email_idna_basic() {
        assert!(matches_email_idna("user@example.com", "user@example.com"));
    }

    #[test]
    fn test_matches_email_idna_unicode_domain() {
        // Both sides use Unicode domain — should match via IDNA2008
        assert!(matches_email_idna("user@münchen.de", "user@münchen.de"));
    }

    #[test]
    fn test_matches_email_idna_mixed_unicode_punycode() {
        // Cert has punycode, target has Unicode — should match
        assert!(matches_email_idna(
            "user@xn--mnchen-3ya.de",
            "user@münchen.de"
        ));
        // And vice versa
        assert!(matches_email_idna(
            "user@münchen.de",
            "user@xn--mnchen-3ya.de"
        ));
    }

    #[test]
    fn test_matches_email_idna_utf8_local_part() {
        // RFC 9598: UTF-8 local parts compared byte-for-byte
        assert!(matches_email_idna("用户@example.com", "用户@example.com"));
        assert!(!matches_email_idna("用户@example.com", "user@example.com"));
    }

    #[test]
    fn test_matches_email_idna_utf8_full_intl() {
        // Full internationalized: UTF-8 local + Unicode domain
        assert!(matches_email_idna(
            "用户@münchen.de",
            "用户@xn--mnchen-3ya.de"
        ));
    }
}
