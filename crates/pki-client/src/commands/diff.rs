//! Certificate diff command - compare two certificates.

use anyhow::{Context, Result};
use clap::Args;
use colored::Colorize;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::compat::{load_certificate, Certificate};

use super::CmdResult;
use crate::config::GlobalConfig;

/// Arguments for 'diff' command
#[derive(Args)]
pub struct DiffArgs {
    /// First certificate file
    #[arg(value_name = "CERT1")]
    pub cert1: PathBuf,

    /// Second certificate file
    #[arg(value_name = "CERT2")]
    pub cert2: PathBuf,

    /// Interactive comparison mode
    #[arg(long, short = 'I')]
    pub interactive: bool,

    /// Show only differences
    #[arg(long)]
    pub only_diff: bool,

    /// Side-by-side comparison view
    #[arg(long)]
    pub side_by_side: bool,
}

/// Run the diff command.
pub fn run(args: DiffArgs, config: &GlobalConfig) -> Result<CmdResult> {
    let cert1 = load_certificate(&args.cert1)
        .with_context(|| format!("Failed to load: {}", args.cert1.display()))?;
    let cert2 = load_certificate(&args.cert2)
        .with_context(|| format!("Failed to load: {}", args.cert2.display()))?;

    if args.interactive {
        return run_interactive_diff(&cert1, &cert2, &args, config);
    }

    if args.side_by_side {
        print_side_by_side(&cert1, &cert2, &args);
    } else if args.only_diff {
        print_only_differences(&cert1, &cert2, &args);
    } else {
        print_comparison(&cert1, &cert2, &args, config);
    }

    Ok(CmdResult::Success)
}

/// Compare two values and return a match indicator.
fn compare_match(val1: &str, val2: &str) -> (bool, colored::ColoredString) {
    if val1 == val2 {
        (true, "✓ MATCH".green().bold())
    } else {
        (false, "✗ DIFFERS".red().bold())
    }
}

/// Print the standard comparison output.
fn print_comparison(
    cert1: &Certificate,
    cert2: &Certificate,
    args: &DiffArgs,
    _config: &GlobalConfig,
) {
    let file1 = args
        .cert1
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();
    let file2 = args
        .cert2
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();

    println!("{}:", "Certificate Comparison".cyan().bold());
    println!("    File 1:         {}", file1);
    println!("    File 2:         {}", file2);
    println!();

    let mut matches = 0;
    let mut differs = 0;

    // Subject
    let (is_match, indicator) = compare_match(&cert1.subject, &cert2.subject);
    if is_match {
        matches += 1;
    } else {
        differs += 1;
    }
    println!("{}:", "Subject".cyan());
    println!("    Cert 1:         {}", cert1.subject);
    println!("    Cert 2:         {}  {}", cert2.subject, indicator);
    println!();

    // Issuer
    let (is_match, indicator) = compare_match(&cert1.issuer, &cert2.issuer);
    if is_match {
        matches += 1;
    } else {
        differs += 1;
    }
    println!("{}:", "Issuer".cyan());
    println!("    Cert 1:         {}", cert1.issuer);
    println!("    Cert 2:         {}  {}", cert2.issuer, indicator);
    println!();

    // Validity
    let v1 = format!(
        "{} to {}",
        cert1.not_before.format("%Y-%m-%d"),
        cert1.not_after.format("%Y-%m-%d")
    );
    let v2 = format!(
        "{} to {}",
        cert2.not_before.format("%Y-%m-%d"),
        cert2.not_after.format("%Y-%m-%d")
    );
    let (is_match, indicator) = compare_match(&v1, &v2);
    if is_match {
        matches += 1;
    } else {
        differs += 1;
    }
    println!("{}:", "Validity".cyan());
    println!(
        "    Cert 1:         {} ({} days remaining)",
        v1,
        cert1.days_until_expiry()
    );
    println!(
        "    Cert 2:         {} ({} days remaining)  {}",
        v2,
        cert2.days_until_expiry(),
        indicator
    );
    println!();

    // Key
    let k1 = format!("{} {}-bit", cert1.key_algorithm_name, cert1.key_size);
    let k2 = format!("{} {}-bit", cert2.key_algorithm_name, cert2.key_size);
    let (is_match, indicator) = compare_match(&k1, &k2);
    if is_match {
        matches += 1;
    } else {
        differs += 1;
    }
    println!("{}:", "Key".cyan());
    println!("    Cert 1:         {}", k1);
    println!("    Cert 2:         {}  {}", k2, indicator);
    println!();

    // Serial
    let (is_match, indicator) = compare_match(&cert1.serial, &cert2.serial);
    if is_match {
        matches += 1;
    } else {
        differs += 1;
    }
    println!("{}:", "Serial".cyan());
    println!("    Cert 1:         {}", cert1.serial);
    println!("    Cert 2:         {}  {}", cert2.serial, indicator);
    println!();

    // Signature Algorithm
    let (is_match, indicator) = compare_match(
        &cert1.signature_algorithm_name,
        &cert2.signature_algorithm_name,
    );
    if is_match {
        matches += 1;
    } else {
        differs += 1;
    }
    println!("{}:", "Signature".cyan());
    println!("    Cert 1:         {}", cert1.signature_algorithm_name);
    println!(
        "    Cert 2:         {}  {}",
        cert2.signature_algorithm_name, indicator
    );
    println!();

    // Fingerprint
    let (is_match, indicator) = compare_match(&cert1.fingerprint_sha256, &cert2.fingerprint_sha256);
    if is_match {
        matches += 1;
    } else {
        differs += 1;
    }
    println!("{}:", "SHA-256 Fingerprint".cyan());
    println!("    Cert 1:         {}", cert1.fingerprint_sha256);
    println!(
        "    Cert 2:         {}  {}",
        cert2.fingerprint_sha256, indicator
    );
    println!();

    // Summary
    let same_cert = cert1.fingerprint_sha256 == cert2.fingerprint_sha256;
    println!("{}:", "Summary".cyan().bold());
    println!("    Matches:        {} fields", matches.to_string().green());
    println!("    Differs:        {} fields", differs.to_string().red());
    println!(
        "    Same cert:      {}",
        if same_cert {
            "✓ YES".green().bold()
        } else {
            "✗ NO".red().bold()
        }
    );
}

/// Print side-by-side comparison with colorful table.
fn print_side_by_side(cert1: &Certificate, cert2: &Certificate, args: &DiffArgs) {
    let file1 = args
        .cert1
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();
    let file2 = args
        .cert2
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();

    let col1_width = 30;
    let col2_width = 30;
    let label_width = 14;

    println!();
    println!("  {} Side-by-Side Certificate Comparison", "📋".cyan());
    println!();

    // Table header
    println!(
        "  ┌{:─<lw$}┬{:─<c1$}┬{:─<c2$}┬{:─<4}┐",
        "",
        "",
        "",
        "",
        lw = label_width,
        c1 = col1_width,
        c2 = col2_width
    );
    println!(
        "  │ {:<lw$}│ {:<c1$}│ {:<c2$}│    │",
        "Field".white().bold(),
        truncate(&file1, col1_width - 2).cyan(),
        truncate(&file2, col2_width - 2).cyan(),
        lw = label_width - 1,
        c1 = col1_width - 1,
        c2 = col2_width - 1
    );
    println!(
        "  ├{:─<lw$}┼{:─<c1$}┼{:─<c2$}┼{:─<4}┤",
        "",
        "",
        "",
        "",
        lw = label_width,
        c1 = col1_width,
        c2 = col2_width
    );

    // Helper closure to print rows with colored indicators
    let print_table_row = |label: &str, val1: &str, val2: &str| {
        let is_match = val1 == val2;
        let indicator = if is_match {
            "✓".green().bold()
        } else {
            "✗".red().bold()
        };
        let v1_display = if is_match {
            val1.to_string()
        } else {
            val1.yellow().to_string()
        };
        let v2_display = if is_match {
            val2.to_string()
        } else {
            val2.yellow().to_string()
        };
        println!(
            "  │ {:<lw$}│ {:<c1$}│ {:<c2$}│ {} │",
            label.white(),
            truncate(&v1_display, col1_width - 2),
            truncate(&v2_display, col2_width - 2),
            indicator,
            lw = label_width - 1,
            c1 = col1_width - 1,
            c2 = col2_width - 1
        );
    };

    // Rows
    let cn1 = cert1.common_name().unwrap_or(&cert1.subject);
    let cn2 = cert2.common_name().unwrap_or(&cert2.subject);
    print_table_row("Subject", cn1, cn2);

    let iss1 = extract_cn(&cert1.issuer);
    let iss2 = extract_cn(&cert2.issuer);
    print_table_row("Issuer", &iss1, &iss2);

    print_table_row(
        "Not Before",
        &cert1.not_before.format("%Y-%m-%d").to_string(),
        &cert2.not_before.format("%Y-%m-%d").to_string(),
    );

    print_table_row(
        "Not After",
        &cert1.not_after.format("%Y-%m-%d").to_string(),
        &cert2.not_after.format("%Y-%m-%d").to_string(),
    );

    // Days left with color coding
    let d1 = cert1.days_until_expiry();
    let d2 = cert2.days_until_expiry();
    let d1_str = if d1 < 30 {
        format!("{} ⚠", d1).red().to_string()
    } else if d1 < 90 {
        format!("{}", d1).yellow().to_string()
    } else {
        format!("{}", d1).green().to_string()
    };
    let d2_str = if d2 < 30 {
        format!("{} ⚠", d2).red().to_string()
    } else if d2 < 90 {
        format!("{}", d2).yellow().to_string()
    } else {
        format!("{}", d2).green().to_string()
    };
    println!(
        "  │ {:<lw$}│ {:<c1$}│ {:<c2$}│ {} │",
        "Days Left".white(),
        d1_str,
        d2_str,
        if d1 == d2 {
            "✓".green().bold()
        } else {
            "✗".red().bold()
        },
        lw = label_width - 1,
        c1 = col1_width - 1,
        c2 = col2_width - 1
    );

    print_table_row(
        "Key Type",
        &format!("{} {}", cert1.key_algorithm_name, cert1.key_size),
        &format!("{} {}", cert2.key_algorithm_name, cert2.key_size),
    );

    print_table_row(
        "Signature",
        &cert1.signature_algorithm_name,
        &cert2.signature_algorithm_name,
    );

    print_table_row("Serial", &cert1.serial, &cert2.serial);

    print_table_row(
        "SANs Count",
        &cert1.san.len().to_string(),
        &cert2.san.len().to_string(),
    );

    // Table footer
    println!(
        "  └{:─<lw$}┴{:─<c1$}┴{:─<c2$}┴{:─<4}┘",
        "",
        "",
        "",
        "",
        lw = label_width,
        c1 = col1_width,
        c2 = col2_width
    );

    // Summary
    let same_cert = cert1.fingerprint_sha256 == cert2.fingerprint_sha256;
    println!();
    println!(
        "  {} Same Certificate: {}",
        "📌".cyan(),
        if same_cert {
            "✓ YES (identical fingerprints)".green().bold()
        } else {
            "✗ NO (different certificates)".red().bold()
        }
    );
    println!();
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max - 3])
    } else {
        s.to_string()
    }
}

fn extract_cn(dn: &str) -> String {
    for part in dn.split(',') {
        let part = part.trim();
        if part.starts_with("CN=") || part.starts_with("CN =") {
            return part
                .trim_start_matches("CN=")
                .trim_start_matches("CN =")
                .trim()
                .to_string();
        }
    }
    dn.to_string()
}

/// Print only the differences.
fn print_only_differences(cert1: &Certificate, cert2: &Certificate, args: &DiffArgs) {
    let file1 = args
        .cert1
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();
    let file2 = args
        .cert2
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();

    println!("{}:", "Differences Only".cyan().bold());
    println!("    {} {}", "<".red(), file1.dimmed());
    println!("    {} {}", ">".green(), file2.dimmed());
    println!();

    let mut any_diff = false;

    if cert1.subject != cert2.subject {
        any_diff = true;
        println!("{}:", "Subject".yellow());
        println!("    {} {}", "<".red(), cert1.subject);
        println!("    {} {}", ">".green(), cert2.subject);
        println!();
    }

    if cert1.issuer != cert2.issuer {
        any_diff = true;
        println!("{}:", "Issuer".yellow());
        println!("    {} {}", "<".red(), cert1.issuer);
        println!("    {} {}", ">".green(), cert2.issuer);
        println!();
    }

    if cert1.not_before != cert2.not_before {
        any_diff = true;
        println!("{}:", "Not Before".yellow());
        println!(
            "    {} {}",
            "<".red(),
            cert1.not_before.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!(
            "    {} {}",
            ">".green(),
            cert2.not_before.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!();
    }

    if cert1.not_after != cert2.not_after {
        any_diff = true;
        println!("{}:", "Not After".yellow());
        println!(
            "    {} {}",
            "<".red(),
            cert1.not_after.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!(
            "    {} {}",
            ">".green(),
            cert2.not_after.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!();
    }

    if cert1.serial != cert2.serial {
        any_diff = true;
        println!("{}:", "Serial Number".yellow());
        println!("    {} {}", "<".red(), cert1.serial);
        println!("    {} {}", ">".green(), cert2.serial);
        println!();
    }

    if cert1.key_algorithm_name != cert2.key_algorithm_name || cert1.key_size != cert2.key_size {
        any_diff = true;
        println!("{}:", "Key".yellow());
        println!(
            "    {} {} {}-bit",
            "<".red(),
            cert1.key_algorithm_name,
            cert1.key_size
        );
        println!(
            "    {} {} {}-bit",
            ">".green(),
            cert2.key_algorithm_name,
            cert2.key_size
        );
        println!();
    }

    if cert1.san != cert2.san {
        any_diff = true;
        println!("{}:", "SANs".yellow());
        println!(
            "    {} {}",
            "<".red(),
            cert1
                .san
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!(
            "    {} {}",
            ">".green(),
            cert2
                .san
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!();
    }

    if cert1.fingerprint_sha256 != cert2.fingerprint_sha256 {
        any_diff = true;
        println!("{}:", "SHA-256 Fingerprint".yellow());
        println!("    {} {}", "<".red(), cert1.fingerprint_sha256);
        println!("    {} {}", ">".green(), cert2.fingerprint_sha256);
        println!();
    }

    if !any_diff {
        println!("    {} Certificates are identical", "✓".green().bold());
    }
}

/// Interactive diff mode.
fn run_interactive_diff(
    cert1: &Certificate,
    cert2: &Certificate,
    args: &DiffArgs,
    _config: &GlobalConfig,
) -> Result<CmdResult> {
    let file1 = args
        .cert1
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();
    let file2 = args
        .cert2
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();

    // Count differences
    let mut diff_count = 0;
    let mut match_count = 0;
    if cert1.subject == cert2.subject {
        match_count += 1;
    } else {
        diff_count += 1;
    }
    if cert1.issuer == cert2.issuer {
        match_count += 1;
    } else {
        diff_count += 1;
    }
    if cert1.not_before == cert2.not_before && cert1.not_after == cert2.not_after {
        match_count += 1;
    } else {
        diff_count += 1;
    }
    if cert1.key_algorithm_name == cert2.key_algorithm_name && cert1.key_size == cert2.key_size {
        match_count += 1;
    } else {
        diff_count += 1;
    }
    if cert1.serial == cert2.serial {
        match_count += 1;
    } else {
        diff_count += 1;
    }
    if cert1.fingerprint_sha256 == cert2.fingerprint_sha256 {
        match_count += 1;
    } else {
        diff_count += 1;
    }

    println!();
    println!("{}:", "Certificate Comparison".cyan().bold());
    println!("    File 1:         {}", file1);
    println!("    File 2:         {}", file2);
    println!();
    println!(
        "    Summary:        {} matches, {} differences",
        match_count.to_string().green(),
        diff_count.to_string().red()
    );
    println!();

    loop {
        println!("{}:", "Compare".cyan().bold());
        println!("    1. Subject & Issuer");
        println!("    2. Validity periods");
        println!("    3. Key information");
        println!("    4. Extensions");
        println!("    5. SANs");
        println!("    6. Fingerprints");
        println!("    7. Full side-by-side");
        println!("    8. Show only differences");
        println!("    9. Export comparison JSON");
        println!("    q. Quit");
        println!();
        print!("{} ", "Select:".cyan());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let choice = input.trim().to_lowercase();

        println!();

        match choice.as_str() {
            "1" => {
                println!("{}:", "Subject".cyan());
                println!("    Cert 1: {}", cert1.subject);
                println!("    Cert 2: {}", cert2.subject);
                println!(
                    "    Match:  {}",
                    if cert1.subject == cert2.subject {
                        "✓ YES".green()
                    } else {
                        "✗ NO".red()
                    }
                );
                println!();
                println!("{}:", "Issuer".cyan());
                println!("    Cert 1: {}", cert1.issuer);
                println!("    Cert 2: {}", cert2.issuer);
                println!(
                    "    Match:  {}",
                    if cert1.issuer == cert2.issuer {
                        "✓ YES".green()
                    } else {
                        "✗ NO".red()
                    }
                );
            }
            "2" => {
                println!("{}:", "Validity".cyan());
                println!("    Cert 1:");
                println!(
                    "        Not Before: {}",
                    cert1.not_before.format("%Y-%m-%d %H:%M:%S UTC")
                );
                println!(
                    "        Not After:  {} ({} days)",
                    cert1.not_after.format("%Y-%m-%d %H:%M:%S UTC"),
                    cert1.days_until_expiry()
                );
                println!("    Cert 2:");
                println!(
                    "        Not Before: {}",
                    cert2.not_before.format("%Y-%m-%d %H:%M:%S UTC")
                );
                println!(
                    "        Not After:  {} ({} days)",
                    cert2.not_after.format("%Y-%m-%d %H:%M:%S UTC"),
                    cert2.days_until_expiry()
                );
            }
            "3" => {
                println!("{}:", "Key Information".cyan());
                println!(
                    "    Cert 1: {} {}-bit",
                    cert1.key_algorithm_name, cert1.key_size
                );
                if let Some(ref curve) = cert1.ec_curve {
                    println!("            Curve: {}", curve);
                }
                println!(
                    "    Cert 2: {} {}-bit",
                    cert2.key_algorithm_name, cert2.key_size
                );
                if let Some(ref curve) = cert2.ec_curve {
                    println!("            Curve: {}", curve);
                }
                println!(
                    "    Match:  {}",
                    if cert1.key_algorithm_name == cert2.key_algorithm_name
                        && cert1.key_size == cert2.key_size
                    {
                        "✓ YES".green()
                    } else {
                        "✗ NO".red()
                    }
                );
            }
            "4" => {
                println!("{}:", "Extensions".cyan());
                println!("    Cert 1:");
                println!("        Key Usage:      {}", cert1.key_usage.join(", "));
                println!(
                    "        Ext Key Usage:  {}",
                    cert1.extended_key_usage.join(", ")
                );
                println!("        Is CA:          {}", cert1.is_ca);
                println!("    Cert 2:");
                println!("        Key Usage:      {}", cert2.key_usage.join(", "));
                println!(
                    "        Ext Key Usage:  {}",
                    cert2.extended_key_usage.join(", ")
                );
                println!("        Is CA:          {}", cert2.is_ca);
            }
            "5" => {
                println!("{}:", "Subject Alternative Names".cyan());
                println!("    Cert 1 ({} SANs):", cert1.san.len());
                for san in &cert1.san {
                    println!("        {}", san);
                }
                println!("    Cert 2 ({} SANs):", cert2.san.len());
                for san in &cert2.san {
                    println!("        {}", san);
                }
            }
            "6" => {
                println!("{}:", "Fingerprints".cyan());
                println!("    Cert 1:");
                println!("        SHA-256: {}", cert1.fingerprint_sha256);
                println!("        SHA-1:   {}", cert1.fingerprint_sha1.dimmed());
                println!("        SPKI:    {}", cert1.spki_sha256_b64);
                println!("    Cert 2:");
                println!("        SHA-256: {}", cert2.fingerprint_sha256);
                println!("        SHA-1:   {}", cert2.fingerprint_sha1.dimmed());
                println!("        SPKI:    {}", cert2.spki_sha256_b64);
                println!();
                println!(
                    "    Same cert: {}",
                    if cert1.fingerprint_sha256 == cert2.fingerprint_sha256 {
                        "✓ YES".green().bold()
                    } else {
                        "✗ NO".red().bold()
                    }
                );
            }
            "7" => {
                print_side_by_side(cert1, cert2, args);
            }
            "8" => {
                print_only_differences(cert1, cert2, args);
            }
            "9" => {
                let comparison = serde_json::json!({
                    "file1": file1.to_string(),
                    "file2": file2.to_string(),
                    "same_certificate": cert1.fingerprint_sha256 == cert2.fingerprint_sha256,
                    "cert1": {
                        "subject": cert1.subject,
                        "issuer": cert1.issuer,
                        "serial": cert1.serial,
                        "not_before": cert1.not_before.to_rfc3339(),
                        "not_after": cert1.not_after.to_rfc3339(),
                        "days_until_expiry": cert1.days_until_expiry(),
                        "key_algorithm": cert1.key_algorithm_name,
                        "key_size": cert1.key_size,
                        "fingerprint_sha256": cert1.fingerprint_sha256,
                        "san_count": cert1.san.len(),
                    },
                    "cert2": {
                        "subject": cert2.subject,
                        "issuer": cert2.issuer,
                        "serial": cert2.serial,
                        "not_before": cert2.not_before.to_rfc3339(),
                        "not_after": cert2.not_after.to_rfc3339(),
                        "days_until_expiry": cert2.days_until_expiry(),
                        "key_algorithm": cert2.key_algorithm_name,
                        "key_size": cert2.key_size,
                        "fingerprint_sha256": cert2.fingerprint_sha256,
                        "san_count": cert2.san.len(),
                    }
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&comparison).unwrap_or_default()
                );
            }
            "q" | "quit" | "exit" => {
                println!("{}", "Goodbye!".dimmed());
                break;
            }
            _ => {
                println!("{}", "Invalid choice. Enter 1-9 or q.".yellow());
            }
        }

        println!();
    }

    Ok(CmdResult::Success)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_match_same() {
        let (is_match, _indicator) = compare_match("hello", "hello");
        assert!(is_match);
    }

    #[test]
    fn test_compare_match_different() {
        let (is_match, _indicator) = compare_match("hello", "world");
        assert!(!is_match);
    }

    #[test]
    fn test_truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_exact_length() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_long_string() {
        let result = truncate("hello world this is long", 10);
        assert_eq!(result, "hello w...");
        assert_eq!(result.len(), 10);
    }

    #[test]
    fn test_extract_cn_present() {
        assert_eq!(extract_cn("CN=test.com, O=Test Inc"), "test.com");
    }

    #[test]
    fn test_extract_cn_with_space() {
        assert_eq!(extract_cn("CN =test.com, O=Test Inc"), "test.com");
    }

    #[test]
    fn test_extract_cn_only() {
        assert_eq!(extract_cn("CN=example.com"), "example.com");
    }

    #[test]
    fn test_extract_cn_missing() {
        let dn = "O=Test Inc, C=US";
        assert_eq!(extract_cn(dn), dn);
    }

    #[test]
    fn test_extract_cn_complex_dn() {
        assert_eq!(
            extract_cn("DC=com, DC=example, OU=PKI, CN=Root CA"),
            "Root CA"
        );
    }
}
