//! Scope boundary assertions for v0.9.0.
//!
//! These tests ensure that removed enrollment subcommands (acme, est, scep)
//! are not advertised in help output and do not accept any invocation.

use assert_cmd::Command;

#[test]
fn help_does_not_advertise_enrollment() {
    let output = Command::cargo_bin("pki")
        .unwrap()
        .arg("--help")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}").to_lowercase();

    // "acme" must not appear anywhere in help
    assert!(
        !combined.contains("acme"),
        "pki --help must not mention 'acme' (found in output)"
    );

    // "scep" must not appear anywhere in help
    assert!(
        !combined.contains("scep"),
        "pki --help must not mention 'scep' (found in output)"
    );

    // "enrollment" must not appear anywhere in help
    assert!(
        !combined.contains("enrollment"),
        "pki --help must not mention 'enrollment' (found in output)"
    );

    // "est" as a standalone subcommand token — check it is not listed as a
    // command. We match " est " (space-padded) and "est\n" to avoid false
    // positives on words like "latest", "test", "forest", "request", etc.
    let no_est_subcommand = !combined.contains("\n  est ")
        && !combined.contains(" est\n")
        && !combined.contains("  est\t");
    assert!(
        no_est_subcommand,
        "pki --help must not list 'est' as a subcommand"
    );
}

#[test]
fn acme_subcommand_is_gone() {
    Command::cargo_bin("pki")
        .unwrap()
        .arg("acme")
        .arg("--help")
        .assert()
        .failure();
}

#[test]
fn scep_subcommand_is_gone() {
    Command::cargo_bin("pki")
        .unwrap()
        .arg("scep")
        .arg("--help")
        .assert()
        .failure();
}

#[test]
fn est_subcommand_is_gone() {
    Command::cargo_bin("pki")
        .unwrap()
        .arg("est")
        .arg("--help")
        .assert()
        .failure();
}
