//! TPM 2.0 integration test — run on a machine with a real or software TPM
//!
//! Usage: tpm_test [blob_dir]
//!
//! Tests key generation, signing, public key export, key persistence,
//! and error handling. Outputs detailed logs for documentation.

#[cfg(feature = "tpm")]
fn main() {
    use spork_core::hsm::{KeySpec, KeyStore, TpmKeyStore};
    use std::path::PathBuf;

    let blob_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/spork-tpm-test"));

    println!("=== SPORK TPM 2.0 Integration Test ===\n");
    println!("Blob directory: {}", blob_dir.display());

    // Step 1: Auto-detect TPM
    println!("\n--- Step 1: Auto-detect TPM device ---");
    let store = match TpmKeyStore::auto_detect(&blob_dir) {
        Ok(s) => {
            println!("  [OK] TPM device opened and SRK verified");
            s
        }
        Err(e) => {
            println!("  [FAIL] {}", e);
            println!("\n  TROUBLESHOOTING:");
            println!("  1. Check TPM device exists: ls -la /dev/tpm* /dev/tpmrm*");
            println!("  2. Check permissions: groups $(whoami) | grep tss");
            println!("  3. Provision SRK: tpm2_createprimary -C o -g sha256 -G ecc \\");
            println!("                    -c /tmp/srk.ctx && tpm2_evictcontrol -C o \\");
            println!("                    -c /tmp/srk.ctx 0x81000001");
            std::process::exit(1);
        }
    };

    // Step 2: Health check
    println!("\n--- Step 2: Health check ---");
    match store.health_check() {
        Ok(()) => println!(
            "  [OK] TPM health check passed (backend: {})",
            store.backend_name()
        ),
        Err(e) => println!("  [FAIL] Health check failed: {}", e),
    }

    // Step 3: Generate ECDSA P-256 key
    println!("\n--- Step 3: Generate ECDSA P-256 key ---");
    let p256_id = match store.generate_key("test-p256", KeySpec::EcdsaP256) {
        Ok(id) => {
            println!("  [OK] Generated key: {}", id);
            id
        }
        Err(e) => {
            println!("  [FAIL] Key generation failed: {}", e);
            println!("\n  This usually means the SRK is not provisioned or the TPM");
            println!("  rejected the key creation parameters.");
            std::process::exit(1);
        }
    };

    // Step 4: Get key info
    println!("\n--- Step 4: Key info ---");
    match store.key_info(&p256_id) {
        Ok(info) => {
            println!("  Key ID:      {}", info.id);
            println!("  Algorithm:   {}", info.spec.algorithm_name());
            println!("  Label:       {}", info.label);
            println!("  Exportable:  {}", info.exportable);
            println!("  Fingerprint: {}", info.fingerprint);
            println!("  Created:     {}", info.created_at);
        }
        Err(e) => println!("  [FAIL] {}", e),
    }

    // Step 5: Get public key DER
    println!("\n--- Step 5: Public key export (SPKI DER) ---");
    match store.public_key_der(&p256_id) {
        Ok(der) => {
            println!("  [OK] Public key: {} bytes (SPKI DER)", der.len());
            println!("  First 16 bytes: {:02X?}", &der[..der.len().min(16)]);
        }
        Err(e) => println!("  [FAIL] {}", e),
    }

    // Step 6: Sign data
    println!("\n--- Step 6: Sign data ---");
    let test_data = b"SPORK CA TPM signing test - this data is signed by the TPM chip";
    match store.sign(&p256_id, test_data) {
        Ok(sig) => {
            println!("  [OK] Signature: {} bytes (DER-encoded ECDSA)", sig.len());
            println!("  First 16 bytes: {:02X?}", &sig[..sig.len().min(16)]);
        }
        Err(e) => {
            println!("  [FAIL] Signing failed: {}", e);
            println!("\n  The key was generated but signing failed. This could mean:");
            println!("  - TPM transient memory full (try: tpm2_flushcontext -t)");
            println!("  - Key blob corrupted on disk");
            println!("  - TPM device became unavailable");
        }
    }

    // Step 7: Test export (should fail — TPM keys are non-exportable)
    println!("\n--- Step 7: Export key (should fail) ---");
    match store.export_private_key(&p256_id) {
        Ok(_) => println!("  [UNEXPECTED] Export succeeded — this should not happen with TPM"),
        Err(e) => println!("  [OK] Export correctly denied: {}", e),
    }

    // Step 8: Test verify (should return NotSupported)
    println!("\n--- Step 8: Verify (should return NotSupported) ---");
    match store.verify(&p256_id, b"data", &[0u8; 64]) {
        Ok(_) => println!("  [UNEXPECTED] Verify returned OK"),
        Err(e) => println!("  [OK] Verify correctly deferred: {}", e),
    }

    // Step 9: List keys
    println!("\n--- Step 9: List keys ---");
    match store.list_keys() {
        Ok(keys) => {
            println!("  [OK] {} key(s) in store:", keys.len());
            for k in &keys {
                println!("    - {} ({}, {})", k.id, k.spec.algorithm_name(), k.label);
            }
        }
        Err(e) => println!("  [FAIL] {}", e),
    }

    // Step 10: Generate ECDSA P-384 key
    println!("\n--- Step 10: Generate ECDSA P-384 key ---");
    match store.generate_key("test-p384", KeySpec::EcdsaP384) {
        Ok(id) => {
            println!("  [OK] Generated P-384 key: {}", id);
            // Sign with P-384
            match store.sign(&id, test_data) {
                Ok(sig) => println!("  [OK] P-384 signature: {} bytes", sig.len()),
                Err(e) => println!("  [FAIL] P-384 signing failed: {}", e),
            }
        }
        Err(e) => println!("  [FAIL] P-384 generation failed: {}", e),
    }

    // Step 11: Generate RSA-2048 key (slower)
    println!("\n--- Step 11: Generate RSA-2048 key (this may take a moment) ---");
    match store.generate_key("test-rsa2048", KeySpec::Rsa2048) {
        Ok(id) => {
            println!("  [OK] Generated RSA-2048 key: {}", id);
            match store.sign(&id, test_data) {
                Ok(sig) => println!("  [OK] RSA signature: {} bytes", sig.len()),
                Err(e) => println!("  [FAIL] RSA signing failed: {}", e),
            }
        }
        Err(e) => println!("  [FAIL] RSA-2048 generation failed: {}", e),
    }

    // Step 12: Delete and verify
    println!("\n--- Step 12: Delete key and verify ---");
    if store.key_exists(&p256_id) {
        match store.delete_key(&p256_id) {
            Ok(()) => println!("  [OK] Key deleted"),
            Err(e) => println!("  [FAIL] Delete failed: {}", e),
        }
        println!("  Key exists after delete: {}", store.key_exists(&p256_id));
    }

    // Final list
    println!("\n--- Final key count ---");
    match store.list_keys() {
        Ok(keys) => println!("  {} key(s) remaining", keys.len()),
        Err(e) => println!("  [FAIL] {}", e),
    }

    // Cleanup
    println!("\n--- Cleanup ---");
    let _ = std::fs::remove_dir_all(&blob_dir);
    println!("  Removed blob directory");

    println!("\n=== TPM Integration Test Complete ===");
}

#[cfg(not(feature = "tpm"))]
fn main() {
    eprintln!("ERROR: This binary must be compiled with --features tpm");
    eprintln!("  cargo build --example tpm_test --features tpm");
    std::process::exit(1);
}
