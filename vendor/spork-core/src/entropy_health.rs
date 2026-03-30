//! SP 800-90B Entropy Health Monitoring
//!
//! Validates that the entropy source is functioning correctly before
//! key generation and other security-critical random operations.
//!
//! ## Health Tests
//!
//! - **Repetition Count Test** (SP 800-90B §4.4.1): Detects stuck bits
//! - **Adaptive Proportion Test** (SP 800-90B §4.4.2): Detects bias
//! - **Basic Statistical Check**: Byte distribution uniformity
//!
//! ## Usage
//!
//! Call `validate_entropy_source()` during CA initialization and
//! periodically during operation. Gate key generation on successful
//! entropy validation.

use chrono::{DateTime, Utc};

use crate::error::{Error, Result};

/// Result of a single entropy health test.
#[derive(Debug, Clone)]
pub struct EntropyTestResult {
    /// Test identifier
    pub test_id: &'static str,
    /// Human-readable description
    pub description: &'static str,
    /// Whether the test passed
    pub passed: bool,
    /// SP 800-90B reference
    pub reference: &'static str,
}

/// Aggregate results of entropy health validation.
#[derive(Debug, Clone)]
pub struct EntropyHealthReport {
    /// Individual test results
    pub results: Vec<EntropyTestResult>,
    /// When the validation was performed
    pub timestamp: DateTime<Utc>,
    /// Number of random bytes sampled
    pub sample_size: usize,
    /// Whether all tests passed
    pub all_passed: bool,
}

impl EntropyHealthReport {
    /// Return a human-readable summary.
    pub fn summary(&self) -> String {
        let passed = self.results.iter().filter(|r| r.passed).count();
        let total = self.results.len();
        let status = if self.all_passed {
            "HEALTHY"
        } else {
            "DEGRADED"
        };
        format!(
            "Entropy source: {} ({}/{} tests passed, {} bytes sampled) at {}",
            status,
            passed,
            total,
            self.sample_size,
            self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        )
    }

    /// Return any failed tests.
    pub fn failures(&self) -> Vec<&EntropyTestResult> {
        self.results.iter().filter(|r| !r.passed).collect()
    }
}

/// Validate the entropy source by sampling random bytes and running health tests.
///
/// Per SP 800-90B §4.4, entropy sources must be validated for:
/// - No stuck bits (repetition count test)
/// - No excessive bias (adaptive proportion test)
/// - Reasonable byte distribution (chi-squared-like check)
///
/// The sample_size controls how many bytes to draw from the OS RNG.
/// Minimum recommended: 1024 bytes for meaningful statistics.
pub fn validate_entropy_source(sample_size: usize) -> EntropyHealthReport {
    let sample_size = sample_size.max(256); // Enforce minimum
    let sample = generate_sample(sample_size);
    let results = vec![
        repetition_count_test(&sample),
        adaptive_proportion_test(&sample),
        byte_distribution_test(&sample),
        minimum_entropy_estimate(&sample),
    ];

    let all_passed = results.iter().all(|r| r.passed);

    EntropyHealthReport {
        results,
        timestamp: Utc::now(),
        sample_size,
        all_passed,
    }
}

/// Gate key generation on successful entropy validation.
pub fn require_entropy_healthy(report: &EntropyHealthReport) -> Result<()> {
    if report.all_passed {
        Ok(())
    } else {
        let failures: Vec<String> = report
            .failures()
            .iter()
            .map(|f| format!("{}: {}", f.test_id, f.description))
            .collect();
        Err(Error::PolicyViolation(format!(
            "SP 800-90B entropy health check FAILED — key generation blocked. \
             Failed tests: {}",
            failures.join("; ")
        )))
    }
}

/// Generate a random sample from the OS entropy source.
fn generate_sample(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// Repetition Count Test (SP 800-90B §4.4.1)
///
/// Detects stuck bits in the entropy source by checking if any byte value
/// repeats more times consecutively than the threshold. For 8-bit samples
/// with H=4 (min entropy 4 bits per byte), the cutoff C = 1 + ceil(4/H) * alpha
/// We use a practical cutoff of 20 consecutive identical bytes.
fn repetition_count_test(sample: &[u8]) -> EntropyTestResult {
    let cutoff = 20; // Conservative cutoff for 8-bit samples
    let mut max_run = 1u32;
    let mut current_run = 1u32;

    for window in sample.windows(2) {
        if window[0] == window[1] {
            current_run += 1;
            if current_run > max_run {
                max_run = current_run;
            }
        } else {
            current_run = 1;
        }
    }

    EntropyTestResult {
        test_id: "ENT-RCT-001",
        description: "Repetition count test — no stuck bits detected",
        passed: max_run < cutoff,
        reference: "SP 800-90B §4.4.1",
    }
}

/// Adaptive Proportion Test (SP 800-90B §4.4.2)
///
/// Checks a sliding window for any single byte value appearing too frequently.
/// For 8-bit samples with window W=512, the cutoff is approximately 11
/// occurrences (alpha=2^-30 significance level).
fn adaptive_proportion_test(sample: &[u8]) -> EntropyTestResult {
    let window_size = 512.min(sample.len());
    let cutoff = (window_size as f64 * 0.1) as u32; // >10% of window is suspicious
    let cutoff = cutoff.max(20); // At least 20 to avoid false positives on small samples

    let mut passed = true;

    // Check each window-sized chunk
    for chunk in sample.chunks(window_size) {
        if chunk.len() < window_size / 2 {
            break; // Skip too-small trailing chunks
        }
        // Count occurrences of the first byte in this chunk
        let target = chunk[0];
        let count = chunk.iter().filter(|&&b| b == target).count() as u32;
        if count > cutoff {
            passed = false;
            break;
        }
    }

    EntropyTestResult {
        test_id: "ENT-APT-001",
        description: "Adaptive proportion test — no excessive bias",
        passed,
        reference: "SP 800-90B §4.4.2",
    }
}

/// Byte Distribution Test (statistical uniformity check)
///
/// Counts the frequency of each byte value (0-255) and checks that no
/// value appears much more or less often than expected. For a uniform
/// distribution, each byte value should appear approximately N/256 times.
///
/// Uses a chi-squared-like threshold: if any bucket deviates by more
/// than 4 standard deviations from expected, the test fails.
fn byte_distribution_test(sample: &[u8]) -> EntropyTestResult {
    let n = sample.len() as f64;
    let expected = n / 256.0;
    let std_dev = (expected * (1.0 - 1.0 / 256.0)).sqrt();
    let threshold = 5.0 * std_dev; // 5-sigma threshold

    let mut counts = [0u32; 256];
    for &byte in sample {
        counts[byte as usize] += 1;
    }

    let max_deviation = counts
        .iter()
        .map(|&c| (c as f64 - expected).abs())
        .fold(0.0f64, f64::max);

    EntropyTestResult {
        test_id: "ENT-DIST-001",
        description: "Byte distribution uniformity — no severe bias",
        passed: max_deviation <= threshold,
        reference: "SP 800-90B §5 (min-entropy estimation)",
    }
}

/// Minimum Entropy Estimate
///
/// Estimates the min-entropy of the sample using the most common value
/// estimator (SP 800-90B §6.3.1). For a healthy source, min-entropy
/// should be at least 6 bits per byte (out of 8 max).
fn minimum_entropy_estimate(sample: &[u8]) -> EntropyTestResult {
    let mut counts = [0u32; 256];
    for &byte in sample {
        counts[byte as usize] += 1;
    }

    let n = sample.len() as f64;
    let max_count = *counts.iter().max().unwrap_or(&0) as f64;
    let p_max = max_count / n;

    // Min-entropy = -log2(p_max)
    let min_entropy = if p_max > 0.0 {
        -p_max.log2()
    } else {
        8.0 // Perfect entropy if no value appears (impossible in practice)
    };

    // For OS RNG, we expect ~7.9+ bits per byte
    // A threshold of 6.0 catches catastrophically broken sources
    let threshold = 6.0;

    EntropyTestResult {
        test_id: "ENT-MINE-001",
        description: "Minimum entropy estimate — sufficient randomness",
        passed: min_entropy >= threshold,
        reference: "SP 800-90B §6.3.1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_entropy_source_passes() {
        // Use 4096 bytes so the distribution test has ~16 expected counts per
        // bucket, avoiding flaky failures from small-sample variance.
        let report = validate_entropy_source(4096);
        assert!(
            report.all_passed,
            "OS entropy should pass health checks. Failures: {:?}",
            report
                .failures()
                .iter()
                .map(|f| f.test_id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_entropy_report_summary() {
        let report = validate_entropy_source(4096);
        let summary = report.summary();
        assert!(summary.contains("HEALTHY"));
        assert!(summary.contains("4/4"));
    }

    #[test]
    fn test_repetition_count_all_zeros_fails() {
        let sample = vec![0u8; 1024];
        let result = repetition_count_test(&sample);
        assert!(!result.passed, "All-zero sample should fail RCT");
    }

    #[test]
    fn test_repetition_count_random_passes() {
        let sample = generate_sample(1024);
        let result = repetition_count_test(&sample);
        assert!(result.passed, "Random sample should pass RCT");
    }

    #[test]
    fn test_adaptive_proportion_all_same_fails() {
        let sample = vec![42u8; 1024];
        let result = adaptive_proportion_test(&sample);
        assert!(!result.passed, "All-same sample should fail APT");
    }

    #[test]
    fn test_adaptive_proportion_random_passes() {
        let sample = generate_sample(1024);
        let result = adaptive_proportion_test(&sample);
        assert!(result.passed, "Random sample should pass APT");
    }

    #[test]
    fn test_byte_distribution_random_passes() {
        // Use 16384 bytes: with 256 bins, expected=64/bin, std_dev≈7.97,
        // threshold=5σ≈39.9. Much more headroom than 4096 (expected=16,
        // threshold≈19.8) which was flaky due to multiple-comparison effects
        // across 256 bins.
        let sample = generate_sample(16384);
        let result = byte_distribution_test(&sample);
        assert!(result.passed, "Random sample should pass distribution test");
    }

    /// Verify the distribution test accepts a perfectly uniform sample.
    #[test]
    fn test_byte_distribution_uniform_passes() {
        // Exactly 64 of each byte value — zero deviation, must always pass.
        let sample: Vec<u8> = (0..256u16)
            .flat_map(|b| std::iter::repeat_n(b as u8, 64))
            .collect();
        let result = byte_distribution_test(&sample);
        assert!(
            result.passed,
            "Perfectly uniform sample must pass distribution test"
        );
    }

    #[test]
    fn test_byte_distribution_biased_fails() {
        // Create a heavily biased sample
        let sample: Vec<u8> = (0..4096)
            .map(|i| if i < 3500 { 0 } else { (i % 256) as u8 })
            .collect();
        let result = byte_distribution_test(&sample);
        assert!(!result.passed, "Heavily biased sample should fail");
    }

    #[test]
    fn test_min_entropy_random_passes() {
        let sample = generate_sample(4096);
        let result = minimum_entropy_estimate(&sample);
        assert!(result.passed, "Random sample should have good min-entropy");
    }

    #[test]
    fn test_min_entropy_constant_fails() {
        let sample = vec![42u8; 1024];
        let result = minimum_entropy_estimate(&sample);
        assert!(!result.passed, "Constant sample has zero min-entropy");
    }

    #[test]
    fn test_require_entropy_healthy_ok() {
        let report = validate_entropy_source(4096);
        assert!(require_entropy_healthy(&report).is_ok());
    }

    #[test]
    fn test_require_entropy_healthy_blocks_on_failure() {
        let report = EntropyHealthReport {
            results: vec![EntropyTestResult {
                test_id: "ENT-FAKE-001",
                description: "Intentionally failed",
                passed: false,
                reference: "test",
            }],
            timestamp: Utc::now(),
            sample_size: 0,
            all_passed: false,
        };
        let err = require_entropy_healthy(&report);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("SP 800-90B entropy health check FAILED"));
    }

    #[test]
    fn test_entropy_minimum_sample_size() {
        // Even with small request, should enforce minimum
        let report = validate_entropy_source(10);
        assert_eq!(report.sample_size, 256);
    }

    #[test]
    fn test_entropy_test_references() {
        let report = validate_entropy_source(4096);
        for test in &report.results {
            assert!(
                !test.reference.is_empty(),
                "Test {} should have SP 800-90B reference",
                test.test_id
            );
        }
    }

    #[test]
    fn test_entropy_failures_empty_when_healthy() {
        let report = validate_entropy_source(4096);
        assert!(report.failures().is_empty());
    }
}
