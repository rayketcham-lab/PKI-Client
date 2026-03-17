//! Prometheus Metrics Module
//!
//! This module provides Prometheus-compatible metrics for SPORK services.
//! Metrics are exposed in Prometheus text format for scraping.
//!
//! # Usage
//!
//! ```rust,no_run
//! use spork_core::metrics::{Metrics, MetricsRegistry};
//!
//! let registry = MetricsRegistry::new();
//! let metrics = Metrics::new(&registry);
//!
//! // Record metrics
//! metrics.certificates_issued.inc();
//! metrics.request_duration.observe(0.5);
//!
//! // Export for Prometheus
//! let output = registry.export();
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};

/// Metric type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    /// Counter (monotonically increasing)
    Counter,
    /// Gauge (can go up and down)
    Gauge,
    /// Histogram (distribution of values)
    Histogram,
}

/// A single metric value
#[derive(Debug)]
pub struct Metric {
    /// Metric name
    pub name: String,
    /// Metric help text
    pub help: String,
    /// Metric type
    pub metric_type: MetricType,
    /// Labels
    pub labels: Vec<(String, String)>,
    /// Value (for counter/gauge)
    value: AtomicU64,
    /// Histogram buckets (for histogram)
    buckets: Option<Vec<HistogramBucket>>,
}

/// Histogram bucket
#[derive(Debug)]
struct HistogramBucket {
    /// Upper bound
    le: f64,
    /// Count
    count: AtomicU64,
}

impl Metric {
    /// Create a new counter
    pub fn counter(name: &str, help: &str) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            metric_type: MetricType::Counter,
            labels: Vec::new(),
            value: AtomicU64::new(0),
            buckets: None,
        }
    }

    /// Create a new gauge
    pub fn gauge(name: &str, help: &str) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            metric_type: MetricType::Gauge,
            labels: Vec::new(),
            value: AtomicU64::new(0),
            buckets: None,
        }
    }

    /// Create a new histogram with default buckets
    pub fn histogram(name: &str, help: &str) -> Self {
        let default_buckets = vec![
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ];
        Self::histogram_with_buckets(name, help, &default_buckets)
    }

    /// Create a new histogram with custom buckets
    pub fn histogram_with_buckets(name: &str, help: &str, bounds: &[f64]) -> Self {
        let buckets: Vec<HistogramBucket> = bounds
            .iter()
            .map(|&le| HistogramBucket {
                le,
                count: AtomicU64::new(0),
            })
            .collect();

        Self {
            name: name.to_string(),
            help: help.to_string(),
            metric_type: MetricType::Histogram,
            labels: Vec::new(),
            value: AtomicU64::new(0), // Sum
            buckets: Some(buckets),
        }
    }

    /// Add a label
    pub fn with_label(mut self, name: &str, value: &str) -> Self {
        self.labels.push((name.to_string(), value.to_string()));
        self
    }

    /// Increment counter by 1
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Add to counter
    pub fn add(&self, v: u64) {
        self.value.fetch_add(v, Ordering::Relaxed);
    }

    /// Set gauge value
    pub fn set(&self, v: f64) {
        self.value.store(v.to_bits(), Ordering::Relaxed);
    }

    /// Get gauge value
    pub fn get(&self) -> f64 {
        f64::from_bits(self.value.load(Ordering::Relaxed))
    }

    /// Observe a histogram value
    pub fn observe(&self, v: f64) {
        if let Some(ref buckets) = self.buckets {
            for bucket in buckets {
                if v <= bucket.le {
                    bucket.count.fetch_add(1, Ordering::Relaxed);
                }
            }
            // Add to sum
            loop {
                let current = self.value.load(Ordering::Relaxed);
                let current_f = f64::from_bits(current);
                let new_f = current_f + v;
                if self.value.compare_exchange(
                    current,
                    new_f.to_bits(),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ).is_ok() {
                    break;
                }
            }
        }
    }

    /// Export in Prometheus format
    pub fn export(&self) -> String {
        let mut output = String::new();

        // TYPE and HELP
        let type_str = match self.metric_type {
            MetricType::Counter => "counter",
            MetricType::Gauge => "gauge",
            MetricType::Histogram => "histogram",
        };
        output.push_str(&format!("# HELP {} {}\n", self.name, self.help));
        output.push_str(&format!("# TYPE {} {}\n", self.name, type_str));

        // Format labels
        let labels_str = if self.labels.is_empty() {
            String::new()
        } else {
            let pairs: Vec<String> = self.labels
                .iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, v))
                .collect();
            format!("{{{}}}", pairs.join(","))
        };

        match self.metric_type {
            MetricType::Counter => {
                let value = self.value.load(Ordering::Relaxed);
                output.push_str(&format!("{}{} {}\n", self.name, labels_str, value));
            }
            MetricType::Gauge => {
                let value = f64::from_bits(self.value.load(Ordering::Relaxed));
                output.push_str(&format!("{}{} {}\n", self.name, labels_str, value));
            }
            MetricType::Histogram => {
                if let Some(ref buckets) = self.buckets {
                    let mut total_count = 0u64;
                    for bucket in buckets {
                        let count = bucket.count.load(Ordering::Relaxed);
                        total_count = count; // Last bucket has total
                        let bucket_labels = if labels_str.is_empty() {
                            format!("{{le=\"{}\"}}", bucket.le)
                        } else {
                            let base = &labels_str[1..labels_str.len()-1];
                            format!("{{{},le=\"{}\"}}", base, bucket.le)
                        };
                        output.push_str(&format!(
                            "{}_bucket{} {}\n",
                            self.name, bucket_labels, count
                        ));
                    }
                    // +Inf bucket
                    let inf_labels = if labels_str.is_empty() {
                        "{le=\"+Inf\"}".to_string()
                    } else {
                        let base = &labels_str[1..labels_str.len()-1];
                        format!("{{{},le=\"+Inf\"}}", base)
                    };
                    output.push_str(&format!(
                        "{}_bucket{} {}\n",
                        self.name, inf_labels, total_count
                    ));

                    let sum = f64::from_bits(self.value.load(Ordering::Relaxed));
                    output.push_str(&format!("{}_sum{} {}\n", self.name, labels_str, sum));
                    output.push_str(&format!("{}_count{} {}\n", self.name, labels_str, total_count));
                }
            }
        }

        output
    }
}

/// Metrics registry
pub struct MetricsRegistry {
    /// Registered metrics
    metrics: RwLock<HashMap<String, Arc<Metric>>>,
    /// Start time
    start_time: DateTime<Utc>,
}

impl MetricsRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self {
            metrics: RwLock::new(HashMap::new()),
            start_time: Utc::now(),
        }
    }

    /// Register a metric
    pub fn register(&self, metric: Metric) -> Arc<Metric> {
        let arc = Arc::new(metric);
        let name = arc.name.clone();
        self.metrics.write().unwrap_or_else(|e| e.into_inner()).insert(name, arc.clone());
        arc
    }

    /// Export all metrics in Prometheus format
    pub fn export(&self) -> String {
        let metrics = self.metrics.read().unwrap_or_else(|e| e.into_inner());
        let mut output = String::new();

        for metric in metrics.values() {
            output.push_str(&metric.export());
        }

        output
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> f64 {
        (Utc::now() - self.start_time).num_milliseconds() as f64 / 1000.0
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// SPORK-specific metrics
pub struct SporkMetrics {
    /// Certificates issued counter
    pub certificates_issued: Arc<Metric>,
    /// Certificates revoked counter
    pub certificates_revoked: Arc<Metric>,
    /// CRLs generated counter
    pub crls_generated: Arc<Metric>,
    /// OCSP requests counter
    pub ocsp_requests: Arc<Metric>,
    /// Request duration histogram
    pub request_duration: Arc<Metric>,
    /// Active connections gauge
    pub active_connections: Arc<Metric>,
    /// Nonce pool size gauge
    pub nonce_pool_size: Arc<Metric>,
    /// Certificate expiring soon gauge
    pub certs_expiring_soon: Arc<Metric>,
    /// Key operations counter
    pub key_operations: Arc<Metric>,
    /// Error counter
    pub errors: Arc<Metric>,
}

impl SporkMetrics {
    /// Create and register SPORK metrics
    pub fn new(registry: &MetricsRegistry) -> Self {
        Self {
            certificates_issued: registry.register(
                Metric::counter("spork_certificates_issued_total", "Total certificates issued")
            ),
            certificates_revoked: registry.register(
                Metric::counter("spork_certificates_revoked_total", "Total certificates revoked")
            ),
            crls_generated: registry.register(
                Metric::counter("spork_crls_generated_total", "Total CRLs generated")
            ),
            ocsp_requests: registry.register(
                Metric::counter("spork_ocsp_requests_total", "Total OCSP requests processed")
            ),
            request_duration: registry.register(
                Metric::histogram("spork_request_duration_seconds", "Request duration in seconds")
            ),
            active_connections: registry.register(
                Metric::gauge("spork_active_connections", "Number of active connections")
            ),
            nonce_pool_size: registry.register(
                Metric::gauge("spork_nonce_pool_size", "Size of the nonce pool")
            ),
            certs_expiring_soon: registry.register(
                Metric::gauge("spork_certificates_expiring_30d", "Certificates expiring in 30 days")
            ),
            key_operations: registry.register(
                Metric::counter("spork_key_operations_total", "Total key operations")
            ),
            errors: registry.register(
                Metric::counter("spork_errors_total", "Total errors")
            ),
        }
    }

    /// Record a certificate issuance
    pub fn record_certificate_issued(&self) {
        self.certificates_issued.inc();
    }

    /// Record a certificate revocation
    pub fn record_certificate_revoked(&self) {
        self.certificates_revoked.inc();
    }

    /// Record a CRL generation
    pub fn record_crl_generated(&self) {
        self.crls_generated.inc();
    }

    /// Record an OCSP request
    pub fn record_ocsp_request(&self) {
        self.ocsp_requests.inc();
    }

    /// Record request duration
    pub fn record_request_duration(&self, duration_secs: f64) {
        self.request_duration.observe(duration_secs);
    }

    /// Set active connections
    pub fn set_active_connections(&self, count: u64) {
        self.active_connections.set(count as f64);
    }

    /// Record an error
    pub fn record_error(&self) {
        self.errors.inc();
    }
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Overall health status
    pub status: HealthState,
    /// Service name
    pub service: String,
    /// Version
    pub version: String,
    /// Uptime in seconds
    pub uptime_seconds: f64,
    /// Individual component health
    pub components: HashMap<String, ComponentHealth>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Health state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthState {
    /// All systems operational
    Healthy,
    /// Some issues but operational
    Degraded,
    /// Not operational
    Unhealthy,
}

/// Component health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component status
    pub status: HealthState,
    /// Optional message
    pub message: Option<String>,
    /// Last check time
    pub last_check: DateTime<Utc>,
}

use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let counter = Metric::counter("test_counter", "A test counter");
        counter.inc();
        counter.inc();
        counter.add(5);

        let output = counter.export();
        assert!(output.contains("test_counter 7"));
    }

    #[test]
    fn test_gauge() {
        let gauge = Metric::gauge("test_gauge", "A test gauge");
        gauge.set(42.5);

        let output = gauge.export();
        assert!(output.contains("test_gauge 42.5"));
    }

    #[test]
    fn test_histogram() {
        let hist = Metric::histogram("test_histogram", "A test histogram");
        hist.observe(0.1);
        hist.observe(0.5);
        hist.observe(1.5);

        let output = hist.export();
        assert!(output.contains("test_histogram_bucket"));
        assert!(output.contains("test_histogram_sum"));
        assert!(output.contains("test_histogram_count"));
    }

    #[test]
    fn test_registry() {
        let registry = MetricsRegistry::new();

        registry.register(Metric::counter("counter1", "First counter"));
        registry.register(Metric::gauge("gauge1", "First gauge"));

        let output = registry.export();
        assert!(output.contains("counter1"));
        assert!(output.contains("gauge1"));
    }

    #[test]
    fn test_spork_metrics() {
        let registry = MetricsRegistry::new();
        let metrics = SporkMetrics::new(&registry);

        metrics.record_certificate_issued();
        metrics.record_certificate_issued();
        metrics.record_request_duration(0.5);

        let output = registry.export();
        assert!(output.contains("spork_certificates_issued_total 2"));
        assert!(output.contains("spork_request_duration"));
    }
}
