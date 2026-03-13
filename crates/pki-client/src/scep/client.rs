//! SCEP Client Implementation
//!
//! Provides a client for interacting with SCEP servers (RFC 8894).
//!
//! Note: SCEP uses PKCS#7 enveloped data for encryption and signing.
//! This client provides the HTTP transport layer and basic operations.
//! Full PKCS#7 message handling requires additional cryptographic operations.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use std::path::Path;
use std::time::Duration;

use super::types::{CaCapabilities, ScepOperation};

/// SCEP content types.
pub mod content_type {
    /// PKCS#7 for PKI operation
    pub const PKI_MESSAGE: &str = "application/x-pki-message";
}

/// SCEP Client.
pub struct ScepClient {
    /// HTTP client
    client: Client,
    /// SCEP server base URL
    base_url: String,
}

impl ScepClient {
    /// Create a new SCEP client with TLS options.
    ///
    /// - `insecure`: if true, disables all TLS certificate verification (MITM risk!)
    /// - `ca_cert`: optional path to a PEM CA certificate for server verification
    pub fn with_options(
        base_url: impl Into<String>,
        insecure: bool,
        ca_cert: Option<&Path>,
    ) -> Self {
        let mut builder = Client::builder().timeout(Duration::from_secs(30));

        if insecure {
            eprintln!("WARNING: TLS certificate verification is DISABLED (--insecure).");
            eprintln!("         This connection is vulnerable to man-in-the-middle attacks.");
            eprintln!("         Only use this for testing with self-signed certificates.\n");
            builder = builder.danger_accept_invalid_certs(true);
        } else if let Some(ca_path) = ca_cert {
            match std::fs::read(ca_path) {
                Ok(pem_data) => match reqwest::Certificate::from_pem(&pem_data) {
                    Ok(cert) => {
                        builder = builder.add_root_certificate(cert);
                    }
                    Err(e) => {
                        eprintln!(
                            "WARNING: Failed to parse CA certificate {}: {}",
                            ca_path.display(),
                            e
                        );
                    }
                },
                Err(e) => {
                    eprintln!(
                        "WARNING: Failed to read CA certificate {}: {}",
                        ca_path.display(),
                        e
                    );
                }
            }
        }

        let client = builder.build().unwrap_or_else(|_| Client::new());

        Self {
            client,
            base_url: base_url.into(),
        }
    }

    /// Build URL for a SCEP operation.
    fn build_url(&self, operation: ScepOperation, message: Option<&str>) -> String {
        let base = self.base_url.trim_end_matches('/');
        match message {
            Some(msg) => format!("{}?operation={}&message={}", base, operation.param(), msg),
            None => format!("{}?operation={}", base, operation.param()),
        }
    }

    /// Get CA capabilities.
    ///
    /// Returns the list of capabilities supported by the SCEP server.
    pub fn get_ca_caps(&self) -> Result<CaCapabilities> {
        let url = self.build_url(ScepOperation::GetCACaps, None);

        let response = self
            .client
            .get(&url)
            .send()
            .with_context(|| format!("Failed to connect to SCEP server: {}", url))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "SCEP server returned error: HTTP {}",
                response.status()
            ));
        }

        let body = response.text().context("Failed to read SCEP response")?;
        Ok(CaCapabilities::from_response(&body))
    }

    /// Get CA certificate(s).
    ///
    /// Returns PKCS#7 degenerate (certs-only) containing CA certificate chain.
    /// The response is returned as PEM.
    pub fn get_ca_cert(&self) -> Result<String> {
        let url = self.build_url(ScepOperation::GetCACert, None);

        let response = self
            .client
            .get(&url)
            .send()
            .with_context(|| format!("Failed to connect to SCEP server: {}", url))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "SCEP server returned error: HTTP {}",
                response.status()
            ));
        }

        let body = response
            .bytes()
            .context("Failed to read SCEP response body")?;

        // Response is PKCS#7 DER or Base64
        self.pkcs7_to_pem(&body)
    }

    /// Get next CA certificate (for rollover).
    ///
    /// Returns PKCS#7 containing the next CA certificate, if available.
    pub fn get_next_ca_cert(&self) -> Result<Option<String>> {
        let url = self.build_url(ScepOperation::GetNextCACert, None);

        let response = self
            .client
            .get(&url)
            .send()
            .with_context(|| format!("Failed to connect to SCEP server: {}", url))?;

        // 404 or empty response means no rollover cert available
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(anyhow!(
                "SCEP server returned error: HTTP {}",
                response.status()
            ));
        }

        let body = response
            .bytes()
            .context("Failed to read SCEP response body")?;

        if body.is_empty() {
            return Ok(None);
        }

        let pem = self.pkcs7_to_pem(&body)?;
        Ok(Some(pem))
    }

    /// Send PKI operation via GET (for simple queries).
    ///
    /// The message should be a base64-encoded PKCS#7 SignedData.
    /// Returns the response as PEM-wrapped PKCS#7.
    pub fn pki_operation_get(&self, message: &[u8]) -> Result<Vec<u8>> {
        let encoded = STANDARD.encode(message);
        let url = self.build_url(ScepOperation::PKIOperation, Some(&encoded));

        let response = self
            .client
            .get(&url)
            .send()
            .with_context(|| "Failed to send SCEP GET request")?;

        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("SCEP PKI operation failed: HTTP {}", status));
        }

        let body = response.bytes().context("Failed to read SCEP response")?;

        Ok(body.to_vec())
    }

    /// Send PKI operation via POST.
    ///
    /// The message should be DER-encoded PKCS#7 SignedData.
    /// Returns the response as raw DER bytes.
    pub fn pki_operation_post(&self, message: &[u8]) -> Result<Vec<u8>> {
        let url = self.build_url(ScepOperation::PKIOperation, None);

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(content_type::PKI_MESSAGE),
        );

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body(message.to_vec())
            .send()
            .with_context(|| "Failed to send SCEP POST request")?;

        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("SCEP PKI operation failed: HTTP {}", status));
        }

        let body = response.bytes().context("Failed to read SCEP response")?;

        Ok(body.to_vec())
    }

    /// Convert PKCS#7 response to PEM.
    fn pkcs7_to_pem(&self, data: &[u8]) -> Result<String> {
        // SCEP responses may be raw DER or base64-encoded
        let der_data = if data.iter().all(|&b| b.is_ascii()) {
            // Looks like base64
            STANDARD
                .decode(data)
                .context("Failed to decode base64 response")?
        } else {
            data.to_vec()
        };

        // Return as PEM-wrapped PKCS#7
        let pem = pem::Pem::new("PKCS7", der_data);
        Ok(pem::encode(&pem))
    }

    /// Load PKCS#7 message from file.
    pub fn load_message(path: &Path) -> Result<Vec<u8>> {
        let data = std::fs::read(path)
            .with_context(|| format!("Failed to read SCEP message: {}", path.display()))?;

        // Convert PEM to DER if needed
        if data.starts_with(b"-----BEGIN") {
            let pem = pem::parse(&data).context("Failed to parse PEM")?;
            Ok(pem.into_contents())
        } else {
            Ok(data)
        }
    }

    /// Save response to file.
    pub fn save_response(path: &Path, data: &[u8]) -> Result<()> {
        std::fs::write(path, data)
            .with_context(|| format!("Failed to write response: {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = ScepClient::with_options("https://scep.example.com/scep", false, None);
        assert!(client.base_url.contains("scep.example.com"));
    }

    #[test]
    fn test_url_building() {
        let client = ScepClient::with_options("https://scep.example.com/scep", false, None);
        assert_eq!(
            client.build_url(ScepOperation::GetCACaps, None),
            "https://scep.example.com/scep?operation=GetCACaps"
        );
        assert_eq!(
            client.build_url(ScepOperation::GetCACert, None),
            "https://scep.example.com/scep?operation=GetCACert"
        );
    }

    #[test]
    fn test_url_building_with_message() {
        let client = ScepClient::with_options("https://scep.example.com/scep", false, None);
        let url = client.build_url(ScepOperation::PKIOperation, Some("ABC123"));
        assert!(url.contains("operation=PKIOperation"));
        assert!(url.contains("message=ABC123"));
    }

    #[test]
    fn test_ca_capabilities_parsing() {
        let response = "POSTPKIOperation\nSHA-256\nAES\nRenewal\n";
        let caps = CaCapabilities::from_response(response);
        assert!(caps.supports_post());
        assert!(caps.supports_sha256());
        assert!(caps.supports_aes());
        assert!(caps.supports_renewal());
    }

    #[test]
    fn test_ca_capabilities_case_insensitive() {
        let response = "postpkioperation\nsha-256\naes\n";
        let caps = CaCapabilities::from_response(response);
        assert!(caps.supports_post());
        assert!(caps.supports_sha256());
        assert!(caps.supports_aes());
    }
}
