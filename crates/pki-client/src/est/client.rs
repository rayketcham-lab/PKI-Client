//! EST Client Implementation
//!
//! Provides a client for interacting with EST servers (RFC 7030).

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use std::path::Path;
use std::time::Duration;

use super::types::{content_type, EstOperation, ServerKeyGenResponse};

/// EST Client.
pub struct EstClient {
    /// HTTP client
    client: Client,
    /// EST server base URL
    base_url: String,
    /// Username for HTTP Basic Auth
    username: Option<String>,
    /// Password for HTTP Basic Auth
    password: Option<String>,
    /// Client certificate path (for TLS client auth)
    client_cert: Option<String>,
    /// Client key path (for TLS client auth)
    client_key: Option<String>,
    /// Custom label (for non-default EST paths)
    label: Option<String>,
}

impl EstClient {
    /// Create a new EST client with TLS options.
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
            username: None,
            password: None,
            client_cert: None,
            client_key: None,
            label: None,
        }
    }

    /// Set HTTP Basic Auth credentials.
    pub fn with_basic_auth(mut self, username: &str, password: &str) -> Self {
        self.username = Some(username.to_string());
        self.password = Some(password.to_string());
        self
    }

    /// Set client certificate for mutual TLS.
    #[allow(dead_code)]
    pub fn with_client_cert(mut self, cert_path: &str, key_path: &str) -> Self {
        self.client_cert = Some(cert_path.to_string());
        self.client_key = Some(key_path.to_string());
        self
    }

    /// Set custom EST label (for /arbitraryLabel/ paths).
    #[allow(dead_code)]
    pub fn with_label(mut self, label: &str) -> Self {
        self.label = Some(label.to_string());
        self
    }

    /// Build the URL for an EST operation.
    fn build_url(&self, operation: EstOperation) -> String {
        let path = match &self.label {
            Some(label) => format!("/.well-known/est/{}/{}", label, operation.path()),
            None => format!("/.well-known/est/{}", operation.path()),
        };
        format!("{}{}", self.base_url.trim_end_matches('/'), path)
    }

    /// Build authorization header for HTTP Basic Auth.
    fn auth_header(&self) -> Option<HeaderValue> {
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            let credentials = format!("{}:{}", username, password);
            let encoded = STANDARD.encode(credentials.as_bytes());
            HeaderValue::from_str(&format!("Basic {}", encoded)).ok()
        } else {
            None
        }
    }

    /// Get CA certificates from the EST server.
    ///
    /// Returns PEM-encoded CA certificates.
    pub fn get_ca_certs(&self) -> Result<String> {
        let url = self.build_url(EstOperation::CaCerts);

        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static(content_type::PKCS7_CERTS));

        let response = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .with_context(|| format!("Failed to connect to EST server: {}", url))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "EST server returned error: HTTP {}",
                response.status()
            ));
        }

        let body = response
            .bytes()
            .context("Failed to read EST response body")?;

        // Response is PKCS#7 (DER or Base64)
        // Convert to PEM certificates
        self.pkcs7_to_pem(&body)
    }

    /// Simple enrollment - request a certificate using a CSR.
    ///
    /// Takes PEM or DER encoded CSR, returns PEM certificate.
    pub fn simple_enroll(&self, csr: &[u8]) -> Result<String> {
        self.enroll_internal(EstOperation::SimpleEnroll, csr)
    }

    /// Re-enrollment - renew an existing certificate using a CSR.
    ///
    /// Takes PEM or DER encoded CSR, returns PEM certificate.
    pub fn simple_reenroll(&self, csr: &[u8]) -> Result<String> {
        self.enroll_internal(EstOperation::SimpleReEnroll, csr)
    }

    /// Internal enrollment implementation.
    fn enroll_internal(&self, operation: EstOperation, csr: &[u8]) -> Result<String> {
        let url = self.build_url(operation);

        // Convert CSR to base64 (EST uses base64 for CSR body)
        let csr_der = if csr.starts_with(b"-----BEGIN") {
            // PEM - extract DER
            let pem = pem::parse(csr).context("Failed to parse CSR PEM")?;
            pem.into_contents()
        } else {
            csr.to_vec()
        };

        let csr_base64 = STANDARD.encode(&csr_der);

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type::PKCS10));
        headers.insert(ACCEPT, HeaderValue::from_static(content_type::PKCS7_ENROLL));

        if let Some(auth) = self.auth_header() {
            headers.insert(AUTHORIZATION, auth);
        }

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body(csr_base64)
            .send()
            .with_context(|| format!("Failed to connect to EST server: {}", url))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            return Err(anyhow!("EST enrollment failed: HTTP {} - {}", status, body));
        }

        let body = response
            .bytes()
            .context("Failed to read EST response body")?;

        // Response is PKCS#7 certificate
        self.pkcs7_to_pem(&body)
    }

    /// Server-side key generation - let the server generate the keypair.
    ///
    /// Takes PEM or DER encoded CSR (with subject info), returns certificate and private key.
    pub fn server_keygen(&self, csr: &[u8]) -> Result<ServerKeyGenResponse> {
        let url = self.build_url(EstOperation::ServerKeyGen);

        // Convert CSR to base64
        let csr_der = if csr.starts_with(b"-----BEGIN") {
            let pem = pem::parse(csr).context("Failed to parse CSR PEM")?;
            pem.into_contents()
        } else {
            csr.to_vec()
        };

        let csr_base64 = STANDARD.encode(&csr_der);

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type::PKCS10));
        // Server keygen returns multipart with cert + key
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("multipart/mixed, application/pkcs7-mime"),
        );

        if let Some(auth) = self.auth_header() {
            headers.insert(AUTHORIZATION, auth);
        }

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body(csr_base64)
            .send()
            .with_context(|| format!("Failed to connect to EST server: {}", url))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            return Err(anyhow!(
                "EST server keygen failed: HTTP {} - {}",
                status,
                body
            ));
        }

        // Parse multipart response
        // For simplicity, we'll try to extract both parts
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();

        let body = response
            .bytes()
            .context("Failed to read EST response body")?;

        self.parse_server_keygen_response(&content_type, &body)
    }

    /// Get CSR attributes from the EST server.
    ///
    /// Returns the CSR attributes as a string (may be ASN.1 or descriptive).
    pub fn get_csr_attrs(&self) -> Result<Option<String>> {
        let url = self.build_url(EstOperation::CsrAttrs);

        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static(content_type::CSR_ATTRS));

        if let Some(auth) = self.auth_header() {
            headers.insert(AUTHORIZATION, auth);
        }

        let response = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .with_context(|| format!("Failed to connect to EST server: {}", url))?;

        // 204 No Content is valid - no required attributes
        if response.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(anyhow!(
                "EST server returned error: HTTP {}",
                response.status()
            ));
        }

        let body = response.text().context("Failed to read EST response")?;
        Ok(Some(body))
    }

    /// Convert PKCS#7 response to PEM certificates.
    fn pkcs7_to_pem(&self, data: &[u8]) -> Result<String> {
        // EST responses may be base64-encoded or raw DER
        let der_data = if data.iter().all(|&b| b.is_ascii()) {
            // Looks like base64
            STANDARD
                .decode(data)
                .context("Failed to decode base64 response")?
        } else {
            data.to_vec()
        };

        // For now, return as PEM-wrapped PKCS#7
        // A full implementation would parse PKCS#7 and extract individual certs
        let pem = pem::Pem::new("PKCS7", der_data);
        Ok(pem::encode(&pem))
    }

    /// Parse server keygen response (multipart or simple).
    fn parse_server_keygen_response(
        &self,
        content_type: &str,
        body: &[u8],
    ) -> Result<ServerKeyGenResponse> {
        // Simple implementation - try to detect parts
        // Real implementation would parse multipart/mixed properly

        if content_type.contains("multipart") {
            // Extract boundary and parse parts
            // For simplicity, we'll look for PEM markers
            let body_str = String::from_utf8_lossy(body);

            let cert_start = body_str
                .find("-----BEGIN CERTIFICATE-----")
                .ok_or_else(|| anyhow!("No certificate found in response"))?;
            let cert_end = body_str
                .find("-----END CERTIFICATE-----")
                .ok_or_else(|| anyhow!("Certificate not properly terminated"))?
                + 25;
            let certificate = body_str[cert_start..cert_end].to_string();

            let key_start = body_str
                .find("-----BEGIN PRIVATE KEY-----")
                .or_else(|| body_str.find("-----BEGIN RSA PRIVATE KEY-----"))
                .or_else(|| body_str.find("-----BEGIN EC PRIVATE KEY-----"))
                .ok_or_else(|| anyhow!("No private key found in response"))?;

            let key_marker = if body_str[key_start..].starts_with("-----BEGIN PRIVATE KEY") {
                "-----END PRIVATE KEY-----"
            } else if body_str[key_start..].starts_with("-----BEGIN RSA") {
                "-----END RSA PRIVATE KEY-----"
            } else {
                "-----END EC PRIVATE KEY-----"
            };

            let key_end = body_str
                .find(key_marker)
                .ok_or_else(|| anyhow!("Private key not properly terminated"))?
                + key_marker.len();
            let private_key = body_str[key_start..key_end].to_string();

            Ok(ServerKeyGenResponse {
                private_key,
                certificate,
            })
        } else {
            // Single PKCS#7 response - try to extract cert
            let cert_pem = self.pkcs7_to_pem(body)?;
            Err(anyhow!(
                "Server keygen response doesn't include private key. Certificate:\n{}",
                cert_pem
            ))
        }
    }

    /// Load CSR from file.
    pub fn load_csr(path: &Path) -> Result<Vec<u8>> {
        std::fs::read(path).with_context(|| format!("Failed to read CSR: {}", path.display()))
    }

    /// Save certificate to file.
    pub fn save_cert(path: &Path, cert: &str) -> Result<()> {
        std::fs::write(path, cert)
            .with_context(|| format!("Failed to write certificate: {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = EstClient::with_options("https://est.example.com", false, None);
        assert!(client.username.is_none());
        assert!(client.password.is_none());
    }

    #[test]
    fn test_with_basic_auth() {
        let client = EstClient::with_options("https://est.example.com", false, None)
            .with_basic_auth("user", "pass");
        assert_eq!(client.username.as_deref(), Some("user"));
        assert_eq!(client.password.as_deref(), Some("pass"));
    }

    #[test]
    fn test_url_building() {
        let client = EstClient::with_options("https://est.example.com", false, None);
        assert_eq!(
            client.build_url(EstOperation::CaCerts),
            "https://est.example.com/.well-known/est/cacerts"
        );
        assert_eq!(
            client.build_url(EstOperation::SimpleEnroll),
            "https://est.example.com/.well-known/est/simpleenroll"
        );
    }

    #[test]
    fn test_url_building_with_label() {
        let client =
            EstClient::with_options("https://est.example.com", false, None).with_label("myca");
        assert_eq!(
            client.build_url(EstOperation::CaCerts),
            "https://est.example.com/.well-known/est/myca/cacerts"
        );
    }

    #[test]
    fn test_auth_header() {
        let client = EstClient::with_options("https://est.example.com", false, None)
            .with_basic_auth("admin", "secret");
        let header = client.auth_header().expect("Should have auth header");
        let value = header.to_str().unwrap();
        assert!(value.starts_with("Basic "));
        // "admin:secret" in base64 is "YWRtaW46c2VjcmV0"
        assert!(value.contains("YWRtaW46c2VjcmV0"));
    }

    #[test]
    fn test_operation_paths() {
        assert_eq!(EstOperation::CaCerts.path(), "cacerts");
        assert_eq!(EstOperation::SimpleEnroll.path(), "simpleenroll");
        assert_eq!(EstOperation::SimpleReEnroll.path(), "simplereenroll");
        assert_eq!(EstOperation::ServerKeyGen.path(), "serverkeygen");
        assert_eq!(EstOperation::CsrAttrs.path(), "csrattrs");
    }

    #[test]
    fn test_operation_methods() {
        assert_eq!(EstOperation::CaCerts.method(), "GET");
        assert_eq!(EstOperation::CsrAttrs.method(), "GET");
        assert_eq!(EstOperation::SimpleEnroll.method(), "POST");
        assert_eq!(EstOperation::SimpleReEnroll.method(), "POST");
        assert_eq!(EstOperation::ServerKeyGen.method(), "POST");
    }
}
