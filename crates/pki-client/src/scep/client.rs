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

use super::envelope::{build_get_cert_initial, build_message_material, build_pkcs_req};
use super::response::parse_cert_rep;
use super::types::{CaCapabilities, EnrollConfig, EnrollmentResponse, PkiStatus, ScepOperation};

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

    /// Perform SCEP enrollment (RFC 8894).
    ///
    /// Orchestrates the full enrollment flow:
    /// 1. Fetch CA capabilities (GetCACaps)
    /// 2. Fetch CA certificate (GetCACert)
    /// 3. Generate key pair and build CSR
    /// 4. Build and submit PKCSReq message
    /// 5. Parse response; if PENDING, poll with GetCertInitial
    /// 6. Return issued certificate and private key
    pub fn enroll(&self, config: &EnrollConfig) -> Result<EnrollmentResponse> {
        // Step 1: Fetch CA capabilities
        let caps = self
            .get_ca_caps()
            .context("Failed to fetch CA capabilities")?;
        let use_post = caps.supports_post();

        // Step 2: Fetch CA certificate
        let ca_cert_pem = self
            .get_ca_cert()
            .context("Failed to fetch CA certificate")?;
        let ca_pub_key_der = extract_pub_key_from_pem_cert(&ca_cert_pem)
            .context("Failed to extract CA public key")?;

        // Step 3: Generate key pair, CSR, requester cert
        let material = build_message_material(
            &config.subject_cn,
            config.challenge.as_deref(),
            config.key_type,
            &config.san_names,
        )
        .context("Failed to build SCEP message material")?;

        let transaction_id = material.transaction_id.clone();
        let sender_nonce = material.sender_nonce;

        // Step 4: Build PKCSReq message
        let pkcs_req = build_pkcs_req(
            &material.csr_der,
            &material.requester_cert_der,
            &transaction_id,
            &sender_nonce,
            &ca_pub_key_der,
            &material.key_pair,
        )
        .context("Failed to build PKCSReq message")?;

        // Step 5: Submit via POST or GET
        let response_der = self
            .submit_pki_operation(&pkcs_req, use_post)
            .context("Failed to submit PKCSReq")?;

        // Step 6: Parse initial response
        let parsed = parse_cert_rep(&response_der).context("Failed to parse CertRep response")?;

        match parsed.status {
            PkiStatus::Success => {
                build_success_response(&transaction_id, &parsed.certificates, &material.key_pair)
            }
            PkiStatus::Failure => {
                let fail_str = parsed
                    .fail_info
                    .map(|f| f.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                Err(anyhow::anyhow!(
                    "SCEP enrollment failed: failInfo = {}",
                    fail_str
                ))
            }
            PkiStatus::Pending => {
                // Poll with GetCertInitial
                self.poll_for_cert(
                    config,
                    &transaction_id,
                    &sender_nonce,
                    &material.requester_cert_der,
                    &ca_pub_key_der,
                    &material.key_pair,
                    use_post,
                )
            }
        }
    }

    /// Poll the SCEP server with GetCertInitial messages until SUCCESS or FAILURE.
    #[allow(clippy::too_many_arguments)]
    fn poll_for_cert(
        &self,
        config: &EnrollConfig,
        transaction_id: &str,
        sender_nonce: &[u8; 16],
        requester_cert_der: &[u8],
        ca_pub_key_der: &[u8],
        key_pair: &spork_core::algo::KeyPair,
        use_post: bool,
    ) -> Result<EnrollmentResponse> {
        use std::thread;
        use std::time::Duration;

        for attempt in 0..config.max_polls {
            thread::sleep(Duration::from_secs(config.poll_interval_secs));

            eprintln!(
                "SCEP: enrollment pending, polling ({}/{})...",
                attempt + 1,
                config.max_polls
            );

            let get_cert_msg = build_get_cert_initial(
                &config.subject_cn,
                transaction_id,
                sender_nonce,
                requester_cert_der,
                ca_pub_key_der,
                key_pair,
            )
            .context("Failed to build GetCertInitial message")?;

            let response_der = self
                .submit_pki_operation(&get_cert_msg, use_post)
                .context("Failed to submit GetCertInitial")?;

            let parsed =
                parse_cert_rep(&response_der).context("Failed to parse GetCertInitial response")?;

            match parsed.status {
                PkiStatus::Success => {
                    return build_success_response(transaction_id, &parsed.certificates, key_pair);
                }
                PkiStatus::Failure => {
                    let fail_str = parsed
                        .fail_info
                        .map(|f| f.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    return Err(anyhow::anyhow!(
                        "SCEP enrollment failed during polling: failInfo = {}",
                        fail_str
                    ));
                }
                PkiStatus::Pending => {
                    // Continue polling
                }
            }
        }

        Err(anyhow::anyhow!(
            "SCEP enrollment still PENDING after {} polls",
            config.max_polls
        ))
    }

    /// Submit a PKI operation message via POST or GET.
    fn submit_pki_operation(&self, message: &[u8], use_post: bool) -> Result<Vec<u8>> {
        if use_post {
            self.pki_operation_post(message)
        } else {
            self.pki_operation_get(message)
        }
    }
}

/// Extract the SubjectPublicKeyInfo DER from a PEM-encoded X.509 certificate.
fn extract_pub_key_from_pem_cert(cert_pem: &str) -> Result<Vec<u8>> {
    // The PEM may contain multiple certs; use the first one (CA cert)
    let pem_data = pem::parse(cert_pem).context("Failed to parse CA certificate PEM")?;

    let cert_der = pem_data.contents();

    // Certificate ::= SEQUENCE { TBSCertificate, ... }
    // TBSCertificate contains SubjectPublicKeyInfo
    extract_spki_from_cert_der(cert_der)
}

/// Extract SPKI bytes from a DER-encoded X.509 certificate.
fn extract_spki_from_cert_der(cert_der: &[u8]) -> Result<Vec<u8>> {
    // Simple DER walk: SEQUENCE(SEQUENCE(version[0]? serial sig issuer validity subject SPKI...))
    if cert_der.is_empty() || cert_der[0] != 0x30 {
        return Err(anyhow::anyhow!(
            "Certificate DER does not start with SEQUENCE"
        ));
    }

    // Get outer SEQUENCE content
    let (cert_content, _) = parse_der_tlv(cert_der)?;

    // First field is TBSCertificate SEQUENCE
    if cert_content.is_empty() || cert_content[0] != 0x30 {
        return Err(anyhow::anyhow!("TBSCertificate is not a SEQUENCE"));
    }
    let (tbs_content, _) = parse_der_tlv(cert_content)?;

    // Walk TBS fields: version[0]?, serial, signature, issuer, validity, subject, SPKI
    let mut pos = 0;

    // Optional version [0]
    if pos < tbs_content.len() && tbs_content[pos] == 0xa0 {
        let (_, vlen) = parse_der_tlv(&tbs_content[pos..])?;
        pos += vlen;
    }

    // serial
    let (_, slen) = parse_der_tlv(&tbs_content[pos..])?;
    pos += slen;

    // signature AlgorithmIdentifier
    let (_, alen) = parse_der_tlv(&tbs_content[pos..])?;
    pos += alen;

    // issuer Name
    let (_, ilen) = parse_der_tlv(&tbs_content[pos..])?;
    pos += ilen;

    // validity
    let (_, valen) = parse_der_tlv(&tbs_content[pos..])?;
    pos += valen;

    // subject Name
    let (_, sublen) = parse_der_tlv(&tbs_content[pos..])?;
    pos += sublen;

    // SubjectPublicKeyInfo SEQUENCE — this is what we want (full TLV)
    if pos >= tbs_content.len() || tbs_content[pos] != 0x30 {
        return Err(anyhow::anyhow!("Expected SPKI SEQUENCE in TBSCertificate"));
    }
    let (_, spki_total) = parse_der_tlv(&tbs_content[pos..])?;
    Ok(tbs_content[pos..pos + spki_total].to_vec())
}

/// Parse a DER TLV. Returns `(content_slice_within_input, total_bytes_consumed)`.
fn parse_der_tlv(data: &[u8]) -> Result<(&[u8], usize)> {
    if data.len() < 2 {
        return Err(anyhow::anyhow!("DER TLV too short"));
    }
    let (len, hdr) = parse_der_len(&data[1..])?;
    let total = 1 + hdr + len;
    if data.len() < total {
        return Err(anyhow::anyhow!(
            "DER TLV truncated: need {}, have {}",
            total,
            data.len()
        ));
    }
    Ok((&data[1 + hdr..total], total))
}

/// Parse DER length field. Returns `(length, bytes_consumed)`.
fn parse_der_len(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(anyhow::anyhow!("Empty DER length field"));
    }
    if data[0] < 0x80 {
        return Ok((data[0] as usize, 1));
    }
    let n = (data[0] & 0x7f) as usize;
    if n == 0 || n > 4 {
        return Err(anyhow::anyhow!("Unsupported DER length form"));
    }
    if data.len() < 1 + n {
        return Err(anyhow::anyhow!("DER length truncated"));
    }
    let mut l = 0usize;
    for i in 0..n {
        l = (l << 8) | data[1 + i] as usize;
    }
    Ok((l, 1 + n))
}

/// Build an EnrollmentResponse from issued certificate DER bytes.
fn build_success_response(
    transaction_id: &str,
    cert_ders: &[Vec<u8>],
    key_pair: &spork_core::algo::KeyPair,
) -> Result<EnrollmentResponse> {
    use super::types::PkiStatus;

    // Convert first certificate to PEM
    let cert_pem = if let Some(first_cert) = cert_ders.first() {
        let p = pem::Pem::new("CERTIFICATE", first_cert.clone());
        Some(pem::encode(&p))
    } else {
        return Err(anyhow::anyhow!(
            "SCEP SUCCESS but no certificate in response"
        ));
    };

    // Export private key to PEM (PKCS#8)
    let key_pem = export_key_pem(key_pair)?;

    Ok(EnrollmentResponse {
        transaction_id: transaction_id.to_string(),
        status: PkiStatus::Success,
        fail_info: None,
        certificate: cert_pem,
        private_key_pem: Some(key_pem),
    })
}

/// Export key pair private key as PKCS#8 PEM.
fn export_key_pem(key_pair: &spork_core::algo::KeyPair) -> Result<String> {
    key_pair
        .private_key_pem()
        .map(|s| s.to_string())
        .context("Failed to export private key to PEM")
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
