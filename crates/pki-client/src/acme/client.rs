//! ACME Client Implementation
//!
//! Provides a client for interacting with ACME servers (RFC 8555).

use anyhow::{anyhow, Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, LOCATION};
use std::path::Path;
use std::thread;
use std::time::Duration;

use super::jws::{base64url_encode, AccountKey};
use super::types::*;

/// ACME Client.
pub struct AcmeClient {
    /// HTTP client
    client: Client,
    /// ACME directory URL
    directory_url: String,
    /// Cached directory
    directory: Option<Directory>,
    /// Account key
    account_key: Option<AccountKey>,
    /// Account URL (after registration)
    account_url: Option<String>,
    /// Current nonce
    nonce: Option<String>,
}

impl AcmeClient {
    /// Create a new ACME client.
    pub fn new(directory_url: impl Into<String>) -> Self {
        Self::with_options(directory_url, false, None)
    }

    /// Create a new ACME client with TLS options.
    ///
    /// - `insecure`: if true, disables all TLS certificate verification (MITM risk!)
    /// - `ca_cert`: optional path to a PEM CA certificate for server verification
    pub fn with_options(
        directory_url: impl Into<String>,
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
            directory_url: directory_url.into(),
            directory: None,
            account_key: None,
            account_url: None,
            nonce: None,
        }
    }

    /// Create a client for Let's Encrypt production.
    pub fn letsencrypt() -> Self {
        Self::new("https://acme-v02.api.letsencrypt.org/directory")
    }

    /// Create a client for Let's Encrypt staging.
    pub fn letsencrypt_staging() -> Self {
        Self::new("https://acme-staging-v02.api.letsencrypt.org/directory")
    }

    /// Set the account key.
    #[allow(dead_code)]
    pub fn with_account_key(mut self, key: AccountKey) -> Self {
        self.account_key = Some(key);
        self
    }

    /// Set the account URL (for existing accounts).
    #[allow(dead_code)]
    pub fn with_account_url(mut self, url: impl Into<String>) -> Self {
        self.account_url = Some(url.into());
        self
    }

    /// Generate a new account key.
    pub fn generate_account_key(&mut self) -> &AccountKey {
        self.account_key = Some(AccountKey::generate());
        self.account_key.as_ref().unwrap()
    }

    /// Load account key from PEM file.
    pub fn load_account_key(&mut self, path: &Path) -> Result<()> {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read account key: {}", path.display()))?;
        self.account_key = Some(AccountKey::from_pem(&pem)?);
        Ok(())
    }

    /// Save account key to PEM file with restrictive permissions (0600).
    pub fn save_account_key(&self, path: &Path) -> Result<()> {
        let key = self
            .account_key
            .as_ref()
            .ok_or_else(|| anyhow!("No account key"))?;
        crate::util::write_sensitive_file(path, key.to_pem())
            .with_context(|| format!("Failed to save account key: {}", path.display()))
    }

    /// Get the ACME directory.
    pub fn directory(&mut self) -> Result<&Directory> {
        if self.directory.is_none() {
            self.fetch_directory()?;
        }
        Ok(self.directory.as_ref().unwrap())
    }

    /// Fetch the ACME directory.
    fn fetch_directory(&mut self) -> Result<()> {
        let response = self
            .client
            .get(&self.directory_url)
            .send()
            .context("Failed to fetch ACME directory")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to fetch directory: HTTP {}",
                response.status()
            ));
        }

        // Get nonce from response headers
        if let Some(nonce) = response.headers().get("replay-nonce") {
            self.nonce = nonce.to_str().ok().map(String::from);
        }

        self.directory = Some(response.json().context("Failed to parse directory")?);
        Ok(())
    }

    /// Get a fresh nonce.
    fn get_nonce(&mut self) -> Result<String> {
        if let Some(nonce) = self.nonce.take() {
            return Ok(nonce);
        }

        // Fetch a new nonce
        let directory = self.directory()?.clone();
        let response = self
            .client
            .head(&directory.new_nonce)
            .send()
            .context("Failed to get nonce")?;

        let nonce = response
            .headers()
            .get("replay-nonce")
            .ok_or_else(|| anyhow!("No nonce in response"))?
            .to_str()
            .context("Invalid nonce header")?
            .to_string();

        Ok(nonce)
    }

    /// Make a signed POST request to an ACME endpoint with retry logic.
    ///
    /// Retries on:
    /// - `badNonce` errors (RFC 8555 §6.5) — fetches new nonce and retries
    /// - HTTP 429 (rate limited) — respects Retry-After header
    /// - Transient network errors — exponential backoff (1s, 2s, 4s)
    fn post_jws(
        &mut self,
        url: &str,
        payload: Option<&[u8]>,
    ) -> Result<reqwest::blocking::Response> {
        const MAX_RETRIES: u32 = 3;
        let mut attempt = 0;

        loop {
            // Get nonce first before borrowing account_key
            let nonce = self.get_nonce()?;

            let key = self
                .account_key
                .as_ref()
                .ok_or_else(|| anyhow!("No account key set"))?;

            let jws = if let Some(kid) = &self.account_url {
                key.sign_with_kid(url, &nonce, kid, payload)?
            } else {
                key.sign_with_jwk(url, &nonce, payload)?
            };

            let mut headers = HeaderMap::new();
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/jose+json"),
            );

            let response = match self.client.post(url).headers(headers).body(jws).send() {
                Ok(resp) => resp,
                Err(e) if attempt < MAX_RETRIES => {
                    attempt += 1;
                    let delay = Duration::from_secs(1 << (attempt - 1));
                    eprintln!(
                        "ACME request failed (attempt {}/{}): {}. Retrying in {:?}...",
                        attempt, MAX_RETRIES, e, delay
                    );
                    thread::sleep(delay);
                    continue;
                }
                Err(e) => return Err(e).context("Failed to send ACME request"),
            };

            // Store new nonce for next request
            if let Some(new_nonce) = response.headers().get("replay-nonce") {
                self.nonce = new_nonce.to_str().ok().map(String::from);
            }

            // Handle badNonce — RFC 8555 §6.5: retry with fresh nonce
            if response.status() == reqwest::StatusCode::FORBIDDEN
                || response.status() == reqwest::StatusCode::BAD_REQUEST
            {
                // Peek at error type without consuming body
                if attempt < MAX_RETRIES {
                    let body = response.text().unwrap_or_default();
                    if body.contains("urn:ietf:params:acme:error:badNonce") {
                        attempt += 1;
                        self.nonce = None; // Force fresh nonce fetch
                        eprintln!(
                            "Bad nonce (attempt {}/{}), retrying with fresh nonce...",
                            attempt, MAX_RETRIES
                        );
                        continue;
                    }
                    // Not a nonce error — reconstruct a minimal error response
                    return Err(anyhow!("ACME request failed: {}", body));
                }
            }

            // Handle rate limiting — RFC 8555 §6.6
            if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS && attempt < MAX_RETRIES
            {
                attempt += 1;
                let retry_after = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(5);
                let delay = Duration::from_secs(retry_after.min(60));
                eprintln!(
                    "Rate limited (attempt {}/{}). Waiting {:?}...",
                    attempt, MAX_RETRIES, delay
                );
                thread::sleep(delay);
                continue;
            }

            return Ok(response);
        }
    }

    /// Create or find an account.
    pub fn create_account(&mut self, email: Option<&str>, agree_tos: bool) -> Result<Account> {
        let directory = self.directory()?.clone();

        let contact = email
            .map(|e| vec![format!("mailto:{}", e)])
            .unwrap_or_default();

        let request = NewAccountRequest {
            contact,
            terms_of_service_agreed: if agree_tos { Some(true) } else { None },
            only_return_existing: None,
        };

        let payload = serde_json::to_vec(&request)?;
        let response = self.post_jws(&directory.new_account, Some(&payload))?;

        // Store account URL from Location header
        if let Some(location) = response.headers().get(LOCATION) {
            self.account_url = location.to_str().ok().map(String::from);
        }

        let status = response.status();
        if !status.is_success() && status != reqwest::StatusCode::CREATED {
            let problem: AcmeProblem = response.json().unwrap_or_else(|_| AcmeProblem {
                problem_type: "unknown".to_string(),
                detail: format!("HTTP {}", status),
                status: Some(status.as_u16()),
            });
            return Err(anyhow!("Account creation failed: {}", problem));
        }

        response.json().context("Failed to parse account response")
    }

    /// Create a new order for certificate issuance.
    pub fn create_order(&mut self, domains: &[String]) -> Result<(Order, String)> {
        let directory = self.directory()?.clone();

        let identifiers: Vec<Identifier> = domains.iter().map(Identifier::dns).collect();

        let request = NewOrderRequest {
            identifiers,
            not_before: None,
            not_after: None,
        };

        let payload = serde_json::to_vec(&request)?;
        let response = self.post_jws(&directory.new_order, Some(&payload))?;

        // Get order URL from Location header
        let order_url = response
            .headers()
            .get(LOCATION)
            .and_then(|h| h.to_str().ok())
            .map(String::from)
            .ok_or_else(|| anyhow!("No Location header in order response"))?;

        let status = response.status();
        if !status.is_success() && status != reqwest::StatusCode::CREATED {
            let problem: AcmeProblem = response.json().unwrap_or_else(|_| AcmeProblem {
                problem_type: "unknown".to_string(),
                detail: format!("HTTP {}", status),
                status: Some(status.as_u16()),
            });
            return Err(anyhow!("Order creation failed: {}", problem));
        }

        let order: Order = response.json().context("Failed to parse order response")?;
        Ok((order, order_url))
    }

    /// Get authorization details.
    pub fn get_authorization(&mut self, url: &str) -> Result<Authorization> {
        let response = self.post_jws(url, None)?;
        let status = response.status();

        if !status.is_success() {
            let problem: AcmeProblem = response.json().unwrap_or_else(|_| AcmeProblem {
                problem_type: "unknown".to_string(),
                detail: format!("HTTP {}", status),
                status: Some(status.as_u16()),
            });
            return Err(anyhow!("Failed to get authorization: {}", problem));
        }

        response.json().context("Failed to parse authorization")
    }

    /// Get the key authorization for a challenge.
    pub fn key_authorization(&self, token: &str) -> Result<String> {
        let key = self
            .account_key
            .as_ref()
            .ok_or_else(|| anyhow!("No account key set"))?;

        let thumbprint = key.thumbprint()?;
        Ok(format!("{}.{}", token, thumbprint))
    }

    /// Get the DNS-01 challenge value (base64url encoded SHA-256 of key authorization).
    pub fn dns_challenge_value(&self, token: &str) -> Result<String> {
        use sha2::{Digest, Sha256};

        let key_authz = self.key_authorization(token)?;
        let hash = Sha256::digest(key_authz.as_bytes());
        Ok(base64url_encode(&hash))
    }

    /// Respond to a challenge.
    pub fn respond_to_challenge(&mut self, url: &str) -> Result<Challenge> {
        let payload = b"{}";
        let response = self.post_jws(url, Some(payload))?;
        let status = response.status();

        if !status.is_success() {
            let problem: AcmeProblem = response.json().unwrap_or_else(|_| AcmeProblem {
                problem_type: "unknown".to_string(),
                detail: format!("HTTP {}", status),
                status: Some(status.as_u16()),
            });
            return Err(anyhow!("Challenge response failed: {}", problem));
        }

        response
            .json()
            .context("Failed to parse challenge response")
    }

    /// Wait for a challenge to be validated.
    pub fn wait_for_challenge(&mut self, url: &str, timeout: Duration) -> Result<Challenge> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_secs(2);

        loop {
            if start.elapsed() > timeout {
                return Err(anyhow!("Timeout waiting for challenge validation"));
            }

            let response = self.post_jws(url, None)?;
            let challenge: Challenge = response.json()?;

            match challenge.status {
                ChallengeStatus::Valid => return Ok(challenge),
                ChallengeStatus::Invalid => {
                    let error = challenge
                        .error
                        .map(|e| e.detail)
                        .unwrap_or_else(|| "Unknown error".to_string());
                    return Err(anyhow!("Challenge validation failed: {}", error));
                }
                _ => {
                    thread::sleep(poll_interval);
                }
            }
        }
    }

    /// Get order status.
    #[allow(dead_code)]
    pub fn get_order(&mut self, url: &str) -> Result<Order> {
        let response = self.post_jws(url, None)?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to get order: HTTP {}", response.status()));
        }

        response.json().context("Failed to parse order")
    }

    /// Wait for order to be ready.
    #[allow(dead_code)]
    pub fn wait_for_order_ready(&mut self, url: &str, timeout: Duration) -> Result<Order> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_secs(2);

        loop {
            if start.elapsed() > timeout {
                return Err(anyhow!("Timeout waiting for order to be ready"));
            }

            let order = self.get_order(url)?;

            match order.status {
                OrderStatus::Ready | OrderStatus::Valid => return Ok(order),
                OrderStatus::Invalid => {
                    return Err(anyhow!("Order became invalid"));
                }
                _ => {
                    thread::sleep(poll_interval);
                }
            }
        }
    }

    /// Finalize an order with a CSR.
    pub fn finalize_order(&mut self, finalize_url: &str, csr_der: &[u8]) -> Result<Order> {
        let request = FinalizeRequest {
            csr: base64url_encode(csr_der),
        };

        let payload = serde_json::to_vec(&request)?;
        let response = self.post_jws(finalize_url, Some(&payload))?;
        let status = response.status();

        if !status.is_success() {
            let problem: AcmeProblem = response.json().unwrap_or_else(|_| AcmeProblem {
                problem_type: "unknown".to_string(),
                detail: format!("HTTP {}", status),
                status: Some(status.as_u16()),
            });
            return Err(anyhow!("Order finalization failed: {}", problem));
        }

        response.json().context("Failed to parse finalized order")
    }

    /// Wait for certificate to be issued.
    #[allow(dead_code)]
    pub fn wait_for_certificate(&mut self, order_url: &str, timeout: Duration) -> Result<Order> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_secs(2);

        loop {
            if start.elapsed() > timeout {
                return Err(anyhow!("Timeout waiting for certificate"));
            }

            let order = self.get_order(order_url)?;

            match order.status {
                OrderStatus::Valid => return Ok(order),
                OrderStatus::Invalid => {
                    return Err(anyhow!("Order became invalid"));
                }
                _ => {
                    thread::sleep(poll_interval);
                }
            }
        }
    }

    /// Download the certificate chain.
    pub fn download_certificate(&mut self, cert_url: &str) -> Result<String> {
        let response = self.post_jws(cert_url, None)?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to download certificate: HTTP {}",
                response.status()
            ));
        }

        response.text().context("Failed to read certificate")
    }

    /// Revoke a certificate.
    pub fn revoke_certificate(&mut self, cert_der: &[u8], reason: Option<u8>) -> Result<()> {
        let directory = self.directory()?.clone();

        let revoke_url = directory
            .revoke_cert
            .as_ref()
            .ok_or_else(|| anyhow!("Revocation not supported"))?;

        let request = RevocationRequest {
            certificate: base64url_encode(cert_der),
            reason,
        };

        let payload = serde_json::to_vec(&request)?;
        let response = self.post_jws(revoke_url, Some(&payload))?;
        let status = response.status();

        if status == reqwest::StatusCode::OK {
            return Ok(());
        }

        let problem: AcmeProblem = response.json().unwrap_or_else(|_| AcmeProblem {
            problem_type: "unknown".to_string(),
            detail: format!("HTTP {}", status),
            status: Some(status.as_u16()),
        });
        Err(anyhow!("Revocation failed: {}", problem))
    }

    /// Get the account URL.
    pub fn account_url(&self) -> Option<&str> {
        self.account_url.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = AcmeClient::new("https://example.com/directory");
        assert!(client.account_key.is_none());
        assert!(client.account_url.is_none());
    }

    #[test]
    fn test_letsencrypt_urls() {
        let prod = AcmeClient::letsencrypt();
        assert!(prod.directory_url.contains("api.letsencrypt.org"));

        let staging = AcmeClient::letsencrypt_staging();
        assert!(staging.directory_url.contains("staging"));
    }

    #[test]
    fn test_account_key_generation() {
        let mut client = AcmeClient::new("https://example.com/directory");
        client.generate_account_key();
        assert!(client.account_key.is_some());
    }

    #[test]
    fn test_key_authorization() {
        let mut client = AcmeClient::new("https://example.com/directory");
        client.generate_account_key();

        let key_authz = client.key_authorization("test-token").unwrap();
        assert!(key_authz.contains("test-token"));
        assert!(key_authz.contains('.'));
    }

    #[test]
    fn test_dns_challenge_value() {
        let mut client = AcmeClient::new("https://example.com/directory");
        client.generate_account_key();

        let value = client.dns_challenge_value("test-token").unwrap();
        // DNS challenge value is base64url encoded SHA-256 (43 chars)
        assert_eq!(value.len(), 43);
    }
}
