//! Standalone HTTP server for ACME HTTP-01 challenge validation.
//!
//! Binds to port 80 and serves challenge tokens at
//! `/.well-known/acme-challenge/{token}`. Used when no existing
//! web server is available (`--standalone` mode).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{anyhow, Result};

/// A minimal HTTP server that serves ACME HTTP-01 challenge responses.
///
/// The server only responds to `GET /.well-known/acme-challenge/{token}`
/// with the corresponding key authorization. All other paths return 404.
pub struct StandaloneServer {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    tokens: Arc<Mutex<HashMap<String, String>>>,
    #[allow(dead_code)]
    local_port: u16,
}

const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

impl StandaloneServer {
    /// Start the standalone HTTP server on the given port.
    ///
    /// Typically port 80 for ACME HTTP-01 challenges.
    pub fn start(port: u16) -> Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", port)).map_err(|e| {
            match e.kind() {
                std::io::ErrorKind::AddrInUse => {
                    anyhow!(
                        "Port {} is already in use. Stop your web server first, or use --webroot instead.",
                        port
                    )
                }
                std::io::ErrorKind::PermissionDenied => {
                    anyhow!(
                        "Permission denied binding to port {}. Run with sudo/admin privileges, or use --webroot instead.",
                        port
                    )
                }
                _ => anyhow!("Failed to bind to port {}: {}", port, e),
            }
        })?;

        let local_port = listener.local_addr()?.port();

        // Non-blocking so we can check the shutdown flag
        listener.set_nonblocking(true)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let tokens: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

        let shutdown_clone = Arc::clone(&shutdown);
        let tokens_clone = Arc::clone(&tokens);

        let handle = thread::spawn(move || {
            Self::accept_loop(listener, shutdown_clone, tokens_clone);
        });

        Ok(Self {
            shutdown,
            handle: Some(handle),
            tokens,
            local_port,
        })
    }

    /// Returns the port the server is actually listening on.
    ///
    /// Useful when started with port 0 (OS-assigned).
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.local_port
    }

    /// Register a challenge token and its key authorization.
    pub fn add_challenge(&self, token: &str, key_authz: &str) {
        if let Ok(mut map) = self.tokens.lock() {
            map.insert(token.to_string(), key_authz.to_string());
        }
    }

    /// Signal the server to shut down and wait for the thread to exit.
    pub fn stop(mut self) -> Result<()> {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            // Give the thread a moment to notice the shutdown flag
            let _ = handle.join();
        }
        Ok(())
    }

    /// Main accept loop — runs in a background thread.
    fn accept_loop(
        listener: TcpListener,
        shutdown: Arc<AtomicBool>,
        tokens: Arc<Mutex<HashMap<String, String>>>,
    ) {
        loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }

            match listener.accept() {
                Ok((stream, _addr)) => {
                    Self::handle_connection(stream, &tokens);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => {
                    // Transient error, keep going
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }

    /// Handle a single HTTP connection.
    fn handle_connection(
        mut stream: std::net::TcpStream,
        tokens: &Arc<Mutex<HashMap<String, String>>>,
    ) {
        // Set timeouts to prevent hanging connections
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

        // Read request (just enough to get the first line)
        let mut buf = [0u8; 4096];
        let n = match stream.read(&mut buf) {
            Ok(n) if n > 0 => n,
            _ => return,
        };

        let request = String::from_utf8_lossy(&buf[..n]);

        // Parse first line: "GET /path HTTP/1.x"
        let first_line = match request.lines().next() {
            Some(line) => line,
            None => return,
        };

        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            let _ = Self::send_response(&mut stream, 400, "Bad Request");
            return;
        }

        let method = parts[0];
        let path = parts[1];

        // Only serve GET requests to the challenge path
        if method != "GET" {
            let _ = Self::send_response(&mut stream, 405, "Method Not Allowed");
            return;
        }

        if let Some(token) = path.strip_prefix(CHALLENGE_PREFIX) {
            // Validate token contains only base64url characters
            if !is_valid_token(token) {
                let _ = Self::send_response(&mut stream, 404, "Not Found");
                return;
            }

            if let Ok(map) = tokens.lock() {
                if let Some(key_authz) = map.get(token) {
                    let _ = Self::send_challenge_response(&mut stream, key_authz);
                    return;
                }
            }
        }

        let _ = Self::send_response(&mut stream, 404, "Not Found");
    }

    /// Send an ACME challenge response (RFC 8555 §8.3).
    fn send_challenge_response(stream: &mut std::net::TcpStream, key_authz: &str) -> Result<()> {
        let body = key_authz.as_bytes();
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            body.len()
        );
        stream.write_all(response.as_bytes())?;
        stream.write_all(body)?;
        stream.flush()?;
        Ok(())
    }

    /// Send a simple HTTP error response.
    fn send_response(stream: &mut std::net::TcpStream, status: u16, reason: &str) -> Result<()> {
        let response = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\
             \r\n",
            status, reason
        );
        stream.write_all(response.as_bytes())?;
        stream.flush()?;
        Ok(())
    }
}

impl Drop for StandaloneServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Don't join here — just signal. The thread will exit on next poll.
    }
}

/// Validate that an ACME challenge token contains only base64url characters.
/// Per RFC 8555 §8.3, tokens are base64url-encoded.
pub fn is_valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 256
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Validate that a domain name is safe for filesystem and command use.
/// Accepts both ASCII and internationalized domain names (IDN).
/// Unicode labels are validated via IDNA 2008; the domain is checked
/// in its A-label (punycode) form. Wildcards are allowed.
pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.starts_with('-') || domain.starts_with('.') {
        return false;
    }

    // Reject characters that are never valid in domain names (shell injection, etc.)
    if domain
        .bytes()
        .any(|b| b == b' ' || b == b';' || b == b'\'' || b == b'"' || b == b'/' || b == b'\\')
    {
        return false;
    }

    // Strip wildcard prefix for validation
    let name = domain.strip_prefix("*.").unwrap_or(domain);
    if name.is_empty() {
        return false;
    }

    // Try IDNA conversion (handles both Unicode and ASCII input)
    let ascii = match idna::domain_to_ascii(name) {
        Ok(a) => a,
        Err(_) => return false,
    };

    // Final safety: result must be DNS-safe characters only
    ascii.len() <= 253
        && !ascii.contains("..")
        && ascii
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    #[test]
    fn test_is_valid_token() {
        assert!(is_valid_token("abc123"));
        assert!(is_valid_token("abc_123-def"));
        assert!(is_valid_token(
            "DGk3LT4e6t8Yf1kCpDlI7mXVPI3sjfKEFyFHBqua2Sw"
        ));
        assert!(!is_valid_token(""));
        assert!(!is_valid_token("abc/def"));
        assert!(!is_valid_token("abc\\def"));
        assert!(!is_valid_token("../../../etc/passwd"));
        assert!(!is_valid_token("abc def"));
        assert!(!is_valid_token("abc\0def"));
        assert!(!is_valid_token(&"a".repeat(257)));
    }

    #[test]
    fn test_is_valid_domain() {
        // Standard ASCII domains
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("*.example.com"));
        assert!(is_valid_domain("my-host.rk.local"));

        // IDN / Punycode domains
        assert!(is_valid_domain("xn--mnchen-3ya.de")); // münchen.de in punycode

        // Invalid domains
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("../../../etc"));
        assert!(!is_valid_domain("example.com; rm -rf /"));
        assert!(!is_valid_domain("example.com'"));
        assert!(!is_valid_domain("-example.com"));
        assert!(!is_valid_domain(".example.com"));
        assert!(!is_valid_domain(&"a".repeat(254)));
    }

    #[test]
    fn test_server_start_stop() {
        let server = StandaloneServer::start(0).expect("Failed to start server");
        assert!(server.port() > 0);
        server.stop().expect("Failed to stop server");
    }

    #[test]
    fn test_server_serves_challenge() {
        let server = StandaloneServer::start(0).expect("Failed to start server");
        let port = server.port();
        server.add_challenge("test-token-123", "test-token-123.thumbprint-value");

        std::thread::sleep(Duration::from_millis(100));

        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{port}")).expect("Failed to connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(
            stream,
            "GET /.well-known/acme-challenge/test-token-123 HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();

        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);

        assert!(response.contains("200 OK"), "Expected 200, got: {response}");
        assert!(
            response.contains("test-token-123.thumbprint-value"),
            "Expected key authz in body"
        );

        server.stop().expect("Failed to stop server");
    }

    #[test]
    fn test_server_404_for_unknown_token() {
        let server = StandaloneServer::start(0).expect("Failed to start server");
        let port = server.port();
        server.add_challenge("known-token", "known-value");

        std::thread::sleep(Duration::from_millis(100));

        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{port}")).expect("Failed to connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(
            stream,
            "GET /.well-known/acme-challenge/unknown-token HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();

        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);

        assert!(
            response.contains("404 Not Found"),
            "Expected 404, got: {response}"
        );

        server.stop().expect("Failed to stop server");
    }

    #[test]
    fn test_server_404_for_wrong_path() {
        let server = StandaloneServer::start(0).expect("Failed to start server");
        let port = server.port();

        std::thread::sleep(Duration::from_millis(100));

        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{port}")).expect("Failed to connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(
            stream,
            "GET /etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();

        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);

        assert!(
            response.contains("404 Not Found"),
            "Expected 404, got: {response}"
        );

        server.stop().expect("Failed to stop server");
    }

    #[test]
    fn test_server_rejects_path_traversal() {
        let server = StandaloneServer::start(0).expect("Failed to start server");
        let port = server.port();
        server.add_challenge("legit", "legit-value");

        std::thread::sleep(Duration::from_millis(100));

        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{port}")).expect("Failed to connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(
            stream,
            "GET /.well-known/acme-challenge/../../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();

        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);

        assert!(
            response.contains("404"),
            "Expected 404 for traversal, got: {response}"
        );

        server.stop().expect("Failed to stop server");
    }

    #[test]
    fn test_server_multiple_tokens() {
        let server = StandaloneServer::start(0).expect("Failed to start server");
        let port = server.port();
        server.add_challenge("token-a", "auth-a");
        server.add_challenge("token-b", "auth-b");

        std::thread::sleep(Duration::from_millis(100));

        // Check token-a
        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{port}")).expect("Failed to connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(
            stream,
            "GET /.well-known/acme-challenge/token-a HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        assert!(response.contains("auth-a"), "Expected auth-a in body");

        // Check token-b
        let mut stream2 =
            TcpStream::connect(format!("127.0.0.1:{port}")).expect("Failed to connect");
        stream2
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(
            stream2,
            "GET /.well-known/acme-challenge/token-b HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();
        let mut response2 = String::new();
        let _ = stream2.read_to_string(&mut response2);
        assert!(response2.contains("auth-b"), "Expected auth-b in body");

        server.stop().expect("Failed to stop server");
    }
}
