//! ACME Client Commands - RFC 8555
//!
//! Commands for automatic certificate issuance via ACME protocol.
//! Includes certbot-like automation: certonly, install, renew, rollback.

mod certonly;
mod csr;
mod helpers;
mod install;
mod protocol;
mod renew;
mod rollback;
mod status;

use crate::commands::CmdResult;
use crate::config::GlobalConfig;
use anyhow::Result;
use clap::Subcommand;
use std::path::PathBuf;

/// ACME client commands.
#[derive(Subcommand)]
pub enum AcmeCommands {
    /// Register a new account or retrieve existing account.
    #[command(after_help = "Examples:
  pki acme register --email admin@example.com
  pki acme register --email admin@example.com --staging")]
    Register {
        /// Contact email address
        #[arg(long, short = 'e')]
        email: Option<String>,

        /// Path to account key (will create if doesn't exist)
        #[arg(long, short = 'k', default_value = "acme-account.pem")]
        key_file: PathBuf,

        /// Agree to terms of service
        #[arg(long)]
        agree_tos: bool,

        /// Use Let's Encrypt staging environment
        #[arg(long)]
        staging: bool,

        /// Custom ACME directory URL
        #[arg(long)]
        directory: Option<String>,

        /// Accept invalid TLS certificates (for self-signed ACME servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Create a new certificate order.
    #[command(after_help = "Examples:
  pki acme order example.com www.example.com
  pki acme order *.example.com --staging")]
    Order {
        /// Domain names to include in certificate
        #[arg(required = true)]
        domains: Vec<String>,

        /// Path to account key
        #[arg(long, short = 'k', default_value = "acme-account.pem")]
        key_file: PathBuf,

        /// Use Let's Encrypt staging environment
        #[arg(long)]
        staging: bool,

        /// Custom ACME directory URL
        #[arg(long)]
        directory: Option<String>,

        /// Accept invalid TLS certificates (for self-signed ACME servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Show challenge information for an authorization.
    #[command(after_help = "Examples:
  pki acme challenges https://acme.example.com/authz/abc123
  pki acme challenges https://acme.example.com/authz/abc123 --type dns-01
  pki acme challenges --directory http://localhost:6446/directory URL")]
    Challenges {
        /// Authorization URL
        url: String,

        /// Path to account key
        #[arg(long, short = 'k', default_value = "acme-account.pem")]
        key_file: PathBuf,

        /// Filter by challenge type
        #[arg(long, short = 't')]
        challenge_type: Option<String>,

        /// Use Let's Encrypt staging environment
        #[arg(long)]
        staging: bool,

        /// Custom ACME directory URL
        #[arg(long)]
        directory: Option<String>,

        /// Accept invalid TLS certificates (for self-signed ACME servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Get the HTTP-01 challenge content.
    #[command(after_help = "Examples:
  pki acme http-token abc123

Place the output at:
  http://DOMAIN/.well-known/acme-challenge/TOKEN")]
    HttpToken {
        /// Challenge token
        token: String,

        /// Path to account key
        #[arg(long, short = 'k', default_value = "acme-account.pem")]
        key_file: PathBuf,
    },

    /// Get the DNS-01 challenge TXT record value.
    #[command(after_help = "Examples:
  pki acme dns-record abc123

Create TXT record:
  _acme-challenge.DOMAIN TXT \"VALUE\"")]
    DnsRecord {
        /// Challenge token
        token: String,

        /// Path to account key
        #[arg(long, short = 'k', default_value = "acme-account.pem")]
        key_file: PathBuf,
    },

    /// Respond to a challenge (trigger validation).
    #[command(after_help = "Examples:
  pki acme respond https://acme.example.com/chall/abc123
  pki acme respond --directory http://localhost:6446/directory URL")]
    Respond {
        /// Challenge URL
        url: String,

        /// Path to account key
        #[arg(long, short = 'k', default_value = "acme-account.pem")]
        key_file: PathBuf,

        /// Wait for validation to complete
        #[arg(long, short = 'w', default_value = "60")]
        timeout: u64,

        /// Use Let's Encrypt staging environment
        #[arg(long)]
        staging: bool,

        /// Custom ACME directory URL
        #[arg(long)]
        directory: Option<String>,

        /// Accept invalid TLS certificates (for self-signed ACME servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Finalize an order with a CSR.
    #[command(after_help = "Examples:
  pki acme finalize https://acme.example.com/order/abc123/finalize -c request.csr
  pki acme finalize --directory http://localhost:6446/directory URL -c request.csr")]
    Finalize {
        /// Finalize URL
        url: String,

        /// CSR file (PEM or DER)
        #[arg(long, short = 'c')]
        csr: PathBuf,

        /// Path to account key
        #[arg(long, short = 'k', default_value = "acme-account.pem")]
        key_file: PathBuf,

        /// Use Let's Encrypt staging environment
        #[arg(long)]
        staging: bool,

        /// Custom ACME directory URL
        #[arg(long)]
        directory: Option<String>,

        /// Accept invalid TLS certificates (for self-signed ACME servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Download issued certificate.
    #[command(after_help = "Examples:
  pki acme download https://acme.example.com/cert/abc123 -o cert.pem
  pki acme download --directory http://localhost:6446/directory URL -o cert.pem")]
    Download {
        /// Certificate URL
        url: String,

        /// Output file
        #[arg(long, short = 'o', default_value = "cert.pem")]
        output: PathBuf,

        /// Path to account key
        #[arg(long, short = 'k', default_value = "acme-account.pem")]
        key_file: PathBuf,

        /// Use Let's Encrypt staging environment
        #[arg(long)]
        staging: bool,

        /// Custom ACME directory URL
        #[arg(long)]
        directory: Option<String>,

        /// Accept invalid TLS certificates (for self-signed ACME servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Revoke a certificate.
    #[command(after_help = "Examples:
  pki acme revoke cert.pem
  pki acme revoke cert.pem --reason keyCompromise")]
    Revoke {
        /// Certificate file to revoke
        cert: PathBuf,

        /// Revocation reason
        #[arg(long, short = 'r')]
        reason: Option<u8>,

        /// Path to account key
        #[arg(long, short = 'k', default_value = "acme-account.pem")]
        key_file: PathBuf,

        /// Use Let's Encrypt staging environment
        #[arg(long)]
        staging: bool,

        /// Custom ACME directory URL
        #[arg(long)]
        directory: Option<String>,

        /// Accept invalid TLS certificates (for self-signed ACME servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Fetch and display ACME directory.
    #[command(after_help = "Examples:
  pki acme directory
  pki acme directory --staging")]
    Directory {
        /// Use Let's Encrypt staging environment
        #[arg(long)]
        staging: bool,

        /// Custom ACME directory URL
        #[arg(long)]
        url: Option<String>,

        /// Accept invalid TLS certificates (for self-signed ACME servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Request a certificate (like certbot certonly).
    ///
    /// Performs full ACME flow: register, order, challenge, finalize, download.
    /// Saves certificate and key to `~/.pki-client/certs/<domain>/`.
    #[command(after_help = "Examples:
  pki acme certonly -d example.com --server https://acme.internal:6446/directory
  pki acme certonly -d example.com -d www.example.com --webroot /var/www/html
  pki acme certonly -d example.com --standalone --email admin@example.com")]
    Certonly {
        /// Domain name(s) to request certificate for
        #[arg(long, short = 'd', required = true)]
        domain: Vec<String>,

        /// ACME server directory URL
        #[arg(long, short = 's')]
        server: String,

        /// Contact email address
        #[arg(long, short = 'e')]
        email: Option<String>,

        /// Web root directory for HTTP-01 challenge (writes .well-known/acme-challenge/)
        #[arg(long, conflicts_with = "standalone")]
        webroot: Option<PathBuf>,

        /// Use built-in HTTP server on port 80 for challenge
        #[arg(long, conflicts_with = "webroot")]
        standalone: bool,

        /// Use DNS-01 challenge (manual TXT record)
        #[arg(long)]
        dns: bool,

        /// Output directory for cert and key files
        #[arg(long, short = 'o')]
        output_dir: Option<PathBuf>,

        /// Agree to terms of service
        #[arg(long)]
        agree_tos: bool,

        /// Accept invalid TLS certificates (for self-signed ACME servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Request and install a certificate into a web server (EXPERIMENTAL).
    ///
    /// Performs certonly flow, then detects web server, backs up config,
    /// deploys certificate, tests config, and reloads. Rolls back on failure.
    #[command(
        after_help = "EXPERIMENTAL: This command modifies web server configuration.
A backup is created before any changes. Use 'pki acme rollback' to restore.

Examples:
  pki acme install -d example.com --server https://acme:6446/directory --apache
  pki acme install -d example.com --server https://acme:6446/directory --nginx"
    )]
    Install {
        /// Domain name(s)
        #[arg(long, short = 'd', required = true)]
        domain: Vec<String>,

        /// ACME server directory URL
        #[arg(long, short = 's')]
        server: String,

        /// Contact email address
        #[arg(long, short = 'e')]
        email: Option<String>,

        /// Web root directory for HTTP-01 challenge
        #[arg(long)]
        webroot: Option<PathBuf>,

        /// Use Apache HTTP Server
        #[cfg(not(target_os = "windows"))]
        #[arg(long, conflicts_with = "nginx")]
        apache: bool,

        /// Use Nginx
        #[cfg(not(target_os = "windows"))]
        #[arg(long, conflicts_with = "apache")]
        nginx: bool,

        /// Use IIS (Internet Information Services)
        #[cfg(target_os = "windows")]
        #[arg(long)]
        iis: bool,

        /// Custom backup directory
        #[arg(long)]
        backup_dir: Option<PathBuf>,

        /// Agree to terms of service
        #[arg(long)]
        agree_tos: bool,

        /// Accept invalid TLS certificates (for self-signed ACME servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Renew a previously issued certificate.
    ///
    /// Uses saved renewal configuration from initial certonly. Server URL, challenge
    /// method, and email are restored automatically. Override with CLI flags if needed.
    #[command(after_help = "Examples:
  pki acme renew --domain example.com
  pki acme renew --domain example.com --server https://acme:6446/directory
  pki acme renew --cert-path ~/.pki-client/certs/example.com/
  pki acme renew --force --domain example.com")]
    Renew {
        /// Domain to renew
        #[arg(long, short = 'd')]
        domain: Option<String>,

        /// Path to existing cert directory
        #[arg(long)]
        cert_path: Option<PathBuf>,

        /// ACME server directory URL (overrides saved config)
        #[arg(long, short = 's', default_value = "")]
        server: String,

        /// Force renewal even if certificate is not near expiry
        #[arg(long)]
        force: bool,

        /// Dry run — check if renewal is needed without actually renewing
        #[arg(long)]
        dry_run: bool,

        /// Accept invalid TLS certificates (for self-signed ACME servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Renew all certificates that have saved renewal configs.
    ///
    /// Checks every domain in ~/.pki-client/certs/ for a renewal.json and renews
    /// any certificate within 30 days of expiry. Ideal for cron/systemd timer.
    #[command(after_help = "Examples:
  pki acme renew-all
  pki acme renew-all --dry-run
  pki acme renew-all --force")]
    RenewAll {
        /// Force renewal of all certificates regardless of expiry
        #[arg(long)]
        force: bool,

        /// Dry run — check what would be renewed without acting
        #[arg(long)]
        dry_run: bool,
    },

    /// Show certificate status for a domain.
    #[command(after_help = "Examples:
  pki acme status --domain example.com
  pki acme status --cert-path ~/.pki-client/certs/example.com/")]
    Status {
        /// Domain to check
        #[arg(long, short = 'd')]
        domain: Option<String>,

        /// Path to cert directory
        #[arg(long)]
        cert_path: Option<PathBuf>,
    },

    /// Rollback a web server configuration change.
    ///
    /// Restores config and certificates from the most recent backup,
    /// tests the restored config, and reloads the web server.
    #[command(after_help = "Examples:
  pki acme rollback
  pki acme rollback --backup-id 2026-02-11-120000")]
    Rollback {
        /// Specific backup ID to restore (default: most recent)
        #[arg(long)]
        backup_id: Option<String>,

        /// Custom backup directory root
        #[arg(long)]
        backup_dir: Option<PathBuf>,
    },

    /// List available configuration backups.
    #[command(after_help = "Examples:
  pki acme backups")]
    Backups {
        /// Custom backup directory root
        #[arg(long)]
        backup_dir: Option<PathBuf>,
    },
}

/// Run ACME command.
pub fn run(cmd: AcmeCommands, config: &GlobalConfig) -> Result<CmdResult> {
    match cmd {
        AcmeCommands::Register {
            email,
            key_file,
            agree_tos,
            staging,
            directory,
            insecure,
            ca_cert,
        } => protocol::register_account(
            email.as_deref(),
            &key_file,
            agree_tos,
            staging,
            directory,
            insecure,
            ca_cert.as_deref(),
            config,
        ),

        AcmeCommands::Order {
            domains,
            key_file,
            staging,
            directory,
            insecure,
            ca_cert,
        } => protocol::create_order(
            &domains,
            &key_file,
            staging,
            directory,
            insecure,
            ca_cert.as_deref(),
            config,
        ),

        AcmeCommands::Challenges {
            url,
            key_file,
            challenge_type,
            staging,
            directory,
            insecure,
            ca_cert,
        } => protocol::show_challenges(
            &url,
            &key_file,
            challenge_type.as_deref(),
            staging,
            directory,
            insecure,
            ca_cert.as_deref(),
            config,
        ),

        AcmeCommands::HttpToken { token, key_file } => {
            protocol::show_http_token(&token, &key_file, config)
        }

        AcmeCommands::DnsRecord { token, key_file } => {
            protocol::show_dns_record(&token, &key_file, config)
        }

        AcmeCommands::Respond {
            url,
            key_file,
            timeout,
            staging,
            directory,
            insecure,
            ca_cert,
        } => protocol::respond_to_challenge(
            &url,
            &key_file,
            timeout,
            staging,
            directory,
            insecure,
            ca_cert.as_deref(),
            config,
        ),

        AcmeCommands::Finalize {
            url,
            csr,
            key_file,
            staging,
            directory,
            insecure,
            ca_cert,
        } => protocol::finalize_order(
            &url,
            &csr,
            &key_file,
            staging,
            directory,
            insecure,
            ca_cert.as_deref(),
            config,
        ),

        AcmeCommands::Download {
            url,
            output,
            key_file,
            staging,
            directory,
            insecure,
            ca_cert,
        } => protocol::download_cert(
            &url,
            &output,
            &key_file,
            staging,
            directory,
            insecure,
            ca_cert.as_deref(),
            config,
        ),

        AcmeCommands::Revoke {
            cert,
            reason,
            key_file,
            staging,
            directory,
            insecure,
            ca_cert,
        } => protocol::revoke_cert(
            &cert,
            reason,
            &key_file,
            staging,
            directory,
            insecure,
            ca_cert.as_deref(),
            config,
        ),

        AcmeCommands::Directory {
            staging,
            url,
            insecure,
            ca_cert,
        } => protocol::show_directory(
            staging,
            url.as_deref(),
            insecure,
            ca_cert.as_deref(),
            config,
        ),

        AcmeCommands::Certonly {
            domain,
            server,
            email,
            webroot,
            standalone,
            dns,
            output_dir,
            agree_tos,
            insecure,
            ca_cert,
        } => certonly::cmd_certonly(
            &domain,
            &server,
            email.as_deref(),
            webroot.as_deref(),
            standalone,
            dns,
            output_dir.as_deref(),
            agree_tos,
            insecure,
            ca_cert.as_deref(),
            config,
        ),

        AcmeCommands::Install {
            domain,
            server,
            email,
            webroot,
            #[cfg(not(target_os = "windows"))]
            apache,
            #[cfg(not(target_os = "windows"))]
            nginx,
            #[cfg(target_os = "windows")]
            iis,
            backup_dir,
            agree_tos,
            insecure,
            ca_cert,
        } => {
            #[cfg(not(target_os = "windows"))]
            {
                install::cmd_install(
                    &domain,
                    &server,
                    email.as_deref(),
                    webroot.as_deref(),
                    apache,
                    nginx,
                    backup_dir.as_deref(),
                    agree_tos,
                    insecure,
                    ca_cert.as_deref(),
                    config,
                )
            }
            #[cfg(target_os = "windows")]
            {
                install::cmd_install_windows(
                    &domain,
                    &server,
                    email.as_deref(),
                    webroot.as_deref(),
                    iis,
                    backup_dir.as_deref(),
                    agree_tos,
                    insecure,
                    ca_cert.as_deref(),
                    config,
                )
            }
        }

        AcmeCommands::Renew {
            domain,
            cert_path,
            server,
            force,
            dry_run,
            insecure,
            ca_cert,
        } => renew::cmd_renew(
            domain.as_deref(),
            cert_path.as_deref(),
            &server,
            force,
            dry_run,
            insecure,
            ca_cert.as_deref(),
            config,
        ),

        AcmeCommands::RenewAll { force, dry_run } => renew::cmd_renew_all(force, dry_run, config),

        AcmeCommands::Status { domain, cert_path } => {
            status::cmd_status(domain.as_deref(), cert_path.as_deref(), config)
        }

        AcmeCommands::Rollback {
            backup_id,
            backup_dir,
        } => rollback::cmd_rollback(backup_id.as_deref(), backup_dir.as_deref(), config),

        AcmeCommands::Backups { backup_dir } => {
            rollback::cmd_backups(backup_dir.as_deref(), config)
        }
    }
}
