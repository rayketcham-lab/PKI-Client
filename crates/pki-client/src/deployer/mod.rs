//! Web Server Deployer — certificate deployment with backup/rollback.
//!
//! Supports Apache, Nginx (Linux), and IIS (Windows) with automatic
//! config detection, backup, validation, and rollback capabilities.

pub mod backup;

#[cfg(not(target_os = "windows"))]
pub mod apache;
#[cfg(not(target_os = "windows"))]
pub mod nginx;

#[cfg(target_os = "windows")]
pub mod iis;

use anyhow::Result;
use backup::BackupManifest;
use std::path::Path;

/// Trait for web server certificate deployers.
pub trait WebServerDeployer {
    /// Detect if this web server is installed and running.
    fn detect(&self) -> Result<bool>;

    /// Create a backup of current config and certificates for a domain.
    fn backup(&self, domain: &str, backup_dir: &Path) -> Result<BackupManifest>;

    /// Deploy certificate files to the web server.
    fn deploy_cert(
        &self,
        cert_path: &Path,
        key_path: &Path,
        chain_path: Option<&Path>,
        domain: &str,
    ) -> Result<()>;

    /// Test the web server configuration (dry run).
    fn test_config(&self) -> Result<()>;

    /// Reload the web server to pick up new certificates.
    fn reload(&self) -> Result<()>;

    /// Rollback from a backup manifest.
    fn rollback(&self, manifest: &BackupManifest) -> Result<()>;

    /// Human-readable name of the web server.
    #[allow(dead_code)]
    fn name(&self) -> &str;
}

/// Detected web server type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerType {
    #[cfg(not(target_os = "windows"))]
    Apache,
    #[cfg(not(target_os = "windows"))]
    Nginx,
    #[cfg(target_os = "windows")]
    Iis,
}

impl std::fmt::Display for ServerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(not(target_os = "windows"))]
            ServerType::Apache => write!(f, "Apache"),
            #[cfg(not(target_os = "windows"))]
            ServerType::Nginx => write!(f, "Nginx"),
            #[cfg(target_os = "windows")]
            ServerType::Iis => write!(f, "IIS"),
        }
    }
}

/// Auto-detect installed web servers.
///
/// Returns a list of detected server types. On Linux, checks for Apache and Nginx.
/// On Windows, checks for IIS.
pub fn detect_servers() -> Vec<ServerType> {
    let mut found = Vec::new();

    #[cfg(not(target_os = "windows"))]
    {
        let apache = apache::ApacheDeployer::new();
        if apache.detect().unwrap_or(false) {
            found.push(ServerType::Apache);
        }

        let nginx_deployer = nginx::NginxDeployer::new();
        if nginx_deployer.detect().unwrap_or(false) {
            found.push(ServerType::Nginx);
        }
    }

    #[cfg(target_os = "windows")]
    {
        let iis_deployer = iis::IisDeployer::new();
        if iis_deployer.detect().unwrap_or(false) {
            found.push(ServerType::Iis);
        }
    }

    found
}

/// Get a deployer for the specified server type.
pub fn get_deployer(server_type: &ServerType) -> Box<dyn WebServerDeployer> {
    match server_type {
        #[cfg(not(target_os = "windows"))]
        ServerType::Apache => Box::new(apache::ApacheDeployer::new()),
        #[cfg(not(target_os = "windows"))]
        ServerType::Nginx => Box::new(nginx::NginxDeployer::new()),
        #[cfg(target_os = "windows")]
        ServerType::Iis => Box::new(iis::IisDeployer::new()),
    }
}
