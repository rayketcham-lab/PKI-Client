//! PKI hierarchy commands — build complete CA hierarchies from TOML config

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;

use super::CmdResult;
use crate::config::GlobalConfig;

/// PKI hierarchy operations
#[derive(Subcommand)]
pub enum PkiCommands {
    /// Validate a hierarchy configuration file
    ///
    /// Parses the TOML config, checks topology (no cycles, single root),
    /// and validates constraints (path length, validity, algorithms, URLs).
    Validate {
        /// Path to hierarchy TOML configuration file
        config: PathBuf,
    },

    /// Preview hierarchy as a formatted tree
    ///
    /// Validates the config then displays the CA tree with algorithms,
    /// validity periods, and extension details.
    Preview {
        /// Path to hierarchy TOML configuration file
        config: PathBuf,
    },

    /// Build a complete CA hierarchy
    ///
    /// Validates config, generates all CA key pairs and certificates
    /// in topological order (root first), then exports to disk.
    Build {
        /// Path to hierarchy TOML configuration file
        config: PathBuf,

        /// Output directory (overrides config file setting)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Overwrite existing output directory
        #[arg(long)]
        force: bool,
    },

    /// Export an existing hierarchy build to a different directory/format
    Export {
        /// Path to hierarchy TOML configuration file
        config: PathBuf,

        /// Output directory
        #[arg(short, long, default_value = "./pki-export")]
        output: PathBuf,
    },
}

pub fn run(cmd: PkiCommands, config: &GlobalConfig) -> Result<CmdResult> {
    match cmd {
        PkiCommands::Validate { config: path } => validate(path, config),
        PkiCommands::Preview { config: path } => preview(path, config),
        PkiCommands::Build {
            config: path,
            output,
            force,
        } => build(path, output, force, config),
        PkiCommands::Export {
            config: path,
            output,
        } => export(path, output, config),
    }
}

fn validate(path: PathBuf, _config: &GlobalConfig) -> Result<CmdResult> {
    let toml_str = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let hierarchy_config = pki_hierarchy::parse_config(&toml_str)
        .with_context(|| "failed to parse hierarchy config")?;

    let result = pki_hierarchy::validate_hierarchy(&hierarchy_config)
        .with_context(|| "hierarchy validation failed")?;

    println!(
        "{} Hierarchy '{}' is valid ({} CAs)",
        "✓".green().bold(),
        hierarchy_config.hierarchy.name,
        hierarchy_config.ca.len()
    );

    for warning in &result.warnings {
        println!(
            "  {} [{}] {}",
            "warning:".yellow(),
            warning.ca_id,
            warning.message
        );
    }

    Ok(CmdResult::Success)
}

fn preview(path: PathBuf, _config: &GlobalConfig) -> Result<CmdResult> {
    let toml_str = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let hierarchy_config = pki_hierarchy::parse_config(&toml_str)
        .with_context(|| "failed to parse hierarchy config")?;

    let output = pki_hierarchy::preview_hierarchy(&hierarchy_config)
        .with_context(|| "failed to generate preview")?;

    print!("{}", output);
    Ok(CmdResult::Success)
}

fn build(
    path: PathBuf,
    output_override: Option<PathBuf>,
    force: bool,
    _config: &GlobalConfig,
) -> Result<CmdResult> {
    let toml_str = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let hierarchy_config = pki_hierarchy::parse_config(&toml_str)
        .with_context(|| "failed to parse hierarchy config")?;

    let output_dir = output_override
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| hierarchy_config.hierarchy.output_dir.clone());

    // Check if output directory exists
    let output_path = std::path::Path::new(&output_dir);
    if output_path.exists() && !force {
        anyhow::bail!(
            "output directory '{}' already exists (use --force to overwrite)",
            output_dir
        );
    }

    println!(
        "{} Building hierarchy '{}'...",
        "→".blue().bold(),
        hierarchy_config.hierarchy.name
    );

    let result = pki_hierarchy::build_hierarchy(&hierarchy_config)
        .with_context(|| "failed to build hierarchy")?;

    println!(
        "{} Built {} CAs",
        "✓".green().bold(),
        result.build_order.len()
    );

    // Export
    let files = pki_hierarchy::export_hierarchy(&result, &output_dir)
        .with_context(|| "failed to export hierarchy")?;

    println!(
        "{} Exported {} files to {}",
        "✓".green().bold(),
        files.len(),
        output_dir
    );

    for id in &result.build_order {
        let ca = &result.cas[id];
        let cert_size = ca.certificate_der.len();
        println!("  {} {} ({} bytes)", "•".dimmed(), id, cert_size);
    }

    Ok(CmdResult::Success)
}

fn export(path: PathBuf, output: PathBuf, _config: &GlobalConfig) -> Result<CmdResult> {
    let toml_str = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let hierarchy_config = pki_hierarchy::parse_config(&toml_str)
        .with_context(|| "failed to parse hierarchy config")?;

    println!("{} Building hierarchy for export...", "→".blue().bold());

    let result = pki_hierarchy::build_hierarchy(&hierarchy_config)
        .with_context(|| "failed to build hierarchy")?;

    let output_dir = output.display().to_string();
    let files = pki_hierarchy::export_hierarchy(&result, &output_dir)
        .with_context(|| "failed to export hierarchy")?;

    println!(
        "{} Exported {} files to {}",
        "✓".green().bold(),
        files.len(),
        output_dir
    );

    Ok(CmdResult::Success)
}
