//! Output format types and traits.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Output format options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum OutputFormat {
    /// Human-readable text with colors
    #[default]
    Text,
    /// JSON output
    Json,
    /// Compact single-line output
    Compact,
    /// Forensic deep-dive — every field, hex dumps, security assessments
    Forensic,
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" | "t" => Ok(Self::Text),
            "json" | "j" => Ok(Self::Json),
            "compact" | "c" => Ok(Self::Compact),
            "forensic" | "f" | "deep" | "verbose" => Ok(Self::Forensic),
            _ => Err(format!(
                "Unknown format '{s}'. Valid options: text, json, compact, forensic"
            )),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::Json => write!(f, "json"),
            Self::Compact => write!(f, "compact"),
            Self::Forensic => write!(f, "forensic"),
        }
    }
}

/// Trait for types that can be formatted for output.
pub trait Formatter {
    /// Format as human-readable text.
    fn to_text(&self, colored: bool) -> String;

    /// Format as JSON.
    fn to_json(&self) -> String;

    /// Format in compact form.
    fn to_compact(&self) -> String;

    /// Format in forensic deep-dive mode.
    fn to_forensic(&self, colored: bool) -> String;

    /// Format according to the specified output format.
    fn format(&self, format: OutputFormat, colored: bool) -> String {
        match format {
            OutputFormat::Text => self.to_text(colored),
            OutputFormat::Json => self.to_json(),
            OutputFormat::Compact => self.to_compact(),
            OutputFormat::Forensic => self.to_forensic(colored),
        }
    }
}
