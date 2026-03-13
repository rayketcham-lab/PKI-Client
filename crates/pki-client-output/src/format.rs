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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_names() {
        assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!(
            "compact".parse::<OutputFormat>().unwrap(),
            OutputFormat::Compact
        );
        assert_eq!(
            "forensic".parse::<OutputFormat>().unwrap(),
            OutputFormat::Forensic
        );
    }

    #[test]
    fn test_parse_short_aliases() {
        assert_eq!("t".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert_eq!("j".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!("c".parse::<OutputFormat>().unwrap(), OutputFormat::Compact);
        assert_eq!("f".parse::<OutputFormat>().unwrap(), OutputFormat::Forensic);
    }

    #[test]
    fn test_parse_forensic_aliases() {
        assert_eq!(
            "deep".parse::<OutputFormat>().unwrap(),
            OutputFormat::Forensic
        );
        assert_eq!(
            "verbose".parse::<OutputFormat>().unwrap(),
            OutputFormat::Forensic
        );
    }

    #[test]
    fn test_parse_case_insensitive() {
        assert_eq!("TEXT".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert_eq!("JSON".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!(
            "Forensic".parse::<OutputFormat>().unwrap(),
            OutputFormat::Forensic
        );
    }

    #[test]
    fn test_parse_invalid() {
        assert!("xml".parse::<OutputFormat>().is_err());
        assert!("".parse::<OutputFormat>().is_err());
        assert!("html".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_display_roundtrip() {
        for fmt in [
            OutputFormat::Text,
            OutputFormat::Json,
            OutputFormat::Compact,
            OutputFormat::Forensic,
        ] {
            let s = fmt.to_string();
            assert_eq!(s.parse::<OutputFormat>().unwrap(), fmt);
        }
    }

    #[test]
    fn test_default_is_text() {
        assert_eq!(OutputFormat::default(), OutputFormat::Text);
    }
}
