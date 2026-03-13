//! Interactive shell mode using rustyline with file path completion.

use anyhow::Result;
use colored::Colorize;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};

use crate::commands::CmdResult;
use crate::config::GlobalConfig;

const BANNER: &str = r#"
  ██████╗ ██╗  ██╗██╗
  ██╔══██╗██║ ██╔╝██║
  ██████╔╝█████╔╝ ██║
  ██╔═══╝ ██╔═██╗ ██║
  ██║     ██║  ██╗██║
  ╚═╝     ╚═╝  ╚═╝╚═╝
"#;

const HELP_TEXT: &str = r#"
PKI Interactive Shell - PKI operations made human

Commands:
  show <file>                   Show certificate details (shortcut)
  show <file> --lint            Run security lint checks
  show <file> --check           Check revocation status (OCSP/CRL)
  show <file> --all             Full analysis (details + lint + revocation)
  show <file> --interactive     Interactive menu mode

  cert show <file>              Show certificate details
  cert expires <file>           Check certificate expiration
  cert fingerprint <file>       Show certificate fingerprint

  key gen ec|rsa|ed25519        Generate private key
  key show <file>               Show key information
  key match <key> <cert>        Check if key matches certificate

  chain build <file>            Build certificate chain
  chain show <file>             Display chain as tree
  chain verify <file>           Verify chain integrity

Shell commands:
  help, ?                       Show this help
  history                       Show command history
  clear                         Clear screen
  exit, quit, q                 Exit shell

Tips:
  - Use Tab for file path completion
  - Use Up/Down arrows for history
  - Most commands support --help for more options
  - Paste PEM certificates directly to view them
"#;

/// Commands that take a file argument (for completion hints)
const FILE_COMMANDS: &[&str] = &[
    "show",
    "cert show",
    "cert expires",
    "cert fingerprint",
    "key show",
    "key match",
    "chain build",
    "chain show",
    "chain verify",
];

/// Top-level commands for completion
const TOP_COMMANDS: &[&str] = &[
    "show", "cert", "key", "chain", "help", "clear", "exit", "quit", "history",
];

/// Subcommands for each top-level command
fn get_subcommands(cmd: &str) -> &'static [&'static str] {
    match cmd {
        "cert" => &["show", "expires", "fingerprint"],
        "key" => &["gen", "show", "match"],
        "chain" => &["build", "show", "verify"],
        _ => &[],
    }
}

/// Custom helper for rustyline with command and file completion
struct PkiHelper {
    file_completer: FilenameCompleter,
}

impl PkiHelper {
    fn new() -> Self {
        Self {
            file_completer: FilenameCompleter::new(),
        }
    }
}

impl Completer for PkiHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let line_up_to_pos = &line[..pos];
        let parts: Vec<&str> = line_up_to_pos.split_whitespace().collect();

        // Determine if we're completing a file path
        let is_file_context = !parts.is_empty() && {
            let cmd_so_far = parts.join(" ");
            FILE_COMMANDS
                .iter()
                .any(|fc| cmd_so_far.starts_with(fc) || fc.starts_with(&cmd_so_far))
        };

        // Check if we should complete a file path
        let completing_file = if parts.is_empty() {
            false
        } else if parts.len() == 1 && parts[0] == "show" && line_up_to_pos.ends_with(' ') {
            true
        } else if parts.len() >= 2 {
            let cmd = format!("{} {}", parts[0], parts[1]);
            FILE_COMMANDS.contains(&cmd.as_str()) && parts.len() >= 2
        } else {
            false
        };

        if completing_file || (parts.len() >= 2 && is_file_context) {
            // Complete file path
            return self.file_completer.complete(line, pos, ctx);
        }

        // Complete commands
        let mut completions = Vec::new();

        if parts.is_empty() || (parts.len() == 1 && !line_up_to_pos.ends_with(' ')) {
            // Complete top-level command
            let prefix = parts.first().copied().unwrap_or("");
            let start = if parts.is_empty() {
                0
            } else {
                pos - prefix.len()
            };

            for cmd in TOP_COMMANDS {
                if cmd.starts_with(prefix) {
                    completions.push(Pair {
                        display: (*cmd).to_string(),
                        replacement: (*cmd).to_string(),
                    });
                }
            }
            return Ok((start, completions));
        }

        if parts.len() == 1 && line_up_to_pos.ends_with(' ') {
            // Complete subcommand after top-level
            let subcmds = get_subcommands(parts[0]);
            for sub in subcmds {
                completions.push(Pair {
                    display: (*sub).to_string(),
                    replacement: (*sub).to_string(),
                });
            }
            return Ok((pos, completions));
        }

        if parts.len() == 2 && !line_up_to_pos.ends_with(' ') {
            // Complete partial subcommand
            let subcmds = get_subcommands(parts[0]);
            let prefix = parts[1];
            let start = pos - prefix.len();

            for sub in subcmds {
                if sub.starts_with(prefix) {
                    completions.push(Pair {
                        display: (*sub).to_string(),
                        replacement: (*sub).to_string(),
                    });
                }
            }
            return Ok((start, completions));
        }

        // Default to file completion for anything else
        self.file_completer.complete(line, pos, ctx)
    }
}

impl Hinter for PkiHelper {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
        None
    }
}

impl Highlighter for PkiHelper {}
impl Validator for PkiHelper {}
impl Helper for PkiHelper {}

/// Run the interactive shell.
pub fn run(config: &GlobalConfig) -> Result<CmdResult> {
    if !config.quiet {
        println!("{}", BANNER.cyan());
        println!(
            "  {} - {}\n",
            "PKI".bold().cyan(),
            "Modern PKI Operations Tool".dimmed()
        );
        println!(
            "  Type {} for commands, {} to quit\n",
            "help".green(),
            "exit".green()
        );
    }

    let helper = PkiHelper::new();
    let mut rl = Editor::new()?;
    rl.set_helper(Some(helper));

    // Load history if available
    let history_path = dirs::data_dir()
        .map(|d| d.join("pki-client").join("history"))
        .unwrap_or_else(|| std::path::PathBuf::from(".pki_history"));

    if history_path.exists() {
        let _ = rl.load_history(&history_path);
    }

    let mut multiline_buffer: Option<String> = None;

    loop {
        let prompt = if multiline_buffer.is_some() {
            format!("{} ", "....>".dimmed())
        } else {
            format!("{} ", "pki>".cyan().bold())
        };
        let readline = rl.readline(&prompt);

        match readline {
            Ok(line) => {
                // Handle multi-line PEM paste
                if let Some(ref mut buffer) = multiline_buffer {
                    buffer.push('\n');
                    buffer.push_str(&line);

                    // Check if we've reached the end of PEM
                    if line.contains("-----END") {
                        let full_input = buffer.clone();
                        multiline_buffer = None;

                        let _ = rl.add_history_entry(&full_input);

                        match handle_shell_command(&full_input, config) {
                            ShellAction::Continue => continue,
                            ShellAction::Exit => break,
                            ShellAction::RunCommand(args) => {
                                if let Err(e) = run_cli_command(&args, config) {
                                    eprintln!("{}: {}", "error".red().bold(), e);
                                }
                            }
                        }
                    }
                    continue;
                }

                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                // Check if this line starts a multi-line PEM input
                if line.contains("-----BEGIN") && !line.contains("-----END") {
                    multiline_buffer = Some(line.to_string());
                    continue;
                }

                let _ = rl.add_history_entry(line);

                match handle_shell_command(line, config) {
                    ShellAction::Continue => continue,
                    ShellAction::Exit => break,
                    ShellAction::RunCommand(args) => {
                        if let Err(e) = run_cli_command(&args, config) {
                            eprintln!("{}: {}", "error".red().bold(), e);
                        }
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                if multiline_buffer.is_some() {
                    println!("^C (cancelled multi-line input)");
                    multiline_buffer = None;
                } else {
                    println!("^C");
                }
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!("^D");
                break;
            }
            Err(err) => {
                eprintln!("{}: {}", "error".red().bold(), err);
                break;
            }
        }
    }

    // Save history
    if let Some(parent) = history_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = rl.save_history(&history_path);

    if !config.quiet {
        println!("\n{}", "Goodbye!".dimmed());
    }

    Ok(CmdResult::Success)
}

enum ShellAction {
    Continue,
    Exit,
    RunCommand(Vec<String>),
}

fn handle_shell_command(line: &str, _config: &GlobalConfig) -> ShellAction {
    // Check if line contains embedded PEM content
    let (command_part, pem_content) = if let Some(begin_idx) = line.find("-----BEGIN") {
        let cmd = line[..begin_idx].trim();
        let pem = &line[begin_idx..];
        (cmd, Some(pem.to_string()))
    } else {
        (line, None)
    };

    let parts: Vec<&str> = command_part.split_whitespace().collect();
    if parts.is_empty() && pem_content.is_none() {
        return ShellAction::Continue;
    }

    // Handle case where only PEM is pasted (implicit "show")
    #[allow(clippy::unnecessary_unwrap)]
    if parts.is_empty() && pem_content.is_some() {
        return ShellAction::RunCommand(vec!["show".to_string(), pem_content.unwrap()]);
    }

    match parts.first().map(|s| s.to_lowercase()).as_deref() {
        Some("exit") | Some("quit") | Some("q") => ShellAction::Exit,
        Some("help") | Some("?") => {
            println!("{}", HELP_TEXT);
            ShellAction::Continue
        }
        Some("clear") | Some("cls") => {
            print!("\x1B[2J\x1B[1;1H");
            ShellAction::Continue
        }
        Some("history") => {
            println!("Use Up/Down arrows to navigate history");
            ShellAction::Continue
        }
        _ => {
            // Pass to CLI command handler
            let mut args: Vec<String> = parts.iter().map(|s| (*s).to_string()).collect();

            // If we have PEM content, add it as the file argument
            if let Some(pem) = pem_content {
                args.push(pem);
            }

            ShellAction::RunCommand(args)
        }
    }
}

fn run_cli_command(args: &[String], config: &GlobalConfig) -> Result<()> {
    use crate::commands::{cert, chain, key};

    if args.is_empty() {
        return Ok(());
    }

    match args[0].as_str() {
        "show" => {
            // Shortcut for cert show
            if args.len() < 2 {
                println!("Usage: show <file|PEM> [options]");
                println!("Options:");
                println!("  --check, -c     Check revocation status");
                println!("  --lint, -l      Run security lint checks");
                println!("  --interactive, -I  Interactive menu mode");
                println!("  --all, -a       Full analysis (details + lint + revocation)");
                println!();
                println!("Tip: You can paste a PEM certificate directly!");
                return Ok(());
            }

            // Check if arg looks like PEM content (may be multi-line joined)
            let file_arg = if args[1].starts_with("-----BEGIN") {
                // It's inline PEM content
                args[1].clone()
            } else {
                args[1].clone()
            };

            let cmd = cert::CertCommands::Show(cert::ShowArgs {
                file: file_arg.into(),
                subject: false,
                san: false,
                issuer: false,
                check: args.contains(&"--check".to_string()) || args.contains(&"-c".to_string()),
                issuer_cert: None,
                lint: args.contains(&"--lint".to_string()) || args.contains(&"-l".to_string()),
                interactive: args.contains(&"--interactive".to_string())
                    || args.contains(&"-I".to_string()),
                all: args.contains(&"--all".to_string()) || args.contains(&"-a".to_string()),
                no_chain: args.contains(&"--no-chain".to_string()),
            });
            cert::run(cmd, config)?;
        }
        "cert" => {
            if args.len() < 2 {
                println!("Usage: cert <show|expires|fingerprint> <file>");
                return Ok(());
            }
            match args[1].as_str() {
                "show" => {
                    if args.len() < 3 {
                        println!("Usage: cert show <file|PEM> [options]");
                        println!("Options:");
                        println!("  --check, -c     Check revocation status");
                        println!("  --lint, -l      Run security lint checks");
                        println!("  --interactive, -I  Interactive menu mode");
                        println!("  --all, -a       Full analysis");
                        println!("  --subject       Show only subject");
                        println!("  --san           Show only SANs");
                        println!("  --issuer        Show only issuer");
                        println!("  --no-chain      Skip certificate chain display");
                        println!();
                        println!("Tip: You can paste a PEM certificate directly!");
                        return Ok(());
                    }
                    let cmd = cert::CertCommands::Show(cert::ShowArgs {
                        file: args[2].clone().into(),
                        subject: args.contains(&"--subject".to_string()),
                        san: args.contains(&"--san".to_string()),
                        issuer: args.contains(&"--issuer".to_string()),
                        check: args.contains(&"--check".to_string())
                            || args.contains(&"-c".to_string()),
                        issuer_cert: None,
                        lint: args.contains(&"--lint".to_string())
                            || args.contains(&"-l".to_string()),
                        interactive: args.contains(&"--interactive".to_string())
                            || args.contains(&"-I".to_string()),
                        all: args.contains(&"--all".to_string())
                            || args.contains(&"-a".to_string()),
                        no_chain: args.contains(&"--no-chain".to_string()),
                    });
                    cert::run(cmd, config)?;
                }
                "expires" => {
                    if args.len() < 3 {
                        println!("Usage: cert expires <file> [--within <duration>]");
                        return Ok(());
                    }
                    let within = args
                        .iter()
                        .position(|a| a == "--within")
                        .and_then(|i| args.get(i + 1))
                        .cloned();
                    let cmd = cert::CertCommands::Expires(cert::ExpiresArgs {
                        files: vec![args[2].clone().into()],
                        within,
                        epoch: args.contains(&"--epoch".to_string()),
                    });
                    cert::run(cmd, config)?;
                }
                "fingerprint" => {
                    if args.len() < 3 {
                        println!("Usage: cert fingerprint <file>");
                        return Ok(());
                    }
                    let cmd = cert::CertCommands::Fingerprint(cert::FingerprintArgs {
                        file: args[2].clone().into(),
                        sha1: args.contains(&"--sha1".to_string()),
                        raw: args.contains(&"--raw".to_string()),
                    });
                    cert::run(cmd, config)?;
                }
                other => {
                    println!("Unknown cert command: {other}");
                    println!("Available: show, expires, fingerprint");
                }
            }
        }
        "key" => {
            if args.len() < 2 {
                println!("Usage: key <gen|show|match> [args]");
                return Ok(());
            }
            match args[1].as_str() {
                "gen" => {
                    if args.len() < 3 {
                        println!("Usage: key gen <ec|rsa|ed25519> [options]");
                        println!("Options:");
                        println!("  --bits <size>   RSA key size (default: 4096)");
                        println!("  --curve <name>  EC curve: p256, p384 (default: p384)");
                        println!("  -o <file>       Output to file");
                        return Ok(());
                    }
                    let output = args
                        .iter()
                        .position(|a| a == "-o" || a == "--output")
                        .and_then(|i| args.get(i + 1))
                        .map(|s| s.clone().into());
                    let bits = args
                        .iter()
                        .position(|a| a == "--bits")
                        .and_then(|i| args.get(i + 1))
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(4096);
                    let curve = args
                        .iter()
                        .position(|a| a == "--curve")
                        .and_then(|i| args.get(i + 1))
                        .cloned()
                        .unwrap_or_else(|| "p384".to_string());
                    let cmd = key::KeyCommands::Gen(key::GenArgs {
                        algorithm: args[2].clone(),
                        bits,
                        curve,
                        output,
                    });
                    key::run(cmd, config)?;
                }
                "show" => {
                    if args.len() < 3 {
                        println!("Usage: key show <file> [--public]");
                        return Ok(());
                    }
                    let cmd = key::KeyCommands::Show(key::ShowArgs {
                        file: args[2].clone().into(),
                        public: args.contains(&"--public".to_string()),
                    });
                    key::run(cmd, config)?;
                }
                "match" => {
                    if args.len() < 4 {
                        println!("Usage: key match <key-file> <cert-file>");
                        return Ok(());
                    }
                    let cmd = key::KeyCommands::Match(key::MatchArgs {
                        key: args[2].clone().into(),
                        cert: args[3].clone().into(),
                    });
                    key::run(cmd, config)?;
                }
                other => {
                    println!("Unknown key command: {other}");
                    println!("Available: gen, show, match");
                }
            }
        }
        "chain" => {
            if args.len() < 2 {
                println!("Usage: chain <build|show|verify> <file> [options]");
                return Ok(());
            }
            match args[1].as_str() {
                "build" => {
                    if args.len() < 3 {
                        println!("Usage: chain build <file> [options]");
                        println!("Options:");
                        println!("  -o <file>       Output chain to file");
                        println!("  --no-fetch      Don't fetch from network");
                        println!("  --ca <file>     Custom CA bundle");
                        return Ok(());
                    }
                    let output = args
                        .iter()
                        .position(|a| a == "-o" || a == "--output")
                        .and_then(|i| args.get(i + 1))
                        .cloned();
                    let ca = args
                        .iter()
                        .position(|a| a == "--ca")
                        .and_then(|i| args.get(i + 1))
                        .cloned();
                    let cmd = chain::ChainCommands::Build {
                        file: args[2].clone(),
                        output,
                        no_fetch: args.contains(&"--no-fetch".to_string()),
                        ca,
                    };
                    chain::run(cmd, config)?;
                }
                "show" => {
                    if args.len() < 3 {
                        println!("Usage: chain show <file> [--verify]");
                        return Ok(());
                    }
                    let cmd = chain::ChainCommands::Show {
                        file: args[2].clone(),
                        verify: args.contains(&"--verify".to_string()),
                    };
                    chain::run(cmd, config)?;
                }
                "verify" => {
                    if args.len() < 3 {
                        println!("Usage: chain verify <file> [--ca <ca-file>] [--no-revocation]");
                        return Ok(());
                    }
                    let ca = args
                        .iter()
                        .position(|a| a == "--ca")
                        .and_then(|i| args.get(i + 1))
                        .cloned();
                    let cmd = chain::ChainCommands::Verify {
                        file: args[2].clone(),
                        ca,
                        no_revocation: args.contains(&"--no-revocation".to_string()),
                        no_check_time: args.contains(&"--no-check-time".to_string()),
                    };
                    chain::run(cmd, config)?;
                }
                other => {
                    println!("Unknown chain command: {other}");
                    println!("Available: build, show, verify");
                }
            }
        }
        other => {
            println!("Unknown command: {other}");
            println!("Type 'help' for available commands");
        }
    }

    Ok(())
}

// Helper function to get data directory
mod dirs {
    use std::path::PathBuf;

    pub fn data_dir() -> Option<PathBuf> {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|p| p.join(".local").join("share"))
    }
}
