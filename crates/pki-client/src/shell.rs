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

  csr create --key <file> --cn <name>   Create a CSR
  csr show <file>               Show CSR details

  key gen ec|rsa|ed25519        Generate private key
  key show <file>               Show key information
  key match <key> <cert>        Check if key matches certificate

  chain build <file>            Build certificate chain
  chain show <file>             Display chain as tree
  chain verify <file>           Verify chain integrity

  convert <file> --to pem|der   Convert certificate format
  diff <file1> <file2>          Compare two certs or CSRs
  probe server <host:port>      Probe TLS server
  probe check <host:port>       Quick TLS connectivity check

  scep cacaps <url>             SCEP: CA capabilities
  scep enroll <url> -s <cn>     SCEP: automated enrollment
  acme certonly <domain>        ACME: get certificate
  est enroll <url>              EST: simple enrollment

Shell commands:
  help, ?                       Show this help
  version                       Show version
  history                       Show command history
  clear                         Clear screen
  exit, quit, q                 Exit shell

Tips:
  - Use Tab for file path completion
  - Use Up/Down arrows for history
  - The "pki" prefix is optional (e.g., "key gen ec" works)
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

/// Check if a line looks like the start of a new command (not a continuation of a previous one).
/// Returns true if the first word matches a known command or pki prefix.
fn looks_like_new_command(line: &str) -> bool {
    let first_word = line.split_whitespace().next().unwrap_or("");
    let lower = first_word.to_lowercase();
    // Known command names (subset — anything that could start a command)
    const CMD_STARTS: &[&str] = &[
        "show",
        "cert",
        "csr",
        "key",
        "chain",
        "convert",
        "diff",
        "probe",
        "scep",
        "acme",
        "est",
        "pki",
        "dane",
        "crl",
        "revoke",
        "compliance",
        "batch",
        "build",
        "preview",
        "validate",
        "export",
        "help",
        "clear",
        "exit",
        "quit",
        "history",
        "version",
    ];
    CMD_STARTS.contains(&lower.as_str())
}

/// Top-level commands for completion
const TOP_COMMANDS: &[&str] = &[
    "show",
    "cert",
    "csr",
    "key",
    "chain",
    "convert",
    "diff",
    "probe",
    "scep",
    "acme",
    "est",
    "pki",
    "dane",
    "crl",
    "revoke",
    "compliance",
    "batch",
    "help",
    "clear",
    "exit",
    "quit",
    "history",
    "version",
];

/// Subcommands for each top-level command
fn get_subcommands(cmd: &str) -> &'static [&'static str] {
    match cmd {
        "cert" => &["show", "expires", "fingerprint"],
        "csr" => &["create", "show"],
        "key" => &["gen", "show", "match"],
        "chain" => &["build", "show", "verify"],
        "probe" => &["check", "server"],
        "scep" => &["cacaps", "cacert", "enroll", "pkiop"],
        "acme" => &["certonly", "directory", "register"],
        "est" => &["cacerts", "enroll", "reenroll"],
        "pki" => &["build", "preview", "validate", "export"],
        "dane" => &["generate", "verify"],
        "compliance" => &["check", "levels", "bridge"],
        "crl" => &["show", "check"],
        "revoke" => &["check"],
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
    let mut pending_command: Option<String> = None;

    loop {
        let prompt = if multiline_buffer.is_some() || pending_command.is_some() {
            format!("{} ", "....>".dimmed())
        } else {
            format!("{} ", "pki>".cyan().bold())
        };
        let readline = rl.readline(&prompt);

        match readline {
            Ok(line) => {
                // --- Line continuation across readline calls ---
                // If there's a pending command and this line arrives:
                //   - Explicit `\` continuation: keep buffering
                //   - Line doesn't look like a new command: join and execute
                //   - Line IS a new command: flush pending, then process new line
                if pending_command.is_some() {
                    let trimmed = line.trim();

                    if trimmed.is_empty() {
                        // Empty line → flush pending command
                        let cmd = pending_command.take().unwrap();
                        let _ = rl.add_history_entry(&cmd);
                        match handle_shell_command(&cmd, config) {
                            ShellAction::Continue => continue,
                            ShellAction::Exit => break,
                            ShellAction::RunCommand(args) => {
                                if let Err(e) = run_cli_command(&args, config) {
                                    eprintln!("{}: {}", "error".red().bold(), e);
                                }
                            }
                        }
                        continue;
                    }

                    // Explicit continuation: line ends with `\`
                    if let Some(without_slash) = trimmed.strip_suffix('\\') {
                        if let Some(ref mut buf) = pending_command {
                            buf.push(' ');
                            buf.push_str(without_slash.trim_end());
                        }
                        continue;
                    }

                    // Auto-join: line doesn't look like a new command
                    if !looks_like_new_command(trimmed) {
                        let mut cmd = pending_command.take().unwrap();
                        cmd.push(' ');
                        cmd.push_str(trimmed);
                        // Execute the joined command now
                        let _ = rl.add_history_entry(&cmd);
                        match handle_shell_command(&cmd, config) {
                            ShellAction::Continue => continue,
                            ShellAction::Exit => break,
                            ShellAction::RunCommand(args) => {
                                if let Err(e) = run_cli_command(&args, config) {
                                    eprintln!("{}: {}", "error".red().bold(), e);
                                }
                            }
                        }
                        continue;
                    }

                    // It IS a new command — flush pending first, then fall through
                    let prev = pending_command.take().unwrap();
                    let _ = rl.add_history_entry(&prev);
                    match handle_shell_command(&prev, config) {
                        ShellAction::Continue => {}
                        ShellAction::Exit => break,
                        ShellAction::RunCommand(args) => {
                            if let Err(e) = run_cli_command(&args, config) {
                                eprintln!("{}: {}", "error".red().bold(), e);
                            }
                        }
                    }
                    // Fall through to process current line as new command
                }

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

                // Split on newlines to handle multi-line paste
                let lines: Vec<&str> = line.split('\n').collect();
                let mut should_exit = false;

                for single_line in lines {
                    let single_line = single_line.trim();
                    if single_line.is_empty() {
                        continue;
                    }

                    // If we're buffering PEM, keep adding lines
                    if let Some(ref mut buffer) = multiline_buffer {
                        buffer.push('\n');
                        buffer.push_str(single_line);
                        if single_line.contains("-----END") {
                            let full_pem = buffer.clone();
                            multiline_buffer = None;
                            // Auto-show the pasted PEM
                            if let Err(e) = show_inline_pem(&full_pem, config) {
                                eprintln!("{}: {}", "error".red().bold(), e);
                            }
                        }
                        continue;
                    }

                    // Check if this line starts a multi-line PEM input
                    if single_line.contains("-----BEGIN") {
                        if single_line.contains("-----END") {
                            // Single-line PEM (unlikely but handle it)
                            if let Err(e) = show_inline_pem(single_line, config) {
                                eprintln!("{}: {}", "error".red().bold(), e);
                            }
                        } else {
                            multiline_buffer = Some(single_line.to_string());
                        }
                        continue;
                    }

                    // Detect raw base64 DER paste (e.g. "MIIFqj..." without PEM headers)
                    if single_line.len() > 40
                        && single_line.starts_with("MII")
                        && single_line
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
                    {
                        // Wrap in PEM and show
                        let pem = format!(
                            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                            single_line
                        );
                        if let Err(e) = show_inline_pem(&pem, config) {
                            eprintln!("{}: {}", "error".red().bold(), e);
                        }
                        continue;
                    }

                    // --- Line continuation support ---
                    // 1. Explicit: line ends with `\` → buffer and wait for more
                    if let Some(without_slash) = single_line.strip_suffix('\\') {
                        let stripped = without_slash.trim_end();
                        if let Some(ref mut buf) = pending_command {
                            buf.push(' ');
                            buf.push_str(stripped);
                        } else {
                            pending_command = Some(stripped.to_string());
                        }
                        continue;
                    }

                    // 2. Auto-join: if there's a pending command and this line
                    //    doesn't look like a new command, join it
                    if let Some(ref mut buf) = pending_command {
                        if !looks_like_new_command(single_line) {
                            buf.push(' ');
                            buf.push_str(single_line);
                            // Check if THIS line also ends with \
                            // (already handled above, so this line is complete)
                            let full_cmd = buf.clone();
                            pending_command = None;
                            let _ = rl.add_history_entry(&full_cmd);
                            match handle_shell_command(&full_cmd, config) {
                                ShellAction::Continue => continue,
                                ShellAction::Exit => {
                                    should_exit = true;
                                    break;
                                }
                                ShellAction::RunCommand(args) => {
                                    if let Err(e) = run_cli_command(&args, config) {
                                        eprintln!("{}: {}", "error".red().bold(), e);
                                    }
                                }
                            }
                            continue;
                        }
                        // This IS a new command — flush the pending one first
                        let prev_cmd = buf.clone();
                        pending_command = None;
                        let _ = rl.add_history_entry(&prev_cmd);
                        match handle_shell_command(&prev_cmd, config) {
                            ShellAction::Continue => {}
                            ShellAction::Exit => {
                                should_exit = true;
                                break;
                            }
                            ShellAction::RunCommand(args) => {
                                if let Err(e) = run_cli_command(&args, config) {
                                    eprintln!("{}: {}", "error".red().bold(), e);
                                }
                            }
                        }
                        // Fall through to process current line as new command
                    }

                    // Check if this is a shell builtin (version, help, clear, exit)
                    // that should execute immediately without buffering.
                    // Only buffer CLI commands (RunCommand) for potential continuation.
                    match handle_shell_command(single_line, config) {
                        ShellAction::Continue => {
                            // Builtin already handled (printed version, help, etc.)
                            let _ = rl.add_history_entry(single_line);
                        }
                        ShellAction::Exit => {
                            should_exit = true;
                            break;
                        }
                        ShellAction::RunCommand(_) => {
                            // CLI command — buffer for potential line continuation
                            pending_command = Some(single_line.to_string());
                        }
                    }
                }

                if should_exit {
                    break;
                }
            }
            Err(ReadlineError::Interrupted) => {
                if multiline_buffer.is_some() || pending_command.is_some() {
                    println!("^C (cancelled multi-line input)");
                    multiline_buffer = None;
                    pending_command = None;
                } else {
                    println!("^C");
                }
                continue;
            }
            Err(ReadlineError::Eof) => {
                // Flush pending command before exit
                if let Some(cmd) = pending_command.take() {
                    let _ = rl.add_history_entry(&cmd);
                    match handle_shell_command(&cmd, config) {
                        ShellAction::Continue | ShellAction::Exit => {}
                        ShellAction::RunCommand(args) => {
                            if let Err(e) = run_cli_command(&args, config) {
                                eprintln!("{}: {}", "error".red().bold(), e);
                            }
                        }
                    }
                }
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

/// Run commands from a script file (batch mode).
///
/// Reads the file line-by-line, skips comments and blanks, and executes
/// each line as a shell command. Errors don't halt execution.
pub fn run_batch(path: &std::path::Path, config: &GlobalConfig) -> Result<CmdResult> {
    use anyhow::Context;
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read batch file: {}", path.display()))?;

    let mut succeeded = 0u32;
    let mut failed = 0u32;

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip blanks and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if !config.quiet {
            println!("{} {}", format!("[{}]", line_num + 1).dimmed(), line.cyan());
        }

        match handle_shell_command(line, config) {
            ShellAction::Continue => {}
            ShellAction::Exit => break,
            ShellAction::RunCommand(args) => {
                if let Err(e) = run_cli_command(&args, config) {
                    eprintln!("{}: {}", "error".red().bold(), e);
                    failed += 1;
                    continue;
                }
                succeeded += 1;
            }
        }
    }

    if !config.quiet {
        println!(
            "\n{}: {} succeeded, {} failed",
            "Batch complete".bold(),
            succeeded.to_string().green(),
            if failed > 0 {
                failed.to_string().red().to_string()
            } else {
                "0".to_string()
            }
        );
    }

    if failed > 0 {
        Ok(CmdResult::ExitCode(1))
    } else {
        Ok(CmdResult::Success)
    }
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

    let split = shell_split(command_part);
    let parts: Vec<&str> = split.iter().map(|s| s.as_str()).collect();
    if parts.is_empty() && pem_content.is_none() {
        return ShellAction::Continue;
    }

    // Strip "pki" prefix — users often type "pki key gen" inside the shell.
    // BUT: don't strip if the second word is a subcommand of the `pki` hierarchy command
    // (build, preview, validate, export), since "pki build" IS the hierarchy command.
    let pki_hierarchy_subs = ["build", "preview", "validate", "export"];
    let parts: Vec<&str> = if parts.first().map(|s| s.eq_ignore_ascii_case("pki")) == Some(true) {
        let next = parts.get(1).map(|s| s.to_lowercase());
        if next
            .as_deref()
            .is_some_and(|n| pki_hierarchy_subs.contains(&n))
        {
            // "pki build ..." → keep as-is, it's the hierarchy command
            parts
        } else {
            // "pki show ..." → strip redundant prefix
            parts[1..].to_vec()
        }
    } else {
        parts
    };

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
        Some("help") | Some("?") | Some("--help") | Some("-h") => {
            println!("{}", HELP_TEXT);
            ShellAction::Continue
        }
        Some("version") | Some("--version") | Some("-v") => {
            println!("pki {}", env!("CARGO_PKG_VERSION"));
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
            let cmd = parts[0];

            // Skip lines that are clearly not commands (comments, TOML, etc.)
            if cmd.starts_with('#')
                || cmd.starts_with('[')
                || cmd.starts_with("//")
                || cmd.contains('=')
            {
                return ShellAction::Continue;
            }

            // Fuzzy prefix match: if the input is a unique prefix of a known command, use it
            let cmd_lower = cmd.to_lowercase();
            let matches: Vec<&&str> = TOP_COMMANDS
                .iter()
                .filter(|c| c.starts_with(&cmd_lower))
                .collect();

            if matches.len() == 1 {
                let resolved = *matches[0];
                // If it resolves to a shell builtin, handle directly
                match resolved {
                    "version" => {
                        println!("pki {}", env!("CARGO_PKG_VERSION"));
                        return ShellAction::Continue;
                    }
                    "help" => {
                        println!("{}", HELP_TEXT);
                        return ShellAction::Continue;
                    }
                    "exit" | "quit" => return ShellAction::Exit,
                    "clear" => {
                        print!("\x1B[2J\x1B[1;1H");
                        return ShellAction::Continue;
                    }
                    "history" => {
                        println!("Use Up/Down arrows to navigate history");
                        return ShellAction::Continue;
                    }
                    _ => {
                        // CLI command — substitute the full name
                        let mut args: Vec<String> =
                            parts.iter().map(|s| (*s).to_string()).collect();
                        args[0] = resolved.to_string();
                        if let Some(pem) = pem_content {
                            args.push(pem);
                        }
                        return ShellAction::RunCommand(args);
                    }
                }
            }

            // Multiple prefix matches — suggest
            if matches.len() > 1 {
                let suggestions: Vec<&str> = matches.iter().map(|s| **s).collect();
                println!(
                    "Unknown command: {} — did you mean {}?",
                    cmd,
                    suggestions.join(" or ")
                );
                return ShellAction::Continue;
            }

            // No prefix match — pass to CLI handler
            let mut args: Vec<String> = parts.iter().map(|s| (*s).to_string()).collect();
            if let Some(pem) = pem_content {
                args.push(pem);
            }

            ShellAction::RunCommand(args)
        }
    }
}

fn run_cli_command(args: &[String], config: &GlobalConfig) -> Result<()> {
    use crate::commands::{cert, chain, csr, key};

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
        "csr" => {
            if args.len() < 2 {
                println!("Usage: csr <create|show> [args]");
                return Ok(());
            }
            match args[1].as_str() {
                "create" => {
                    if args.len() < 3 || !args.iter().any(|a| a == "--cn") {
                        println!("Usage: csr create --key <file> --cn <name> [options]");
                        println!("Options:");
                        println!("  --key <file>    Private key file (required)");
                        println!("  --cn <name>     Common Name (required)");
                        println!("  --san <san>     Subject Alternative Name (repeatable)");
                        println!("  --org <org>     Organization");
                        println!("  --country <CC>  Country code");
                        println!("  -o <file>       Output file");
                        return Ok(());
                    }
                    let get_arg = |flag: &str| {
                        args.iter()
                            .position(|a| a == flag)
                            .and_then(|i| args.get(i + 1))
                            .cloned()
                    };
                    let key = get_arg("--key").or_else(|| get_arg("-k"));
                    let cn = get_arg("--cn");
                    let Some(key) = key else {
                        println!("Missing required: --key <file>");
                        return Ok(());
                    };
                    let Some(cn) = cn else {
                        println!("Missing required: --cn <name>");
                        return Ok(());
                    };
                    let san: Vec<String> = args
                        .iter()
                        .enumerate()
                        .filter(|(_, a)| *a == "--san")
                        .filter_map(|(i, _)| args.get(i + 1).cloned())
                        .collect();
                    let cmd = csr::CsrCommands::Create(csr::CreateArgs {
                        key: key.into(),
                        cn,
                        org: get_arg("--org"),
                        ou: get_arg("--ou"),
                        country: get_arg("--country"),
                        state: get_arg("--state"),
                        locality: get_arg("--locality"),
                        san,
                        output: get_arg("-o")
                            .or_else(|| get_arg("--output"))
                            .map(|s| s.into()),
                    });
                    csr::run(cmd, config)?;
                }
                "show" => {
                    if args.len() < 3 {
                        println!("Usage: csr show <file>");
                        return Ok(());
                    }
                    let cmd = csr::CsrCommands::Show(csr::ShowArgs {
                        file: args[2].clone().into(),
                    });
                    csr::run(cmd, config)?;
                }
                other => {
                    println!("Unknown csr command: {other}");
                    println!("Available: create, show");
                }
            }
        }
        // Bare hierarchy commands → route to "pki build", "pki preview", etc.
        "build" | "preview" | "validate" | "export" => {
            let mut pki_args = vec!["pki".to_string()];
            pki_args.extend(args.iter().cloned());
            passthrough_to_cli(&pki_args, config)?;
        }
        // Passthrough: run any other command via the full CLI parser
        other => {
            // Known passthrough commands — CLI already printed its own error
            const KNOWN_PASSTHROUGH: &[&str] = &[
                "probe",
                "diff",
                "convert",
                "scep",
                "acme",
                "est",
                "pki",
                "dane",
                "crl",
                "revoke",
                "compliance",
                "batch",
            ];
            if let Err(_e) = passthrough_to_cli(args, config) {
                if !KNOWN_PASSTHROUGH.contains(&other) {
                    println!("Unknown command: {other}");
                    println!("Type 'help' for available commands");
                }
            }
        }
    }

    Ok(())
}

/// Passthrough commands to the full CLI dispatcher for commands not
/// explicitly handled in the shell (probe, diff, convert, scep, acme, est, etc.)
/// Show inline PEM content — auto-detects type (cert, CSR, key, CRL, PKCS#7).
fn show_inline_pem(pem_text: &str, config: &GlobalConfig) -> Result<()> {
    use std::io::Write;

    // Write PEM to a temp file, show it, clean up
    let tmp_path = std::env::temp_dir().join(format!("pki-paste-{}.pem", std::process::id()));
    let mut f = std::fs::File::create(&tmp_path)?;
    f.write_all(pem_text.as_bytes())?;
    f.flush()?;
    drop(f);

    let args = vec!["show".to_string(), tmp_path.display().to_string()];
    let result = run_cli_command(&args, config);

    let _ = std::fs::remove_file(&tmp_path);
    result
}

/// Split a command line respecting double and single quotes.
fn shell_split(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_double = false;
    let mut in_single = false;

    for c in input.chars() {
        match c {
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            ' ' | '\t' if !in_double && !in_single => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

fn passthrough_to_cli(args: &[String], config: &GlobalConfig) -> Result<()> {
    // Reconstruct CLI args as "pki <command> [args...]" and dispatch
    let cli_args: Vec<String> = std::iter::once("pki".to_string())
        .chain(args.iter().cloned())
        .collect();

    crate::run_from_args(&cli_args, config)
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
