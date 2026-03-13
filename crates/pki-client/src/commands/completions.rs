//! Shell completion generation.

use crate::commands::CmdResult;
use anyhow::Result;
use clap::{Command, CommandFactory};
use clap_complete::{generate, Shell};
use std::io;

/// Generate shell completions for the specified shell.
pub fn run(shell: Shell) -> Result<CmdResult> {
    let mut cmd = crate::Cli::command();
    generate_completions(shell, &mut cmd);
    Ok(CmdResult::Success)
}

/// Generate completions to stdout.
fn generate_completions(shell: Shell, cmd: &mut Command) {
    generate(shell, cmd, "pki", &mut io::stdout());
}

/// Generate man pages.
pub fn generate_manpages(output_dir: &std::path::Path) -> Result<CmdResult> {
    use std::fs;

    fs::create_dir_all(output_dir)?;

    let cmd = crate::Cli::command();
    let man = clap_mangen::Man::new(cmd.clone());
    let mut buffer = Vec::new();
    man.render(&mut buffer)?;

    let manpage_path = output_dir.join("pki.1");
    fs::write(&manpage_path, buffer)?;
    println!("Generated: {}", manpage_path.display());

    // Generate subcommand man pages
    for subcommand in cmd.get_subcommands() {
        if subcommand.get_name() == "help" {
            continue;
        }

        let sub_man = clap_mangen::Man::new(subcommand.clone());
        let mut sub_buffer = Vec::new();
        sub_man.render(&mut sub_buffer)?;

        let sub_path = output_dir.join(format!("pki-{}.1", subcommand.get_name()));
        fs::write(&sub_path, sub_buffer)?;
        println!("Generated: {}", sub_path.display());
    }

    Ok(CmdResult::Success)
}
