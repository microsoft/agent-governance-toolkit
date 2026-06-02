// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `agt` operator CLI entrypoint.
//!
//! `main` does exactly two things: parse args (clap auto-exits 2 on usage errors)
//! and map `run`'s result to a process exit code. `run` returns the intended exit
//! code on success (`check` uses it to encode the policy decision: 0 allow / 1
//! not-allowed) or a structured `CliError` on a fail-closed failure. All logic
//! lives in `run`/`cmd::*`, which never panic on user input.

mod cli;
mod cmd;
mod error;

use clap::Parser;
use cli::{Cli, Commands};
use error::CliError;

fn main() {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(err.exit_code());
        }
    }
}

fn run(cli: Cli) -> Result<i32, CliError> {
    match cli.command {
        Commands::Check { policy, input } => cmd::check::run(&policy, &input),
        Commands::Policy { command } => cmd::policy::run(command).map(|()| 0),
        Commands::Audit { command } => cmd::audit::run(command).map(|()| 0),
        Commands::Trust { command } => cmd::trust::run(command).map(|()| 0),
    }
}
