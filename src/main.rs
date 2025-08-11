// Copyright Soumyadip Sarkar 2025. All Rights Reserved

use clap::Parser;

use cryptrsa::cli::commands::{run, Cli};

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    run(cli)
}

