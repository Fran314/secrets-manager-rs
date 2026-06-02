#![allow(clippy::result_large_err)]

use anyhow::{Result, anyhow};

mod checksum;
mod chown_spec;
mod crypto;
mod manifest;
mod snapshot;

mod cli;
mod export;
mod import;
mod safe_fs;
mod utf8path_ext;
mod verify_export;

fn execute() -> Result<()> {
    let args = cli::args();

    match args.command {
        cli::Command::Export { source, target } => {
            let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
            let passphrase_check = rpassword::prompt_password("Enter passphrase again: ")?;
            if passphrase != passphrase_check {
                return Err(anyhow!("passphrases do not match"));
            }
            println!();

            export::export(source, target, passphrase)?;
        }
        cli::Command::VerifyExport { source } => {
            verify_export::verify_export(source)?;
        }
        cli::Command::Import {
            source,
            target,
            paths,
        } => {
            let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
            println!();

            import::import(source, target, paths, passphrase)?;
        }
    };

    Ok(())
}

fn main() {
    match execute() {
        Ok(_) => {}
        Err(err) => {
            eprintln!("Error: {err}");
            std::process::exit(1)
        }
    }
}
