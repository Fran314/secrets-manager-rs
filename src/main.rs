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
        cli::Command::Export {
            secrets_dir,
            export_dir,
        } => {
            let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
            let passphrase_check = rpassword::prompt_password("Enter passphrase again: ")?;
            if passphrase != passphrase_check {
                return Err(anyhow!("passphrases do not match"));
            }
            println!();

            export::export(secrets_dir, export_dir, passphrase)?;
        }
        cli::Command::VerifyExport { export_dir } => {
            verify_export::verify_export(export_dir)?;
        }
        cli::Command::Import {
            export_dir,
            secrets_dir,
            pick,
            from_plaintext,
            skip_chown_chmod,
        } => {
            let source_type = if from_plaintext {
                import::SourceType::Plaintext
            } else {
                let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
                println!();
                import::SourceType::Encrypted { passphrase }
            };

            import::import(export_dir, secrets_dir, pick, source_type, skip_chown_chmod)?;
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
