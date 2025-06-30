use anyhow::{Result, anyhow};

mod checksum;
mod config;
mod crypto;

mod cli;
mod export;
mod import;
mod safe_fs;
mod verify_export;

fn execute() -> Result<()> {
    let args = cli::args()?;

    let config = config::load_config()?;

    match &args.command {
        cli::Command::Export { endpoint } => {
            let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
            let passphrase_check = rpassword::prompt_password("Enter passphrase again: ")?;
            if passphrase != passphrase_check {
                return Err(anyhow!("passphrases do not match"));
            }
            println!();

            export::export(&args.profile, endpoint, &config, &passphrase)?;
        }
        cli::Command::VerifyExport { source } => {
            verify_export::verify_export(source)?;
        }
        cli::Command::Import { source } => {
            let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
            println!();

            import::import(&args.profile, source, &config, &passphrase)?;
        }
    };

    Ok(())
}

fn main() {
    match execute() {
        Ok(_) => {}
        Err(err) => {
            println!();
            eprintln!("Error: {err}");
            println!();
            println!(
                "Export failed. The current export state is partial and is likely to fail upon import. It's suggested to delete the export and start fresh."
            );
            std::process::exit(1)
        }
    }
}
