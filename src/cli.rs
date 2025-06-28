use clap::{Parser, Subcommand};
use thiserror::Error;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Exports secrets to specified endpoint
    Export {
        #[clap(index = 1)]
        endpoint: String,
    },

    /// Verify the integrity of an existing export (already done when creating an export)
    VerifyExport {
        #[clap(index = 1)]
        source: String,
    },

    /// Imports secrets from existing export
    Import {
        #[clap(index = 1)]
        source: String,
    },
}

/// Import and export secrets to backup
#[derive(Debug, Parser)]
#[clap(version)]
struct _Args {
    #[clap(long, short, global = true)]
    profile: Option<String>,

    #[clap(subcommand)]
    command: Command,
}

pub struct Args {
    pub profile: String,
    pub command: Command,
}

#[derive(Error, Debug)]
pub enum ArgsError {
    #[error("path '{0}' does not exist")]
    MissingPath(String),

    #[error("path '{0}' is not a directory")]
    PathNotDir(String),
}

pub fn args() -> Result<Args, ArgsError> {
    let _Args { profile, command } = _Args::parse();

    let profile = match profile {
        Some(profile) => profile,
        None => gethostname::gethostname().to_string_lossy().to_string(),
    };

    match &command {
        Command::Export { endpoint: path_str }
        | Command::VerifyExport { source: path_str }
        | Command::Import { source: path_str } => {
            let path = std::path::Path::new(path_str);
            if !path.exists() {
                return Err(ArgsError::MissingPath(path_str.clone()));
            } else if !path.is_dir() {
                return Err(ArgsError::PathNotDir(path_str.clone()));
            }
        }
    }

    Ok(Args { profile, command })
}
