use clap::{Parser, Subcommand};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Exports secrets to specified endpoint
    Export {
        /// Path to the secrets directory
        #[clap(long, short, default_value = "/secrets")]
        source: String,

        /// Path where to export the secrets
        #[clap(index = 1)]
        target: String,
    },

    /// Verify the integrity of an existing export (already done when creating an export)
    VerifyExport {
        /// Path to the directory containing the existing export to verify
        #[clap(index = 1)]
        source: String,
    },

    /// Imports secrets from existing export
    Import {
        /// Path to the directory containing the existing export to import
        #[clap(index = 1)]
        source: String,

        /// Path where to import the secrets
        #[clap(long, short, default_value = "/secrets")]
        target: String,
    },
}

/// Import and export secrets to backup
#[derive(Debug, Parser)]
#[clap(version)]
struct _Args {
    /// Specifies which profile's settings to use [default: $HOST]
    #[clap(long, short, global = true)]
    profile: Option<String>,

    #[clap(subcommand)]
    command: Command,
}

pub struct Args {
    pub profile: String,
    pub command: Command,
}

pub fn args() -> Args {
    let _Args { profile, command } = _Args::parse();

    let profile = match profile {
        Some(profile) => profile,
        None => gethostname::gethostname().to_string_lossy().to_string(),
    };

    Args { profile, command }
}
