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

        /// Create checksum files if missing [default: false]
        #[clap(long, short)]
        create_checksum: bool,
    },

    /// Verify the integrity of an existing export (already done when creating an export)
    VerifyExport {
        /// Path to the directory containing the existing export to verify
        #[clap(index = 1)]
        source: String,
    },

    /// Imports secrets from existing export
    Import {
        /// Path to the directory containing the existing export (to import the latest export), or a specific snapshot inside it
        #[clap(index = 1)]
        source: String,

        /// Specific secrets to import (relative paths). If omitted, the whole export is imported
        #[clap(index = 2)]
        paths: Vec<String>,

        /// Path where to import the secrets
        #[clap(long, short, default_value = "/secrets")]
        target: String,
    },
}

/// Import and export secrets to backup
#[derive(Debug, Parser)]
#[clap(version)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Command,
}

pub fn args() -> Args {
    Args::parse()
}
