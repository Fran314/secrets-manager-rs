use clap::{Parser, Subcommand};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Exports secrets to an export container
    Export {
        /// Path to the secrets directory to back up
        #[clap(index = 1, value_name = "secrets-dir")]
        secrets_dir: String,

        /// Path to the export container (a new timestamped snapshot is created inside it)
        #[clap(index = 2, value_name = "export-dir")]
        export_dir: String,
    },

    /// Verify the integrity of an existing export (already done when creating an export)
    VerifyExport {
        /// Path to the export container (verifies every snapshot), or a specific snapshot inside it
        #[clap(index = 1, value_name = "export-dir")]
        export_dir: String,
    },

    /// Imports secrets from an existing export
    Import {
        /// Path to the export container (imports the newest snapshot), or a specific snapshot inside it
        #[clap(index = 1, value_name = "export-dir")]
        export_dir: String,

        /// Path to the secrets directory to restore into
        #[clap(index = 2, value_name = "secrets-dir")]
        secrets_dir: String,

        /// Restore only these specific secrets (relative paths). If omitted, the whole export is imported
        #[clap(long, value_name = "path", num_args = 1..)]
        pick: Vec<String>,

        /// Treat the source as already-decrypted plaintext (skip decryption, no passphrase prompt)
        #[clap(long)]
        from_plaintext: bool,

        /// Do not apply the manifest's owner/mode to restored files (leave them owned by the runner at 0600)
        #[clap(long)]
        skip_chown_chmod: bool,
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
