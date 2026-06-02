use std::io::Write;

use camino::Utf8PathBuf;
use thiserror::Error;

use crate::checksum;
use crate::snapshot;

#[derive(Error, Debug)]
pub enum VerifyExportError {
    #[error("source path '{0}' does not exist")]
    MissingSourcePath(Utf8PathBuf),
    #[error("source path '{0}' is not a directory")]
    SourceNotDir(Utf8PathBuf),

    #[error("failed to list snapshots in container '{0}'\n{1}")]
    ListSnapshots(Utf8PathBuf, std::io::Error),

    #[error("container '{0}' holds no snapshots to verify")]
    EmptyContainer(Utf8PathBuf),

    #[error("source '{0}' is neither a snapshot nor a container of snapshots")]
    NotSnapshotOrContainer(Utf8PathBuf),

    #[error("{failed} of {total} snapshots failed verification")]
    SnapshotsFailed { failed: usize, total: usize },

    #[error(transparent)]
    VerifySource(checksum::ChecksumError),
}
impl VerifyExportError {
    fn list_snapshots(container: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ListSnapshots(container.clone(), e)
    }
}

fn verify_snapshot(snapshot: &Utf8PathBuf) -> Result<(), VerifyExportError> {
    print!("Verifying export integrity... ");
    std::io::stdout().flush().unwrap();
    checksum::verify_checksums(snapshot)
        .map_err(VerifyExportError::VerifySource)
        .inspect_err(|_| println!("error"))?;
    println!("ok");
    println!();
    println!("Export integrity verified successfully!");

    Ok(())
}

fn verify_container(container: &Utf8PathBuf) -> Result<(), VerifyExportError> {
    let mut snapshots = snapshot::list_snapshots(container)
        .map_err(VerifyExportError::list_snapshots(container))?;
    if snapshots.is_empty() {
        return Err(VerifyExportError::EmptyContainer(container.clone()));
    }
    snapshots.sort();

    let total = snapshots.len();
    let mut failed = 0;
    for name in &snapshots {
        print!("Verifying {name}... ");
        std::io::stdout().flush().unwrap();
        match checksum::verify_checksums(&container.join(name)) {
            Ok(()) => println!("ok"),
            Err(e) => {
                println!("FAILED");
                println!("  {e}");
                failed += 1;
            }
        }
    }
    println!();

    if failed > 0 {
        return Err(VerifyExportError::SnapshotsFailed { failed, total });
    }

    println!("All {total} snapshots verified successfully!");

    Ok(())
}

pub fn verify_export(source: String) -> Result<(), VerifyExportError> {
    let source = {
        let path = Utf8PathBuf::from(&source);
        if !path.exists() {
            return Err(VerifyExportError::MissingSourcePath(path));
        } else if !path.is_dir() {
            return Err(VerifyExportError::SourceNotDir(path));
        }
        path
    };

    match snapshot::classify(&source) {
        snapshot::SourceKind::Snapshot => verify_snapshot(&source),
        snapshot::SourceKind::Container => verify_container(&source),
        snapshot::SourceKind::Neither => Err(VerifyExportError::NotSnapshotOrContainer(source)),
    }
}
