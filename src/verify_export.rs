use std::io::Write;

use camino::Utf8PathBuf;
use thiserror::Error;

use crate::checksum;

#[derive(Error, Debug)]
pub enum VerifyExportError {
    #[error("source path '{0}' does not exist")]
    MissingSourcePath(Utf8PathBuf),
    #[error("source path '{0}' is not a directory")]
    SourceNotDir(Utf8PathBuf),

    #[error(transparent)]
    VerifySource(checksum::ChecksumError),
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
    print!("Verifying export integrity... ");
    std::io::stdout().flush().unwrap();
    checksum::verify_checksums(&source)
        .map_err(VerifyExportError::VerifySource)
        .inspect_err(|_| println!("error"))?;
    println!("ok");

    println!();
    println!("Export integrity verified succesfully!");

    Ok(())
}
