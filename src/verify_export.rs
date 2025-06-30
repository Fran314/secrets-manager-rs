use std::io::Write;

use thiserror::Error;

use crate::checksum;

#[derive(Error, Debug)]
pub enum VerifyExportError {}

pub fn verify_export(source: &str) -> Result<(), checksum::ChecksumError> {
    print!("Verifying export integrity... ");
    std::io::stdout().flush().unwrap();
    checksum::verify_checksums(source).inspect_err(|_| println!("error"))?;
    println!("ok");

    println!();
    println!("Export integrity verified succesfully!");

    Ok(())
}
