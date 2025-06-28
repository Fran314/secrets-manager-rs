use std::io::Write;

use thiserror::Error;
use walkdir::WalkDir;

use crate::checksum;

#[derive(Error, Debug)]
pub enum VerifyExportError {}

pub fn verify_export(source: &str) -> Result<(), checksum::VerifyError> {
    println!("Verify export integrity...");
    for entry in WalkDir::new(source)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|entry| entry.file_name().eq("sha256sums.txt"))
    {
        let dir = entry.path().parent().unwrap();

        print!("verifying integrity at '{}'... ", dir.to_string_lossy());
        std::io::stdout().flush().unwrap();
        checksum::verify_checksum(dir)?;
        println!("ok");
    }

    println!();
    println!("Export integrity verified succesfully!");

    Ok(())
}
