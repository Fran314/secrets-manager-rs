use std::fs;

use thiserror::Error;

// pub fn generate_checksum<P>(dir: P, filenames: &Vec<String>) -> Result<()>
// where
//     P: AsRef<std::path::Path>,
// {
//     let join = |lines: Vec<String>| lines.join("\n") + "\n";
//     let filter_filenames = |line: &String| {
//         for filename in filenames {
//             if line.ends_with(&format!("  {filename}")) {
//                 return false;
//             }
//         }
//         true
//     };
//     let sha256sums = dir.as_ref().join("sha256sums.txt");
//
//     let digests = filenames
//         .iter()
//         .map(|filename| {
//             let path = dir.as_ref().join(filename);
//             let digest = sha256::digest(fs::read(path)?);
//
//             Ok(format!("{digest}  {filename}"))
//         })
//         .collect::<Result<Vec<_>>>()?;
//
//     if fs::exists(&sha256sums)? {
//         let old_lines = fs::read_to_string(&sha256sums)?;
//         let new_lines: Vec<String> = vec![
//             old_lines
//                 .lines()
//                 .map(str::to_owned)
//                 .filter(filter_filenames)
//                 .collect(),
//             digests,
//         ]
//         .concat();
//
//         fs::write(&sha256sums, join(new_lines))?;
//     } else {
//         fs::write(&sha256sums, join(digests))?;
//     }
//     Ok(())
// }

#[derive(Error, Debug)]
pub enum GenerateError {
    #[error("failed to read file at path '{0}' to generate checksum\n{1}")]
    ReadFileFail(String, std::io::Error),

    #[error("failed to read existing checksum file at path '{0}' to update it\n{1}")]
    ReadChecksumFail(String, std::io::Error),

    #[error("ill-formatted existing checksum file at path '{0}'")]
    IllFormattedExistingChecksum(String),

    #[error("failed to write to checksum file at path '{0}'\n{1}")]
    WriteFail(String, std::io::Error),
}
impl GenerateError {
    fn read_file_fail(path: &std::path::Path) -> impl Fn(std::io::Error) -> GenerateError {
        |e| GenerateError::ReadFileFail(path.to_string_lossy().to_string(), e)
    }

    fn read_checksum_fail(path: &std::path::Path) -> impl Fn(std::io::Error) -> GenerateError {
        |e| GenerateError::ReadChecksumFail(path.to_string_lossy().to_string(), e)
    }

    fn ill_formatted_existing_checksum(path: &std::path::Path) -> GenerateError {
        GenerateError::IllFormattedExistingChecksum(path.to_string_lossy().to_string())
    }

    fn write_fail(path: &std::path::Path) -> impl Fn(std::io::Error) -> GenerateError {
        |e| GenerateError::WriteFail(path.to_string_lossy().to_string(), e)
    }
}

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("missing checksum file at path '{0}'")]
    MissingChecksum(String),

    #[error("failed to read checksum file at path '{0}'\n{1}")]
    ReadChecksumFail(String, std::io::Error),

    #[error("ill-formatted checksum file at path '{0}'")]
    IllFormattedChecksum(String),

    #[error("failed to read file at path '{0}' to verify checksum\n{1}")]
    ReadFileFail(String, std::io::Error),

    #[error("checksum at path '{1}' does not match for file '{0}'. Possible integrity issue")]
    ChecksumMismatch(String, String),
}
impl VerifyError {
    fn missing_checksum(path: &std::path::Path) -> VerifyError {
        VerifyError::MissingChecksum(path.to_string_lossy().to_string())
    }

    fn read_checksum_fail(path: &std::path::Path) -> impl Fn(std::io::Error) -> VerifyError {
        |e| VerifyError::ReadChecksumFail(path.to_string_lossy().to_string(), e)
    }

    fn ill_formatted_checksum(path: &std::path::Path) -> VerifyError {
        VerifyError::IllFormattedChecksum(path.to_string_lossy().to_string())
    }

    fn read_file_fail(path: &std::path::Path) -> impl Fn(std::io::Error) -> VerifyError {
        |e| VerifyError::ReadFileFail(path.to_string_lossy().to_string(), e)
    }

    fn checksum_mismatch(file: &str, sums_path: &std::path::Path) -> VerifyError {
        VerifyError::ChecksumMismatch(file.to_string(), sums_path.to_string_lossy().to_string())
    }
}

pub fn generate_checksum<P>(dir: P, filenames: &Vec<String>) -> Result<(), GenerateError>
where
    P: AsRef<std::path::Path>,
{
    let sums_path = dir.as_ref().join("sha256sums.txt");
    let re = regex::Regex::new(r"^([0-9a-fA-F]{64})  (.+)$").unwrap();

    let mut digests = Vec::new();
    for filename in filenames {
        let path = dir.as_ref().join(filename);
        let digest = sha256::digest(fs::read(&path).map_err(GenerateError::read_file_fail(&path))?);
        digests.push(format!("{digest}  {filename}"));
    }

    let lines = match sums_path.exists() {
        false => digests,
        true => {
            let old_lines = fs::read_to_string(&sums_path)
                .map_err(GenerateError::read_checksum_fail(&sums_path))?;
            let mut new_lines = Vec::new();
            for line in old_lines.lines() {
                let caps = re
                    .captures(line)
                    .ok_or(GenerateError::ill_formatted_existing_checksum(&sums_path))?;
                let (_, [_, filename]) = caps.extract();

                if !filenames.contains(&filename.to_string()) {
                    new_lines.push(line.to_string());
                }
            }
            new_lines.append(&mut digests);
            new_lines
        }
    };

    fs::write(&sums_path, lines.join("\n") + "\n")
        .map_err(GenerateError::write_fail(&sums_path))?;

    Ok(())
}

pub fn verify_checksum<P>(dir: P) -> Result<(), VerifyError>
where
    P: AsRef<std::path::Path>,
{
    let sums_path = dir.as_ref().join("sha256sums.txt");
    let re = regex::Regex::new(r"^([0-9a-fA-F]{64})  (.+)$").unwrap();

    if !sums_path.exists() {
        return Err(VerifyError::missing_checksum(&sums_path));
    }
    let sums_content =
        fs::read_to_string(&sums_path).map_err(VerifyError::read_checksum_fail(&sums_path))?;

    let mut entries = Vec::new();
    for line in sums_content.lines() {
        let caps = re
            .captures(line)
            .ok_or(VerifyError::ill_formatted_checksum(&sums_path))?;
        let (_, [digest, filename]) = caps.extract();
        entries.push((digest, filename));
    }

    for (digest, filename) in entries {
        let file_path = dir.as_ref().join(filename);
        let file_content = fs::read(&file_path).map_err(VerifyError::read_file_fail(&file_path))?;
        let actual_digest = sha256::digest(file_content);

        if actual_digest != digest {
            return Err(VerifyError::checksum_mismatch(filename, &sums_path));
        }
    }

    Ok(())
}
