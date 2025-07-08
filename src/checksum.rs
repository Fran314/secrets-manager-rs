use std::fs;

use camino::Utf8PathBuf;
use thiserror::Error;

use crate::utf8path_ext::ExtraUtf8Path;

#[derive(Error, Debug)]
pub enum ChecksumError {
    #[error("failed to read file at path '{0}'\n{1}")]
    ReadSource(Utf8PathBuf, std::io::Error),

    #[error("missing checksum file at path '{0}'")]
    MissingChecksum(Utf8PathBuf),

    #[error("failed to read checksum file at path '{0}'\n{1}")]
    ReadChecksum(Utf8PathBuf, std::io::Error),

    #[error("ill-formatted checksum file at path '{0}'")]
    IllFormattedChecksum(Utf8PathBuf),

    #[error("failed to write to checksum file at path '{0}'\n{1}")]
    WriteChecksum(Utf8PathBuf, std::io::Error),

    #[error("file at path '{0}' doesn't match its hash at path '{1}'. Possible integrity issue")]
    ChecksumMismatch(Utf8PathBuf, Utf8PathBuf),
}
impl ChecksumError {
    fn read_source(path: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadSource(path.clone(), e)
    }

    fn read_checksum(path: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadChecksum(path.clone(), e)
    }

    fn write_checksum(path: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::WriteChecksum(path.clone(), e)
    }
}
pub fn verify_checksums(dir: &Utf8PathBuf) -> Result<(), ChecksumError> {
    let sums_path = dir.join("sha256sums.txt");
    let re = regex::Regex::new(r"^([0-9a-fA-F]{64})  (.+)$").unwrap();

    if !sums_path.exists() {
        return Err(ChecksumError::MissingChecksum(sums_path));
    }
    let sums_content =
        fs::read_to_string(&sums_path).map_err(ChecksumError::read_checksum(&sums_path))?;

    let mut entries = Vec::new();
    for line in sums_content.lines() {
        let caps = re
            .captures(line)
            .ok_or(ChecksumError::IllFormattedChecksum(sums_path.clone()))?;
        let (_, [digest, filename]) = caps.extract();
        entries.push((digest, filename));
    }

    for (digest, filename) in entries {
        let file_path = dir.join(filename);
        let file_content = fs::read(&file_path).map_err(ChecksumError::read_source(&file_path))?;
        let actual_digest = sha256::digest(file_content);

        if actual_digest != digest {
            return Err(ChecksumError::ChecksumMismatch(file_path, sums_path));
        }
    }

    Ok(())
}

pub fn append_checksum(
    dir: &Utf8PathBuf,
    file_rel_path: &Utf8PathBuf,
) -> Result<(), ChecksumError> {
    let re = regex::Regex::new(r"^([0-9a-fA-F]{64})  (.+)$").unwrap();

    let file_source = dir.join(file_rel_path);
    let sums_path = dir.join("sha256sums.txt");

    let checksum = {
        let digest = sha256::digest(
            fs::read(&file_source).map_err(ChecksumError::read_source(&file_source))?,
        );
        format!("{digest}  {file_rel_path}")
    };

    let lines = match sums_path.exists() {
        false => vec![checksum],
        true => {
            let old_lines =
                fs::read_to_string(&sums_path).map_err(ChecksumError::read_checksum(&sums_path))?;

            let mut new_lines = Vec::new();
            for line in old_lines.lines() {
                let caps = re
                    .captures(line)
                    .ok_or(ChecksumError::IllFormattedChecksum(sums_path.clone()))?;
                let (_, [_, filename]) = caps.extract();

                if filename != file_rel_path {
                    new_lines.push(line.to_string());
                }
            }
            new_lines.push(checksum);
            new_lines
        }
    };

    fs::write(&sums_path, lines.join("\n") + "\n")
        .map_err(ChecksumError::write_checksum(&sums_path))?;

    Ok(())
}

pub fn verify_file_checksum(
    dir: &Utf8PathBuf,
    file_rel_path: &Utf8PathBuf,
) -> Result<(), ChecksumError> {
    let re = regex::Regex::new(r"^([0-9a-fA-F]{64})  (.+)$").unwrap();

    let file_source = dir.join(file_rel_path);
    let sha_source = file_source.add_extension("sha256");

    if !sha_source.exists() {
        return Err(ChecksumError::MissingChecksum(sha_source));
    }

    let sha_content =
        fs::read_to_string(&sha_source).map_err(ChecksumError::read_checksum(&sha_source))?;
    let sha_content = sha_content.trim();

    let caps = re
        .captures(sha_content)
        .ok_or(ChecksumError::IllFormattedChecksum(sha_source.clone()))?;
    let (_, [digest, _]) = caps.extract();

    let file_content = fs::read(&file_source).map_err(ChecksumError::read_source(&file_source))?;

    let actual_digest = sha256::digest(file_content);

    if actual_digest != digest {
        return Err(ChecksumError::ChecksumMismatch(file_source, sha_source));
    }

    Ok(())
}
