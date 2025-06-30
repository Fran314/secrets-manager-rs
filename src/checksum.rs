use std::fs;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChecksumError {
    #[error("failed to get relative path of '{0}' with respect to '{1}'\n{2}")]
    GetRelativePath(String, String, std::path::StripPrefixError),

    #[error("failed to read file at path '{0}'\n{1}")]
    ReadSource(String, std::io::Error),

    #[error("missing checksum file at path '{0}'")]
    MissingChecksum(String),

    #[error("failed to read checksum file at path '{0}'\n{1}")]
    ReadChecksum(String, std::io::Error),

    #[error("ill-formatted checksum file at path '{0}'")]
    IllFormattedChecksum(String),

    #[error("failed to write to checksum file at path '{0}'\n{1}")]
    WriteChecksum(String, std::io::Error),

    #[error("checksum at path '{1}' does not match for file '{0}'. Possible integrity issue")]
    ChecksumMismatch(String, String),
}
impl ChecksumError {
    fn get_relative_path(
        file: &std::path::Path,
        dir: &std::path::Path,
    ) -> impl Fn(std::path::StripPrefixError) -> Self {
        |e| {
            Self::GetRelativePath(
                file.to_string_lossy().to_string(),
                dir.to_string_lossy().to_string(),
                e,
            )
        }
    }

    fn read_source(path: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadSource(path.to_string_lossy().to_string(), e)
    }

    fn missing_checksum(path: &std::path::Path) -> Self {
        Self::MissingChecksum(path.to_string_lossy().to_string())
    }

    fn read_checksum(path: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadChecksum(path.to_string_lossy().to_string(), e)
    }

    fn ill_formatted_checksum(path: &std::path::Path) -> Self {
        Self::IllFormattedChecksum(path.to_string_lossy().to_string())
    }

    fn write_checksum(path: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::WriteChecksum(path.to_string_lossy().to_string(), e)
    }

    fn checksum_mismatch(file: &str, sums_path: &std::path::Path) -> Self {
        Self::ChecksumMismatch(file.to_string(), sums_path.to_string_lossy().to_string())
    }
}

// pub fn generate_checksum<P>(dir: P, filenames: &Vec<String>) -> Result<(), ChecksumError>
// where
//     P: AsRef<std::path::Path>,
// {
//     let sums_path = dir.as_ref().join("sha256sums.txt");
//     let re = regex::Regex::new(r"^([0-9a-fA-F]{64})  (.+)$").unwrap();
//
//     let mut digests = Vec::new();
//     for filename in filenames {
//         let path = dir.as_ref().join(filename);
//         let digest = sha256::digest(fs::read(&path).map_err(ChecksumError::read_source(&path))?);
//         digests.push(format!("{digest}  {filename}"));
//     }
//
//     let lines = match sums_path.exists() {
//         false => digests,
//         true => {
//             let old_lines =
//                 fs::read_to_string(&sums_path).map_err(ChecksumError::read_checksum(&sums_path))?;
//             let mut new_lines = Vec::new();
//             for line in old_lines.lines() {
//                 let caps = re
//                     .captures(line)
//                     .ok_or(ChecksumError::ill_formatted_checksum(&sums_path))?;
//                 let (_, [_, filename]) = caps.extract();
//
//                 if !filenames.contains(&filename.to_string()) {
//                     new_lines.push(line.to_string());
//                 }
//             }
//             new_lines.append(&mut digests);
//             new_lines
//         }
//     };
//
//     fs::write(&sums_path, lines.join("\n") + "\n")
//         .map_err(ChecksumError::write_checksum(&sums_path))?;
//
//     Ok(())
// }

pub fn verify_checksums<P>(dir: P) -> Result<(), ChecksumError>
where
    P: AsRef<std::path::Path>,
{
    let sums_path = dir.as_ref().join("sha256sums.txt");
    let re = regex::Regex::new(r"^([0-9a-fA-F]{64})  (.+)$").unwrap();

    if !sums_path.exists() {
        return Err(ChecksumError::missing_checksum(&sums_path));
    }
    let sums_content =
        fs::read_to_string(&sums_path).map_err(ChecksumError::read_checksum(&sums_path))?;

    let mut entries = Vec::new();
    for line in sums_content.lines() {
        let caps = re
            .captures(line)
            .ok_or(ChecksumError::ill_formatted_checksum(&sums_path))?;
        let (_, [digest, filename]) = caps.extract();
        entries.push((digest, filename));
    }

    for (digest, filename) in entries {
        let file_path = dir.as_ref().join(filename);
        let file_content = fs::read(&file_path).map_err(ChecksumError::read_source(&file_path))?;
        let actual_digest = sha256::digest(file_content);

        if actual_digest != digest {
            return Err(ChecksumError::checksum_mismatch(filename, &sums_path));
        }
    }

    Ok(())
}

pub fn append_checksum<P, Q>(dir: P, file_source: Q) -> Result<(), ChecksumError>
where
    P: AsRef<std::path::Path>,
    Q: AsRef<std::path::Path>,
{
    let re = regex::Regex::new(r"^([0-9a-fA-F]{64})  (.+)$").unwrap();

    let dir = dir.as_ref();
    let sums_path = dir.join("sha256sums.txt");
    let file_source = file_source.as_ref();
    let relative_file_path = file_source
        .strip_prefix(dir)
        .map_err(ChecksumError::get_relative_path(file_source, dir))?
        .to_string_lossy()
        .to_string();

    let checksum = {
        let digest = sha256::digest(
            fs::read(&file_source).map_err(ChecksumError::read_source(&file_source))?,
        );
        format!("{digest}  {relative_file_path}")
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
                    .ok_or(ChecksumError::ill_formatted_checksum(&sums_path))?;
                let (_, [_, filename]) = caps.extract();

                if filename != relative_file_path {
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

pub fn verify_file_checksum<P>(dir: P, filename: &str) -> Result<(), ChecksumError>
where
    P: AsRef<std::path::Path>,
{
    let re = regex::Regex::new(r"^([0-9a-fA-F]{64})  (.+)$").unwrap();

    let dir = dir.as_ref();
    let file_source = dir.join(filename);
    let sha_source = dir.join(filename.to_string() + ".sha256");

    if !sha_source.exists() {
        return Err(ChecksumError::missing_checksum(&sha_source));
    }

    let sha_content =
        fs::read_to_string(&sha_source).map_err(ChecksumError::read_checksum(&sha_source))?;
    let sha_content = sha_content.trim();

    let caps = re
        .captures(&sha_content)
        .ok_or(ChecksumError::ill_formatted_checksum(&sha_source))?;
    let (_, [digest, filename]) = caps.extract();

    let file_content = fs::read(&file_source).map_err(ChecksumError::read_source(&file_source))?;

    let actual_digest = sha256::digest(file_content);

    if actual_digest != digest {
        return Err(ChecksumError::checksum_mismatch(filename, &sha_source));
    }

    Ok(())
}
