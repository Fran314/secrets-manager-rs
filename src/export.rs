use std::os::unix::fs::MetadataExt;
use std::{fs, io::Write};

use thiserror::Error;

use crate::crypto;
use crate::{
    checksum,
    config::{self, Config, ExportInfo},
};

fn format_path(path: &str, profile: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(&path.replace("$profile", profile))
}

#[derive(Error, Debug)]
pub enum ExportFileError {
    #[error("failed to verify integrity of source file at '{0}'\n{1}")]
    VerifySource(String, checksum::ChecksumError),

    #[error("failed to read file at '{0}'\n{1}")]
    Read(String, std::io::Error),

    #[error("failed to read file's metadata at '{0}'\n{1}")]
    ReadMetadata(String, std::io::Error),

    #[error("failed to encrypt contents of source file at '{0}'\n{1}")]
    Encryption(String, age::EncryptError),

    #[error("failed to write to file at endpoint ('{0}')\n{1}")]
    WriteToEndpoint(String, std::io::Error),

    #[error("failed to read file at endpoint ('{0}') to verify correct decryption\n{1}")]
    ReadEndpoint(String, std::io::Error),

    #[error("failed to decrypt content of exported file to verify correct decryption\n{0}")]
    DecryptEndpoint(age::DecryptError),

    #[error(
        "failed to verify correctness of exported file. Decryption of exported file does not match source file"
    )]
    VerifyExport,

    #[error("failed to assign ownership to file at endpoint ('{0}')\n{1}")]
    AssignOwnership(String, std::io::Error),

    #[error("failed to assign permissions to file at endpoint ('{0}')\n{1}")]
    AssignPermissions(String, std::io::Error),

    #[error("failed to append exported file ('{0}') checksum to export's sha256sums.txt\n{1}")]
    AppendChecksum(String, checksum::ChecksumError),
}
impl ExportFileError {
    fn verify_source(source: &std::path::Path) -> impl Fn(checksum::ChecksumError) -> Self {
        |e| Self::VerifySource(source.to_string_lossy().to_string(), e)
    }
    fn read(source: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::Read(source.to_string_lossy().to_string(), e)
    }

    fn read_metadata(source: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadMetadata(source.to_string_lossy().to_string(), e)
    }

    fn encryption(source: &std::path::Path) -> impl Fn(age::EncryptError) -> Self {
        |e| Self::Encryption(source.to_string_lossy().to_string(), e)
    }

    fn write_to_endpoint(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::WriteToEndpoint(endpoint.to_string_lossy().to_string(), e)
    }

    fn read_endpoint(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadEndpoint(endpoint.to_string_lossy().to_string(), e)
    }

    fn assign_ownership(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::AssignOwnership(endpoint.to_string_lossy().to_string(), e)
    }

    fn assign_permissions(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::AssignPermissions(endpoint.to_string_lossy().to_string(), e)
    }

    fn append_checksum(endpoint: &std::path::Path) -> impl Fn(checksum::ChecksumError) -> Self {
        |e| Self::AppendChecksum(endpoint.to_string_lossy().to_string(), e)
    }
}

fn export_file<P, Q, R>(
    filename: &str,
    source: P,
    endpoint: Q,
    endpoint_root: R,
    passphrase: &str,
) -> Result<(), ExportFileError>
where
    P: AsRef<std::path::Path>,
    Q: AsRef<std::path::Path>,
    R: AsRef<std::path::Path>,
{
    let source = source.as_ref();
    let endpoint = endpoint.as_ref();
    let endpoint_root = endpoint_root.as_ref();

    let file_source = source.join(filename);
    let file_endpoint = endpoint.join(filename.to_string() + ".age");

    let sha_source = source.join(filename.to_string() + ".sha256");
    let sha_endpoint = endpoint.join(filename.to_string() + ".sha256");

    checksum::verify_file_checksum(source, filename)
        .map_err(ExportFileError::verify_source(&file_source))?;

    // --- Export file --- //
    let file_content = fs::read(&file_source).map_err(ExportFileError::read(&file_source))?;
    let (file_perm, file_uid, file_gid) = {
        let meta =
            fs::metadata(&file_source).map_err(ExportFileError::read_metadata(&file_source))?;
        (meta.permissions(), meta.uid(), meta.gid())
    };

    let encrypted_content = crypto::encrypt(&file_content, passphrase)
        .map_err(ExportFileError::encryption(&file_source))?;

    fs::write(&file_endpoint, encrypted_content)
        .map_err(ExportFileError::write_to_endpoint(&file_endpoint))?;

    let encrypted_content =
        fs::read(&file_endpoint).map_err(ExportFileError::read_endpoint(&file_endpoint))?;
    let decrypted_content =
        crypto::decrypt(encrypted_content, passphrase).map_err(ExportFileError::DecryptEndpoint)?;

    if decrypted_content != file_content {
        return Err(ExportFileError::VerifyExport);
    }

    std::os::unix::fs::chown(&file_endpoint, Some(file_uid), Some(file_gid))
        .map_err(ExportFileError::assign_ownership(&file_endpoint))?;
    std::fs::set_permissions(&file_endpoint, file_perm)
        .map_err(ExportFileError::assign_permissions(&file_endpoint))?;
    // --- --- //

    // --- Export checksum --- //
    let sha_content = fs::read(&sha_source).map_err(ExportFileError::read(&sha_source))?;
    let (sha_perm, sha_uid, sha_gid) = {
        let meta =
            fs::metadata(&sha_source).map_err(ExportFileError::read_metadata(&sha_source))?;
        (meta.permissions(), meta.uid(), meta.gid())
    };
    fs::write(&sha_endpoint, sha_content)
        .map_err(ExportFileError::write_to_endpoint(&sha_endpoint))?;
    std::os::unix::fs::chown(&sha_endpoint, Some(sha_uid), Some(sha_gid))
        .map_err(ExportFileError::assign_ownership(&sha_endpoint))?;
    std::fs::set_permissions(&sha_endpoint, sha_perm)
        .map_err(ExportFileError::assign_permissions(&sha_endpoint))?;
    // --- --- //

    // --- Append checksum --- //
    checksum::append_checksum(endpoint_root, &file_endpoint)
        .map_err(ExportFileError::append_checksum(&file_endpoint))?;
    checksum::append_checksum(endpoint_root, &sha_endpoint)
        .map_err(ExportFileError::append_checksum(&sha_endpoint))?;
    // --- --- //

    Ok(())
}

#[derive(Error, Debug)]
pub enum ExportSourceError {
    #[error("failed to create endpoint directory '{0}'\n{1}")]
    CreateEndpoint(String, std::io::Error),

    #[error("failed to export file '{0}'\n{1}")]
    ExportFile(String, ExportFileError),
}
impl ExportSourceError {
    fn create_endpoint(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::CreateEndpoint(endpoint.to_string_lossy().to_string(), e)
    }

    fn export_file(file: String) -> impl FnOnce(ExportFileError) -> Self {
        |e| Self::ExportFile(file, e)
    }
}
fn export_source<P>(
    profile: &str,
    endpoint_root: P,
    exports: &ExportInfo,
    passphrase: &str,
) -> Result<(), ExportSourceError>
where
    P: AsRef<std::path::Path>,
{
    let endpoint_root = endpoint_root.as_ref();
    let endpoint = endpoint_root.join(format_path(&exports.endpoint, profile));
    let source = format_path(&exports.source, profile);

    println!("Exporting files from '{}'...", &exports.source);

    fs::create_dir_all(&endpoint).map_err(ExportSourceError::create_endpoint(&endpoint))?;

    for filename in &exports.files {
        print!("exporting '{filename}'... ");
        std::io::stdout().flush().unwrap();
        export_file(filename, &source, &endpoint, &endpoint_root, passphrase)
            .map_err(ExportSourceError::export_file(filename.clone()))
            .inspect_err(|_| println!("error"))?;
        println!("ok");
    }

    println!();

    Ok(())
}

#[derive(Error, Debug)]
pub enum ExportAdditionalError {
    #[error("failed to obtain executable path\n{0}")]
    GetExePath(std::io::Error),

    #[error("executable somehow has invalid file name")]
    InvalidExeFilename,

    #[error("failed to copy executable to export\n{0}")]
    CopyExe(std::io::Error),

    #[error("failed to export config file\n{0}")]
    SaveConfig(config::SaveConfigError),

    #[error("failed to generate checksum for exported file '{0}'\n{1}")]
    GenerateChecksum(String, checksum::ChecksumError),
}
impl ExportAdditionalError {
    fn generate_checksum(file: &std::path::Path) -> impl Fn(checksum::ChecksumError) -> Self {
        |e| Self::GenerateChecksum(file.to_string_lossy().to_string(), e)
    }
}
fn export_additional<P>(endpoint_root: P, config: &Config) -> Result<(), ExportAdditionalError>
where
    P: AsRef<std::path::Path>,
{
    let endpoint_root = endpoint_root.as_ref();
    println!("Exporting additional files... ");

    print!("exporting executable... ");
    std::io::stdout().flush().unwrap();
    let exe_path = std::env::current_exe()
        .map_err(ExportAdditionalError::GetExePath)
        .inspect_err(|_| println!("error"))?;
    let exe_name = exe_path
        .file_name()
        .ok_or(ExportAdditionalError::InvalidExeFilename)
        .inspect_err(|_| println!("error"))?
        .to_string_lossy()
        .to_string();
    let exe_endpoint = endpoint_root.join(&exe_name);
    fs::copy(&exe_path, &exe_endpoint)
        .map_err(ExportAdditionalError::CopyExe)
        .inspect_err(|_| println!("error"))?;
    checksum::append_checksum(endpoint_root, &exe_endpoint)
        .map_err(ExportAdditionalError::generate_checksum(&exe_endpoint))?;
    println!("ok");

    print!("exporting config... ");
    std::io::stdout().flush().unwrap();
    let config_endpoint = endpoint_root.join("secrets-manager.toml");
    config::save_config(&config_endpoint, config)
        .map_err(ExportAdditionalError::SaveConfig)
        .inspect_err(|_| println!("error"))?;
    checksum::append_checksum(endpoint_root, &config_endpoint)
        .map_err(ExportAdditionalError::generate_checksum(&config_endpoint))?;
    println!("ok");

    println!();

    Ok(())
}

#[derive(Error, Debug)]
pub enum ExportError {
    #[error(transparent)]
    ExportSource(ExportSourceError),

    #[error(transparent)]
    ExportAdditional(ExportAdditionalError),

    #[error(transparent)]
    VerifyExport(checksum::ChecksumError),
}
pub fn export(
    profile: &str,
    endpoint: &str,
    config: &Config,
    passphrase: &str,
) -> Result<(), ExportError> {
    let endpoint_root = std::path::Path::new(endpoint);

    if let Some(exports) = config.exports.get("shared") {
        for export_info in exports {
            export_source(profile, endpoint_root, export_info, passphrase)
                .map_err(ExportError::ExportSource)?;
        }
    }
    if let Some(exports) = config.exports.get(profile) {
        for export_info in exports {
            export_source(profile, endpoint_root, export_info, passphrase)
                .map_err(ExportError::ExportSource)?;
        }
    }

    export_additional(endpoint_root, config).map_err(ExportError::ExportAdditional)?;

    print!("Verifying export integrity... ");
    std::io::stdout().flush().unwrap();
    checksum::verify_checksums(endpoint_root)
        .map_err(ExportError::VerifyExport)
        .inspect_err(|_| println!("error"))?;
    println!("ok");
    println!();

    println!("Export completed succesfully!");

    Ok(())
}
