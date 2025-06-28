use std::os::unix::fs::MetadataExt;
use std::{fs, io::Write};

use thiserror::Error;

use crate::crypto;
use crate::{
    checksum,
    config::{self, Config, ExportInfo},
};

enum ExportFileSuccess {
    Write,
    Skip,
}

#[derive(Error, Debug)]
pub enum ExportFileError {
    #[error("failed to read source file at '{0}'\n{1}")]
    ReadFail(String, std::io::Error),

    #[error("failed to read source file's metadata at '{0}'\n{1}")]
    ReadMetadataFail(String, std::io::Error),

    #[error("failed to encrypt contents of source file at '{0}'\n{1}")]
    EncryptionFail(String, age::EncryptError),

    #[error(
        "failed to read file at endpoint ('{0}', which already exists) while attempting to check that its content matches the intended content\n{1}"
    )]
    ReadExistingFail(String, std::io::Error),

    #[error(
        "failed to decrypt file at endpoint ('{0}', which already exists) while attempting to check that its content matches the intended content. It is possible that the passphrase used for the existing file does not match the current passphrase, hence the content of the existing file cannot be decrypted and verified\n{1}"
    )]
    DecryptExistingFail(String, age::DecryptError),

    #[error(
        "file at endpoint ('{1}') already exists and correctly decrypts but does not contain the content of the source file ('{0}'). This program won't override existing file at endpoint"
    )]
    CompareExistingFail(String, String),

    #[error("failed to write to file at endpoint ('{0}')\n{1}")]
    WriteFail(String, std::io::Error),

    #[error("failed to read file at endpoint ('{0}') to verify correct decryption\n{1}")]
    ReadToVerifyFail(String, std::io::Error),

    #[error("failed to decrypt content of exported file to verify correct decryption\n{0}")]
    DecryptToVerifyFail(age::DecryptError),

    #[error(
        "failed to verify correctness of exported file. Decryption of exported file does not match source file"
    )]
    VerifyFail,

    #[error("failed to assign ownership to file at endpoint ('{0}')\n{1}")]
    ChownFail(String, std::io::Error),

    #[error("failed to assign permissions to file at endpoint ('{0}')\n{1}")]
    ChmodFail(String, std::io::Error),
}
impl ExportFileError {
    fn read_fail(source: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadFail(source.to_string_lossy().to_string(), e)
    }

    fn read_metadata_fail(source: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadMetadataFail(source.to_string_lossy().to_string(), e)
    }

    fn encryption_fail(source: &std::path::Path) -> impl Fn(age::EncryptError) -> Self {
        |e| Self::EncryptionFail(source.to_string_lossy().to_string(), e)
    }

    fn read_existing_fail(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadExistingFail(endpoint.to_string_lossy().to_string(), e)
    }

    fn decrypt_existing_fail(endpoint: &std::path::Path) -> impl Fn(age::DecryptError) -> Self {
        |e| Self::DecryptExistingFail(endpoint.to_string_lossy().to_string(), e)
    }

    fn compare_existing(source: &std::path::Path, endpoint: &std::path::Path) -> Self {
        Self::CompareExistingFail(
            source.to_string_lossy().to_string(),
            endpoint.to_string_lossy().to_string(),
        )
    }

    fn write_fail(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::WriteFail(endpoint.to_string_lossy().to_string(), e)
    }

    fn read_to_verify_fail(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadToVerifyFail(endpoint.to_string_lossy().to_string(), e)
    }

    fn chown_fail(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ChownFail(endpoint.to_string_lossy().to_string(), e)
    }

    fn chmod_fail(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ChmodFail(endpoint.to_string_lossy().to_string(), e)
    }
}

#[derive(Error, Debug)]
pub enum ExportSourceError {
    #[error("failed to create endpoint directory '{0}'\n{1}")]
    CreateEndpointFail(String, std::io::Error),

    #[error("failed to verify integrity of source '{0}'\n{1}")]
    VerifySourceFail(String, checksum::VerifyError),

    #[error("failed to export file '{0}'\n{1}")]
    ExportFileFail(String, ExportFileError),

    #[error("failed to generate checksum for exported files at path '{0}'\n{1}")]
    GenerateChecksumFail(String, checksum::GenerateError),

    #[error("failed to verify integrity of export '{0}'\n{1}")]
    VerifyExportFail(String, checksum::VerifyError),
}
impl ExportSourceError {
    fn create_endpoint_fail(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::CreateEndpointFail(endpoint.to_string_lossy().to_string(), e)
    }

    fn verify_source_fail(source: &std::path::Path) -> impl Fn(checksum::VerifyError) -> Self {
        |e| Self::VerifySourceFail(source.to_string_lossy().to_string(), e)
    }

    fn export_file_fail(file: String) -> impl FnOnce(ExportFileError) -> Self {
        |e| Self::ExportFileFail(file, e)
    }

    fn generate_checksum_fail(
        endpoint: &std::path::Path,
    ) -> impl Fn(checksum::GenerateError) -> Self {
        |e| Self::GenerateChecksumFail(endpoint.to_string_lossy().to_string(), e)
    }

    fn verify_export_fail(export: &std::path::Path) -> impl Fn(checksum::VerifyError) -> Self {
        |e| Self::VerifyExportFail(export.to_string_lossy().to_string(), e)
    }
}

#[derive(Error, Debug)]
pub enum ExportAdditionalError {
    #[error("failed to obtain executable path\n{0}")]
    GetExePathFail(std::io::Error),

    #[error("executable somehow has invalid file name")]
    InvalidExeFilename,

    #[error("failed to copy executable to export\n{0}")]
    CopyExeFail(std::io::Error),

    #[error("failed to export config file\n{0}")]
    SaveConfigFail(config::SaveConfigError),

    #[error("failed to generate checksum for exported additional files\n{0}")]
    GenerateChecksumFail(checksum::GenerateError),

    #[error("failed to verify integrity of exported additional files\n{0}")]
    VerifyExportFail(checksum::VerifyError),
}

#[derive(Error, Debug)]
pub enum ExportError {
    #[error(transparent)]
    ExportSourceFail(ExportSourceError),

    #[error(transparent)]
    ExportAdditionalFail(ExportAdditionalError),
}

fn format_path(path: &str, profile: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(&path.replace("$profile", profile))
}

fn export_file<P, Q>(
    source: P,
    endpoint: Q,
    passphrase: &str,
) -> Result<ExportFileSuccess, ExportFileError>
where
    P: AsRef<std::path::Path>,
    Q: AsRef<std::path::Path>,
{
    let source = source.as_ref();
    let endpoint = endpoint.as_ref();
    let content = fs::read(source).map_err(ExportFileError::read_fail(source))?;
    let (perm, uid, gid) = {
        let meta = fs::metadata(source).map_err(ExportFileError::read_metadata_fail(source))?;
        (meta.permissions(), meta.uid(), meta.gid())
    };

    let success_type = match endpoint.exists() {
        true => {
            let actual_content =
                fs::read(endpoint).map_err(ExportFileError::read_existing_fail(endpoint))?;

            let decrypted_content = crypto::decrypt(actual_content, passphrase)
                .map_err(ExportFileError::decrypt_existing_fail(endpoint))?;

            if content != decrypted_content {
                return Err(ExportFileError::compare_existing(source, endpoint));
            }

            ExportFileSuccess::Skip
        }
        false => {
            let encrypted_content = crypto::encrypt(&content, passphrase)
                .map_err(ExportFileError::encryption_fail(source))?;

            fs::write(endpoint, encrypted_content)
                .map_err(ExportFileError::write_fail(endpoint))?;

            let encrypted_content =
                fs::read(endpoint).map_err(ExportFileError::read_to_verify_fail(endpoint))?;
            let decrypted_content = crypto::decrypt(encrypted_content, passphrase)
                .map_err(ExportFileError::DecryptToVerifyFail)?;

            if decrypted_content != content {
                return Err(ExportFileError::VerifyFail);
            }

            ExportFileSuccess::Write
        }
    };

    std::os::unix::fs::chown(endpoint, Some(uid), Some(gid))
        .map_err(ExportFileError::chown_fail(endpoint))?;
    std::fs::set_permissions(endpoint, perm).map_err(ExportFileError::chmod_fail(endpoint))?;

    Ok(success_type)
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
    let endpoint = endpoint_root
        .as_ref()
        .join(format_path(&exports.endpoint, profile));
    let source = format_path(&exports.source, profile);

    println!("Exporting files from '{}'...", &exports.source);

    fs::create_dir_all(&endpoint).map_err(ExportSourceError::create_endpoint_fail(&endpoint))?;

    print!("verifying source integrity... ");
    std::io::stdout().flush().unwrap();
    checksum::verify_checksum(&source)
        .map_err(ExportSourceError::verify_source_fail(&source))
        .inspect_err(|_| println!("error"))?;
    println!("ok");

    let files = {
        let mut files = exports.files.clone();
        files.push("sha256sums.txt".to_string());
        files
    };
    for file in &files {
        let file_source = source.join(file);
        let file_endpoint = endpoint.join(file.to_string() + ".age");

        print!("exporting '{file}'... ");
        std::io::stdout().flush().unwrap();
        let file_success = export_file(file_source, file_endpoint, passphrase)
            .map_err(ExportSourceError::export_file_fail(file.clone()))
            .inspect_err(|_| println!("error"))?;

        match file_success {
            ExportFileSuccess::Write => {
                println!("ok");
            }
            ExportFileSuccess::Skip => {
                println!("already exported");
            }
        }
    }

    print!("generating export checksum... ");
    std::io::stdout().flush().unwrap();
    checksum::generate_checksum(
        &endpoint,
        &files.iter().map(|f| f.to_string() + ".age").collect(),
    )
    .map_err(ExportSourceError::generate_checksum_fail(&endpoint))
    .inspect_err(|_| println!("error"))?;
    println!("ok");

    print!("verifying export integrity... ");
    std::io::stdout().flush().unwrap();
    checksum::verify_checksum(&endpoint)
        .map_err(ExportSourceError::verify_export_fail(&endpoint))
        .inspect_err(|_| println!("error"))?;
    println!("ok");

    println!();

    Ok(())
}

// fn export_executable<P>(endpoint_root: P) -> Result<(), ExportAdditionalError>
// where
//     P: AsRef<std::path::Path>,
// {
//     println!("Exporting executable... ");
//     let exe_path = std::env::current_exe()
//         .map_err(ExportAdditionalError::GetExePathFail)
//         .inspect_err(|_| println!("error"))?;
//     let exe_name = exe_path
//         .file_name()
//         .ok_or(ExportAdditionalError::InvalidExeFilename)
//         .inspect_err(|_| println!("error"))?;
//
//     let endpoint = endpoint_root.as_ref().join(exe_name);
//     fs::copy(exe_path, endpoint)
//         .map_err(ExportAdditionalError::CopyExeFail)
//         .inspect_err(|_| println!("error"))?;
//
//     println!("ok");
//
//     println!();
//
//     Ok(())
// }
//
// fn export_config<P>(endpoint_root: P, config: &Config) -> Result<(), config::SaveConfigError>
// where
//     P: AsRef<std::path::Path>,
// {
//     println!("Exporting config... ");
//     let endpoint = endpoint_root.as_ref().join("secrets-manager.toml");
//     config::save_config(endpoint, config).inspect_err(|_| println!("error"))?;
//
//     println!("ok");
//
//     println!();
//
//     Ok(())
// }

fn export_additional<P>(endpoint_root: P, config: &Config) -> Result<(), ExportAdditionalError>
where
    P: AsRef<std::path::Path>,
{
    let endpoint_root = endpoint_root.as_ref();
    println!("Exporting additional files... ");

    print!("exporting executable... ");
    std::io::stdout().flush().unwrap();
    let exe_path = std::env::current_exe()
        .map_err(ExportAdditionalError::GetExePathFail)
        .inspect_err(|_| println!("error"))?;
    let exe_name = exe_path
        .file_name()
        .ok_or(ExportAdditionalError::InvalidExeFilename)
        .inspect_err(|_| println!("error"))?
        .to_string_lossy()
        .to_string();
    let exe_endpoint = endpoint_root.join(&exe_name);
    fs::copy(exe_path, exe_endpoint)
        .map_err(ExportAdditionalError::CopyExeFail)
        .inspect_err(|_| println!("error"))?;
    println!("ok");

    print!("exporting config... ");
    std::io::stdout().flush().unwrap();
    let config_endpoint = endpoint_root.join("secrets-manager.toml");
    config::save_config(config_endpoint, config)
        .map_err(ExportAdditionalError::SaveConfigFail)
        .inspect_err(|_| println!("error"))?;
    println!("ok");

    print!("generating export checksum... ");
    std::io::stdout().flush().unwrap();
    checksum::generate_checksum(
        endpoint_root,
        &vec![exe_name, "secrets-manager.toml".to_string()],
    )
    .map_err(ExportAdditionalError::GenerateChecksumFail)
    .inspect_err(|_| println!("error"))?;
    println!("ok");

    print!("verifying export integrity... ");
    std::io::stdout().flush().unwrap();
    checksum::verify_checksum(endpoint_root)
        .map_err(ExportAdditionalError::VerifyExportFail)
        .inspect_err(|_| println!("error"))?;
    println!("ok");

    println!();

    Ok(())
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
                .map_err(ExportError::ExportSourceFail)?;
        }
    }
    if let Some(exports) = config.exports.get(profile) {
        for export_info in exports {
            export_source(profile, endpoint_root, export_info, passphrase)
                .map_err(ExportError::ExportSourceFail)?;
        }
    }

    export_additional(endpoint_root, config).map_err(ExportError::ExportAdditionalFail)?;

    println!("Export completed succesfully!");

    Ok(())
}
