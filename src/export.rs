use std::{fs, io::Write};

use camino::Utf8PathBuf;
use thiserror::Error;

use crate::crypto;
use crate::utf8path_ext::ExtraUtf8Path;
use crate::{
    checksum,
    config::{self, Config},
};

#[derive(Error, Debug)]
pub enum ExportFileError {
    #[error("failed to verify integrity of source file at '{0}'\n{1}")]
    VerifySource(Utf8PathBuf, checksum::ChecksumError),

    #[error("failed to read file at '{0}'\n{1}")]
    Read(Utf8PathBuf, std::io::Error),

    #[error("failed to encrypt contents of source file at '{0}'\n{1}")]
    Encryption(Utf8PathBuf, age::EncryptError),

    #[error("failed to write to file at target ('{0}')\n{1}")]
    WriteToTarget(Utf8PathBuf, std::io::Error),

    #[error("failed to create target directory '{0}'\n{1}")]
    CreateTargetParent(Utf8PathBuf, std::io::Error),

    #[error("failed to read file at target ('{0}') to verify correct decryption\n{1}")]
    ReadTarget(Utf8PathBuf, std::io::Error),

    #[error("failed to decrypt content of exported file to verify correct decryption\n{0}")]
    DecryptEndpoint(age::DecryptError),

    #[error(
        "failed to verify correctness of exported file. Decryption of exported file does not match source file"
    )]
    VerifyExport,

    #[error("failed to append checksum of exported file ('{0}') to export's sha256sums.txt\n{1}")]
    AppendChecksum(Utf8PathBuf, checksum::ChecksumError),
}
impl ExportFileError {
    fn verify_source(source: &Utf8PathBuf) -> impl Fn(checksum::ChecksumError) -> Self {
        |e| Self::VerifySource(source.clone(), e)
    }
    fn read(source: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::Read(source.clone(), e)
    }

    fn encryption(source: &Utf8PathBuf) -> impl Fn(age::EncryptError) -> Self {
        |e| Self::Encryption(source.clone(), e)
    }

    fn write_to_target(target: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::WriteToTarget(target.clone(), e)
    }

    fn create_target_parent(target: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::CreateTargetParent(target.clone(), e)
    }

    fn read_target(target: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadTarget(target.clone(), e)
    }

    fn append_checksum(target: &Utf8PathBuf) -> impl Fn(checksum::ChecksumError) -> Self {
        |e| Self::AppendChecksum(target.clone(), e)
    }
}

fn export_file(
    file_rel_path: &Utf8PathBuf,
    source: &Utf8PathBuf,
    target: &Utf8PathBuf,
    passphrase: &str,
) -> Result<(), ExportFileError> {
    let file_source = source.join(file_rel_path);
    let file_target = target.join(file_rel_path).add_extension("age");
    let file_target_rel_path = file_rel_path.add_extension("age");

    let sha_source = source.join(file_rel_path).add_extension("sha256");
    let sha_target = target.join(file_rel_path).add_extension("sha256");
    let sha_target_rel_path = file_rel_path.add_extension("sha256");

    // TODO add "sha256 doesn't exist, do you want to create it?"
    checksum::verify_file_checksum(source, file_rel_path)
        .map_err(ExportFileError::verify_source(&file_source))?;

    let file_content = fs::read(&file_source).map_err(ExportFileError::read(&file_source))?;
    let encrypted_content = crypto::encrypt(&file_content, passphrase)
        .map_err(ExportFileError::encryption(&file_source))?;

    if let Some(parent) = file_target.parent() {
        let parent = parent.to_path_buf();
        if !parent.exists() {
            fs::create_dir_all(&parent).map_err(ExportFileError::create_target_parent(&parent))?;
        }
    }
    fs::write(&file_target, encrypted_content)
        .map_err(ExportFileError::write_to_target(&file_target))?;

    let encrypted_content =
        fs::read(&file_target).map_err(ExportFileError::read_target(&file_target))?;
    let decrypted_content =
        crypto::decrypt(encrypted_content, passphrase).map_err(ExportFileError::DecryptEndpoint)?;

    if decrypted_content != file_content {
        return Err(ExportFileError::VerifyExport);
    }

    let sha_content = fs::read(&sha_source).map_err(ExportFileError::read(&sha_source))?;
    fs::write(&sha_target, sha_content).map_err(ExportFileError::write_to_target(&sha_target))?;

    checksum::append_checksum(target, &file_target_rel_path)
        .map_err(ExportFileError::append_checksum(&file_target))?;
    checksum::append_checksum(target, &sha_target_rel_path)
        .map_err(ExportFileError::append_checksum(&sha_target))?;

    Ok(())
}

#[derive(Error, Debug)]
pub enum ExportAdditionalError {
    #[error("failed to obtain executable path\n{0}")]
    GetExePath(std::io::Error),

    #[error("executable path is not utf8. Only utf8 paths are supported")]
    InvalidExePath,

    #[error("executable has somehow invalid filename")]
    InvalidExeFilename,

    #[error("failed to copy executable to export\n{0}")]
    CopyExe(std::io::Error),

    #[error("failed to export config file\n{0}")]
    SaveConfig(config::SaveConfigError),

    #[error("failed to generate checksum for exported file '{0}'\n{1}")]
    GenerateChecksum(Utf8PathBuf, checksum::ChecksumError),
}
impl ExportAdditionalError {
    fn generate_checksum(file: &Utf8PathBuf) -> impl Fn(checksum::ChecksumError) -> Self {
        |e| Self::GenerateChecksum(file.clone(), e)
    }
}
fn export_additional(target: &Utf8PathBuf, config: &Config) -> Result<(), ExportAdditionalError> {
    println!("Exporting additional files... ");

    print!("exporting executable... ");
    std::io::stdout().flush().unwrap();

    let exe_path = std::env::current_exe()
        .map_err(ExportAdditionalError::GetExePath)
        .inspect_err(|_| println!("error"))?;
    let exe_path = Utf8PathBuf::from_path_buf(exe_path)
        .map_err(|_| ExportAdditionalError::InvalidExePath)
        .inspect_err(|_| println!("error"))?;

    let exe_name = exe_path
        .file_name()
        .ok_or(ExportAdditionalError::InvalidExeFilename)
        .inspect_err(|_| println!("error"))?;
    let exe_name = Utf8PathBuf::from(exe_name);

    let exe_target = target.join(&exe_name);
    fs::copy(&exe_path, &exe_target)
        .map_err(ExportAdditionalError::CopyExe)
        .inspect_err(|_| println!("error"))?;
    checksum::append_checksum(target, &exe_name)
        .map_err(ExportAdditionalError::generate_checksum(&exe_target))?;
    println!("ok");

    print!("exporting config... ");
    std::io::stdout().flush().unwrap();
    let config_name = Utf8PathBuf::from("secrets-manager.toml");
    let config_target = target.join(&config_name);
    config::save_config(&config_target, config)
        .map_err(ExportAdditionalError::SaveConfig)
        .inspect_err(|_| println!("error"))?;
    checksum::append_checksum(target, &config_name)
        .map_err(ExportAdditionalError::generate_checksum(&config_target))?;
    println!("ok");

    println!();

    Ok(())
}

#[derive(Error, Debug)]
pub enum ExportError {
    #[error("source path '{0}' does not exist")]
    MissingSourcePath(Utf8PathBuf),
    #[error("source path '{0}' is not a directory")]
    SourceNotDir(Utf8PathBuf),

    #[error("target path '{0}' does not exist")]
    MissingTargetPath(Utf8PathBuf),
    #[error("target path '{0}' is not a directory")]
    TargetNotDir(Utf8PathBuf),

    #[error("failed to export file '{0}'\n{1}")]
    ExportFile(Utf8PathBuf, ExportFileError),

    #[error(transparent)]
    ExportAdditional(ExportAdditionalError),

    #[error(transparent)]
    VerifyExport(checksum::ChecksumError),
}
impl ExportError {
    fn export_file(file: &Utf8PathBuf) -> impl FnOnce(ExportFileError) -> Self {
        |e| Self::ExportFile(file.clone(), e)
    }
}
pub fn export(
    profile: String,
    source: String,
    target: String,
    config: Config,
    passphrase: String,
) -> Result<(), ExportError> {
    let source = {
        let path = Utf8PathBuf::from(&source);
        if !path.exists() {
            return Err(ExportError::MissingSourcePath(path));
        } else if !path.is_dir() {
            return Err(ExportError::SourceNotDir(path));
        }
        path
    };

    let target = {
        let path = Utf8PathBuf::from(&target);
        if !path.exists() {
            return Err(ExportError::MissingTargetPath(path));
        } else if !path.is_dir() {
            return Err(ExportError::TargetNotDir(path));
        }
        path
    };

    // TODO maybe return error if there is nothing for this profile
    let secrets = config.secrets.get(&profile).map_or(vec![], Vec::clone);

    println!("Exporting secrets... ");
    for file_rel_path in secrets {
        print!("exporting '{file_rel_path}'... ");
        std::io::stdout().flush().unwrap();

        export_file(&file_rel_path, &source, &target, &passphrase)
            .map_err(ExportError::export_file(&file_rel_path))
            .inspect_err(|_| println!("error"))?;
        println!("ok");
    }
    println!();

    export_additional(&target, &config).map_err(ExportError::ExportAdditional)?;

    print!("Verifying export integrity... ");
    std::io::stdout().flush().unwrap();
    checksum::verify_checksums(&target)
        .map_err(ExportError::VerifyExport)
        .inspect_err(|_| println!("error"))?;
    println!("ok");
    println!();

    println!("Export completed succesfully!");

    Ok(())
}
