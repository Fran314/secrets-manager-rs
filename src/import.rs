use std::{
    fs::{self, Permissions},
    io::Write,
    os::unix::fs::PermissionsExt,
};

use thiserror::Error;

use camino::{Utf8Path, Utf8PathBuf};

use crate::{checksum, config::Config, crypto, safe_fs, utf8path_ext::ExtraUtf8Path};

#[derive(Error, Debug)]
pub enum ImportFileError {
    #[error("failed to read source file at '{0}'\n{1}")]
    ReadFail(Utf8PathBuf, std::io::Error),

    #[error("failed to decrypt contents of source file at '{0}'\n{1}")]
    DecryptionFail(Utf8PathBuf, age::DecryptError),

    #[error("file at '{0}' has ill-formed parent directory, cannot resolve")]
    IllFormedParent(Utf8PathBuf),

    #[error("failed to create directory at '{0}'\n{1}")]
    CreateParent(Utf8PathBuf, std::io::Error),

    #[error("failed to assign ownership to file at endpoint ('{0}')\n{1}")]
    ChownFail(Utf8PathBuf, std::io::Error),

    #[error("failed to assign permissions to file at endpoint ('{0}')\n{1}")]
    ChmodFail(Utf8PathBuf, std::io::Error),

    #[error("failed to safely write file at endpoint ('{0}')\n{1}")]
    SafeWrite(Utf8PathBuf, safe_fs::SafeFsError),

    #[error("failed to verify integrity of imported file at '{0}'\n{1}")]
    VerifyImport(Utf8PathBuf, checksum::ChecksumError),
}
impl ImportFileError {
    fn read_fail(source: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadFail(source.clone(), e)
    }

    fn decryption_fail(source: &Utf8PathBuf) -> impl Fn(age::DecryptError) -> Self {
        |e| Self::DecryptionFail(source.clone(), e)
    }

    fn create_parent(target: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::CreateParent(target.clone(), e)
    }

    fn chown_fail(target: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ChownFail(target.clone(), e)
    }

    fn chmod_fail(target: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ChmodFail(target.clone(), e)
    }

    fn safe_write(target: &Utf8PathBuf) -> impl Fn(safe_fs::SafeFsError) -> Self {
        |e| Self::SafeWrite(target.clone(), e)
    }

    fn verify_import(target: &Utf8PathBuf) -> impl Fn(checksum::ChecksumError) -> Self {
        |e| Self::VerifyImport(target.clone(), e)
    }
}
fn chmod_chown_file(path: &Utf8PathBuf) -> Result<(), ImportFileError> {
    std::os::unix::fs::chown(path, Some(0), Some(0)).map_err(ImportFileError::chown_fail(path))?;
    let permissions = Permissions::from_mode(0o600);
    std::fs::set_permissions(path, permissions).map_err(ImportFileError::chmod_fail(path))?;

    Ok(())
}
fn chmod_chown_dir(path: &Utf8PathBuf) -> Result<(), ImportFileError> {
    std::os::unix::fs::chown(path, Some(0), Some(0)).map_err(ImportFileError::chown_fail(path))?;
    let permissions = Permissions::from_mode(0o755);
    std::fs::set_permissions(path, permissions).map_err(ImportFileError::chmod_fail(path))?;

    Ok(())
}
fn import_file(
    file_rel_path: &Utf8PathBuf,
    source: &Utf8PathBuf,
    target: &Utf8PathBuf,
    passphrase: &str,
) -> Result<(), ImportFileError> {
    let file_source = source.join(file_rel_path).add_extension("age");
    let file_target = target.join(file_rel_path);

    let sha_source = source.join(file_rel_path).add_extension("sha256");
    let sha_target = target.join(file_rel_path).add_extension("sha256");

    let encrypted_content =
        fs::read(&file_source).map_err(ImportFileError::read_fail(&file_source))?;
    let decrypted_content = crypto::decrypt(encrypted_content, passphrase)
        .map_err(ImportFileError::decryption_fail(&file_source))?;

    if let Some(parent) = file_rel_path.parent() {
        let ancestors = {
            // For some reason calling directly .rev() after .ancestors() doesn't work
            // since the iterator size isn't know beforehand, so this workaround is
            // needed
            let mut ancestors = parent.ancestors().collect::<Vec<_>>().into_iter().rev();
            let root_ancestor = ancestors.next();
            if root_ancestor != Some(Utf8Path::new("")) {
                return Err(ImportFileError::IllFormedParent(file_rel_path.clone()));
            }
            ancestors
        };

        for ancestor in ancestors {
            let ancestor_path = target.join(ancestor);
            if !ancestor_path.exists() {
                fs::create_dir(&ancestor_path)
                    .map_err(ImportFileError::create_parent(&ancestor_path))?;
                chmod_chown_dir(&ancestor_path)?;
            }
        }
    }

    safe_fs::safe_write(&file_target, decrypted_content)
        .map_err(ImportFileError::safe_write(&file_target))?;
    chmod_chown_file(&file_target)?;

    let sha_content = fs::read(&sha_source).map_err(ImportFileError::read_fail(&sha_source))?;

    safe_fs::safe_write(&sha_target, sha_content)
        .map_err(ImportFileError::safe_write(&sha_target))?;
    chmod_chown_file(&sha_target)?;

    checksum::verify_file_checksum(&file_target)
        .map_err(ImportFileError::verify_import(&file_target))?;

    Ok(())
}

#[derive(Error, Debug)]
pub enum ImportError {
    #[error(transparent)]
    VerifySource(checksum::ChecksumError),

    #[error("source path '{0}' does not exist")]
    MissingSourcePath(Utf8PathBuf),
    #[error("source path '{0}' is not a directory")]
    SourceNotDir(Utf8PathBuf),

    #[error("target path '{0}' does not exist")]
    MissingTargetPath(Utf8PathBuf),
    #[error("target path '{0}' is not a directory")]
    TargetNotDir(Utf8PathBuf),

    #[error("failed to import file '{0}'\n{1}")]
    ImportFile(Utf8PathBuf, ImportFileError),
}
impl ImportError {
    fn import_file(file: &Utf8PathBuf) -> impl FnOnce(ImportFileError) -> Self {
        |e| Self::ImportFile(file.clone(), e)
    }
}
pub fn import(
    profile: String,
    source: String,
    target: String,
    config: Config,
    passphrase: String,
) -> Result<(), ImportError> {
    let source = {
        let path = Utf8PathBuf::from(&source);
        if !path.exists() {
            return Err(ImportError::MissingSourcePath(path));
        } else if !path.is_dir() {
            return Err(ImportError::SourceNotDir(path));
        }
        path
    };

    let target = {
        let path = Utf8PathBuf::from(&target);
        if !path.exists() {
            return Err(ImportError::MissingTargetPath(path));
        } else if !path.is_dir() {
            return Err(ImportError::TargetNotDir(path));
        }
        path
    };

    print!("Verifying source integrity... ");
    std::io::stdout().flush().unwrap();
    checksum::verify_checksums(&source)
        .map_err(ImportError::VerifySource)
        .inspect_err(|_| println!("error"))?;
    println!("ok");
    println!();

    let secrets = config.secrets.get(&profile).map_or(vec![], Vec::clone);
    let additional_imports = config
        .additional_imports
        .get(&profile)
        .map_or(vec![], Vec::clone);

    let files = [secrets, additional_imports].concat();

    println!("Importing secrets... ");
    for file in files {
        print!("importing '{file}'... ");
        std::io::stdout().flush().unwrap();

        import_file(&file, &source, &target, &passphrase)
            .map_err(ImportError::import_file(&file))
            .inspect_err(|_| println!("error"))?;
        println!("ok");
    }

    println!();

    Ok(())
}
