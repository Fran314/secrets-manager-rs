use std::{fs, io::Write, os::unix::fs::MetadataExt};

use thiserror::Error;

use crate::{
    checksum,
    config::{Config, ImportInfo},
    crypto, safe_fs,
};

fn format_path(path: &str, profile: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(&path.replace("$profile", profile))
}

#[derive(Error, Debug)]
pub enum ImportFileError {
    #[error("failed to read source file at '{0}'\n{1}")]
    ReadFail(String, std::io::Error),

    #[error("failed to read source file's metadata at '{0}'\n{1}")]
    ReadMetadataFail(String, std::io::Error),

    #[error("failed to decrypt contents of source file at '{0}'\n{1}")]
    DecryptionFail(String, age::DecryptError),

    #[error("failed to safely write file at endpoint ('{0}')\n{1}")]
    SafeWrite(String, safe_fs::SafeFsError),

    #[error("failed to assign ownership to file at endpoint ('{0}')\n{1}")]
    ChownFail(String, std::io::Error),

    #[error("failed to assign permissions to file at endpoint ('{0}')\n{1}")]
    ChmodFail(String, std::io::Error),

    #[error("failed to verify integrity of imported file at '{0}'\n{1}")]
    VerifyImport(String, checksum::ChecksumError),
}
impl ImportFileError {
    fn read_fail(source: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadFail(source.to_string_lossy().to_string(), e)
    }

    fn read_metadata_fail(source: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadMetadataFail(source.to_string_lossy().to_string(), e)
    }

    fn decryption_fail(source: &std::path::Path) -> impl Fn(age::DecryptError) -> Self {
        |e| Self::DecryptionFail(source.to_string_lossy().to_string(), e)
    }

    fn safe_write(endpoint: &std::path::Path) -> impl Fn(safe_fs::SafeFsError) -> Self {
        |e| Self::SafeWrite(endpoint.to_string_lossy().to_string(), e)
    }

    fn chown_fail(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ChownFail(endpoint.to_string_lossy().to_string(), e)
    }

    fn chmod_fail(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ChmodFail(endpoint.to_string_lossy().to_string(), e)
    }

    fn verify_import(endpoint: &std::path::Path) -> impl Fn(checksum::ChecksumError) -> Self {
        |e| Self::VerifyImport(endpoint.to_string_lossy().to_string(), e)
    }
}
fn import_file<P, Q>(
    filename: &str,
    source: P,
    endpoint: Q,
    passphrase: &str,
) -> Result<(), ImportFileError>
where
    P: AsRef<std::path::Path>,
    Q: AsRef<std::path::Path>,
{
    let source = source.as_ref();
    let endpoint = endpoint.as_ref();

    let file_source = source.join(filename.to_string() + ".age");
    let file_endpoint = endpoint.join(filename);

    let sha_source = source.join(filename.to_string() + ".sha256");
    let sha_endpoint = endpoint.join(filename.to_string() + ".sha256");

    let encrypted_content =
        fs::read(&file_source).map_err(ImportFileError::read_fail(&file_source))?;
    let (file_perm, file_uid, file_gid) = {
        let meta = fs::metadata(&file_source)
            .map_err(ImportFileError::read_metadata_fail(&file_source))?;
        (meta.permissions(), meta.uid(), meta.gid())
    };
    let decrypted_content = crypto::decrypt(encrypted_content, passphrase)
        .map_err(ImportFileError::decryption_fail(&file_source))?;
    safe_fs::safe_write(&file_endpoint, decrypted_content)
        .map_err(ImportFileError::safe_write(&file_endpoint))?;
    std::os::unix::fs::chown(&file_endpoint, Some(file_uid), Some(file_gid))
        .map_err(ImportFileError::chown_fail(&file_endpoint))?;
    std::fs::set_permissions(&file_endpoint, file_perm)
        .map_err(ImportFileError::chmod_fail(&file_endpoint))?;

    let sha_content = fs::read(&sha_source).map_err(ImportFileError::read_fail(&sha_source))?;
    let (sha_perm, sha_uid, sha_gid) = {
        let meta =
            fs::metadata(&sha_source).map_err(ImportFileError::read_metadata_fail(&sha_source))?;
        (meta.permissions(), meta.uid(), meta.gid())
    };
    safe_fs::safe_write(&sha_endpoint, sha_content)
        .map_err(ImportFileError::safe_write(&sha_endpoint))?;
    std::os::unix::fs::chown(&sha_endpoint, Some(sha_uid), Some(sha_gid))
        .map_err(ImportFileError::chown_fail(&sha_endpoint))?;
    std::fs::set_permissions(&sha_endpoint, sha_perm)
        .map_err(ImportFileError::chmod_fail(&sha_endpoint))?;

    checksum::verify_file_checksum(&endpoint, filename)
        .map_err(ImportFileError::verify_import(&file_endpoint))?;

    Ok(())
}

#[derive(Error, Debug)]
pub enum ImportSourceError {
    #[error("failed to import file '{0}'\n{1}")]
    ImportFileFail(String, ImportFileError),

    #[error("cannot create symlink at path '{0}' as path already exists and isn't a symlink")]
    SymlinkIsNotSymlink(String),

    #[error("cannot create symlink at path '{0}' as it already exists with wrong target")]
    WrongSymlinkTarget(String),

    #[error("failed to create symlink at path '{0}'")]
    CreateSymlinkFail(String, std::io::Error),
}
impl ImportSourceError {
    fn import_file_fail(file: String) -> impl FnOnce(ImportFileError) -> Self {
        |e| Self::ImportFileFail(file, e)
    }

    fn create_symlink_fail(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::CreateSymlinkFail(endpoint.to_string_lossy().to_string(), e)
    }
}
fn import_source<P>(
    profile: &str,
    source_root: P,
    imports: &ImportInfo,
    passphrase: &str,
) -> Result<(), ImportSourceError>
where
    P: AsRef<std::path::Path>,
{
    let source = source_root
        .as_ref()
        .join(format_path(&imports.source, profile));
    let endpoint = format_path(&imports.endpoint, profile);

    println!("Importing files to '{}'...", &imports.endpoint);

    for filename in &imports.files {
        print!("importing '{filename}'... ");
        std::io::stdout().flush().unwrap();
        import_file(filename, &source, &endpoint, passphrase)
            .map_err(ImportSourceError::import_file_fail(filename.clone()))
            .inspect_err(|_| println!("error"))?;
        println!("ok");
    }

    if let Some(symlinks_to) = &imports.symlinks_to {
        print!("generating symlinks... ");
        std::io::stdout().flush().unwrap();

        let symlink_endpoint = format_path(symlinks_to, profile);

        for file in &imports.files {
            let symlink_source = endpoint.join(file);
            let symlink_endpoint = symlink_endpoint.join(file);

            if symlink_endpoint.exists() {
                if !symlink_endpoint.is_symlink() {
                    println!("error");
                    return Err(ImportSourceError::SymlinkIsNotSymlink(
                        symlink_endpoint.to_string_lossy().to_string(),
                    ));
                }
                let link = fs::read_link(&symlink_endpoint).unwrap();

                if link != symlink_source {
                    println!("error");
                    return Err(ImportSourceError::WrongSymlinkTarget(
                        symlink_endpoint.to_string_lossy().to_string(),
                    ));
                }
            } else {
                std::os::unix::fs::symlink(symlink_source, &symlink_endpoint)
                    .map_err(ImportSourceError::create_symlink_fail(&symlink_endpoint))?;
            }
        }

        println!("ok");
    }

    println!();

    Ok(())
}

#[derive(Error, Debug)]
pub enum ImportError {
    #[error(transparent)]
    VerifySource(checksum::ChecksumError),

    #[error(transparent)]
    ImportSourceFail(ImportSourceError),
}
pub fn import(
    profile: &str,
    source: &str,
    config: &Config,
    passphrase: &str,
) -> Result<(), ImportError> {
    let source_root = std::path::Path::new(source);

    print!("Verifying source integrity... ");
    std::io::stdout().flush().unwrap();
    checksum::verify_checksums(source_root)
        .map_err(ImportError::VerifySource)
        .inspect_err(|_| println!("error"))?;
    println!("ok");
    println!();

    if let Some(imports) = config.imports.get("shared") {
        for import_info in imports {
            import_source(profile, source_root, import_info, passphrase)
                .map_err(ImportError::ImportSourceFail)?;
        }
    }

    if let Some(imports) = config.imports.get(profile) {
        for import_info in imports {
            import_source(profile, source_root, import_info, passphrase)
                .map_err(ImportError::ImportSourceFail)?;
        }
    }

    Ok(())
}
