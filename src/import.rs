use std::{fs, io::Write, os::unix::fs::MetadataExt};

use thiserror::Error;

use crate::{
    checksum,
    config::{Config, ImportInfo},
    crypto,
};

enum ImportFileSuccess {
    Write,
    Skip,
}

#[derive(Error, Debug)]
pub enum ImportFileError {
    #[error("failed to read source file at '{0}'\n{1}")]
    ReadFail(String, std::io::Error),

    #[error("failed to read source file's metadata at '{0}'\n{1}")]
    ReadMetadataFail(String, std::io::Error),

    #[error("failed to decrypt contents of source file at '{0}'\n{1}")]
    DecryptionFail(String, age::DecryptError),

    #[error(
        "failed to read file at endpoint ('{0}', which already exists) while attempting to check that its content matches the intended content\n{1}"
    )]
    ReadExistingFail(String, std::io::Error),

    #[error(
        "file at endpoint ('{1}') already exists but does not contain the decryption of the content of the source file ('{0}'). This program won't override existing file at endpoint"
    )]
    CompareExistingFail(String, String),

    #[error("failed to write to file at endpoint ('{0}')\n{1}")]
    WriteFail(String, std::io::Error),

    #[error("failed to assign ownership to file at endpoint ('{0}')\n{1}")]
    ChownFail(String, std::io::Error),

    #[error("failed to assign permissions to file at endpoint ('{0}')\n{1}")]
    ChmodFail(String, std::io::Error),
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

    fn read_existing_fail(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadExistingFail(endpoint.to_string_lossy().to_string(), e)
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

    fn chown_fail(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ChownFail(endpoint.to_string_lossy().to_string(), e)
    }

    fn chmod_fail(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ChmodFail(endpoint.to_string_lossy().to_string(), e)
    }
}

#[derive(Error, Debug)]
pub enum ImportSourceError {
    #[error("failed to create endpoint directory '{0}'\n{1}")]
    CreateEndpointFail(String, std::io::Error),

    #[error("failed to verify integrity of source '{0}'\n{1}")]
    VerifySourceFail(String, checksum::VerifyError),

    #[error("failed to import file '{0}'\n{1}")]
    ImportFileFail(String, ImportFileError),

    #[error("failed to verify integrity of import '{0}'\n{1}")]
    VerifyImportFail(String, checksum::VerifyError),

    #[error("cannot create symlink at path '{0}' as path already exists and isn't a symlink")]
    SymlinkIsNotSymlink(String),

    #[error("cannot create symlink at path '{0}' as it already exists with wrong target")]
    WrongSymlinkTarget(String),

    #[error("failed to create symlink at path '{0}'")]
    CreateSymlinkFail(String, std::io::Error),
}
impl ImportSourceError {
    fn create_endpoint_fail(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::CreateEndpointFail(endpoint.to_string_lossy().to_string(), e)
    }

    fn verify_source_fail(source: &std::path::Path) -> impl Fn(checksum::VerifyError) -> Self {
        |e| Self::VerifySourceFail(source.to_string_lossy().to_string(), e)
    }

    fn import_file_fail(file: String) -> impl FnOnce(ImportFileError) -> Self {
        |e| Self::ImportFileFail(file, e)
    }

    fn verify_import_fail(import: &std::path::Path) -> impl Fn(checksum::VerifyError) -> Self {
        |e| Self::VerifyImportFail(import.to_string_lossy().to_string(), e)
    }

    fn create_symlink_fail(endpoint: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::CreateSymlinkFail(endpoint.to_string_lossy().to_string(), e)
    }
}

#[derive(Error, Debug)]
pub enum ImportError {
    #[error(transparent)]
    ImportSourceFail(ImportSourceError),
}

fn format_path(path: &str, profile: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(&path.replace("$profile", profile))
}

fn import_file<P, Q>(
    source: P,
    endpoint: Q,
    passphrase: &str,
) -> Result<ImportFileSuccess, ImportFileError>
where
    P: AsRef<std::path::Path>,
    Q: AsRef<std::path::Path>,
{
    let source = source.as_ref();
    let endpoint = endpoint.as_ref();
    let encrypted_content = fs::read(source).map_err(ImportFileError::read_fail(source))?;
    let (perm, uid, gid) = {
        let meta = fs::metadata(source).map_err(ImportFileError::read_metadata_fail(source))?;
        (meta.permissions(), meta.uid(), meta.gid())
    };

    let decrypted_content = crypto::decrypt(encrypted_content, passphrase)
        .map_err(ImportFileError::decryption_fail(source))?;

    let success_type = match endpoint.exists() {
        true => {
            let actual_content =
                fs::read(endpoint).map_err(ImportFileError::read_existing_fail(endpoint))?;

            if decrypted_content != actual_content {
                return Err(ImportFileError::compare_existing(source, endpoint));
            }

            ImportFileSuccess::Skip
        }
        false => {
            fs::write(endpoint, decrypted_content)
                .map_err(ImportFileError::write_fail(endpoint))?;

            ImportFileSuccess::Write
        }
    };

    std::os::unix::fs::chown(endpoint, Some(uid), Some(gid))
        .map_err(ImportFileError::chown_fail(endpoint))?;
    std::fs::set_permissions(endpoint, perm).map_err(ImportFileError::chmod_fail(endpoint))?;

    Ok(success_type)
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

    fs::create_dir_all(&endpoint).map_err(ImportSourceError::create_endpoint_fail(&endpoint))?;

    print!("verifying source integrity... ");
    std::io::stdout().flush().unwrap();
    checksum::verify_checksum(&source)
        .map_err(ImportSourceError::verify_source_fail(&source))
        .inspect_err(|_| println!("error"))?;
    println!("ok");

    let files = {
        let mut files = imports.files.clone();
        files.push("sha256sums.txt".to_string());
        files
    };
    for file in &files {
        let file_source = source.join(file.to_string() + ".age");
        let file_endpoint = endpoint.join(file);

        print!("importing '{file}'... ");
        std::io::stdout().flush().unwrap();
        let file_success = import_file(file_source, file_endpoint, passphrase)
            .map_err(ImportSourceError::import_file_fail(file.clone()))
            .inspect_err(|_| println!("error"))?;

        match file_success {
            ImportFileSuccess::Write => {
                println!("ok");
            }
            ImportFileSuccess::Skip => {
                println!("already in place");
            }
        }
    }

    print!("verifying import integrity... ");
    std::io::stdout().flush().unwrap();
    checksum::verify_checksum(&endpoint)
        .map_err(ImportSourceError::verify_import_fail(&endpoint))
        .inspect_err(|_| println!("error"))?;
    println!("ok");

    if let Some(symlinks_to) = &imports.symlinks_to {
        print!("generating symlinks... ");
        std::io::stdout().flush().unwrap();

        let symlink_endpoint = format_path(symlinks_to, profile);

        for file in &files {
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

pub fn import(
    profile: &str,
    source: &str,
    config: &Config,
    passphrase: &str,
) -> Result<(), ImportError> {
    let source_root = std::path::Path::new(source);

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
// fn import_for_profile(
//     profile: &String,
//     identity: &Identity,
//     source: &String,
//     imports: &Vec<ExportInfo>,
// ) -> Result<()> {
//     let source_root = std::path::Path::new(source);
//
//     for import_info in imports.iter() {
//         let source = to_path(&import_info.source, profile);
//         let source = source_root.join(&source);
//
//         let endpoint = to_path(&import_info.endpoint, profile);
//
//         if !checksum::verify_checksum(&source)? {
//             return Err(anyhow!("source checksum does not match"));
//         }
//
//         crypto::decrypt(
//             identity,
//             source.join("sha256sums.txt.age"),
//             endpoint.join("sha256sums.txt"),
//         )?;
//
//         for file in &import_info.files {
//             let file_source = source.join(file);
//             let file_endpoint = endpoint.join(file.to_string() + ".age");
//
//             println!("exporting {file_source:?}");
//
//             crypto::encrypt(recipient, file_source, file_endpoint)?;
//         }
//
//         println!("generating checksum");
//         checksum::generate_checksum(
//             &endpoint,
//             &import_info
//                 .files
//                 .iter()
//                 .map(|s| s.to_string() + ".age")
//                 .collect(),
//         )?;
//
//         println!("checking checksum");
//         if !checksum::verify_checksum(&endpoint)? {
//             return Err(anyhow!("endpoint checksum does not match"));
//         }
//     }
//
//     Ok(())
// }
// pub fn import(profile: &String, source: &String, config: &Config) -> Result<()> {
//     let identity = crypto::get_passpharse_identity()?;
//
//     if let Some(imports) = config.exports.get("shared") {
//         import_for_profile(profile, &identity, source, imports)?;
//     }
//
//     if let Some(imports) = config.exports.get(profile) {
//         import_for_profile(profile, &identity, source, imports)?;
//     }
//     todo!()
// }
