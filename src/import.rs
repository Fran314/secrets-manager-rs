use std::{
    fs::{self, Permissions},
    io::Write,
    os::unix::fs::PermissionsExt,
};

use thiserror::Error;

use camino::{Utf8Path, Utf8PathBuf};

use crate::{
    checksum, chown_spec::ChownSpec, crypto, manifest, safe_fs, snapshot,
    utf8path_ext::ExtraUtf8Path,
};

pub enum SourceType {
    Encrypted { passphrase: String },
    Plaintext,
}

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

    #[error("failed to assign permissions to file at endpoint ('{0}')\n{1}")]
    ChmodFail(Utf8PathBuf, std::io::Error),

    #[error("failed to safely write file at endpoint ('{0}')\n{1}")]
    SafeWrite(Utf8PathBuf, safe_fs::SafeFsError),

    #[error("failed to verify integrity of imported file at '{0}'\n{1}")]
    VerifyImport(Utf8PathBuf, checksum::ChecksumError),

    #[error("failed to run chown for '{0}'\n{1}")]
    ChownSpawn(Utf8PathBuf, std::io::Error),

    #[error("failed to set owner '{1}' on '{0}'\n{2}")]
    ChownFail(Utf8PathBuf, String, String),
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

    fn chmod_fail(target: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ChmodFail(target.clone(), e)
    }

    fn safe_write(target: &Utf8PathBuf) -> impl Fn(safe_fs::SafeFsError) -> Self {
        |e| Self::SafeWrite(target.clone(), e)
    }

    fn verify_import(target: &Utf8PathBuf) -> impl Fn(checksum::ChecksumError) -> Self {
        |e| Self::VerifyImport(target.clone(), e)
    }

    fn chown_spawn(target: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ChownSpawn(target.clone(), e)
    }
}
fn chmod_file(path: &Utf8PathBuf, mode: u32) -> Result<(), ImportFileError> {
    let permissions = Permissions::from_mode(mode);
    std::fs::set_permissions(path, permissions).map_err(ImportFileError::chmod_fail(path))?;

    Ok(())
}
fn chmod_dir(path: &Utf8PathBuf) -> Result<(), ImportFileError> {
    let permissions = Permissions::from_mode(0o755);
    std::fs::set_permissions(path, permissions).map_err(ImportFileError::chmod_fail(path))?;

    Ok(())
}
fn chown(path: &Utf8PathBuf, spec: &ChownSpec) -> Result<(), ImportFileError> {
    let output = std::process::Command::new("chown")
        .arg("--")
        .arg(spec.as_str())
        .arg(path)
        .output()
        .map_err(ImportFileError::chown_spawn(path))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(ImportFileError::ChownFail(
            path.clone(),
            spec.as_str().to_string(),
            stderr,
        ));
    }

    Ok(())
}
fn import_file(
    secret: &manifest::Secret,
    source: &Utf8PathBuf,
    target: &Utf8PathBuf,
    source_type: &SourceType,
    skip_chown_chmod: bool,
) -> Result<(), ImportFileError> {
    let file_rel_path = &secret.path;
    let file_target = target.join(file_rel_path);

    let sha_source = source.join(file_rel_path).add_extension("sha256");
    let sha_target = target.join(file_rel_path).add_extension("sha256");

    let file_content = match source_type {
        SourceType::Encrypted { passphrase } => {
            let file_source = source.join(file_rel_path).add_extension("age");
            let encrypted_content =
                fs::read(&file_source).map_err(ImportFileError::read_fail(&file_source))?;
            crypto::decrypt(encrypted_content, passphrase)
                .map_err(ImportFileError::decryption_fail(&file_source))?
        }
        SourceType::Plaintext => {
            let file_source = source.join(file_rel_path);
            fs::read(&file_source).map_err(ImportFileError::read_fail(&file_source))?
        }
    };

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
                chmod_dir(&ancestor_path)?;
            }
        }
    }

    safe_fs::safe_write(&file_target, file_content)
        .map_err(ImportFileError::safe_write(&file_target))?;
    if !skip_chown_chmod {
        if let Some(mode) = secret.mode {
            chmod_file(&file_target, mode)?;
        }
        if let Some(owner) = &secret.owner {
            chown(&file_target, owner)?;
        }
    }

    let sha_content = fs::read(&sha_source).map_err(ImportFileError::read_fail(&sha_source))?;

    safe_fs::safe_write(&sha_target, sha_content)
        .map_err(ImportFileError::safe_write(&sha_target))?;
    if !skip_chown_chmod {
        chmod_file(&sha_target, 0o600)?;
        if let Some(owner) = &secret.owner {
            chown(&sha_target, owner)?;
        }
    }

    checksum::verify_file_checksum(&file_target)
        .map_err(ImportFileError::verify_import(&file_target))?;

    Ok(())
}

fn restore_manifest(
    source: &Utf8PathBuf,
    target: &Utf8PathBuf,
) -> Result<(), ImportFileError> {
    let name = Utf8PathBuf::from(manifest::MANIFEST_FILENAME);
    let manifest_source = source.join(&name);
    let manifest_target = target.join(&name);

    let content = fs::read(&manifest_source).map_err(ImportFileError::read_fail(&manifest_source))?;
    safe_fs::safe_write(&manifest_target, content)
        .map_err(ImportFileError::safe_write(&manifest_target))?;
    chmod_file(&manifest_target, 0o600)?;

    Ok(())
}

fn confirm(prompt: &str) -> std::io::Result<bool> {
    print!("{prompt} [y/N]: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    Ok(matches!(input.trim(), "y" | "Y"))
}

#[derive(Error, Debug)]
pub enum ImportError {
    #[error(transparent)]
    VerifySource(checksum::ChecksumError),

    #[error("failed to load manifest from export\n{0}")]
    LoadManifest(manifest::ManifestError),

    #[error("failed to load local manifest at target\n{0}")]
    LoadLocalManifest(manifest::ManifestError),

    #[error("failed to read confirmation from stdin\n{0}")]
    Confirm(std::io::Error),

    #[error("source path '{0}' does not exist")]
    MissingSourcePath(Utf8PathBuf),
    #[error("source path '{0}' is not a directory")]
    SourceNotDir(Utf8PathBuf),

    #[error("failed to list snapshots in container '{0}'\n{1}")]
    ListSnapshots(Utf8PathBuf, std::io::Error),

    #[error("container '{0}' holds no snapshots to import")]
    EmptyContainer(Utf8PathBuf),

    #[error("source '{0}' is neither a snapshot nor a container of snapshots")]
    NotSnapshotOrContainer(Utf8PathBuf),

    #[error("target path '{0}' does not exist")]
    MissingTargetPath(Utf8PathBuf),
    #[error("target path '{0}' is not a directory")]
    TargetNotDir(Utf8PathBuf),

    #[error("invalid selected secret path: {0}")]
    InvalidSelection(manifest::InvalidPath),

    #[error("requested secret '{0}' is not present in the export")]
    PathNotInExport(Utf8PathBuf),

    #[error("failed to import file '{0}'\n{1}")]
    ImportFile(Utf8PathBuf, ImportFileError),

    #[error("failed to restore manifest to target\n{0}")]
    RestoreManifest(ImportFileError),
}
impl ImportError {
    fn import_file(file: &Utf8PathBuf) -> impl FnOnce(ImportFileError) -> Self {
        |e| Self::ImportFile(file.clone(), e)
    }

    fn list_snapshots(container: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ListSnapshots(container.clone(), e)
    }
}
pub fn import(
    source: String,
    target: String,
    paths: Vec<String>,
    source_type: SourceType,
    skip_chown_chmod: bool,
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

    let source = match snapshot::classify(&source) {
        snapshot::SourceKind::Snapshot => source,
        snapshot::SourceKind::Container => {
            match snapshot::newest(&source).map_err(ImportError::list_snapshots(&source))? {
                Some(name) => {
                    println!("Using snapshot {name}");
                    println!();
                    source.join(name)
                }
                None => return Err(ImportError::EmptyContainer(source)),
            }
        }
        snapshot::SourceKind::Neither => return Err(ImportError::NotSnapshotOrContainer(source)),
    };

    if matches!(source_type, SourceType::Encrypted { .. }) {
        print!("Verifying source integrity... ");
        std::io::stdout().flush().unwrap();
        checksum::verify_checksums(&source)
            .map_err(ImportError::VerifySource)
            .inspect_err(|_| println!("error"))?;
        println!("ok");
        println!();
    }

    let available = manifest::load(&source).map_err(ImportError::LoadManifest)?;

    let is_full = paths.is_empty();
    let secrets: Vec<manifest::Secret> = if is_full {
        available
    } else {
        let mut selected = Vec::new();
        for path in &paths {
            let path = manifest::normalize_selection_path(path)
                .map_err(ImportError::InvalidSelection)?;
            match available.iter().find(|s| s.path == path) {
                Some(secret) => selected.push(secret.clone()),
                None => return Err(ImportError::PathNotInExport(path)),
            }
        }
        selected
    };

    let local_manifest_path = target.join(manifest::MANIFEST_FILENAME);
    if local_manifest_path.exists() {
        let local = manifest::load(&target).map_err(ImportError::LoadLocalManifest)?;

        if is_full {
            let only_backup: Vec<&Utf8PathBuf> = secrets
                .iter()
                .map(|s| &s.path)
                .filter(|p| !local.iter().any(|l| &l.path == *p))
                .collect();
            let only_local: Vec<&Utf8PathBuf> = local
                .iter()
                .map(|s| &s.path)
                .filter(|p| !secrets.iter().any(|s| &s.path == *p))
                .collect();

            if !only_backup.is_empty() || !only_local.is_empty() {
                println!("The export manifest differs from the local manifest at the target:");
                if !only_backup.is_empty() {
                    println!("  present in the export, missing from local (will be restored):");
                    for p in &only_backup {
                        println!("    + {p}");
                    }
                }
                if !only_local.is_empty() {
                    println!(
                        "  present in local, missing from the export (this backup cannot provide them):"
                    );
                    for p in &only_local {
                        println!("    - {p}");
                    }
                }
                println!();

                if !confirm("Proceed with the import?").map_err(ImportError::Confirm)? {
                    println!("Import aborted.");
                    return Ok(());
                }
                println!();
            }
        } else {
            let unlisted: Vec<&Utf8PathBuf> = secrets
                .iter()
                .map(|s| &s.path)
                .filter(|p| !local.iter().any(|l| &l.path == *p))
                .collect();
            if !unlisted.is_empty() {
                println!("Note: the following specified secrets are not present in the local manifest (they will be restored anyway):");
                for p in &unlisted {
                    println!("  + '{p}'");
                }
                println!();
            }
        }
    }

    println!("Importing secrets... ");
    for secret in &secrets {
        let file = &secret.path;
        print!("importing '{file}'... ");
        std::io::stdout().flush().unwrap();

        import_file(secret, &source, &target, &source_type, skip_chown_chmod)
            .map_err(ImportError::import_file(file))
            .inspect_err(|_| println!("error"))?;
        println!("ok");
    }
    println!();

    if is_full && !local_manifest_path.exists() {
        print!("restoring manifest... ");
        std::io::stdout().flush().unwrap();
        restore_manifest(&source, &target)
            .map_err(ImportError::RestoreManifest)
            .inspect_err(|_| println!("error"))?;
        println!("ok");
        println!();
    }

    Ok(())
}
