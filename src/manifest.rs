use camino::{Utf8Component, Utf8PathBuf};
use std::fs;
use thiserror::Error;

pub const MANIFEST_FILENAME: &str = ".secrets-manifest";

#[derive(Error, Debug)]
pub enum InvalidPath {
    #[error("paths must be relative paths, but '{0}' contains a reference to the root directory")]
    Root(Utf8PathBuf),

    #[error("paths must be normalized paths, but '{0}' contains '.'")]
    Current(Utf8PathBuf),

    #[error("paths must be normalized paths, but '{0}' contains '..'")]
    Parent(Utf8PathBuf),
}
fn to_valid_path(path: &str) -> Result<Utf8PathBuf, InvalidPath> {
    let path = Utf8PathBuf::from(path);

    for component in path.components() {
        match component {
            Utf8Component::Normal(_) => {}

            Utf8Component::RootDir => return Err(InvalidPath::Root(path)),
            Utf8Component::Prefix(_) => unreachable!("Utf8Component::Prefix cannot occur in Unix"),
            Utf8Component::CurDir => return Err(InvalidPath::Current(path)),
            Utf8Component::ParentDir => return Err(InvalidPath::Parent(path)),
        }
    }

    Ok(path)
}

#[derive(Error, Debug)]
pub enum ManifestError {
    #[error("manifest file not found at '{0}'")]
    Missing(Utf8PathBuf),

    #[error("failed to read manifest file at '{0}'\n{1}")]
    Read(Utf8PathBuf, std::io::Error),

    #[error("manifest at '{0}' contains an invalid path\n{1}")]
    InvalidPath(Utf8PathBuf, InvalidPath),

    #[error("manifest at '{0}' declares secret '{1}' multiple times")]
    Duplicate(Utf8PathBuf, Utf8PathBuf),
}
impl ManifestError {
    fn read(path: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::Read(path.clone(), e)
    }

    fn invalid_path(path: &Utf8PathBuf) -> impl Fn(InvalidPath) -> Self {
        |e| Self::InvalidPath(path.clone(), e)
    }
}

pub fn load(dir: &Utf8PathBuf) -> Result<Vec<Utf8PathBuf>, ManifestError> {
    let path = dir.join(MANIFEST_FILENAME);
    if !path.exists() {
        return Err(ManifestError::Missing(path));
    }

    let content = fs::read_to_string(&path).map_err(ManifestError::read(&path))?;

    let mut secrets: Vec<Utf8PathBuf> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let secret = to_valid_path(line).map_err(ManifestError::invalid_path(&path))?;
        if secrets.contains(&secret) {
            return Err(ManifestError::Duplicate(path, secret));
        }
        secrets.push(secret);
    }

    Ok(secrets)
}
