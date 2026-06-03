use camino::{Utf8Component, Utf8PathBuf};
use std::fs;
use thiserror::Error;

use crate::chown_spec::{ChownSpec, InvalidChownSpec};

pub const MANIFEST_FILENAME: &str = ".secrets-manifest";
pub const DEFAULT_MODE: u32 = 0o600;

#[derive(Debug, Clone)]
pub struct Secret {
    pub path: Utf8PathBuf,
    pub owner: Option<ChownSpec>,
    pub mode: u32,
}

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

// Normalize paths by removing leading `./` so that './a/b' and `a/b` match component-wise. Note
// that paths are already normalized by Utf8PathBuf, except for the leading CurDir component. '..'
// components are treated as not valid.
pub fn normalize_selection_path(path: &str) -> Result<Utf8PathBuf, InvalidPath> {
    let original = Utf8PathBuf::from(path);

    let mut normalized = Utf8PathBuf::new();
    for component in original.components() {
        match component {
            Utf8Component::Normal(c) => normalized.push(c),
            Utf8Component::CurDir => {}

            Utf8Component::RootDir => return Err(InvalidPath::Root(original)),
            Utf8Component::Prefix(_) => unreachable!("Utf8Component::Prefix cannot occur in Unix"),
            Utf8Component::ParentDir => return Err(InvalidPath::Parent(original)),
        }
    }

    Ok(normalized)
}

#[derive(Error, Debug)]
pub enum InvalidEntry {
    #[error("invalid path: {0}")]
    Path(#[from] InvalidPath),

    #[error(transparent)]
    Owner(#[from] InvalidChownSpec),

    #[error("'{0}' is not a valid mode (expected 3-4 octal digits, e.g. 0600)")]
    Mode(String),

    #[error("'{0}' is not a recognized annotation (expected owner=... or mode=...)")]
    UnknownAttribute(String),

    #[error("owner specified more than once")]
    DuplicateOwner,

    #[error("mode specified more than once")]
    DuplicateMode,
}
fn is_mode(value: &str) -> bool {
    (3..=4).contains(&value.len()) && value.bytes().all(|b| (b'0'..=b'7').contains(&b))
}
fn parse_entry(line: &str) -> Result<Secret, InvalidEntry> {
    let mut tokens = line.split_whitespace();
    let path = to_valid_path(tokens.next().expect("non-blank line has a first token"))?;

    let mut owner: Option<ChownSpec> = None;
    let mut mode: Option<u32> = None;
    for token in tokens {
        if let Some(spec) = token.strip_prefix("owner=") {
            if owner.is_some() {
                return Err(InvalidEntry::DuplicateOwner);
            }
            owner = Some(spec.parse()?);
        } else if let Some(value) = token.strip_prefix("mode=") {
            if mode.is_some() {
                return Err(InvalidEntry::DuplicateMode);
            }
            if !is_mode(value) {
                return Err(InvalidEntry::Mode(value.to_string()));
            }
            mode = Some(u32::from_str_radix(value, 8).expect("validated octal mode"));
        } else {
            return Err(InvalidEntry::UnknownAttribute(token.to_string()));
        }
    }

    Ok(Secret {
        path,
        owner,
        mode: mode.unwrap_or(DEFAULT_MODE),
    })
}

#[derive(Error, Debug)]
pub enum ManifestError {
    #[error("manifest file not found at '{0}'")]
    Missing(Utf8PathBuf),

    #[error("failed to read manifest file at '{0}'\n{1}")]
    Read(Utf8PathBuf, std::io::Error),

    #[error("manifest at '{0}' has an invalid entry '{1}'\n{2}")]
    InvalidEntry(Utf8PathBuf, String, InvalidEntry),

    #[error("manifest at '{0}' declares secret '{1}' multiple times")]
    Duplicate(Utf8PathBuf, Utf8PathBuf),
}
impl ManifestError {
    fn read(path: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::Read(path.clone(), e)
    }
}

pub fn load(dir: &Utf8PathBuf) -> Result<Vec<Secret>, ManifestError> {
    let path = dir.join(MANIFEST_FILENAME);
    if !path.exists() {
        return Err(ManifestError::Missing(path));
    }

    let content = fs::read_to_string(&path).map_err(ManifestError::read(&path))?;

    let mut secrets: Vec<Secret> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let secret = parse_entry(line)
            .map_err(|e| ManifestError::InvalidEntry(path.clone(), line.to_string(), e))?;
        if secrets.iter().any(|s| s.path == secret.path) {
            return Err(ManifestError::Duplicate(path.clone(), secret.path));
        }
        secrets.push(secret);
    }

    Ok(secrets)
}
