use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
};

use thiserror::Error;

use camino::Utf8PathBuf;

use crate::utf8path_ext::ExtraUtf8Path;

#[derive(Error, Debug)]
pub enum SafeFsError {
    #[error(
        "failed to read file at '{0}' to check if the existing content matches the content meant to be written to it\n{1}"
    )]
    ReadExisting(Utf8PathBuf, std::io::Error),

    #[error(
        "file at '{0}' already exists and its content does not match the content meant to be written to it. Refusing to override it for safety measures"
    )]
    ContentMismatch(Utf8PathBuf),

    #[error("failed to write content to file at '{0}'\n{1}")]
    Write(Utf8PathBuf, std::io::Error),
}
impl SafeFsError {
    fn read_existing(path: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadExisting(path.clone(), e)
    }

    fn content_mismatch(path: &Utf8PathBuf) -> Self {
        Self::ContentMismatch(path.clone())
    }

    fn write(path: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self::Write(path.clone(), e)
    }
}

pub fn safe_write<C>(path: &Utf8PathBuf, content: C) -> Result<(), SafeFsError>
where
    C: AsRef<[u8]>,
{
    let content = content.as_ref();

    if path.exists() {
        let actual_content = fs::read(path).map_err(SafeFsError::read_existing(path))?;

        if content != actual_content {
            return Err(SafeFsError::content_mismatch(path));
        }

        return Ok(());
    }

    let tmp = path.add_extension("partial-import");
    if tmp.exists() {
        fs::remove_file(&tmp).map_err(SafeFsError::write(&tmp))?;
    }

    let commit = || {
        // staged sensitive content: born 0600 so it is never world-readable in
        // the window between creation and the caller's final chmod
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(SafeFsError::write(&tmp))?;
        file.write_all(content).map_err(SafeFsError::write(&tmp))?;
        drop(file);

        fs::rename(&tmp, path).map_err(SafeFsError::write(path))?;
        Ok(())
    };

    commit().inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}
