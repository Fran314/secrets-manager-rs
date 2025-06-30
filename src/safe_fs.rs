use std::fs;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SafeFsError {
    #[error(
        "failed to read file at '{0}' to check if the existing content matches the content meant to be written to it\n{1}"
    )]
    ReadExisting(String, std::io::Error),

    #[error(
        "file at '{0}' already exists and its content does not match the content meant to be written to it. Refusing to override it for safety measures"
    )]
    ContentMismatch(String),

    #[error("failed to write content to file at '{0}'\n{1}")]
    Write(String, std::io::Error),
}
impl SafeFsError {
    fn read_existing(path: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::ReadExisting(path.to_string_lossy().to_string(), e)
    }

    fn content_mismatch(path: &std::path::Path) -> Self {
        Self::ContentMismatch(path.to_string_lossy().to_string())
    }

    fn write(path: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self::Write(path.to_string_lossy().to_string(), e)
    }
}

pub fn safe_write<P, C>(path: P, content: C) -> Result<(), SafeFsError>
where
    P: AsRef<std::path::Path>,
    C: AsRef<[u8]>,
{
    let path = path.as_ref();
    let content = content.as_ref();

    match path.exists() {
        true => {
            let actual_content = fs::read(path).map_err(SafeFsError::read_existing(path))?;

            if content != actual_content {
                return Err(SafeFsError::content_mismatch(path));
            }
        }
        false => {
            fs::write(path, content).map_err(SafeFsError::write(path))?;
        }
    }

    Ok(())
}
