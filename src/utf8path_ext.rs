use camino::{Utf8Path, Utf8PathBuf};

pub trait ExtraUtf8Path {
    fn add_extension(&self, extension: impl AsRef<str>) -> Utf8PathBuf;
}
impl ExtraUtf8Path for Utf8Path {
    fn add_extension(&self, extension: impl AsRef<str>) -> Utf8PathBuf {
        let Some(file_name) = self.file_name() else {
            return Utf8PathBuf::from(self);
        };
        self.with_file_name(file_name.to_string() + "." + extension.as_ref())
    }
}
impl ExtraUtf8Path for Utf8PathBuf {
    fn add_extension(&self, extension: impl AsRef<str>) -> Utf8PathBuf {
        let Some(file_name) = self.file_name() else {
            return Utf8PathBuf::from(self);
        };
        self.with_file_name(file_name.to_string() + "." + extension.as_ref())
    }
}
