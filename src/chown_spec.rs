use std::str::FromStr;

use thiserror::Error;

#[derive(Error, Debug)]
#[error("'{0}' is not a valid owner spec (expected user, user:group, or :group)")]
pub struct InvalidChownSpec(String);

#[derive(Debug, Clone)]
pub struct ChownSpec(String);
impl ChownSpec {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl FromStr for ChownSpec {
    type Err = InvalidChownSpec;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let spec = spec.to_string();

        if spec.matches(':').count() > 1 {
            return Err(InvalidChownSpec(spec));
        }
        let (user, group) = spec.split_once(':').unwrap_or((spec.as_str(), ""));
        if user.is_empty() && group.is_empty() {
            return Err(InvalidChownSpec(spec));
        }
        if user.starts_with('-') || group.starts_with('-') {
            return Err(InvalidChownSpec(spec));
        }

        Ok(Self(spec))
    }
}
