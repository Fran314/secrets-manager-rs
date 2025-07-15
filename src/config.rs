use camino::{Utf8Component, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use thiserror::Error;

#[derive(Debug, Deserialize, Serialize)]
pub struct _Config {
    pub secrets: HashMap<String, Vec<String>>,
    pub additional_imports: HashMap<String, Vec<String>>,
}
#[derive(Debug)]
pub struct Config {
    source: String,
    pub secrets: HashMap<String, Vec<Utf8PathBuf>>,
    pub additional_imports: HashMap<String, Vec<Utf8PathBuf>>,
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
fn to_valid_path(path: String) -> Result<Utf8PathBuf, InvalidPath> {
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
pub enum InvalidSecrets {
    #[error("profile '{0}' contains invalid secret path\n{1}")]
    InvalidPath(String, InvalidPath),

    #[error("profile '{0}' declares secret '{1}' multiple times")]
    MultipleSecretDeclaration(String, Utf8PathBuf),

    #[error("secret '{2}' is declare (hence owned) by multiple profiles: '{0}', '{1}'")]
    MultipleSecretOwnership(String, String, Utf8PathBuf),
}
impl InvalidSecrets {
    fn invalid_path(profile: &str) -> impl Fn(InvalidPath) -> InvalidSecrets {
        |e| InvalidSecrets::InvalidPath(profile.to_string(), e)
    }
}
fn to_valid_secrets(
    secrets: HashMap<String, Vec<String>>,
) -> Result<HashMap<String, Vec<Utf8PathBuf>>, InvalidSecrets> {
    let secrets = {
        let mut hashmap = HashMap::new();
        for (profile, profile_secrets) in secrets {
            let paths: Vec<_> = profile_secrets
                .into_iter()
                .map(to_valid_path)
                .collect::<Result<_, _>>()
                .map_err(InvalidSecrets::invalid_path(&profile))?;

            hashmap.insert(profile, paths);
        }
        hashmap
    };

    for (profile, profile_secrets) in &secrets {
        for secret in profile_secrets {
            let occurrences = profile_secrets.iter().filter(|&s| *s == *secret).count();
            if occurrences > 1 {
                return Err(InvalidSecrets::MultipleSecretDeclaration(
                    profile.clone(),
                    secret.clone(),
                ));
            }
        }
    }

    let items: Vec<_> = secrets.iter().collect();
    for i in 0..items.len() {
        for j in (i + 1)..items.len() {
            let (pi, si) = items[i];
            let (pj, sj) = items[j];

            for secret in si {
                if sj.contains(secret) {
                    return Err(InvalidSecrets::MultipleSecretOwnership(
                        pi.clone(),
                        pj.clone(),
                        secret.clone(),
                    ));
                }
            }
        }
    }

    Ok(secrets)
}

#[derive(Error, Debug)]
pub enum InvalidImports {
    #[error("profile '{0}' contains invalid import path\n{1}")]
    InvalidPath(String, InvalidPath),

    #[error("profile '{0}' declares additional import '{1}' multiple times")]
    MultipleDeclaration(String, Utf8PathBuf),

    #[error(
        "profile '{0}' declares additional import '{1}' but it is already the owner of said secret, so it's redundant"
    )]
    DeclaredRedundant(String, Utf8PathBuf),

    #[error(
        "profile '{0}' declares additional import '{1}' which is never declared as a secert by any profile"
    )]
    DeclaredMissing(String, Utf8PathBuf),
}
impl InvalidImports {
    fn invalid_path(profile: &str) -> impl Fn(InvalidPath) -> InvalidImports {
        |e| InvalidImports::InvalidPath(profile.to_string(), e)
    }
}
fn to_valid_imports(
    secrets: &HashMap<String, Vec<Utf8PathBuf>>,
    additional_imports: HashMap<String, Vec<String>>,
) -> Result<HashMap<String, Vec<Utf8PathBuf>>, InvalidImports> {
    let additional_imports = {
        let mut hashmap = HashMap::new();
        for (profile, profile_imports) in additional_imports {
            let paths: Vec<_> = profile_imports
                .into_iter()
                .map(to_valid_path)
                .collect::<Result<_, _>>()
                .map_err(InvalidImports::invalid_path(&profile))?;

            hashmap.insert(profile, paths);
        }
        hashmap
    };

    for (profile, profile_imports) in &additional_imports {
        for import in profile_imports {
            let occurrences = profile_imports.iter().filter(|&i| *i == *import).count();
            if occurrences > 1 {
                return Err(InvalidImports::MultipleDeclaration(
                    profile.clone(),
                    import.clone(),
                ));
            }

            if let Some(profile_secrets) = secrets.get(profile) {
                if profile_secrets.contains(import) {
                    return Err(InvalidImports::DeclaredRedundant(
                        profile.clone(),
                        import.clone(),
                    ));
                }
            }

            if !secrets.values().any(|ps| ps.contains(import)) {
                return Err(InvalidImports::DeclaredMissing(
                    profile.clone(),
                    import.clone(),
                ));
            }
        }
    }

    Ok(additional_imports)
}

#[derive(Error, Debug)]
pub enum LoadConfigError {
    #[error("failed to retrieve config directory")]
    GetConfigDir,
    #[error("config directory (approx: '{0}') is non utf8, hence is not supported")]
    Utf8ConfigDir(String),

    #[error("could not find any config file. Add one in the current directory or in $XDG_CONFIG")]
    MissingConfig,

    #[error("failed to read config file at path '{0}'\n{1}")]
    ReadConfig(Utf8PathBuf, std::io::Error),

    #[error("failed to parse config file at path '{0}'\n{1}")]
    ParseConfig(Utf8PathBuf, toml::de::Error),

    #[error("invalid config file at path '{0}'\n{1}")]
    InvalidSecrets(Utf8PathBuf, InvalidSecrets),

    #[error("invalid config file at path '{0}'\n{1}")]
    InvalidImports(Utf8PathBuf, InvalidImports),
}
impl LoadConfigError {
    fn read_config_fail(path: &Utf8PathBuf) -> impl Fn(std::io::Error) -> LoadConfigError {
        |e| LoadConfigError::ReadConfig(path.clone(), e)
    }

    fn parse_config_fail(path: &Utf8PathBuf) -> impl Fn(toml::de::Error) -> LoadConfigError {
        |e| LoadConfigError::ParseConfig(path.clone(), e)
    }

    fn invalid_secrets(path: &Utf8PathBuf) -> impl Fn(InvalidSecrets) -> LoadConfigError {
        |e| LoadConfigError::InvalidSecrets(path.clone(), e)
    }

    fn invalid_imports(path: &Utf8PathBuf) -> impl Fn(InvalidImports) -> LoadConfigError {
        |e| LoadConfigError::InvalidImports(path.clone(), e)
    }
}

pub fn get_config_file() -> Result<Utf8PathBuf, LoadConfigError> {
    let user = dirs::config_dir().ok_or(LoadConfigError::GetConfigDir)?;
    let user = Utf8PathBuf::from_path_buf(user)
        .map_err(|path| LoadConfigError::Utf8ConfigDir(path.to_string_lossy().to_string()))?;
    let user = user.join("secrets-manager").join("secrets-manager.toml");
    if user.exists() {
        return Ok(user);
    }

    let local = Utf8PathBuf::from("./secrets-manager.toml");
    if local.exists() {
        return Ok(local);
    }

    Err(LoadConfigError::MissingConfig)
}

pub fn load_config() -> Result<Config, LoadConfigError> {
    let config_path = get_config_file()?;
    let config_str = fs::read_to_string(&config_path)
        .map_err(LoadConfigError::read_config_fail(&config_path))?;

    let config = toml::from_str::<_Config>(&config_str)
        .map_err(LoadConfigError::parse_config_fail(&config_path))?;

    let secrets =
        to_valid_secrets(config.secrets).map_err(LoadConfigError::invalid_secrets(&config_path))?;
    let additional_imports = to_valid_imports(&secrets, config.additional_imports)
        .map_err(LoadConfigError::invalid_imports(&config_path))?;

    Ok(Config {
        source: config_str,
        secrets,
        additional_imports,
    })
}

#[derive(Error, Debug)]
#[error("failed to read config file at path '{0}'\n{1}")]
pub struct SaveConfigError(Utf8PathBuf, std::io::Error);

impl SaveConfigError {
    fn save_config_error(path: &Utf8PathBuf) -> impl Fn(std::io::Error) -> Self {
        |e| Self(path.clone(), e)
    }
}

pub fn save_config(path: &Utf8PathBuf, config: &Config) -> Result<(), SaveConfigError> {
    fs::write(path, config.source.clone()).map_err(SaveConfigError::save_config_error(path))?;

    Ok(())
}
