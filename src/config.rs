use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use thiserror::Error;

#[derive(Debug, Deserialize, Serialize)]
pub struct ExportInfo {
    pub source: String,
    pub endpoint: String,
    pub files: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ImportInfo {
    pub source: String,
    pub endpoint: String,
    pub files: Vec<String>,
    pub symlinks_to: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct _Config {
    pub exports: HashMap<String, Vec<ExportInfo>>,
    pub imports: HashMap<String, Vec<ImportInfo>>,
}
pub struct Config {
    source: String,
    pub exports: HashMap<String, Vec<ExportInfo>>,
    pub imports: HashMap<String, Vec<ImportInfo>>,
}

#[derive(Error, Debug)]
pub enum LoadConfigError {
    #[error("failed to retrieve config directory")]
    GetConfigDirFail,

    #[error("could not find any config file. Add one in the current directory or in $XDG_CONFIG")]
    MissingConfig,

    #[error("failed to read config file at path '{0}'\n{1}")]
    ReadConfigFail(String, std::io::Error),

    #[error("failed to parse config file at path '{0}'\n{1}")]
    ParseConfigFail(String, toml::de::Error),
}
impl LoadConfigError {
    fn read_config_fail(path: &std::path::Path) -> impl Fn(std::io::Error) -> LoadConfigError {
        |e| LoadConfigError::ReadConfigFail(path.to_string_lossy().to_string(), e)
    }

    fn parse_config_fail(path: &std::path::Path) -> impl Fn(toml::de::Error) -> LoadConfigError {
        |e| LoadConfigError::ParseConfigFail(path.to_string_lossy().to_string(), e)
    }
}

#[derive(Error, Debug)]
#[error("failed to read config file at path '{0}'\n{1}")]
pub struct SaveConfigError(String, std::io::Error);

impl SaveConfigError {
    fn save_config_error(path: &std::path::Path) -> impl Fn(std::io::Error) -> Self {
        |e| Self(path.to_string_lossy().to_string(), e)
    }
}

pub fn get_config_file() -> Result<std::path::PathBuf, LoadConfigError> {
    let local = std::path::PathBuf::from("./secrets-manager.toml");
    if local.exists() {
        return Ok(local);
    }

    let user = dirs::config_dir().ok_or(LoadConfigError::GetConfigDirFail)?;
    let user = user.join("secrets-manger.toml");
    if user.exists() {
        return Ok(user);
    }

    Err(LoadConfigError::MissingConfig)
}
pub fn load_config() -> Result<Config, LoadConfigError> {
    let config_path = get_config_file()?;
    let config_str = fs::read_to_string(&config_path)
        .map_err(LoadConfigError::read_config_fail(&config_path))?;

    let config = toml::from_str::<_Config>(&config_str)
        .map_err(LoadConfigError::parse_config_fail(&config_path))?;

    Ok(Config {
        source: config_str,
        exports: config.exports,
        imports: config.imports,
    })
}

pub fn save_config<P>(path: P, config: &Config) -> Result<(), SaveConfigError>
where
    P: AsRef<std::path::Path>,
{
    let path = path.as_ref();
    fs::write(path, config.source.clone()).map_err(SaveConfigError::save_config_error(path))?;

    Ok(())
}
