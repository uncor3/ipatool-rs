use crate::error::IpaToolError;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Config {
    pub config_dir: PathBuf,
    pub cookies_path: PathBuf,
    pub keyring_service: String,
    pub keyring_account_key: String,
    pub user_agent: String,
}

impl Config {
    pub fn default_from_home() -> Result<Self, IpaToolError> {
        let home = dirs::home_dir().ok_or_else(|| IpaToolError::NoHomeDir)?;
        let config_dir = home.join(".ipatool");
        let cookies_path = config_dir.join("cookies");

        Ok(Self {
            config_dir,
            cookies_path,
            keyring_service: "ipatool-auth.service".into(),
            keyring_account_key: "account".into(),
            // FIXME:needed ?/
            user_agent: crate::constants::DEFAULT_USER_AGENT.into(),
        })
    }

    pub fn ensure_dirs(&self) -> Result<(), IpaToolError> {
        if !Path::new(&self.config_dir).exists() {
            std::fs::create_dir_all(&self.config_dir)?;
        }
        Ok(())
    }
}
