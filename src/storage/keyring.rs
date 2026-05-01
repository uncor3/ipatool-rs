use crate::error::{IpaToolError, Result};
use serde::{Serialize, de::DeserializeOwned};

#[derive(Clone)]
pub struct KeyringStore {
    service: String,
    account_key: String,
}

// unfortunately the keyring crate doesn't work the same way as the one in golang
// we may need to rewrite keyring from scratch to match the golang one, maybe?
//
// ❯ lssecret
// Collection:	Login

// Item:	account@ipatool-auth.service:default (keyring v3.6.3)
// Key:	application
// Value:	rust-keyring
// Key:	xdg:schema
// Value:	org.freedesktop.Secret.Generic
// Key:	service
// Value:	ipatool-auth.service
// Key:	target
// Value:	default
// Key:	username
// Value:	account

// Collection:

// Collection:	ipatool-auth.service

// Item:	account
// Key:	profile
// Value:	account
//
impl KeyringStore {
    pub fn new(service: String, account_key: String) -> Self {
        Self {
            service,
            account_key,
        }
    }

    pub fn set_json<T: Serialize>(&self, value: &T) -> Result<()> {
        let entry = keyring::Entry::new(&self.service, &self.account_key)?;
        let data = serde_json::to_string(value)?;
        entry.set_password(&data)?;
        Ok(())
    }

    pub fn get_json<T: DeserializeOwned>(&self) -> Result<Option<T>> {
        let entry = keyring::Entry::new(&self.service, &self.account_key)?;
        let s = match entry.get_password() {
            Ok(s) => s,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let value = serde_json::from_str(&s)?;
        Ok(Some(value))
    }

    pub fn delete(&self) -> Result<()> {
        let entry = keyring::Entry::new(&self.service, &self.account_key)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(IpaToolError::Keyring(e.to_string())),
        }
    }
}
