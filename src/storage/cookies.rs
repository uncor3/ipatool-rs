use crate::error::Result;
use cookie_store::CookieStore;
use reqwest_cookie_store::CookieStoreMutex;
use std::{fs, path::PathBuf, sync::Arc};

#[derive(Clone)]
pub struct PersistentCookies {
    path: PathBuf,
    jar: Arc<CookieStoreMutex>,
}

impl PersistentCookies {
    pub fn load_or_new(path: PathBuf) -> Result<Self> {
        let store = if let Ok(bytes) = fs::read(&path) {
            serde_json::from_slice::<CookieStore>(&bytes).unwrap_or_else(|_| CookieStore::default())
        } else {
            CookieStore::default()
        };

        Ok(Self {
            path,
            jar: Arc::new(CookieStoreMutex::new(store)),
        })
    }

    pub fn jar(&self) -> Arc<CookieStoreMutex> {
        self.jar.clone()
    }

    pub fn save(&self) -> Result<()> {
        let guard = self.jar.lock().unwrap();
        let data = serde_json::to_vec(&*guard)?;
        fs::write(&self.path, data)?;
        Ok(())
    }
}
