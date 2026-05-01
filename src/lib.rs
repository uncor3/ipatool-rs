mod appstore;
mod config;
mod constants;
mod error;
mod http;
mod storage;
pub mod util;

use crate::appstore::types::{Account, ListVersionsResult};
use crate::error::Result;
use appstore::AppStoreClient;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct IpaTool {
    appstore: AppStoreClient,
}

#[derive(Debug, Clone)]
pub struct DownloadArgs {
    pub bundle_id: String,
    pub output_path: Option<String>,
    pub external_version_id: Option<String>,
    pub acquire_license: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadResult {
    pub destination_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub results: Vec<appstore::types::App>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionMetadataResult {
    pub app_id: u64,
    pub bundle_id: Option<String>,
    pub external_version_id: String,
    pub metadata: serde_json::Value,
}

impl IpaTool {
    pub async fn new_default() -> Result<Self> {
        let cfg = config::Config::default_from_home()?;
        let appstore = AppStoreClient::new(cfg).await?;
        Ok(Self { appstore })
    }

    pub async fn login(&self, email: &str, password: &str, auth_code: Option<&str>) -> Result<()> {
        self.appstore.login(email, password, auth_code).await
    }

    pub async fn account_info(&self) -> Result<Option<Account>> {
        self.appstore.load_account()
    }

    pub async fn revoke(&self) -> Result<()> {
        self.appstore.revoke().await
    }

    pub async fn search(&self, term: &str, limit: u32) -> Result<SearchResult> {
        let results = self.appstore.search(term, limit).await?;
        Ok(SearchResult { results })
    }

    pub async fn purchase(&self, bundle_id: &str) -> Result<()> {
        self.appstore.purchase(bundle_id).await
    }

    pub async fn download(&self, args: DownloadArgs) -> Result<String> {
        self.download_with_progress(args, |_downloaded, _total| {})
            .await
    }

    pub async fn download_with_progress<F>(&self, args: DownloadArgs, progress: F) -> Result<String>
    where
        F: FnMut(u64, Option<u64>) + Send,
    {
        self.appstore.download_with_progress(args, progress).await
    }

    pub async fn list_versions(
        &self,
        app_id: Option<u64>,
        bundle_id: Option<&str>,
    ) -> Result<ListVersionsResult> {
        self.appstore.list_versions(app_id, bundle_id).await
    }

    pub async fn get_version_metadata(
        &self,
        app_id: Option<u64>,
        bundle_id: Option<&str>,
        external_version_id: &str,
    ) -> Result<VersionMetadataResult> {
        self.appstore
            .get_version_metadata(app_id, bundle_id, external_version_id)
            .await
    }
}

pub mod prelude {
    // pub use crate::error::{Error, Result};
    pub use crate::{DownloadArgs, IpaTool};
}
