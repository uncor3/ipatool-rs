pub mod types;

mod bag;
mod download;
mod login;
mod purchase;
mod search;
mod version_metadata;
mod versions;

use crate::{
    config::Config,
    error::IpaToolError,
    error::Result,
    http::client::Http,
    storage::{cookies::PersistentCookies, keyring::KeyringStore},
    util::guid_from_mac,
};

use types::{Account, ListVersionsResult};

#[derive(Clone)]
pub struct AppStoreClient {
    // FIXME: do we need cfg ?
    #[allow(dead_code)]
    cfg: Config,
    http: Http,
    keyring: KeyringStore,
    guid: String,
}

impl AppStoreClient {
    pub fn new(cfg: Config) -> Result<Self> {
        cfg.ensure_dirs()?;
        let cookies = PersistentCookies::load_or_new(cfg.cookies_path.clone());
        let http = Http::new(cfg.user_agent.clone(), cookies)?;
        let keyring =
            KeyringStore::new(cfg.keyring_service.clone(), cfg.keyring_account_key.clone());
        let guid = guid_from_mac()?;

        Ok(Self {
            cfg,
            http,
            keyring,
            guid,
        })
    }

    pub fn load_account(&self) -> Result<Option<Account>> {
        self.keyring.get_json::<Account>()
    }

    pub fn require_account(&self) -> Result<Account> {
        match self.keyring.get_json::<Account>()? {
            Some(acc) => Ok(acc),
            None => Err(IpaToolError::NoSavedAccount),
        }
    }

    pub fn revoke(&self) -> Result<()> {
        self.keyring.delete()?;
        Ok(())
    }

    pub async fn login(
        &self,
        email: &str,
        password: &str,
        auth_code_cb: Option<Box<dyn Fn() -> Result<String> + Send + Sync>>,
        auth_code: Option<String>,
    ) -> Result<()> {
        let endpoint = bag::fetch_auth_endpoint(&self.http, &self.guid).await?;

        let account = login::login(
            &self.http,
            &self.keyring,
            &self.guid,
            endpoint,
            email,
            password,
            auth_code_cb,
            auth_code,
        )
        .await?;
        self.keyring.set_json(&account)?;
        Ok(())
    }

    async fn refresh_account(&self, account: &Account) -> Result<Account> {
        let endpoint = bag::fetch_auth_endpoint(&self.http, &self.guid).await?;
        let refreshed = login::login(
            &self.http,
            &self.keyring,
            &self.guid,
            endpoint,
            &account.email,
            &account.password,
            None,
            None,
        )
        .await?;
        self.keyring.set_json(&refreshed)?;
        Ok(refreshed)
    }

    pub async fn search(&self, term: &str, limit: u32) -> Result<Vec<types::App>> {
        search::search(&self.http, term, limit).await
    }

    pub async fn lookup(&self, bundle_id: &str) -> Result<types::App> {
        search::lookup_by_bundle_id(&self.http, bundle_id).await
    }

    pub async fn purchase(&self, bundle_id: &str) -> Result<()> {
        let acc = self.require_account()?;
        let app = self.lookup(bundle_id).await?;

        match purchase::purchase(&self.http, &self.guid, &acc, &app).await {
            Ok(()) | Err(IpaToolError::LicenseAlreadyExists) => Ok(()),
            Err(IpaToolError::PasswordTokenExpired) => {
                let new_acc = self.refresh_account(&acc).await?;
                match purchase::purchase(&self.http, &self.guid, &new_acc, &app).await {
                    Ok(()) | Err(IpaToolError::LicenseAlreadyExists) => Ok(()),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    #[allow(dead_code)]
    pub async fn download(&self, args: crate::DownloadArgs) -> Result<String> {
        self.download_with_progress(args, |_downloaded, _total| {})
            .await
    }

    pub async fn download_with_progress<F>(
        &self,
        args: crate::DownloadArgs,
        mut progress: F,
    ) -> Result<String>
    where
        F: FnMut(u64, Option<u64>) + Send,
    {
        let mut acc = self.require_account()?;
        let app = self.lookup(&args.bundle_id).await?;
        let mut refreshed_account = false;
        let mut attempted_purchase = false;

        loop {
            match download::download_ipa(
                &self.http,
                &self.guid,
                &acc,
                &app,
                args.output_path.as_deref(),
                args.external_version_id.as_deref(),
                &mut progress,
            )
            .await
            {
                Ok(path) => return Ok(path),
                Err(IpaToolError::PasswordTokenExpired) if !refreshed_account => {
                    acc = self.refresh_account(&acc).await?;
                    refreshed_account = true;
                }
                Err(IpaToolError::LicenseRequired)
                    if args.acquire_license && !attempted_purchase =>
                {
                    match purchase::purchase(&self.http, &self.guid, &acc, &app).await {
                        Ok(()) | Err(IpaToolError::LicenseAlreadyExists) => {
                            attempted_purchase = true;
                        }
                        Err(IpaToolError::PasswordTokenExpired) if !refreshed_account => {
                            acc = self.refresh_account(&acc).await?;
                            refreshed_account = true;
                        }
                        Err(err) => return Err(err),
                    }
                }
                Err(err) => return Err(err),
            }
        }
    }

    //FIXME
    pub async fn list_versions(
        &self,
        app_id: Option<u64>,
        bundle_id: Option<&str>,
    ) -> Result<ListVersionsResult> {
        let acc = self.require_account()?;

        let app = match (app_id, bundle_id) {
            (_, Some(b)) => self.lookup(b).await?,
            (Some(id), None) => types::App {
                id,
                bundle_id: None,
                name: None,
                price: None,
            },
            (None, None) => return Err(IpaToolError::MissingAppIdOrBundleId),
        };

        match versions::list_versions(acc, app, self.guid.clone(), &self.http).await {
            Ok(_) => {
                print!("OP WAS SUCCESS")
            }
            Err(e) => {
                println!("err {}", e)
            }
        }
        Ok(ListVersionsResult {
            app_id: app_id.unwrap_or(0),
            bundle_id: bundle_id.map(|s| s.to_string()),
            external_version_ids: vec![],
            note: Some("not implemented".into()),
        })
    }

    pub async fn get_version_metadata(
        &self,
        app_id: Option<u64>,
        bundle_id: Option<&str>,
        external_version_id: &str,
    ) -> Result<crate::VersionMetadataResult> {
        let mut acc = self.require_account()?;
        let app = match (app_id, bundle_id) {
            (_, Some(b)) => self.lookup(b).await?,
            (Some(id), None) => types::App {
                id,
                bundle_id: None,
                name: None,
                price: None,
            },
            (None, None) => {
                return Err(IpaToolError::MissingAppIdOrBundleId);
            }
        };
        let metadata =
            match version_metadata::get(&self.http, &self.guid, &acc, &app, external_version_id)
                .await
            {
                Ok(metadata) => metadata,
                Err(IpaToolError::PasswordTokenExpired) => {
                    acc = self.refresh_account(&acc).await?;
                    version_metadata::get(&self.http, &self.guid, &acc, &app, external_version_id)
                        .await?
                }
                Err(error) => return Err(error),
            };

        Ok(crate::VersionMetadataResult {
            app_id: app.id,
            bundle_id: app.bundle_id.clone(),
            external_version_id: external_version_id.to_string(),
            metadata,
        })
    }
}
