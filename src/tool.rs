use std::path::PathBuf;

use crate::api;
use crate::client::AppleClient;
use crate::credential::{CredentialBackend, CredentialStore};
use crate::error::{ClientError, IpaToolError, StoreError};
use crate::guid::generate_machine_identity;
use crate::model::storefront::country_code_from_store_front;
use crate::model::{Account, App, Platform};
use crate::{Result, ipa, sap};

#[derive(Debug, Clone)]
pub struct DownloadArgs {
    pub bundle_id: String,
    pub output_path: Option<String>,
    pub external_version_id: Option<String>,
    pub acquire_license: bool,
}

pub struct IpaTool {
    client: AppleClient,
    credentials: CredentialStore,
    state_dir: PathBuf,
}

impl IpaTool {
    pub fn new_default() -> Result<Self> {
        Self::new_default_with_passphrase(None)
    }

    pub fn new_default_with_passphrase(passphrase: Option<String>) -> Result<Self> {
        let identity = generate_machine_identity()?;
        let state_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".ipatool");
        create_private_state_dir(&state_dir)?;

        let client = AppleClient::new(
            identity,
            Some(&state_dir.join("cookies")),
            state_dir.join("cache"),
        )?;
        let credentials = CredentialStore::new(state_dir.clone(), passphrase);
        Ok(Self {
            client,
            credentials,
            state_dir,
        })
    }

    pub fn credential_backend(&self) -> CredentialBackend {
        self.credentials.backend()
    }

    pub fn requires_keyring_passphrase(&self) -> bool {
        self.credentials.requires_passphrase()
    }

    pub fn set_keyring_passphrase(&self, passphrase: String) -> Result<()> {
        self.credentials.set_passphrase(passphrase)
    }

    pub async fn login(
        &self,
        email: &str,
        password: &str,
        auth_code_cb: Option<Box<dyn Fn() -> Result<String> + Send + Sync>>,
        auth_code: Option<String>,
    ) -> Result<()> {
        let bag = api::bag::fetch_bag(&self.client).await?;
        let signer =
            sap::new_default_signer(&self.client, &bag.sap, self.client.hardware_id()).await?;

        let first = api::auth::login(
            &self.client,
            email,
            password,
            auth_code.as_deref(),
            &bag.auth_endpoint,
            Some(&signer),
        )
        .await;

        let mut account = match first {
            Ok(account) => account,
            Err(ClientError::Store(StoreError::AuthCodeRequired)) if auth_code.is_none() => {
                let callback = auth_code_cb.ok_or(IpaToolError::AuthCodeRequired)?;
                let code = callback()?;
                api::auth::login(
                    &self.client,
                    email,
                    password,
                    Some(&code),
                    &bag.auth_endpoint,
                    Some(&signer),
                )
                .await?
            }
            Err(error) => return Err(error.into()),
        };

        account.password = Some(password.to_string());
        self.credentials.store_account(&account)?;
        self.client.save_cookies(&self.state_dir.join("cookies"))?;
        Ok(())
    }

    pub fn account_info(&self) -> Result<Option<Account>> {
        self.credentials.load_account()
    }

    pub fn revoke(&self) -> Result<()> {
        self.credentials.delete_account()
    }

    pub async fn search(&self, term: &str, limit: u32) -> Result<Vec<App>> {
        self.search_for_platform(term, limit, Platform::IPhone)
            .await
    }

    pub async fn search_for_platform(
        &self,
        term: &str,
        limit: u32,
        platform: Platform,
    ) -> Result<Vec<App>> {
        let country = self.country()?;
        Ok(api::search::search(&self.client, term, country, platform, limit).await?)
    }

    pub async fn purchase(&self, bundle_id: &str) -> Result<()> {
        let mut account = self.require_account()?;
        let app = self.lookup(bundle_id, &account).await?;
        if let Err(error) = api::purchase::purchase(&self.client, app.id, &account).await {
            if error.is_token_expired() {
                account = self.reauthenticate(&account).await?;
                api::purchase::purchase(&self.client, app.id, &account).await?;
            } else {
                return Err(error.into());
            }
        }
        Ok(())
    }

    pub async fn download_with_progress<F>(&self, args: DownloadArgs, progress: F) -> Result<String>
    where
        F: FnMut(u64, Option<u64>) + Send,
    {
        self.download_for_platform_with_progress(args, Platform::IPhone, progress)
            .await
    }

    pub async fn download_for_platform_with_progress<F>(
        &self,
        args: DownloadArgs,
        platform: Platform,
        progress: F,
    ) -> Result<String>
    where
        F: FnMut(u64, Option<u64>) + Send,
    {
        let account = self.require_account()?;
        let country = country_code_from_store_front(&account.store_front).unwrap_or("US");
        let app = api::lookup::lookup(&self.client, &args.bundle_id, country, platform)
            .await?
            .ok_or_else(|| IpaToolError::AppNotFound(args.bundle_id.clone()))?;
        self.download_resolved_app(args, app, account, platform, progress)
            .await
    }

    /// Numeric IDs allow redownloading owned apps no longer publicly listed.
    /// An optional bundle_id in args is still checked against Apple metadata.
    pub async fn download_by_id_with_progress<F>(
        &self,
        app_id: i64,
        args: DownloadArgs,
        progress: F,
    ) -> Result<String>
    where
        F: FnMut(u64, Option<u64>) + Send,
    {
        self.download_by_id_for_platform_with_progress(app_id, args, Platform::IPhone, progress)
            .await
    }

    pub async fn download_by_id_for_platform_with_progress<F>(
        &self,
        app_id: i64,
        args: DownloadArgs,
        platform: Platform,
        progress: F,
    ) -> Result<String>
    where
        F: FnMut(u64, Option<u64>) + Send,
    {
        if app_id <= 0 {
            return Err(IpaToolError::Unexpected("app ID must be positive".into()));
        }
        let account = self.require_account()?;
        let app = api::platform_version::delisted_app(app_id, &args.bundle_id);
        self.download_resolved_app(args, app, account, platform, progress)
            .await
    }

    async fn download_resolved_app<F>(
        &self,
        args: DownloadArgs,
        app: App,
        mut account: Account,
        platform: Platform,
        mut progress: F,
    ) -> Result<String>
    where
        F: FnMut(u64, Option<u64>) + Send,
    {
        let mut item = api::download::get_download_info_for_app(
            &self.client,
            &app,
            &account,
            args.external_version_id.as_deref(),
            platform,
        )
        .await;

        if matches!(&item, Err(error) if error.is_token_expired()) {
            account = self.reauthenticate(&account).await?;
            item = api::download::get_download_info_for_app(
                &self.client,
                &app,
                &account,
                args.external_version_id.as_deref(),
                platform,
            )
            .await;
        }
        if matches!(&item, Err(error) if error.is_license_not_found()) && args.acquire_license {
            api::purchase::purchase(&self.client, app.id, &account).await?;
            item = api::download::get_download_info_for_app(
                &self.client,
                &app,
                &account,
                args.external_version_id.as_deref(),
                platform,
            )
            .await;
        }
        let item = item?;

        let destination = args.output_path.map(PathBuf::from).unwrap_or_else(|| {
            PathBuf::from(format!(
                "{}.ipa",
                if args.bundle_id.is_empty() {
                    app.id.to_string()
                } else {
                    args.bundle_id
                }
            ))
        });
        let raw = destination.with_extension("ipa.download");
        api::download::download_file(&self.client, &item.url, &raw, &mut progress).await?;
        ipa::platform::validate_package(&raw, platform)?;
        ipa::patch::patch_ipa(&raw, &destination, &item, &account.email)?;
        std::fs::remove_file(&raw)?;
        Ok(destination.to_string_lossy().into_owned())
    }

    pub async fn list_versions(
        &self,
        app_id: Option<u64>,
        bundle_id: Option<&str>,
    ) -> Result<api::versions::ListVersionsOutput> {
        let account = self.require_account()?;
        let id = self.resolve_app_id(app_id, bundle_id, &account).await?;
        Ok(api::versions::list_versions(&self.client, id, &account).await?)
    }

    pub async fn get_version_metadata(
        &self,
        app_id: Option<u64>,
        bundle_id: Option<&str>,
        external_version_id: &str,
    ) -> Result<api::versions::VersionMetadata> {
        let account = self.require_account()?;
        let id = self.resolve_app_id(app_id, bundle_id, &account).await?;
        Ok(
            api::versions::get_version_metadata(&self.client, id, &account, external_version_id)
                .await?,
        )
    }

    fn require_account(&self) -> Result<Account> {
        self.credentials
            .load_account()?
            .ok_or(IpaToolError::NoSavedAccount)
    }

    fn country(&self) -> Result<&'static str> {
        let account = self.credentials.load_account()?;
        Ok(account
            .as_ref()
            .and_then(|account| country_code_from_store_front(&account.store_front))
            .unwrap_or("US"))
    }

    async fn lookup(&self, bundle_id: &str, account: &Account) -> Result<App> {
        let country = country_code_from_store_front(&account.store_front).unwrap_or("US");
        api::lookup::lookup(&self.client, bundle_id, country, Platform::IPhone)
            .await?
            .ok_or_else(|| IpaToolError::AppNotFound(bundle_id.to_string()))
    }

    async fn resolve_app_id(
        &self,
        app_id: Option<u64>,
        bundle_id: Option<&str>,
        account: &Account,
    ) -> Result<i64> {
        if let Some(bundle_id) = bundle_id {
            return Ok(self.lookup(bundle_id, account).await?.id);
        }
        let id = app_id.ok_or(IpaToolError::MissingAppIdOrBundleId)?;
        i64::try_from(id).map_err(|_| IpaToolError::Unexpected("app ID is too large".into()))
    }

    async fn reauthenticate(&self, account: &Account) -> Result<Account> {
        let refreshed = api::reauth::reauthenticate(&self.client, account).await?;
        self.credentials.store_account(&refreshed)?;
        Ok(refreshed)
    }
}

fn create_private_state_dir(path: &std::path::Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}
