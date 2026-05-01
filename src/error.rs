use keyring::error;
use mac_address::MacAddressError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, IpaToolError>;

#[derive(Error, Debug)]
pub enum IpaToolError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Failed to init defualt")]
    InitError,

    #[error("could not resolve home directory")]
    NoHomeDir,

    #[error("failed to get acount info")]
    ErrorAccount,

    #[error("auth code is required")]
    AuthCodeRequired,

    #[error("password token is expired")]
    PasswordTokenExpired,

    #[error("license is required")]
    LicenseRequired,

    #[error("subscription required")]
    SubscriptionRequired,

    #[error("item is temporarily unavailable")]
    TemporarilyUnavailable,

    #[error("purchasing paid apps is not supported")]
    PaidAppsNotSupported,

    #[error("no saved account found")]
    NoSavedAccount,

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("plist error: {0}")]
    Plist(#[from] plist::Error),

    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("keyring error: {0}")]
    Keyring(String),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("unexpected response: {0}")]
    Unexpected(String),

    #[error("either app_id or bundle_identifier must be specified")]
    MissingAppIdOrBundleId,

    #[error(transparent)]
    MacAddress(#[from] MacAddressError),

    #[error("empty mac address")]
    EmptyMacAddress,

    #[error("bag did not contain authenticateAccount")]
    AuthBagError,

    // #[error(transparent)]
    // Reqwest(#[from] reqwest::Error),
    #[error("operation failed with http status {status}")]
    HttpStatus { status: reqwest::StatusCode },

    #[error("missing data: {thing}")]
    MissingData { thing: String },

    #[error("missing sinf target")]
    NoSinfTarget,

    #[error("empty response")]
    EmptyResponse,

    #[error("app not found")]
    NoApp,
}

impl From<keyring::Error> for IpaToolError {
    fn from(e: keyring::Error) -> Self {
        Self::Keyring(e.to_string())
    }
}
