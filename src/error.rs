use std::collections::HashMap;

pub type Result<T> = std::result::Result<T, IpaToolError>;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("password token expired")]
    PasswordTokenExpired,
    #[error("sign-in required")]
    SignInRequired,
    #[error("license not found")]
    LicenseNotFound,
    #[error("temporarily unavailable")]
    TemporarilyUnavailable,
    #[error("purchase couldn't be completed")]
    PurchaseFailed,
    #[error("license already exists")]
    LicenseAlreadyExists,
    #[error("device verification failed")]
    DeviceVerificationFailed,
    #[error("login rejected; password may be wrong or a 2FA code may be required")]
    AuthCodeRequired,
    #[error("account disabled")]
    AccountDisabled,
    #[error("rate limited (HTTP 429)")]
    RateLimited,
    #[error("Apple store error: {code} — {message}")]
    Unknown { code: String, message: String },
}

impl StoreError {
    pub fn from_failure(failure_type: &str, customer_message: Option<&str>) -> Self {
        match failure_type {
            "-5000" => Self::InvalidCredentials,
            "2034" => Self::PasswordTokenExpired,
            "2042" => Self::SignInRequired,
            "9610" => Self::LicenseNotFound,
            // TODO: substring matching on customerMessage is locale-dependent; find a more stable signal
            "2059" => {
                let msg = customer_message.unwrap_or("");
                if msg.contains("completed") || msg.contains("not available") {
                    Self::PurchaseFailed
                } else {
                    Self::TemporarilyUnavailable
                }
            }
            "5002" => Self::LicenseAlreadyExists,
            "1008" => Self::DeviceVerificationFailed,
            "" => {
                let msg = customer_message.unwrap_or("");
                if msg.contains("BadLogin") || msg.contains("MZFinance.BadLogin") {
                    Self::AuthCodeRequired
                } else if msg.contains("disabled") {
                    Self::AccountDisabled
                } else {
                    Self::Unknown {
                        code: String::new(),
                        message: msg.to_string(),
                    }
                }
            }
            code => Self::Unknown {
                code: code.to_string(),
                message: customer_message.unwrap_or("").to_string(),
            },
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::InvalidCredentials)
    }

    pub fn is_token_expired(&self) -> bool {
        matches!(
            self,
            Self::PasswordTokenExpired | Self::SignInRequired | Self::DeviceVerificationFailed
        )
    }

    pub fn from_plist_dict(dict: &HashMap<String, plist::Value>) -> Option<Self> {
        let failure_type = dict.get("failureType").and_then(|v| match v {
            plist::Value::String(s) => Some(s.as_str()),
            plist::Value::Integer(_) => None,
            _ => None,
        });

        let failure_type_str = match &failure_type {
            Some(s) => *s,
            None => {
                if let Some(plist::Value::Integer(i)) = dict.get("failureType") {
                    return Some(Self::from_failure(
                        &i.as_signed().map_or_else(String::new, |v| v.to_string()),
                        dict.get("customerMessage").and_then(|v| v.as_string()),
                    ));
                }
                return None;
            }
        };

        Some(Self::from_failure(
            failure_type_str,
            dict.get("customerMessage").and_then(|v| v.as_string()),
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("iOS catalog lookup returned HTTP 404")]
    IOSCatalogAppNotFound,
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    PlistDe(#[from] plist::Error),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("missing header: {0}")]
    MissingHeader(String),
    #[error("unexpected response: {0}")]
    UnexpectedResponse(String),
    #[error("cookie store: {0}")]
    CookieStore(String),
    #[error("SAP: {0}")]
    Sap(String),
    #[error(
        "Apple rejected the sign-in request because it carried no action signature (HTTP {status}). \
         Since 2026-08 Apple's bag lists MZFinance/authenticate under sign-sap-request, so sign-in \
         requires an X-Apple-ActionSignature header that this build cannot produce yet."
    )]
    SapSignatureRequired { status: u16 },
}

impl ClientError {
    pub fn is_token_expired(&self) -> bool {
        matches!(self, Self::Store(e) if e.is_token_expired())
    }

    pub fn is_license_not_found(&self) -> bool {
        matches!(self, Self::Store(StoreError::LicenseNotFound))
    }

    pub fn is_license_already_exists(&self) -> bool {
        matches!(self, Self::Store(StoreError::LicenseAlreadyExists))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IpaToolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("property list error: {0}")]
    Plist(#[from] plist::Error),

    #[error("ZIP archive error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("credential store error: {0}")]
    Keyring(#[from] keyring::Error),

    #[error("the ipatool account requires a keyring passphrase")]
    KeyringPassphraseRequired,

    #[error("the keyring passphrase is incorrect")]
    IncorrectKeyringPassphrase,

    #[error("the encrypted ipatool account is damaged or unsupported: {0}")]
    InvalidEncryptedAccount(String),

    #[error("could not access the ipatool account store: {0}")]
    AccountStore(String),

    #[error("could not read the ipatool cookie store: {0}")]
    CookieStore(String),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("app not found: {0}")]
    AppNotFound(String),

    #[error("no saved account found")]
    NoSavedAccount,

    #[error("an app ID or bundle identifier must be specified")]
    MissingAppIdOrBundleId,

    #[error("no MAC address available")]
    NoGuid,

    #[error("authentication code is required")]
    AuthCodeRequired,

    #[error("password token expired")]
    PasswordTokenExpired,

    #[error("an App Store license is required")]
    LicenseRequired,

    #[error("the App Store license already exists")]
    LicenseAlreadyExists,

    #[error("item is temporarily unavailable")]
    TemporarilyUnavailable,

    #[error("missing response header: {0}")]
    MissingHeader(String),

    #[error("unexpected response from Apple: {0}")]
    UnexpectedResponse(String),

    #[error("missing data: {thing}")]
    MissingData { thing: String },

    #[error("SAP error: {0}")]
    Sap(String),

    #[error("{0}")]
    Unexpected(String),
}

impl From<ClientError> for IpaToolError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::IOSCatalogAppNotFound => Self::AppNotFound("iOS catalog".into()),
            ClientError::Http(error) => Self::Http(error),
            ClientError::PlistDe(error) => Self::Plist(error),
            ClientError::Store(StoreError::AuthCodeRequired) => Self::AuthCodeRequired,
            ClientError::Store(
                StoreError::PasswordTokenExpired
                | StoreError::SignInRequired
                | StoreError::DeviceVerificationFailed,
            ) => Self::PasswordTokenExpired,
            ClientError::Store(StoreError::LicenseNotFound) => Self::LicenseRequired,
            ClientError::Store(StoreError::LicenseAlreadyExists) => Self::LicenseAlreadyExists,
            ClientError::Store(StoreError::TemporarilyUnavailable) => Self::TemporarilyUnavailable,
            ClientError::Store(error) => Self::Unexpected(error.to_string()),
            ClientError::MissingHeader(header) => Self::MissingHeader(header),
            ClientError::UnexpectedResponse(message) => Self::UnexpectedResponse(message),
            ClientError::CookieStore(message) => Self::CookieStore(message),
            ClientError::Sap(message) => Self::Sap(message),
            ClientError::SapSignatureRequired { status } => Self::Sap(format!(
                "Apple rejected the unsigned sign-in request with HTTP {status}"
            )),
        }
    }
}
