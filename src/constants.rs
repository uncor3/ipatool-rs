pub const FAILURE_TYPE_INVALID_CREDENTIALS: &str = "-5000";
pub const FAILURE_TYPE_PASSWORD_TOKEN_EXPIRED: &str = "2034";
pub const FAILURE_TYPE_LICENSE_NOT_FOUND: &str = "9610";
pub const FAILURE_TYPE_TEMPORARILY_UNAVAILABLE: &str = "2059";

pub const CUSTOMER_MESSAGE_BAD_LOGIN: &str = "MZFinance.BadLogin.Configurator_message";
pub const CUSTOMER_MESSAGE_ACCOUNT_DISABLED: &str = "Your account is disabled.";
pub const CUSTOMER_MESSAGE_SUBSCRIPTION_REQUIRED: &str = "Subscription Required";

// pub const ITUNES_API_DOMAIN: &str = "itunes.apple.com";
pub const ITUNES_API_SEARCH: &str = "https://itunes.apple.com/search";
pub const ITUNES_API_LOOKUP: &str = "https://itunes.apple.com/lookup";

pub const PRIVATE_INIT_URL: &str = "https://init.itunes.apple.com/bag.xml";

pub const PRIVATE_APPSTORE_DOMAIN: &str = "buy.itunes.apple.com";
pub const PRIVATE_PURCHASE_PATH: &str = "/WebObjects/MZFinance.woa/wa/buyProduct";
pub const PRIVATE_DOWNLOAD_PATH: &str = "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct";

pub const HEADER_STOREFRONT: &str = "X-Set-Apple-Store-Front";
pub const HEADER_POD: &str = "pod";

pub const PRICING_PARAMETER_APPSTORE: &str = "STDQ";
pub const PRICING_PARAMETER_APPLE_ARCADE: &str = "GAME";

pub const DEFAULT_USER_AGENT: &str =
    "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6";

pub const APPSTORE_AUTH_URL: &str =
    "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate";

pub const MAX_LOGIN_ATTEMPTS: u32 = 4;
