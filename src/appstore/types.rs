use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub name: String,
    pub email: String,
    pub password_token: String,
    pub directory_services_id: String,
    pub store_front: String,
    pub password: String,
    pub pod: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BagResult {
    #[serde(rename = "urlBag")]
    pub url_bag: UrlBag,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UrlBag {
    #[serde(rename = "authenticateAccount")]
    pub auth_endpoint: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginResult {
    #[serde(rename = "failureType")]
    pub failure_type: Option<String>,
    #[serde(rename = "customerMessage")]
    pub customer_message: Option<String>,
    #[serde(rename = "accountInfo")]
    pub account: Option<LoginAccountResult>,
    #[serde(rename = "dsPersonId")]
    pub directory_services_id: Option<String>,
    #[serde(rename = "passwordToken")]
    pub password_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginAccountResult {
    #[serde(rename = "appleId")]
    pub email: Option<String>,
    pub address: Option<LoginAddressResult>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginAddressResult {
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PurchaseResult {
    #[serde(rename = "failureType")]
    pub failure_type: Option<String>,
    #[serde(rename = "customerMessage")]
    pub customer_message: Option<String>,
    #[serde(rename = "jingleDocType")]
    pub jingle_doc_type: Option<String>,
    pub status: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DownloadResult {
    #[serde(rename = "failureType")]
    pub failure_type: Option<String>,
    #[serde(rename = "customerMessage")]
    pub customer_message: Option<String>,
    #[serde(rename = "songList")]
    pub items: Option<Vec<DownloadItem>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Sinf {
    #[allow(dead_code)]
    #[serde(rename = "id")]
    pub id: Option<i64>,
    #[serde(rename = "sinf")]
    pub data: Option<plist::Data>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DownloadItem {
    #[allow(dead_code)]
    #[serde(rename = "md5")]
    pub md5: Option<String>,
    #[serde(rename = "URL")]
    pub url: Option<String>,
    #[serde(rename = "metadata")]
    pub metadata: Option<BTreeMap<String, plist::Value>>,
    #[serde(rename = "sinfs")]
    pub sinfs: Option<Vec<Sinf>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListVersionsResult {
    pub app_id: u64,
    pub bundle_id: Option<String>,
    pub external_version_ids: Vec<String>,
    pub note: Option<String>,
}
