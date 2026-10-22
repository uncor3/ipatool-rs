use std::collections::HashMap;
use std::path::Path;

use futures_util::StreamExt;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;

use crate::client::AppleClient;
use crate::error::{ClientError, StoreError};
use crate::model::{Account, App, Platform};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadEndpoint {
    VolumeStore,
    Redownload,
    Update,
}

impl DownloadEndpoint {
    fn version_key(self) -> &'static str {
        match self {
            Self::VolumeStore => "externalVersionId",
            Self::Redownload | Self::Update => "appExtVrsId",
        }
    }
}

struct DownloadResponse {
    status: reqwest::StatusCode,
    body: Vec<u8>,
    dict: Option<HashMap<String, plist::Value>>,
}

#[derive(Debug, Deserialize)]
pub struct DownloadItem {
    #[serde(rename = "URL")]
    pub url: String,
    pub sinfs: Vec<Sinf>,
    #[serde(default)]
    pub metadata: HashMap<String, plist::Value>,
}

impl DownloadItem {
    pub fn latest_external_version_id(&self) -> Option<String> {
        metadata_string(
            &self.metadata,
            &[
                "softwareVersionExternalIdentifier",
                "externalVersionIdentifier",
            ],
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Sinf {
    pub id: i64,
    #[serde(with = "serde_bytes")]
    pub sinf: Vec<u8>,
}

mod serde_bytes {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = plist::Value::deserialize(deserializer)?;
        match val {
            plist::Value::Data(d) => Ok(d),
            _ => Err(serde::de::Error::custom("expected data")),
        }
    }
}

const MAX_DOWNLOAD_ATTEMPTS: u32 = 3;

pub async fn get_download_info(
    client: &AppleClient,
    app_id: i64,
    account: &Account,
    external_version_id: Option<&str>,
) -> Result<DownloadItem, ClientError> {
    get_download_info_for_identity(
        client,
        app_id,
        None,
        account,
        external_version_id,
        Platform::IPhone,
    )
    .await
}

pub(crate) async fn get_download_info_for_app(
    client: &AppleClient,
    app: &App,
    account: &Account,
    external_version_id: Option<&str>,
    platform: Platform,
) -> Result<DownloadItem, ClientError> {
    get_download_info_for_identity(
        client,
        app.id,
        Some(&app.bundle_id),
        account,
        external_version_id,
        platform,
    )
    .await
}

async fn get_download_info_for_identity(
    client: &AppleClient,
    app_id: i64,
    bundle_id: Option<&str>,
    account: &Account,
    external_version_id: Option<&str>,
    platform: Platform,
) -> Result<DownloadItem, ClientError> {
    for attempt in 0..MAX_DOWNLOAD_ATTEMPTS {
        match try_get_download_info(
            client,
            app_id,
            bundle_id,
            account,
            external_version_id,
            platform,
        )
        .await
        {
            Err(ClientError::Store(StoreError::TemporarilyUnavailable))
                if attempt + 1 < MAX_DOWNLOAD_ATTEMPTS =>
            {
                let delay = 5 * (attempt as u64 + 1);
                tracing::warn!(
                    attempt = attempt + 1,
                    delay,
                    "temporarily unavailable, retrying"
                );
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            }
            other => return other,
        }
    }
    Err(ClientError::Store(StoreError::TemporarilyUnavailable))
}

async fn try_get_download_info(
    client: &AppleClient,
    app_id: i64,
    bundle_id: Option<&str>,
    account: &Account,
    external_version_id: Option<&str>,
    platform: Platform,
) -> Result<DownloadItem, ClientError> {
    let platform_version = if external_version_id.is_none()
        && matches!(platform, Platform::WatchOS | Platform::AppleTV)
    {
        Some(
            crate::api::platform_version::lookup_latest_version(
                client, app_id, bundle_id, account, platform,
            )
            .await?,
        )
    } else {
        None
    };
    let external_version_id = external_version_id.or(platform_version.as_deref());
    let legacy = send_download_request(
        client,
        download_url(account, client.guid()),
        DownloadEndpoint::VolumeStore,
        app_id,
        account,
        external_version_id,
    )
    .await?;

    if !response_needs_fallback(&legacy) {
        return download_item_from_response(legacy);
    }

    tracing::debug!("legacy download endpoint returned no item; trying redownload endpoint");
    let bag = crate::api::bag::fetch_bag(client).await?;
    let Some(mut redownload_url) = bag.redownload_endpoint else {
        return download_item_from_response(legacy);
    };
    redownload_url
        .query_pairs_mut()
        .append_pair("guid", client.guid());

    let resolved_version = match external_version_id.filter(|version| !version.is_empty()) {
        Some(version) => Some(version.to_string()),
        None => match crate::api::platform_version::lookup_latest_version(
            client, app_id, bundle_id, account, platform,
        )
        .await
        {
            Ok(version) => Some(version),
            // Only an explicit catalog 404 permits an unpinned redownload.
            // Empty/malformed metadata and transport failures remain errors.
            Err(ClientError::IOSCatalogAppNotFound) => None,
            Err(error) => return Err(error),
        },
    };
    let external_version_id = resolved_version.as_deref();

    let redownload = send_download_request(
        client,
        redownload_url.to_string(),
        DownloadEndpoint::Redownload,
        app_id,
        account,
        external_version_id,
    )
    .await?;

    if external_version_id.is_some()
        && response_needs_update_fallback(&redownload)
        && let Some(mut update_url) = bag.update_endpoint
    {
        tracing::debug!("redownload endpoint returned no item; trying update endpoint");
        update_url
            .query_pairs_mut()
            .append_pair("guid", client.guid());
        let update = send_download_request(
            client,
            update_url.to_string(),
            DownloadEndpoint::Update,
            app_id,
            account,
            external_version_id,
        )
        .await?;
        return validated_download_item(update, app_id, bundle_id, external_version_id);
    }

    validated_download_item(redownload, app_id, bundle_id, external_version_id)
}

fn validated_download_item(
    response: DownloadResponse,
    app_id: i64,
    bundle_id: Option<&str>,
    version: Option<&str>,
) -> Result<DownloadItem, ClientError> {
    if let Some(dict) = response.dict.as_ref()
        && StoreError::from_plist_dict(dict).is_none()
        && dict
            .get("songList")
            .and_then(plist::Value::as_array)
            .is_some_and(|items| items.len() != 1)
    {
        return Err(ClientError::UnexpectedResponse(
            "download response must contain exactly one item".into(),
        ));
    }
    let item = download_item_from_response(response)?;
    validate_download_identity(&item, app_id, bundle_id, version)?;
    Ok(item)
}

fn validate_download_identity(
    item: &DownloadItem,
    app_id: i64,
    bundle_id: Option<&str>,
    version: Option<&str>,
) -> Result<(), ClientError> {
    let invalid =
        |message: &str| ClientError::UnexpectedResponse(format!("download response {message}"));
    if metadata_string(&item.metadata, &["itemId"]).as_deref() != Some(app_id.to_string().as_str())
    {
        return Err(invalid("does not match the requested app"));
    }
    if let Some(version) = version
        && item.latest_external_version_id().as_deref() != Some(version)
    {
        return Err(invalid("does not match the requested version"));
    }
    let returned_bundle_id = metadata_string(&item.metadata, &["softwareVersionBundleId"])
        .filter(|id| !id.is_empty())
        .ok_or_else(|| invalid("has no bundle identifier"))?;
    if bundle_id
        .filter(|id| !id.is_empty())
        .is_some_and(|id| id != returned_bundle_id)
    {
        return Err(invalid("does not match the requested bundle identifier"));
    }
    if item.url.is_empty() {
        return Err(invalid("has no package URL"));
    }
    Ok(())
}

async fn send_download_request(
    client: &AppleClient,
    url: String,
    endpoint: DownloadEndpoint,
    app_id: i64,
    account: &Account,
    external_version_id: Option<&str>,
) -> Result<DownloadResponse, ClientError> {
    let body = download_request_body(endpoint, app_id, client.guid(), external_version_id);

    let mut body_bytes = Vec::new();
    plist::to_writer_xml(&mut body_bytes, &body)
        .map_err(|e| ClientError::UnexpectedResponse(format!("plist serialize: {e}")))?;

    tracing::debug!(
        %url,
        endpoint = ?endpoint,
        "download request"
    );

    let resp = client
        .http()
        .post(&url)
        .header("Content-Type", "application/x-apple-plist")
        .header("iCloud-DSID", &account.directory_services_id)
        .header("X-Dsid", &account.directory_services_id)
        .timeout(std::time::Duration::from_secs(30))
        .body(body_bytes)
        .send()
        .await?;

    let status = resp.status();
    tracing::debug!(%status, endpoint = ?endpoint, "download response status");

    let resp_body = resp.bytes().await?;
    let dict = if resp_body.is_empty() {
        None
    } else {
        Some(crate::client::plist_xml::parse_plist_response(&resp_body)?)
    };

    Ok(DownloadResponse {
        status,
        body: resp_body.to_vec(),
        dict,
    })
}

fn download_item_from_response(response: DownloadResponse) -> Result<DownloadItem, ClientError> {
    if response.status != reqwest::StatusCode::OK {
        return Err(ClientError::UnexpectedResponse(format!(
            "download request failed with HTTP {}",
            response.status
        )));
    }
    let dict = response.dict.ok_or_else(|| {
        ClientError::UnexpectedResponse(format!(
            "empty download response (HTTP {})",
            response.status
        ))
    })?;

    download_item_from_response_dict(&dict)
}

fn response_needs_fallback(response: &DownloadResponse) -> bool {
    response.status == reqwest::StatusCode::OK
        && response
            .dict
            .as_ref()
            .is_some_and(is_empty_or_unavailable_download_response)
}

fn response_needs_update_fallback(response: &DownloadResponse) -> bool {
    (response.status == reqwest::StatusCode::INTERNAL_SERVER_ERROR && response.body.is_empty())
        || (response.status == reqwest::StatusCode::OK
            && response
                .dict
                .as_ref()
                .is_some_and(is_unavailable_download_response))
}

fn is_empty_or_unavailable_download_response(dict: &HashMap<String, plist::Value>) -> bool {
    is_empty_download_response(dict) || is_unavailable_download_response(dict)
}

fn is_empty_download_response(dict: &HashMap<String, plist::Value>) -> bool {
    if dict.contains_key("failureType") {
        return false;
    }

    let is_empty = match dict.get("songList") {
        None => true,
        Some(plist::Value::Array(items)) => items.is_empty(),
        Some(_) => false,
    };
    if !is_empty {
        return false;
    }

    dict.get("customerMessage")
        .and_then(plist::Value::as_string)
        .unwrap_or_default()
        .trim()
        .is_empty()
}

fn is_unavailable_download_response(dict: &HashMap<String, plist::Value>) -> bool {
    if dict.contains_key("failureType")
        || !match dict.get("songList") {
            None => true,
            Some(plist::Value::Array(items)) => items.is_empty(),
            Some(_) => false,
        }
    {
        return false;
    }

    let message = dict
        .get("customerMessage")
        .and_then(plist::Value::as_string)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    message == "no longer available" || message.ends_with(" no longer available")
}

fn download_request_body(
    endpoint: DownloadEndpoint,
    app_id: i64,
    guid: &str,
    external_version_id: Option<&str>,
) -> plist::Dictionary {
    let mut body = plist::Dictionary::new();
    body.insert("salableAdamId".into(), plist::Value::Integer(app_id.into()));
    body.insert("guid".into(), plist::Value::String(guid.to_string()));
    body.insert("creditDisplay".into(), plist::Value::String(String::new()));
    body.insert("serialNumber".into(), plist::Value::String("0".into()));

    if let Some(version) = external_version_id {
        body.insert(
            endpoint.version_key().into(),
            plist::Value::String(version.to_string()),
        );
    }

    body
}

fn download_item_from_response_dict(
    dict: &HashMap<String, plist::Value>,
) -> Result<DownloadItem, ClientError> {
    match StoreError::from_plist_dict(dict) {
        Some(StoreError::LicenseAlreadyExists) => {
            if let Some(item) = download_item_from_dict(dict)? {
                Ok(item)
            } else {
                Err(ClientError::Store(StoreError::PasswordTokenExpired))
            }
        }
        Some(err) => Err(ClientError::Store(err)),
        None => {
            if let Some(message) = dict
                .get("customerMessage")
                .and_then(plist::Value::as_string)
                .filter(|message| !message.is_empty())
            {
                return Err(ClientError::UnexpectedResponse(format!(
                    "Apple could not provide the download: {message}"
                )));
            }
            if let Some(item) = download_item_from_dict(dict)? {
                Ok(item)
            } else {
                Err(ClientError::UnexpectedResponse("missing songList".into()))
            }
        }
    }
}

fn download_item_from_dict(
    dict: &HashMap<String, plist::Value>,
) -> Result<Option<DownloadItem>, ClientError> {
    let Some(song_list) = dict.get("songList") else {
        return Ok(None);
    };

    let song_list = song_list
        .as_array()
        .ok_or_else(|| ClientError::UnexpectedResponse("invalid songList".into()))?;

    let first = song_list
        .first()
        .ok_or_else(|| ClientError::UnexpectedResponse("empty songList".into()))?;

    plist::from_value(first)
        .map(Some)
        .map_err(ClientError::PlistDe)
}

fn metadata_string(metadata: &HashMap<String, plist::Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| metadata.get(*key).and_then(metadata_value_to_string))
}

fn metadata_value_to_string(value: &plist::Value) -> Option<String> {
    match value {
        plist::Value::String(s) => Some(s.clone()),
        plist::Value::Integer(i) => i.as_signed().map(|n| n.to_string()),
        _ => None,
    }
}

pub async fn download_file<F>(
    client: &AppleClient,
    url: &str,
    dest: &Path,
    progress: &mut F,
) -> Result<(), ClientError>
where
    F: FnMut(u64, Option<u64>) + Send,
{
    let existing_size = if dest.exists() {
        tokio::fs::metadata(dest)
            .await
            .map(|m| m.len())
            .unwrap_or(0)
    } else {
        0
    };

    let mut req = client.http().get(url);
    if existing_size > 0 {
        req = req.header("Range", format!("bytes={existing_size}-"));
        tracing::info!(existing_size, "resuming download");
    }

    let resp = req.send().await?;

    if resp.status() == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
        tracing::info!("file already fully downloaded");
        progress(existing_size, Some(existing_size));
        return Ok(());
    }

    let status = resp.status();
    if !status.is_success() {
        return Err(ClientError::UnexpectedResponse(format!(
            "IPA download failed with HTTP {status}"
        )));
    }

    let (mut downloaded, total_size, append) =
        download_progress_state(existing_size, status, resp.content_length());
    progress(downloaded, total_size);

    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .open(dest)
        .await
        .map_err(|e| ClientError::UnexpectedResponse(format!("open file: {e}")))?;

    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk)
            .await
            .map_err(|e| ClientError::UnexpectedResponse(format!("write: {e}")))?;
        downloaded += chunk.len() as u64;
        progress(downloaded, total_size);
    }

    file.flush()
        .await
        .map_err(|e| ClientError::UnexpectedResponse(format!("flush: {e}")))?;

    Ok(())
}

fn download_progress_state(
    existing_size: u64,
    status: reqwest::StatusCode,
    response_length: Option<u64>,
) -> (u64, Option<u64>, bool) {
    if existing_size > 0 && status == reqwest::StatusCode::PARTIAL_CONTENT {
        (
            existing_size,
            response_length.map(|remaining| existing_size + remaining),
            true,
        )
    } else {
        (0, response_length, false)
    }
}

fn download_url(account: &Account, guid: &str) -> String {
    let host = match &account.pod {
        Some(pod) => format!("p{pod}-buy.itunes.apple.com"),
        None => "buy.itunes.apple.com".to_string(),
    };
    format!("https://{host}/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid={guid}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_download_item() -> plist::Value {
        let mut sinf = plist::Dictionary::new();
        sinf.insert("id".into(), plist::Value::Integer(1.into()));
        sinf.insert("sinf".into(), plist::Value::Data(vec![1, 2, 3]));

        let mut item = plist::Dictionary::new();
        item.insert(
            "URL".into(),
            plist::Value::String("https://example.invalid/app.ipa".into()),
        );
        item.insert(
            "sinfs".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(sinf)]),
        );

        plist::Value::Dictionary(item)
    }

    #[test]
    fn recovery_download_checks_identity_even_when_unpinned() {
        let mut item: DownloadItem = plist::from_value(&sample_download_item()).unwrap();
        item.metadata
            .insert("itemId".into(), plist::Value::Integer(42.into()));
        item.metadata.insert(
            "softwareVersionBundleId".into(),
            plist::Value::String("com.test.app".into()),
        );
        item.metadata.insert(
            "softwareVersionExternalIdentifier".into(),
            plist::Value::Integer(123.into()),
        );
        assert!(validate_download_identity(&item, 42, Some("com.test.app"), None).is_ok());
        assert!(validate_download_identity(&item, 42, Some("com.test.app"), Some("123")).is_ok());
        assert!(validate_download_identity(&item, 43, None, None).is_err());
        assert!(validate_download_identity(&item, 42, Some("com.other.app"), None).is_err());
        assert!(validate_download_identity(&item, 42, None, Some("456")).is_err());
        item.url.clear();
        assert!(validate_download_identity(&item, 42, None, None).is_err());
    }

    #[test]
    fn empty_success_response_requests_fallback() {
        let mut dict = HashMap::new();
        dict.insert("songList".into(), plist::Value::Array(Vec::new()));

        assert!(is_empty_or_unavailable_download_response(&dict));
    }

    #[test]
    fn unavailable_response_requests_fallback() {
        let mut dict = HashMap::new();
        dict.insert("songList".into(), plist::Value::Array(Vec::new()));
        dict.insert(
            "customerMessage".into(),
            plist::Value::String("This app is No Longer Available".into()),
        );

        assert!(is_empty_or_unavailable_download_response(&dict));
    }

    #[test]
    fn store_failure_does_not_request_fallback() {
        let mut dict = HashMap::new();
        dict.insert("songList".into(), plist::Value::Array(Vec::new()));
        dict.insert("failureType".into(), plist::Value::String("9610".into()));

        assert!(!is_empty_or_unavailable_download_response(&dict));
    }

    #[test]
    fn legacy_request_matches_go_payload_types() {
        let body = download_request_body(
            DownloadEndpoint::VolumeStore,
            42,
            "001122334455",
            Some("123"),
        );

        assert!(matches!(
            body.get("salableAdamId"),
            Some(plist::Value::Integer(value)) if value.as_signed() == Some(42)
        ));
        assert_eq!(
            body.get("externalVersionId")
                .and_then(plist::Value::as_string),
            Some("123")
        );
        assert!(!body.contains_key("appExtVrsId"));
    }

    #[test]
    fn redownload_request_uses_go_version_key() {
        let body = download_request_body(
            DownloadEndpoint::Redownload,
            42,
            "001122334455",
            Some("123"),
        );

        assert_eq!(
            body.get("appExtVrsId").and_then(plist::Value::as_string),
            Some("123")
        );
        assert!(!body.contains_key("externalVersionId"));
    }

    #[test]
    fn resumed_download_progress_includes_existing_bytes() {
        assert_eq!(
            download_progress_state(40, reqwest::StatusCode::PARTIAL_CONTENT, Some(60)),
            (40, Some(100), true)
        );
    }

    #[test]
    fn ignored_range_restarts_download_progress() {
        assert_eq!(
            download_progress_state(40, reqwest::StatusCode::OK, Some(100)),
            (0, Some(100), false)
        );
    }

    #[test]
    fn download_item_wins_over_license_already_exists_marker() {
        let mut dict = HashMap::new();
        dict.insert("failureType".into(), plist::Value::String("5002".into()));
        dict.insert(
            "customerMessage".into(),
            plist::Value::String("license already exists".into()),
        );
        dict.insert(
            "songList".into(),
            plist::Value::Array(vec![sample_download_item()]),
        );

        let item = download_item_from_response_dict(&dict).unwrap();

        assert_eq!(item.url, "https://example.invalid/app.ipa");
        assert_eq!(item.sinfs[0].id, 1);
        assert_eq!(item.sinfs[0].sinf, vec![1, 2, 3]);
    }

    #[test]
    fn bare_license_already_exists_requires_reauth_for_download() {
        let mut dict = HashMap::new();
        dict.insert("failureType".into(), plist::Value::String("5002".into()));
        dict.insert(
            "customerMessage".into(),
            plist::Value::String("license already exists".into()),
        );

        let err = download_item_from_response_dict(&dict).unwrap_err();

        assert!(err.is_token_expired());
    }

    #[test]
    fn download_item_reads_current_latest_version_id() {
        let mut item = plist::Dictionary::new();
        item.insert(
            "URL".into(),
            plist::Value::String("https://example.invalid/app.ipa".into()),
        );
        item.insert("sinfs".into(), plist::Value::Array(Vec::new()));
        let mut metadata = plist::Dictionary::new();
        metadata.insert(
            "softwareVersionExternalIdentifier".into(),
            plist::Value::Integer(887118713.into()),
        );
        item.insert("metadata".into(), plist::Value::Dictionary(metadata));

        let item: DownloadItem = plist::from_value(&plist::Value::Dictionary(item)).unwrap();

        assert_eq!(
            item.latest_external_version_id().as_deref(),
            Some("887118713")
        );
    }

    #[test]
    fn download_item_reads_legacy_latest_version_id() {
        let mut item = plist::Dictionary::new();
        item.insert(
            "URL".into(),
            plist::Value::String("https://example.invalid/app.ipa".into()),
        );
        item.insert("sinfs".into(), plist::Value::Array(Vec::new()));
        let mut metadata = plist::Dictionary::new();
        metadata.insert(
            "externalVersionIdentifier".into(),
            plist::Value::String("12345678".into()),
        );
        item.insert("metadata".into(), plist::Value::Dictionary(metadata));

        let item: DownloadItem = plist::from_value(&plist::Value::Dictionary(item)).unwrap();

        assert_eq!(
            item.latest_external_version_id().as_deref(),
            Some("12345678")
        );
    }

    #[test]
    fn download_item_does_not_guess_latest_version_id_from_array() {
        let mut item = plist::Dictionary::new();
        item.insert(
            "URL".into(),
            plist::Value::String("https://example.invalid/app.ipa".into()),
        );
        item.insert("sinfs".into(), plist::Value::Array(Vec::new()));
        let mut metadata = plist::Dictionary::new();
        metadata.insert(
            "softwareVersionExternalIdentifiers".into(),
            plist::Value::Array(vec![plist::Value::Integer(887118713.into())]),
        );
        item.insert("metadata".into(), plist::Value::Dictionary(metadata));

        let item: DownloadItem = plist::from_value(&plist::Value::Dictionary(item)).unwrap();

        assert_eq!(item.latest_external_version_id(), None);
    }
}
