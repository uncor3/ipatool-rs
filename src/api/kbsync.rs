//! Preferred account/device-bound download protocol and Go-compatible cache.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use super::download::{DownloadItem, DownloadResponse, validated_download_item};
use crate::{
    client::AppleClient,
    error::{ClientError, StoreError},
    model::{Account, Platform},
};

const ENT_PATH: &str = "/WebObjects/DownloadDispatch.woa/wa/ent/download";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CacheEntry {
    dsid: u64,
    guid: String,
    data: String,
}

impl CacheEntry {
    fn valid_for(&self, dsid: u64, guid: &str) -> bool {
        self.dsid == dsid
            && self.guid == guid
            && STANDARD
                .decode(&self.data)
                .is_ok_and(|data| !data.is_empty())
    }
}

fn cached(client: &AppleClient, dsid: u64) -> Option<CacheEntry> {
    let mut memory = client.kbsync.lock().ok()?;
    if let Some(entry) = memory
        .as_ref()
        .filter(|entry| entry.valid_for(dsid, client.guid()))
    {
        return Some(entry.clone());
    }
    let data = client.credentials.as_ref()?.load_kbsync().ok()??;
    let entry: CacheEntry = serde_json::from_slice(&data).ok()?;
    if !entry.valid_for(dsid, client.guid()) {
        return None;
    }
    *memory = Some(entry.clone());
    Some(entry)
}

fn invalidate(client: &AppleClient, rejected: &CacheEntry) {
    if let Ok(mut memory) = client.kbsync.lock() {
        if memory.as_ref() == Some(rejected) {
            *memory = None;
        }
        if let Some(store) = client.credentials.as_ref()
            && let Ok(Some(data)) = store.load_kbsync()
            && serde_json::from_slice::<CacheEntry>(&data).is_ok_and(|entry| entry == *rejected)
        {
            let _ = store.delete_kbsync();
        }
    }
}

fn store(client: &AppleClient, entry: CacheEntry) {
    if let Ok(mut memory) = client.kbsync.lock() {
        if let Some(store) = client.credentials.as_ref()
            && let Ok(data) = serde_json::to_vec(&entry)
        {
            let _ = store.store_kbsync(&data);
        }
        *memory = Some(entry);
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn download(
    client: &AppleClient,
    endpoint: &url::Url,
    app_id: i64,
    bundle_id: Option<&str>,
    account: &Account,
    version: Option<&str>,
    platform: Platform,
) -> Result<DownloadItem, ClientError> {
    validate_endpoint(endpoint)?;
    let dsid = account
        .directory_services_id
        .parse::<u64>()
        .ok()
        .filter(|id| *id != 0)
        .ok_or_else(|| ClientError::Sap("ent/download requires a nonzero numeric DSID".into()))?;
    if client.hardware_id().len() != 6
        || client.guid()
            != client
                .hardware_id()
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>()
    {
        return Err(ClientError::Sap(
            "ent/download requires matching six-byte hardware identity".into(),
        ));
    }
    let version = match version.filter(|version| !version.is_empty()) {
        Some(version) => version.to_string(),
        None => {
            super::platform_version::lookup_latest_version(
                client, app_id, bundle_id, account, platform,
            )
            .await?
        }
    };
    if let Some(entry) = cached(client, dsid) {
        tracing::debug!("ent/download using cached kbsync");
        match send(
            client,
            endpoint,
            app_id,
            bundle_id,
            account,
            &version,
            &entry.data,
        )
        .await
        {
            Ok(item) => return Ok(item),
            Err(error @ ClientError::Sap(_)) => return Err(error),
            Err(_) => invalidate(client, &entry),
        }
    }
    tracing::debug!("generating fresh kbsync for ent/download");
    let blob = crate::sap::machine::kbsync::generate(client, dsid).await?;
    let entry = CacheEntry {
        dsid,
        guid: client.guid().into(),
        data: STANDARD.encode(blob),
    };
    let item = send(
        client,
        endpoint,
        app_id,
        bundle_id,
        account,
        &version,
        &entry.data,
    )
    .await?;
    store(client, entry);
    Ok(item)
}

fn validate_endpoint(url: &url::Url) -> Result<(), ClientError> {
    if url.scheme() != "https"
        || url.host_str() != Some("downloaddispatch.itunes.apple.com")
        || url.path() != ENT_PATH
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
    {
        return Err(ClientError::UnexpectedResponse(
            "invalid ent/download endpoint in bag".into(),
        ));
    }
    Ok(())
}

fn request_body(
    guid: &str,
    hardware: &[u8],
    app_id: i64,
    version: &str,
    blob: &str,
) -> Result<plist::Dictionary, ClientError> {
    if hardware.len() != 6 {
        return Err(ClientError::Sap(
            "ent/download requires six-byte hardware identity".into(),
        ));
    }
    let mut serial = vec![0x54, 0xc8, 0xb0, 0xa9, 0x88];
    serial.extend_from_slice(&hardware[2..]);
    let mut body = plist::Dictionary::new();
    for (key, value) in [
        ("creditDisplay", String::new()),
        ("guid", guid.into()),
        ("kbsync", blob.into()),
        ("salableAdamId", app_id.to_string()),
        ("serialNumber", STANDARD.encode(serial)),
        ("externalVersionId", version.into()),
    ] {
        body.insert(key.into(), plist::Value::String(value));
    }
    Ok(body)
}

#[allow(clippy::too_many_arguments)]
async fn send(
    client: &AppleClient,
    endpoint: &url::Url,
    app_id: i64,
    bundle_id: Option<&str>,
    account: &Account,
    version: &str,
    blob: &str,
) -> Result<DownloadItem, ClientError> {
    let request = build_request(client, endpoint, app_id, account, version, blob)?;
    let parameters = request_body(client.guid(), client.hardware_id(), app_id, version, blob)?;
    let response = client
        .store_send(
            "download",
            request,
            Some(parameters),
            None,
            crate::store::RequestOptions::NO_REDIRECTS,
        )
        .await?;
    let status = response.status();
    tracing::debug!(%status, endpoint = "ent/download", "download response status");
    let bytes = response.bytes().await?;
    parse_response(status, &bytes, app_id, bundle_id, version)
}

fn build_request(
    client: &AppleClient,
    endpoint: &url::Url,
    app_id: i64,
    account: &Account,
    version: &str,
    blob: &str,
) -> Result<reqwest::Request, ClientError> {
    let body = request_body(client.guid(), client.hardware_id(), app_id, version, blob)?;
    let mut bytes = Vec::new();
    plist::to_writer_xml(&mut bytes, &body)?;
    let mut url = endpoint.clone();
    url.query_pairs_mut().append_pair("guid", client.guid());
    Ok(client
        .protected_http()
        .post(url)
        .header(
            "Content-Type",
            "application/x-www-form-urlencoded; charset=utf-8",
        )
        .header(
            "User-Agent",
            "Configurator/2.18 (Macintosh; OS X 15.3.2; 24D81) AppleWebKit/0620.2.4.11.6",
        )
        .header("iCloud-DSID", &account.directory_services_id)
        .header("X-Dsid", &account.directory_services_id)
        .header("X-Apple-Store-Front", &account.store_front)
        .header("X-Token", &account.password_token)
        .timeout(std::time::Duration::from_secs(30))
        .body(bytes)
        .build()?)
}

fn parse_response(
    status: reqwest::StatusCode,
    bytes: &[u8],
    app_id: i64,
    bundle_id: Option<&str>,
    version: &str,
) -> Result<DownloadItem, ClientError> {
    if status != reqwest::StatusCode::OK {
        return Err(ClientError::UnexpectedResponse(format!(
            "ent/download returned HTTP {status}"
        )));
    }
    let mut dict: std::collections::HashMap<String, plist::Value> =
        crate::client::plist_xml::parse_plist_response(bytes)?;
    // Go's omitempty failure field treats absent and empty strings identically.
    if dict.get("failureType").and_then(plist::Value::as_string) == Some("") {
        dict.remove("failureType");
    }
    if let Some(error) = StoreError::from_plist_dict(&dict) {
        return Err(error.into());
    }
    if dict
        .get("customerMessage")
        .and_then(plist::Value::as_string)
        .is_some_and(|message| !message.is_empty())
    {
        return Err(ClientError::UnexpectedResponse(
            "ent/download returned a customer error".into(),
        ));
    }
    validated_download_item(
        DownloadResponse {
            status,
            body: bytes.to_vec(),
            dict: Some(dict),
        },
        app_id,
        bundle_id,
        Some(version),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_matches_go_field_types_and_serial() {
        let body = request_body(
            "AABBCCDDEEFF",
            &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            42,
            "123",
            "YmxvYg==",
        )
        .unwrap();
        assert_eq!(body.len(), 6);
        assert!(body.values().all(|value| value.as_string().is_some()));
        assert_eq!(body["salableAdamId"].as_string(), Some("42"));
        assert_eq!(
            STANDARD
                .decode(body["serialNumber"].as_string().unwrap())
                .unwrap(),
            [0x54, 0xc8, 0xb0, 0xa9, 0x88, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert!(request_body("", &[], 42, "123", "blob").is_err());
    }

    #[test]
    fn token_request_uses_go_headers_and_exact_signed_in_identity() {
        let client = AppleClient::for_tests();
        let endpoint = url::Url::parse(&format!(
            "https://downloaddispatch.itunes.apple.com{ENT_PATH}"
        ))
        .unwrap();
        let account = Account {
            email: "test@example.invalid".into(),
            password_token: "test-token".into(),
            directory_services_id: "42".into(),
            name: String::new(),
            store_front: "143441".into(),
            pod: None,
            password: None,
        };
        let request = build_request(&client, &endpoint, 123, &account, "456", "YmxvYg==").unwrap();
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.url().query(), Some("guid=AABBCCDDEEFF"));
        for (key, value) in [
            (
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            ),
            ("x-token", "test-token"),
            ("icloud-dsid", "42"),
            ("x-dsid", "42"),
            ("x-apple-store-front", "143441"),
        ] {
            assert_eq!(request.headers().get(key).unwrap().to_str().unwrap(), value);
        }
        let body: plist::Dictionary =
            plist::from_bytes(request.body().unwrap().as_bytes().unwrap()).unwrap();
        assert_eq!(body["externalVersionId"].as_string(), Some("456"));
        assert_eq!(body["kbsync"].as_string(), Some("YmxvYg=="));
    }

    #[test]
    fn response_keeps_license_errors_and_rejects_wrong_app_or_redirects() {
        use reqwest::StatusCode;
        let failure = br#"<plist version="1.0"><dict><key>failureType</key><string>9610</string></dict></plist>"#;
        assert!(matches!(
            parse_response(StatusCode::OK, failure, 42, None, "123"),
            Err(ClientError::Store(StoreError::LicenseNotFound))
        ));
        assert!(matches!(
            parse_response(StatusCode::FOUND, &[], 42, None, "123"),
            Err(ClientError::UnexpectedResponse(_))
        ));
        let success = br#"<plist version="1.0"><dict><key>failureType</key><string></string><key>songList</key><array><dict><key>URL</key><string>https://example.invalid/app.ipa</string><key>sinfs</key><array></array><key>metadata</key><dict><key>itemId</key><integer>42</integer><key>softwareVersionExternalIdentifier</key><integer>123</integer><key>softwareVersionBundleId</key><string>example.app</string></dict></dict></array></dict></plist>"#;
        assert!(parse_response(StatusCode::OK, success, 42, Some("example.app"), "123").is_ok());
        assert!(parse_response(StatusCode::OK, success, 43, Some("example.app"), "123").is_err());
        assert!(parse_response(StatusCode::OK, success, 42, Some("other.app"), "123").is_err());
        assert!(parse_response(StatusCode::OK, success, 42, None, "124").is_err());
    }

    #[test]
    fn cache_is_account_and_device_bound() {
        let entry: CacheEntry =
            serde_json::from_str(r#"{"dsid":42,"guid":"AABBCCDDEEFF","data":"YmxvYg=="}"#).unwrap();
        assert!(entry.valid_for(42, "AABBCCDDEEFF"));
        assert!(!entry.valid_for(43, "AABBCCDDEEFF"));
        assert!(!entry.valid_for(42, "OTHER"));
        let invalid = CacheEntry {
            data: "???".into(),
            ..entry
        };
        assert!(!invalid.valid_for(42, "AABBCCDDEEFF"));
    }

    #[test]
    fn invalidation_preserves_a_newer_cached_blob() {
        let client = AppleClient::for_tests();
        let old = CacheEntry {
            dsid: 42,
            guid: client.guid().into(),
            data: STANDARD.encode(b"old"),
        };
        let new = CacheEntry {
            data: STANDARD.encode(b"new"),
            ..old.clone()
        };
        store(&client, new.clone());
        invalidate(&client, &old);
        assert!(cached(&client, 42).is_some_and(|entry| entry == new));
        invalidate(&client, &new);
        assert!(cached(&client, 42).is_none());
    }

    #[test]
    fn rejects_redirect_targets_and_untrusted_endpoint_shapes() {
        assert!(
            validate_endpoint(
                &url::Url::parse(&format!(
                    "https://downloaddispatch.itunes.apple.com{ENT_PATH}"
                ))
                .unwrap()
            )
            .is_ok()
        );
        for url in [
            "http://downloaddispatch.itunes.apple.com",
            "https://example.com",
            "https://user@downloaddispatch.itunes.apple.com",
            "https://downloaddispatch.itunes.apple.com/r/redownload",
        ] {
            assert!(validate_endpoint(&url::Url::parse(url).unwrap()).is_err());
        }
    }
}
