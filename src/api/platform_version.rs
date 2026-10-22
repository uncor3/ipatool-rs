use std::collections::HashMap;

use serde::Deserialize;

use crate::client::AppleClient;
use crate::error::ClientError;
use crate::model::storefront::country_code_from_store_front;
use crate::model::{Account, App, Platform};

const PLATFORM_LOOKUP_URL: &str =
    "https://uclient-api.itunes.apple.com/WebObjects/MZStorePlatform.woa/wa/lookup";

#[derive(Debug, Deserialize)]
struct PlatformLookupResponse {
    #[serde(default, deserialize_with = "null_as_default")]
    results: HashMap<String, PlatformLookupItem>,
}

#[derive(Debug, Deserialize)]
struct PlatformLookupItem {
    #[serde(default, deserialize_with = "null_as_default")]
    offers: Vec<PlatformLookupOffer>,
}

fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Debug, Deserialize)]
struct PlatformLookupOffer {
    #[serde(rename = "buyParams", default)]
    buy_params: String,
    #[serde(default)]
    version: PlatformLookupVersion,
}

#[derive(Debug, Default, Deserialize)]
struct PlatformLookupVersion {
    #[serde(
        rename = "externalId",
        default,
        deserialize_with = "deserialize_external_id"
    )]
    external_id: Option<String>,
}

fn deserialize_external_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value)),
        Some(serde_json::Value::Number(value)) => Ok(Some(value.to_string())),
        Some(value) => Err(serde::de::Error::custom(format!(
            "invalid external version identifier: {value}"
        ))),
    }
}

pub(crate) async fn lookup_latest_version(
    client: &AppleClient,
    app_id: i64,
    bundle_id: Option<&str>,
    account: &Account,
    platform: Platform,
) -> Result<String, ClientError> {
    let country = country_code_from_store_front(&account.store_front).ok_or_else(|| {
        ClientError::UnexpectedResponse(format!(
            "platform version lookup: unknown storefront {:?}",
            account.store_front
        ))
    })?;

    let app_id_string = app_id.to_string();
    let country = country.to_ascii_lowercase();
    let catalogs: &[&str] = match platform {
        Platform::AppleTV => &["atv9"],
        Platform::IPhone | Platform::IPad | Platform::WatchOS => {
            &["enterprisestore", "iphone", "ipad"]
        }
    };
    for &catalog in catalogs {
        let response = client
            .http()
            .get(PLATFORM_LOOKUP_URL)
            .timeout(std::time::Duration::from_secs(30))
            .query(&[
                ("version", "2"),
                ("id", app_id_string.as_str()),
                ("p", "mdm-lockup"),
                ("caller", "MDM"),
                ("platform", catalog),
                ("cc", country.as_str()),
                ("l", "en"),
            ])
            .send()
            .await?;

        let status = response.status();
        if status != reqwest::StatusCode::OK {
            return Err(ClientError::UnexpectedResponse(format!(
                "platform version lookup failed with HTTP {status}"
            )));
        }

        let body = response.bytes().await?;
        let response: PlatformLookupResponse = serde_json::from_slice(&body).map_err(|error| {
            ClientError::UnexpectedResponse(format!(
                "platform version lookup returned invalid JSON: {error}"
            ))
        })?;

        let Some(item) = response.results.get(&app_id_string) else {
            continue;
        };
        let Some(offer) = item.offers.first() else {
            continue;
        };

        if let Some(external_id) = offer
            .version
            .external_id
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            return Ok(external_id.to_string());
        }

        let external_id = url::form_urlencoded::parse(offer.buy_params.as_bytes())
            .find_map(|(key, value)| (key == "appExtVrsId").then(|| value.into_owned()));
        if let Some(external_id) = external_id.filter(|value| !value.is_empty()) {
            return Ok(external_id);
        }

        return Err(ClientError::UnexpectedResponse(
            "platform version lookup returned no external version identifier".into(),
        ));
    }

    // Arcade apps can be absent from all three MDM catalogs. The public
    // Store catalog still exposes their current iOS external version ID.
    if !matches!(platform, Platform::IPhone | Platform::IPad) {
        return Err(ClientError::UnexpectedResponse(
            "platform version lookup returned no offers".into(),
        ));
    }
    let response = client
        .http()
        .get(format!(
            "https://apps.apple.com/api/apps/v1/catalog/{country}/apps/{app_id}?platform={platform}"
        ))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(ClientError::IOSCatalogAppNotFound);
    }
    if response.status() != reqwest::StatusCode::OK {
        return Err(ClientError::UnexpectedResponse(format!(
            "iOS catalog lookup failed with HTTP {}",
            response.status()
        )));
    }
    let body = response.bytes().await?;
    let catalog: serde_json::Value = serde_json::from_slice(&body).map_err(|error| {
        ClientError::UnexpectedResponse(format!("invalid iOS catalog JSON: {error}"))
    })?;
    catalog_version(&catalog, app_id, bundle_id, platform)
}

fn catalog_version(
    catalog: &serde_json::Value,
    app_id: i64,
    bundle_id: Option<&str>,
    platform: Platform,
) -> Result<String, ClientError> {
    let invalid =
        |message: &str| ClientError::UnexpectedResponse(format!("iOS catalog lookup: {message}"));
    let items = catalog
        .get("data")
        .and_then(serde_json::Value::as_array)
        .filter(|items| items.len() == 1)
        .ok_or_else(|| invalid("expected exactly one app"))?;
    let item = &items[0];
    if item.get("id").and_then(serde_json::Value::as_str) != Some(app_id.to_string().as_str())
        || item.get("type").and_then(serde_json::Value::as_str) != Some("apps")
    {
        return Err(invalid("response contains a different app"));
    }
    let attributes = &item["attributes"];
    if !attributes["deviceFamilies"]
        .as_array()
        .is_some_and(|families| {
            families
                .iter()
                .any(|family| family.as_str() == Some(platform.to_string().as_str()))
        })
    {
        return Err(invalid("response has no iPhone offer"));
    }
    let ios = &attributes["platformAttributes"]["ios"];
    if let Some(bundle_id) = bundle_id.filter(|id| !id.is_empty())
        && ios["bundleId"].as_str() != Some(bundle_id)
    {
        return Err(invalid("response contains a different bundle identifier"));
    }
    let version = match &ios["externalVersionId"] {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(value) => value.to_string(),
        _ => return Err(invalid("missing external version identifier")),
    };
    if !version.parse::<u64>().is_ok_and(|value| value > 0) {
        return Err(invalid("invalid external version identifier"));
    }
    Ok(version)
}

// Delisted downloads can be addressed by numeric ID even when lookup returns
// no public listing. The caller still validates the returned package identity.
pub(crate) fn delisted_app(app_id: i64, bundle_id: &str) -> App {
    App {
        id: app_id,
        bundle_id: bundle_id.to_string(),
        name: String::new(),
        version: None,
        price: 0.0,
        extra: HashMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog(version: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"data": [{"id": "42", "type": "apps", "attributes": {
            "deviceFamilies": ["iphone", "ipad"],
            "platformAttributes": {"ios": {"bundleId": "com.test.app", "externalVersionId": version}}
        }}]})
    }

    #[test]
    fn catalog_fallback_accepts_numeric_or_string_versions() {
        for version in [serde_json::json!(123), serde_json::json!("123")] {
            assert_eq!(
                catalog_version(
                    &catalog(version),
                    42,
                    Some("com.test.app"),
                    Platform::IPhone
                )
                .unwrap(),
                "123"
            );
        }
    }

    #[test]
    fn catalog_rejects_wrong_identity_platform_and_invalid_versions() {
        let valid = catalog(serde_json::json!(123));
        assert!(catalog_version(&valid, 43, Some("com.test.app"), Platform::IPhone).is_err());
        assert!(catalog_version(&valid, 42, Some("com.other.app"), Platform::IPhone).is_err());
        let mut wrong_platform = valid.clone();
        wrong_platform["data"][0]["attributes"]["deviceFamilies"] = serde_json::json!(["appletv"]);
        assert!(catalog_version(&wrong_platform, 42, None, Platform::IPhone).is_err());
        for version in [
            serde_json::json!(0),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!(""),
            serde_json::Value::Null,
        ] {
            assert!(catalog_version(&catalog(version), 42, None, Platform::IPhone).is_err());
        }
        assert!(
            catalog_version(&serde_json::json!({"data": []}), 42, None, Platform::IPhone).is_err()
        );
    }

    #[test]
    fn external_id_accepts_strings_and_numbers() {
        let string: PlatformLookupVersion =
            serde_json::from_str(r#"{"externalId":"123"}"#).unwrap();
        let number: PlatformLookupVersion = serde_json::from_str(r#"{"externalId":456}"#).unwrap();

        assert_eq!(string.external_id.as_deref(), Some("123"));
        assert_eq!(number.external_id.as_deref(), Some("456"));
    }

    #[test]
    fn absent_catalog_entries_and_null_offers_allow_fallback() {
        let response: PlatformLookupResponse = serde_json::from_str(r#"{"results":null}"#).unwrap();
        assert!(response.results.is_empty());
        let response: PlatformLookupResponse =
            serde_json::from_str(r#"{"results":{"42":{"offers":null}}}"#).unwrap();
        assert!(response.results["42"].offers.is_empty());
    }
}
