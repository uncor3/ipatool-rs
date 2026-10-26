use std::collections::HashMap;
use std::time::Duration;

use url::Url;

use crate::client::AppleClient;
use crate::error::ClientError;
use crate::sap::SapConfig;

const BAG_URL: &str = "https://init.itunes.apple.com/bag.xml";
const BAG_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The only sign-in action Apple's bag advertises.
pub const AUTH_PATH: &str = "/WebObjects/MZFinance.woa/wa/authenticate";

const AUTH_HOST: &str = "buy.itunes.apple.com";
/// Account-specific pods, e.g. `p14-buy.itunes.apple.com`.
const AUTH_POD_SUFFIX: &str = "-buy.itunes.apple.com";

#[derive(Debug, Clone)]
pub struct BagConfig {
    pub auth_endpoint: Url,
    pub ent_download_endpoint: Option<Url>,
    pub redownload_endpoint: Option<Url>,
    pub update_endpoint: Option<Url>,
    pub sap: SapConfig,
}

pub async fn fetch_bag(client: &AppleClient) -> Result<BagConfig, ClientError> {
    let request = client
        .http()
        .get(BAG_URL)
        .query(&[("guid", client.guid())])
        .header("Accept", "application/xml")
        .timeout(BAG_REQUEST_TIMEOUT)
        .build()?;
    let resp = client
        .store_send(
            "bag",
            request,
            None,
            None,
            crate::store::RequestOptions::PLIST,
        )
        .await?;
    let resp = resp.error_for_status()?;
    let body = resp.bytes().await?;

    parse_bag_response(&body)
}

fn parse_bag_response(body: &[u8]) -> Result<BagConfig, ClientError> {
    let outer: HashMap<String, plist::Value> =
        crate::client::plist_xml::parse_plist_response(body)?;

    if let Some(inner) = outer.get("urlBag").and_then(plist::Value::as_dictionary) {
        return parse_bag(
            &inner
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        );
    }

    let bag_data = outer
        .get("bag")
        .and_then(plist::Value::as_data)
        .ok_or_else(|| ClientError::UnexpectedResponse("bag: missing 'bag' data".into()))?;

    let inner: HashMap<String, plist::Value> =
        plist::from_bytes(bag_data).map_err(ClientError::PlistDe)?;

    parse_bag(&inner)
}

fn parse_bag(inner: &HashMap<String, plist::Value>) -> Result<BagConfig, ClientError> {
    let mut auth_endpoint = bag_url(inner, "authenticateAccount")?;
    validate_auth_endpoint(&auth_endpoint)?;
    // The bare path can return a 301 without Location. Normalize only the
    // validated initial bag endpoint, preserving its host and query.
    auth_endpoint.set_path(&format!("{AUTH_PATH}/"));

    // Apple publishes the version as a string.
    let version_str = inner
        .get("sign-sap-version")
        .and_then(plist::Value::as_string)
        .ok_or_else(|| ClientError::UnexpectedResponse("bag: missing sign-sap-version".into()))?;

    let version = version_str.parse::<u32>().map_err(|e| {
        ClientError::UnexpectedResponse(format!(
            "bag: invalid sign-sap-version {version_str:?}: {e}"
        ))
    })?;

    let sap = SapConfig {
        setup_url: bag_url(inner, "sign-sap-setup")?,
        cert_url: bag_url(inner, "sign-sap-setup-cert")?,
        version,
    };
    sap.validate()?;

    Ok(BagConfig {
        auth_endpoint,
        ent_download_endpoint: inner
            .get("volumeStoreDownloadProduct")
            .and_then(plist::Value::as_string)
            .and_then(|value| Url::parse(value).ok()),
        redownload_endpoint: optional_download_url(inner, "redownloadProduct", "/r/redownload")?,
        update_endpoint: optional_download_url(inner, "updateProduct", "/up/updateProduct")?,
        sap,
    })
}

fn optional_download_url(
    inner: &HashMap<String, plist::Value>,
    key: &str,
    expected_path: &str,
) -> Result<Option<Url>, ClientError> {
    let Some(raw) = inner.get(key).and_then(plist::Value::as_string) else {
        return Ok(None);
    };
    let url = Url::parse(raw)
        .map_err(|e| ClientError::UnexpectedResponse(format!("bag: invalid {key} URL: {e}")))?;
    if url.scheme() != "https"
        || url.host_str() != Some("downloaddispatch.itunes.apple.com")
        || url.path() != expected_path
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ClientError::UnexpectedResponse(format!(
            "bag: unsupported {key} endpoint"
        )));
    }
    Ok(Some(url))
}

fn bag_url(inner: &HashMap<String, plist::Value>, key: &str) -> Result<Url, ClientError> {
    let raw = inner
        .get(key)
        .and_then(plist::Value::as_string)
        .ok_or_else(|| ClientError::UnexpectedResponse(format!("bag: missing {key}")))?;

    Url::parse(raw)
        .map_err(|e| ClientError::UnexpectedResponse(format!("bag: invalid {key} URL: {e}")))
}

/// Credentials are POSTed to this URL, and Apple redirects sign-in to
/// account-specific pods, so every candidate — from the bag and from a redirect
/// alike — is checked against the shape Apple actually uses.
pub fn validate_auth_endpoint(url: &Url) -> Result<(), ClientError> {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port().is_some_and(|port| port != 443)
    {
        return Err(ClientError::UnexpectedResponse(
            "invalid authentication endpoint".into(),
        ));
    }

    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if host != AUTH_HOST && !host.ends_with(AUTH_POD_SUFFIX) {
        return Err(ClientError::UnexpectedResponse(format!(
            "unsupported authentication endpoint {url}: unexpected host"
        )));
    }

    if url.path() != AUTH_PATH && url.path() != format!("{AUTH_PATH}/") {
        return Err(ClientError::UnexpectedResponse(format!(
            "unsupported authentication endpoint {url}: unexpected path"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_go_url_bag_and_encoded_bag_responses() {
        let inner: plist::Dictionary = current_bag().into_iter().collect();
        let mut encoded_inner = Vec::new();
        plist::to_writer_xml(&mut encoded_inner, &inner).unwrap();
        for (key, value) in [
            ("urlBag", plist::Value::Dictionary(inner)),
            ("bag", plist::Value::Data(encoded_inner)),
        ] {
            let mut outer = plist::Dictionary::new();
            outer.insert(key.into(), value);
            let mut body = Vec::new();
            plist::to_writer_xml(&mut body, &outer).unwrap();
            let bag = parse_bag_response(&body).unwrap();
            assert_eq!(bag.auth_endpoint.path(), format!("{AUTH_PATH}/"));
            assert_eq!(bag.sap.version, 200);
        }
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    /// Mirrors what init.itunes.apple.com returns today.
    fn current_bag() -> HashMap<String, plist::Value> {
        HashMap::from([
            (
                "authenticateAccount".to_string(),
                plist::Value::String(
                    "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate".into(),
                ),
            ),
            (
                "sign-sap-setup".to_string(),
                plist::Value::String(
                    "https://fpinit.itunes.apple.com/v1/signSapSetup/legacy".into(),
                ),
            ),
            (
                "sign-sap-setup-cert".to_string(),
                plist::Value::String("https://s.mzstatic.com/sap/setupCert.plist".into()),
            ),
            (
                "sign-sap-version".to_string(),
                plist::Value::String("200".into()),
            ),
            (
                "redownloadProduct".to_string(),
                plist::Value::String(
                    "https://downloaddispatch.itunes.apple.com/r/redownload".into(),
                ),
            ),
            (
                "updateProduct".to_string(),
                plist::Value::String(
                    "https://downloaddispatch.itunes.apple.com/up/updateProduct".into(),
                ),
            ),
        ])
    }

    #[test]
    fn parses_apples_current_bag() {
        let config = parse_bag(&current_bag()).unwrap();

        assert_eq!(
            config.auth_endpoint.as_str(),
            "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/"
        );
        assert_eq!(
            config.sap.setup_url.as_str(),
            "https://fpinit.itunes.apple.com/v1/signSapSetup/legacy"
        );
        assert_eq!(config.sap.version, 200);
        assert_eq!(config.redownload_endpoint.unwrap().path(), "/r/redownload");
    }

    #[test]
    fn fails_when_sap_keys_are_absent() {
        let mut bag = current_bag();
        bag.remove("sign-sap-setup");

        assert!(parse_bag(&bag).is_err());
    }

    #[test]
    fn normalizes_initial_auth_path_without_losing_host_or_query() {
        let mut bag = current_bag();
        bag.insert(
            "authenticateAccount".into(),
            plist::Value::String(
                "https://p12-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate?Pod=12"
                    .into(),
            ),
        );
        assert_eq!(
            parse_bag(&bag).unwrap().auth_endpoint.as_str(),
            "https://p12-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/?Pod=12"
        );
    }

    #[test]
    fn accepts_pod_hosts() {
        assert!(
            validate_auth_endpoint(&url(
                "https://p14-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"
            ))
            .is_ok()
        );
    }

    #[test]
    fn accepts_trailing_slash() {
        assert!(
            validate_auth_endpoint(&url(
                "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/"
            ))
            .is_ok()
        );
    }

    /// The endpoint the previous fix targeted. Apple lists it under
    /// `sign-sap-request` too, so it needs a signature just the same and is no
    /// longer a fallback worth having.
    #[test]
    fn rejects_native_fast_endpoint() {
        assert!(
            validate_auth_endpoint(&url("https://auth.itunes.apple.com/auth/v1/native/fast/"))
                .is_err()
        );
    }

    #[test]
    fn rejects_lookalike_host() {
        assert!(
            validate_auth_endpoint(&url(
                "https://buy.itunes.apple.com.evil.test/WebObjects/MZFinance.woa/wa/authenticate"
            ))
            .is_err()
        );
    }

    #[test]
    fn rejects_other_action_on_valid_host() {
        assert!(
            validate_auth_endpoint(&url(
                "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/buyProduct"
            ))
            .is_err()
        );
    }

    #[test]
    fn rejects_plaintext() {
        assert!(
            validate_auth_endpoint(&url(
                "http://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"
            ))
            .is_err()
        );
    }
}
