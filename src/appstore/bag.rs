use crate::{
    appstore::types::BagResult,
    constants::PRIVATE_INIT_URL,
    error::{IpaToolError, Result},
    http::client::Http,
    util::normalize_plist_body,
};
use reqwest::header::{ACCEPT, HeaderMap};

pub async fn fetch_auth_endpoint(http: &Http, guid: &str) -> Result<String> {
    let url = format!("{}?guid={}", PRIVATE_INIT_URL, guid);
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, "application/xml".parse().unwrap());

    let body = http.get_bytes(&url, headers).await?;
    let normalized = normalize_plist_body(&body);

    let v: BagResult = plist::from_reader_xml(std::io::Cursor::new(normalized))?;
    if v.url_bag.auth_endpoint.is_empty() {
        return Err(IpaToolError::AuthBagError);
    }
    Ok(v.url_bag.auth_endpoint)
}
