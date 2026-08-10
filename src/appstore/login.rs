use crate::{
    appstore::types::{Account, LoginResult},
    constants::{
        APPSTORE_AUTH_URL, CUSTOMER_MESSAGE_ACCOUNT_DISABLED, CUSTOMER_MESSAGE_BAD_LOGIN,
        FAILURE_TYPE_INVALID_CREDENTIALS, HEADER_POD, HEADER_STOREFRONT, MAX_LOGIN_ATTEMPTS,
    },
    error::{IpaToolError, Result},
    http::client::Http,
    storage::keyring::KeyringStore,
    util::normalize_plist_body,
};
use ::log::info;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION};

fn normalize_auth_endpoint(mut endpoint: String) -> String {
    if endpoint.contains("/native/") && !endpoint.ends_with('/') {
        endpoint.push('/');
    }
    endpoint
}

fn failure_type(parsed: &LoginResult) -> &str {
    parsed.failure_type.as_deref().unwrap_or("")
}

fn request_attempt(attempt: u32, following_redirect: bool) -> u32 {
    if following_redirect { 1 } else { attempt }
}

fn looks_like_plist(body: &[u8]) -> bool {
    let body = String::from_utf8_lossy(body).to_ascii_lowercase();
    body.starts_with("bplist")
        || ["<?xml", "<plist", "<dict", "<key"]
            .iter()
            .any(|marker| body.contains(marker))
}

fn response_message(body: &[u8]) -> String {
    let message = String::from_utf8_lossy(body)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    if message.is_empty() {
        "empty or non-plist body".to_string()
    } else {
        message.chars().take(200).collect()
    }
}

fn should_retry_with_legacy(endpoint: &str, status: u16, body: &[u8]) -> bool {
    endpoint.contains("/native/")
        && matches!(status, 204 | 403 | 404 | 503)
        && !looks_like_plist(body)
}

pub async fn login(
    http: &Http,
    _keyring: &KeyringStore,
    guid: &str,
    endpoint: String,
    email: &str,
    password: &str,
    auth_code_cb: Option<Box<dyn Fn() -> Result<String> + Send + Sync>>,
    auth_code: Option<String>,
) -> Result<Account> {
    let mut endpoint = normalize_auth_endpoint(endpoint);
    let mut redirect: Option<String> = None;
    let mut retry = true;

    let mut last: Option<(u16, HeaderMap, LoginResult)> = None;
    let mut auth_code = auth_code.unwrap_or("".to_string());

    let mut attempt = 1;
    while retry && attempt <= MAX_LOGIN_ATTEMPTS {
        retry = false;

        let following_redirect = redirect.is_some();
        if let Some(r) = redirect.take() {
            endpoint = normalize_auth_endpoint(r);
        }

        let current_attempt = request_attempt(attempt, following_redirect);

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let form = vec![
            ("appleId".to_string(), email.to_string()),
            ("attempt".to_string(), current_attempt.to_string()),
            ("guid".to_string(), guid.to_string()),
            (
                "password".to_string(),
                format!("{}{}", password, auth_code.replace(' ', "")),
            ),
            ("rmp".to_string(), "0".into()),
            ("why".to_string(), "signIn".into()),
        ];

        let (status, hdrs, body) = http.post_form_bytes(&endpoint, &form, headers).await?;

        if should_retry_with_legacy(&endpoint, status, &body) {
            info!("Retrying with legacy endpoint: {}", endpoint);
            endpoint = APPSTORE_AUTH_URL.to_string();
            redirect = None;
            attempt = 1;
            retry = true;
            continue;
        }

        if status == 429 {
            return Err(IpaToolError::RateLimited {
                status,
                message: response_message(&body),
            });
        }

        if status == 302 {
            if let Some(loc) = hdrs.get(LOCATION).and_then(|v| v.to_str().ok()) {
                redirect = Some(loc.to_string());
                retry = true;
                attempt += 1;
                continue;
            } else {
                return Err(IpaToolError::Unexpected(
                    "redirect without location header".into(),
                ));
            }
        }

        let normalized = normalize_plist_body(&body);
        if !looks_like_plist(&normalized) {
            return Err(IpaToolError::UnexpectedResponse {
                status,
                message: response_message(&body),
            });
        }
        let parsed: LoginResult = plist::from_reader_xml(std::io::Cursor::new(normalized))?;
        let failure_type = failure_type(&parsed);

        if attempt == 1 && failure_type == FAILURE_TYPE_INVALID_CREDENTIALS {
            retry = true;
        } else if failure_type.is_empty()
            && auth_code.is_empty()
            && parsed.customer_message.as_deref() == Some(CUSTOMER_MESSAGE_BAD_LOGIN)
        {
            let cb = auth_code_cb
                .as_deref()
                .ok_or_else(|| IpaToolError::AuthCodeRequired)?;
            auth_code = cb().map_err(|_| IpaToolError::AuthCodeRequired)?;
            retry = true;
        } else if failure_type.is_empty()
            && parsed.customer_message.as_deref() == Some(CUSTOMER_MESSAGE_ACCOUNT_DISABLED)
        {
            return Err(IpaToolError::Unexpected("account is disabled".into()));
        } else if !failure_type.is_empty() {
            return Err(IpaToolError::Unexpected(
                parsed
                    .customer_message
                    .clone()
                    .unwrap_or_else(|| "something went wrong".into()),
            ));
        } else if status != 200
            || parsed.password_token.as_deref().unwrap_or("").is_empty()
            || parsed
                .directory_services_id
                .as_deref()
                .unwrap_or("")
                .is_empty()
        {
            return Err(IpaToolError::Unexpected("something went wrong".into()));
        }

        last = Some((status, hdrs, parsed));
        if !retry {
            break;
        }

        attempt += 1;
    }

    if retry {
        return Err(IpaToolError::Unexpected("too many login attempts".into()));
    }

    let (_status, hdrs, parsed) =
        last.ok_or_else(|| IpaToolError::Unexpected("no login response".into()))?;

    let store_front = hdrs
        .get(HEADER_STOREFRONT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if store_front.is_empty() {
        return Err(IpaToolError::Unexpected("missing storefront header".into()));
    }

    let pod = hdrs
        .get(HEADER_POD)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let acct = parsed
        .account
        .ok_or_else(|| IpaToolError::Unexpected("missing accountInfo".into()))?;
    let addr = acct
        .address
        .unwrap_or(crate::appstore::types::LoginAddressResult {
            first_name: None,
            last_name: None,
        });

    let first = addr.first_name.unwrap_or_default();
    let last = addr.last_name.unwrap_or_default();
    let name = format!(
        "{}{}",
        first,
        if last.is_empty() {
            "".into()
        } else {
            format!(" {}", last)
        }
    );

    Ok(Account {
        name: name.trim().to_string(),
        email: acct.email.unwrap_or_else(|| email.to_string()),
        password_token: parsed.password_token.unwrap().to_string(),
        directory_services_id: parsed.directory_services_id.unwrap().to_string(),
        store_front,
        password: password.to_string(),
        pod,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_only_native_authentication_endpoints() {
        assert_eq!(
            normalize_auth_endpoint("https://auth.itunes.apple.com/auth/v1/native/fast".into()),
            "https://auth.itunes.apple.com/auth/v1/native/fast/"
        );
        assert_eq!(
            normalize_auth_endpoint(APPSTORE_AUTH_URL.into()),
            APPSTORE_AUTH_URL
        );
    }

    #[test]
    fn falls_back_for_expected_empty_native_responses() {
        for status in [204, 403, 404, 503] {
            assert!(should_retry_with_legacy(
                "https://auth.itunes.apple.com/auth/v1/native/fast/",
                status,
                b""
            ));
        }

        assert!(!should_retry_with_legacy(APPSTORE_AUTH_URL, 204, b""));
        assert!(!should_retry_with_legacy(
            "https://auth.itunes.apple.com/auth/v1/native/fast/",
            403,
            b"<plist><dict/></plist>"
        ));
        assert!(!should_retry_with_legacy(
            "https://auth.itunes.apple.com/auth/v1/native/fast/",
            500,
            b""
        ));
    }

    #[test]
    fn preserves_first_attempt_for_store_pod_redirects() {
        assert_eq!(request_attempt(2, true), 1);
        assert_eq!(request_attempt(2, false), 2);
    }
}
