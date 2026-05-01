use crate::{
    appstore::types::{Account, LoginResult},
    constants::{
        CUSTOMER_MESSAGE_ACCOUNT_DISABLED, CUSTOMER_MESSAGE_BAD_LOGIN,
        FAILURE_TYPE_INVALID_CREDENTIALS, HEADER_POD, HEADER_STOREFRONT, MAX_LOGIN_ATTEMPTS,
    },
    error::{IpaToolError, Result},
    http::client::Http,
    storage::keyring::KeyringStore,
    util::normalize_plist_body,
};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION};

pub async fn login(
    http: &Http,
    _keyring: &KeyringStore,
    guid: &str,
    mut endpoint: String,
    email: &str,
    password: &str,
    auth_code_cb: Option<Box<dyn Fn() -> Result<String> + Send + Sync>>,
    auth_code: Option<String>,
) -> Result<Account> {
    let mut redirect: Option<String> = None;
    let mut retry = true;

    let mut last: Option<(u16, HeaderMap, LoginResult)> = None;
    let mut auth_code = auth_code.unwrap_or("".to_string());

    for attempt in 1..=MAX_LOGIN_ATTEMPTS {
        if !retry {
            break;
        }
        retry = false;

        if let Some(r) = redirect.take() {
            endpoint = r;
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let form = vec![
            ("appleId".to_string(), email.to_string()),
            ("attempt".to_string(), attempt.to_string()),
            ("guid".to_string(), guid.to_string()),
            (
                "password".to_string(),
                format!("{}{}", password, auth_code.replace(' ', "")),
            ),
            ("rmp".to_string(), "0".into()),
            ("why".to_string(), "signIn".into()),
        ];

        let (status, hdrs, body) = http.post_form_bytes(&endpoint, &form, headers).await?;
        let normalized = normalize_plist_body(&body);
        let parsed: LoginResult = plist::from_reader_xml(std::io::Cursor::new(normalized))?;

        /*  redirect */
        if status == 302 {
            if let Some(loc) = hdrs.get(LOCATION).and_then(|v| v.to_str().ok()) {
                redirect = Some(loc.to_string());
                retry = true;
            } else {
                return Err(IpaToolError::Unexpected(
                    "redirect without location header".into(),
                ));
            }
        } else if attempt == 1
            && parsed.failure_type.as_deref() == Some(FAILURE_TYPE_INVALID_CREDENTIALS)
        {
            retry = true;
        } else if parsed.failure_type.is_none()
            && auth_code.is_empty()
            && parsed.customer_message.as_deref() == Some(CUSTOMER_MESSAGE_BAD_LOGIN)
        {
            let cb = auth_code_cb
                .as_deref()
                .ok_or_else(|| IpaToolError::AuthCodeRequired)?;
            auth_code = cb().map_err(|_| IpaToolError::AuthCodeRequired)?;
            retry = true;
        } else if parsed.failure_type.is_none()
            && parsed.customer_message.as_deref() == Some(CUSTOMER_MESSAGE_ACCOUNT_DISABLED)
        {
            return Err(IpaToolError::Unexpected("account is disabled".into()));
        } else if parsed.failure_type.is_some() {
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
