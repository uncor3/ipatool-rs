use std::collections::HashMap;
use std::error::Error as _;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use reqwest::header::{HeaderMap, RETRY_AFTER};
use reqwest::{StatusCode, Url};

use crate::client::AppleClient;
use crate::error::{ClientError, StoreError};
use crate::model::Account;
use crate::sap::ActionSigner;

const MAX_REDIRECTS: u32 = 4;
const MAX_AUTH_REQUEST_ATTEMPTS: u32 = 3;
const AUTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const AUTH_RETRY_DELAY: Duration = Duration::from_secs(10);
const MAX_AUTH_RETRY_DELAY: Duration = Duration::from_secs(30);

/// Header carrying the SAP signature over the request body.
const ACTION_SIGNATURE_HEADER: &str = "X-Apple-ActionSignature";

pub async fn login(
    client: &AppleClient,
    email: &str,
    password: &str,
    auth_code: Option<&str>,
    auth_url: &Url,
    signer: Option<&dyn ActionSigner>,
) -> Result<Account, ClientError> {
    super::bag::validate_auth_endpoint(auth_url)?;
    let auth_code = normalize_auth_code(auth_code.unwrap_or_default())?;

    let password_with_code = format!("{password}{auth_code}");

    let mut attempt = 1u32;
    let mut redirects = 0u32;
    let mut current_url = auth_url.clone();

    loop {
        let body = build_auth_plist(email, &password_with_code, client.guid(), attempt);
        let mut body_bytes = Vec::new();
        plist::to_writer_xml(&mut body_bytes, &body)
            .map_err(|e| ClientError::UnexpectedResponse(format!("plist serialize: {e}")))?;

        // Apple signs the exact bytes it receives, so this has to happen after
        // the body is serialized. Transport retries reuse these exact bytes and
        // this exact signature; they are not new Apple credential attempts.
        let action_signature = signer
            .map(|signer| signer.sign(&body_bytes))
            .transpose()?
            .map(|signature| encode_base64(&signature));

        let response = send_authentication_request(
            client,
            &current_url,
            &body_bytes,
            action_signature.as_deref(),
            phone_number_storefront(email),
            attempt,
        )
        .await?;
        let status = response.status;

        if status.is_redirection() {
            redirects += 1;
            if redirects > MAX_REDIRECTS {
                return Err(ClientError::UnexpectedResponse(
                    "too many auth redirects".into(),
                ));
            }

            current_url = resolve_auth_redirect(status, &response.headers, &current_url)?;
            continue;
        }

        let store_front = response
            .headers
            .get("x-set-apple-store-front")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let pod = response
            .headers
            .get("pod")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let resp_body = response.body;

        // Authentication responses contain account details and password tokens.
        // Log their size, never their contents.
        tracing::debug!(len = resp_body.len(), "auth response body received");

        if resp_body.is_empty() {
            // Apple's application tier drops unsigned sign-in requests with a
            // zero-length 403. Saying so beats reporting an empty response.
            if signer.is_none() && status == reqwest::StatusCode::FORBIDDEN {
                return Err(ClientError::SapSignatureRequired {
                    status: status.as_u16(),
                });
            }

            return Err(ClientError::UnexpectedResponse(format!(
                "empty response (HTTP {status})"
            )));
        }

        let dict: HashMap<String, plist::Value> =
            crate::client::plist_xml::parse_plist_response(&resp_body)?;

        if let Some(err) = StoreError::from_plist_dict(&dict) {
            if err.is_retryable() && attempt == 1 {
                attempt += 1;
                tracing::warn!("retryable error, attempt {attempt}");
                continue;
            }
            if matches!(err, StoreError::AuthCodeRequired) && !auth_code.is_empty() {
                return Err(ClientError::UnexpectedResponse(
                    "Apple did not complete verification; try a fresh 2FA code".into(),
                ));
            }
            return Err(ClientError::Store(err));
        }

        let password_token = dict
            .get("passwordToken")
            .and_then(|v| v.as_string())
            .ok_or_else(|| ClientError::UnexpectedResponse("missing passwordToken".into()))?
            .to_string();

        let ds_person_id = dict
            .get("dsPersonId")
            .map(|v| match v {
                plist::Value::String(s) => s.clone(),
                plist::Value::Integer(i) => {
                    i.as_signed().map_or_else(String::new, |n| n.to_string())
                }
                _ => String::new(),
            })
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ClientError::UnexpectedResponse("missing dsPersonId".into()))?;

        let name = dict
            .get("accountInfo")
            .and_then(|v| v.as_dictionary())
            .and_then(|d| d.get("address"))
            .and_then(|v| v.as_dictionary())
            .and_then(|d| {
                let first = d.get("firstName")?.as_string()?;
                let last = d.get("lastName")?.as_string()?;
                Some(format!("{first} {last}"))
            })
            .unwrap_or_default();

        let sf = store_front.unwrap_or_default();

        return Ok(Account {
            email: email.to_string(),
            password_token,
            directory_services_id: ds_person_id,
            name,
            store_front: sf,
            pod,
            password: None,
        });
    }
}

/// Match Go's pasted-code normalization without modifying the password.
fn normalize_auth_code(code: &str) -> Result<String, ClientError> {
    if code.is_empty() {
        return Ok(String::new());
    }
    let code = code.trim();
    let code = code
        .strip_prefix("\u{1b}[200~")
        .and_then(|code| code.strip_suffix("\u{1b}[201~"))
        .unwrap_or(code);
    let code: String = code.chars().filter(|ch| !ch.is_whitespace()).collect();
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ClientError::UnexpectedResponse(
            "2FA code must contain exactly six digits".into(),
        ));
    }
    Ok(code)
}

fn resolve_auth_redirect(
    status: StatusCode,
    headers: &HeaderMap,
    base: &Url,
) -> Result<Url, ClientError> {
    let location = headers
        .get(reqwest::header::LOCATION)
        .ok_or_else(|| ClientError::MissingHeader(format!("Location (HTTP {status})")))?
        .to_str()
        .map_err(|_| ClientError::MissingHeader("Location (invalid)".into()))?
        .trim();
    if !matches!(status.as_u16(), 301 | 302 | 307 | 308) {
        return Err(ClientError::UnexpectedResponse(format!(
            "unsupported authentication redirect status (HTTP {status})"
        )));
    }
    if location.is_empty() {
        return Err(ClientError::UnexpectedResponse(
            "invalid authentication redirect location".into(),
        ));
    }
    let destination = base.join(location).map_err(|_| {
        ClientError::UnexpectedResponse("invalid authentication redirect URL".into())
    })?;
    super::bag::validate_auth_endpoint(&destination)?;
    Ok(destination)
}

struct AuthHttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

async fn send_authentication_request(
    client: &AppleClient,
    url: &Url,
    body: &[u8],
    action_signature: Option<&str>,
    storefront: Option<&str>,
    apple_attempt: u32,
) -> Result<AuthHttpResponse, ClientError> {
    let mut outcomes = Vec::with_capacity(MAX_AUTH_REQUEST_ATTEMPTS as usize);

    for request_attempt in 1..=MAX_AUTH_REQUEST_ATTEMPTS {
        tracing::debug!(
            attempt = apple_attempt,
            request_attempt,
            %url,
            signed = action_signature.is_some(),
            "sending auth request"
        );

        let mut request = client
            .http()
            .post(url.as_str())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .timeout(AUTH_REQUEST_TIMEOUT);
        if let Some(signature) = action_signature {
            request = request.header(ACTION_SIGNATURE_HEADER, signature);
        }
        if let Some(storefront) = storefront {
            request = request.header("X-Apple-Store-Front", storefront);
        }

        let response = match request.body(body.to_vec()).send().await {
            Ok(response) => response,
            Err(error) if is_retryable_transport_error(&error) => {
                outcomes.push("transport error".to_string());
                if request_attempt == MAX_AUTH_REQUEST_ATTEMPTS {
                    return Err(authentication_attempts_exhausted(&outcomes));
                }
                sleep_before_auth_retry(None, request_attempt).await?;
                continue;
            }
            Err(error) => return Err(ClientError::Http(error)),
        };

        let status = response.status();
        let headers = response.headers().clone();
        let response_body = match response.bytes().await {
            Ok(body) => body,
            Err(error) if is_retryable_transport_error(&error) => {
                outcomes.push("transport error".to_string());
                if request_attempt == MAX_AUTH_REQUEST_ATTEMPTS {
                    return Err(authentication_attempts_exhausted(&outcomes));
                }
                sleep_before_auth_retry(Some(&headers), request_attempt).await?;
                continue;
            }
            Err(error) => return Err(ClientError::Http(error)),
        };
        tracing::debug!(%status, request_attempt, "auth response status");

        if !is_retryable_auth_response(status, &headers, &response_body, action_signature.is_some())
        {
            return Ok(AuthHttpResponse {
                status,
                headers,
                body: response_body,
            });
        }

        outcomes.push(format!("HTTP {}", status.as_u16()));
        if request_attempt == MAX_AUTH_REQUEST_ATTEMPTS {
            return Err(authentication_attempts_exhausted(&outcomes));
        }
        sleep_before_auth_retry(Some(&headers), request_attempt).await?;
    }

    unreachable!("authentication request loop always returns")
}

// Upstream supplies only a routing hint for Chinese/Indian phone accounts;
// never rewrite the original Apple ID in the signed request body.
fn phone_number_storefront(apple_id: &str) -> Option<&'static str> {
    let number = apple_id.trim().replace([' ', '-'], "");
    let (mut number, international) = match number.strip_prefix('+') {
        Some(number) => (number, true),
        None => match number.strip_prefix("00") {
            Some(number) => (number, true),
            None => (number.as_str(), false),
        },
    };
    if !number.bytes().all(|digit| digit.is_ascii_digit()) {
        return None;
    }
    if number.len() == 13 && number.starts_with("861") {
        return Some("143465");
    }
    if number.len() == 12 && number.starts_with("91") {
        number = &number[2..];
    } else if international {
        return None;
    }
    if number.len() == 11 && number.starts_with('1') {
        return Some("143465");
    }
    if !international && number.len() == 11 && number.starts_with('0') {
        number = &number[1..];
    }
    (number.len() == 10 && matches!(number.as_bytes()[0], b'6'..=b'9')).then_some("143467")
}

fn is_retryable_auth_response(
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
    signed: bool,
) -> bool {
    if status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_FOUND
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
    {
        return true;
    }

    // A Store pod can transiently return an empty or HTML 403. Preserve a
    // structured plist 403 so Apple credential errors are decoded normally.
    status == StatusCode::FORBIDDEN
        && signed
        && (body.is_empty()
            || headers
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.to_ascii_lowercase().contains("text/html"))
            || looks_like_html(body))
}

fn looks_like_html(body: &[u8]) -> bool {
    let body = body
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .take(32)
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    body.starts_with(b"<!doctype html") || body.starts_with(b"<html")
}

fn is_retryable_transport_error(error: &reqwest::Error) -> bool {
    if error.is_timeout() || error.is_connect() {
        return true;
    }

    let mut source = error.source();
    while let Some(cause) = source {
        if let Some(error) = cause.downcast_ref::<std::io::Error>()
            && matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            )
        {
            return true;
        }
        source = cause.source();
    }
    false
}

async fn sleep_before_auth_retry(
    headers: Option<&HeaderMap>,
    request_attempt: u32,
) -> Result<(), ClientError> {
    let delay = authentication_retry_delay(headers, request_attempt, SystemTime::now())?;
    tracing::warn!(
        request_attempt,
        delay_seconds = delay.as_secs(),
        "Apple authentication returned a transient response; retrying"
    );
    tokio::time::sleep(delay).await;
    Ok(())
}

fn authentication_retry_delay(
    headers: Option<&HeaderMap>,
    request_attempt: u32,
    now: SystemTime,
) -> Result<Duration, ClientError> {
    let fallback = std::cmp::min(
        AUTH_RETRY_DELAY * (1_u32 << request_attempt.saturating_sub(1)),
        MAX_AUTH_RETRY_DELAY,
    );
    let Some(value) = headers
        .and_then(|headers| headers.get(RETRY_AFTER))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    else {
        return Ok(fallback);
    };

    let requested = value.parse::<u64>().map(Duration::from_secs).or_else(|_| {
        httpdate::parse_http_date(value)
            .map(|deadline| deadline.duration_since(now).unwrap_or(Duration::ZERO))
    });
    let Ok(requested) = requested else {
        return Ok(fallback);
    };
    if requested > MAX_AUTH_RETRY_DELAY {
        return Err(ClientError::UnexpectedResponse(format!(
            "Apple requested an authentication retry after {} seconds, longer than the {}-second limit; try again later",
            requested.as_secs(),
            MAX_AUTH_RETRY_DELAY.as_secs()
        )));
    }
    Ok(std::cmp::max(requested, Duration::from_secs(1)))
}

fn authentication_attempts_exhausted(outcomes: &[String]) -> ClientError {
    ClientError::UnexpectedResponse(format!(
        "authentication request failed after {} attempts ({}); try again later",
        outcomes.len(),
        outcomes.join(", ")
    ))
}

fn encode_base64(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn build_auth_plist(email: &str, password: &str, guid: &str, attempt: u32) -> plist::Dictionary {
    let mut dict = plist::Dictionary::new();
    dict.insert("appleId".into(), plist::Value::String(email.into()));
    dict.insert("attempt".into(), plist::Value::String(attempt.to_string()));
    dict.insert("guid".into(), plist::Value::String(guid.into()));
    dict.insert("password".into(), plist::Value::String(password.into()));
    dict.insert("rmp".into(), plist::Value::String("0".into()));
    dict.insert("why".into(), plist::Value::String("signIn".into()));
    dict
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_pasted_codes_and_preserves_password() {
        for input in ["012345", " 01 23\t45\n", "\u{1b}[200~01 2345\u{1b}[201~"] {
            let code = normalize_auth_code(input).unwrap();
            assert_eq!(code, "012345");
            let password = " \tpäss word\n";
            let body = build_auth_plist("example", &format!("{password}{code}"), "guid", 1);
            assert_eq!(body["password"].as_string(), Some(" \tpäss word\n012345"));
        }
        assert_eq!(normalize_auth_code("").unwrap(), "");
        for input in [
            " ",
            "12345",
            "1234567",
            "１２３４５６",
            "12345a",
            "\u{1b}[200~123456",
        ] {
            assert!(normalize_auth_code(input).is_err());
        }
    }

    #[test]
    fn redirects_require_supported_status_and_valid_location() {
        let base =
            Url::parse("https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/")
                .unwrap();
        let mut headers = HeaderMap::new();
        assert!(matches!(
            resolve_auth_redirect(StatusCode::FOUND, &headers, &base),
            Err(ClientError::MissingHeader(_))
        ));
        headers.insert("location", "?Pod=12".parse().unwrap());
        for status in [301, 302, 307, 308] {
            let url = resolve_auth_redirect(StatusCode::from_u16(status).unwrap(), &headers, &base)
                .unwrap();
            assert_eq!(url.query(), Some("Pod=12"));
        }
        assert!(resolve_auth_redirect(StatusCode::SEE_OTHER, &headers, &base).is_err());
        for location in [
            " ",
            "https://example.com/",
            "https://user@buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/",
            "/other",
        ] {
            headers.insert("location", location.parse().unwrap());
            assert!(resolve_auth_redirect(StatusCode::FOUND, &headers, &base).is_err());
        }
    }

    #[test]
    fn phone_account_routing_preserves_original_apple_id() {
        for (apple_id, expected) in [
            ("13912345678", Some("143465")),
            (" +86 139-1234-5678 ", Some("143465")),
            ("008613912345678", Some("143465")),
            ("9123456789", Some("143467")),
            ("8612345678", Some("143467")),
            ("09123456789", Some("143467")),
            ("+919123456789", Some("143467")),
            ("00919123456789", Some("143467")),
            ("13912345678@example.test", None),
            ("+13912345678", None),
            ("+8612345678", None),
            ("+9109123456789", None),
            ("+８６１３９１２３４５６７８", None),
            ("139\n12345678", None),
            ("++8613912345678", None),
            ("", None),
        ] {
            assert_eq!(phone_number_storefront(apple_id), expected, "{apple_id}");
            assert_eq!(
                build_auth_plist(apple_id, "password", "guid", 1)["appleId"].as_string(),
                Some(apple_id)
            );
        }
    }

    #[test]
    fn retries_transient_authentication_statuses() {
        let headers = HeaderMap::new();
        for status in [
            StatusCode::NO_CONTENT,
            StatusCode::NOT_FOUND,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert!(is_retryable_auth_response(status, &headers, &[], true));
        }
        assert!(!is_retryable_auth_response(
            StatusCode::OK,
            &headers,
            &[],
            true
        ));
    }

    #[test]
    fn retries_only_unstructured_signed_forbidden_responses() {
        let mut html_headers = HeaderMap::new();
        html_headers.insert(
            reqwest::header::CONTENT_TYPE,
            "text/html; charset=utf-8".parse().unwrap(),
        );
        assert!(is_retryable_auth_response(
            StatusCode::FORBIDDEN,
            &HeaderMap::new(),
            &[],
            true
        ));
        assert!(is_retryable_auth_response(
            StatusCode::FORBIDDEN,
            &html_headers,
            b"temporarily unavailable",
            true
        ));
        assert!(!is_retryable_auth_response(
            StatusCode::FORBIDDEN,
            &HeaderMap::new(),
            b"<plist><dict></dict></plist>",
            true
        ));
        assert!(!is_retryable_auth_response(
            StatusCode::FORBIDDEN,
            &HeaderMap::new(),
            &[],
            false
        ));
    }

    #[test]
    fn retry_delay_uses_backoff_and_retry_after() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert_eq!(
            authentication_retry_delay(None, 1, now).unwrap(),
            Duration::from_secs(10)
        );
        assert_eq!(
            authentication_retry_delay(None, 2, now).unwrap(),
            Duration::from_secs(20)
        );

        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, "5".parse().unwrap());
        assert_eq!(
            authentication_retry_delay(Some(&headers), 1, now).unwrap(),
            Duration::from_secs(5)
        );
        headers.insert(RETRY_AFTER, "0".parse().unwrap());
        assert_eq!(
            authentication_retry_delay(Some(&headers), 1, now).unwrap(),
            Duration::from_secs(1)
        );
        headers.insert(
            RETRY_AFTER,
            httpdate::fmt_http_date(now + Duration::from_secs(7))
                .parse()
                .unwrap(),
        );
        assert_eq!(
            authentication_retry_delay(Some(&headers), 1, now).unwrap(),
            Duration::from_secs(7)
        );
        headers.insert(RETRY_AFTER, "31".parse().unwrap());
        assert!(authentication_retry_delay(Some(&headers), 1, now).is_err());
    }
}
