use crate::{
    appstore::types::{Account, App, PurchaseResult},
    constants::{
        CUSTOMER_MESSAGE_SUBSCRIPTION_REQUIRED, FAILURE_TYPE_PASSWORD_TOKEN_EXPIRED,
        FAILURE_TYPE_TEMPORARILY_UNAVAILABLE, PRICING_PARAMETER_APPLE_ARCADE,
        PRICING_PARAMETER_APPSTORE, PRIVATE_APPSTORE_DOMAIN, PRIVATE_PURCHASE_PATH,
    },
    error::{IpaToolError, Result},
    http::client::Http,
    util::normalize_plist_body,
};

fn purchase_url(pod: Option<&str>) -> String {
    let pod_prefix = match pod {
        Some(p) if !p.is_empty() => format!("p{}-", p),
        _ => String::new(),
    };
    format!(
        "https://{}{}{}",
        pod_prefix, PRIVATE_APPSTORE_DOMAIN, PRIVATE_PURCHASE_PATH
    )
}

fn purchase_payload(guid: &str, app_id: u64, pricing_parameters: &str) -> Result<Vec<u8>> {
    let mut dict = plist::Dictionary::new();
    dict.insert("appExtVrsId".into(), plist::Value::String("0".into()));
    dict.insert(
        "hasAskedToFulfillPreorder".into(),
        plist::Value::String("true".into()),
    );
    dict.insert(
        "buyWithoutAuthorization".into(),
        plist::Value::String("true".into()),
    );
    dict.insert(
        "hasDoneAgeCheck".into(),
        plist::Value::String("true".into()),
    );
    dict.insert("guid".into(), plist::Value::String(guid.to_string()));
    dict.insert("needDiv".into(), plist::Value::String("0".into()));
    dict.insert(
        "origPage".into(),
        plist::Value::String(format!("Software-{}", app_id)),
    );
    dict.insert(
        "origPageLocation".into(),
        plist::Value::String("Buy".into()),
    );
    dict.insert("price".into(), plist::Value::String("0".into()));
    dict.insert(
        "pricingParameters".into(),
        plist::Value::String(pricing_parameters.to_string()),
    );
    dict.insert("productType".into(), plist::Value::String("C".into()));
    dict.insert("salableAdamId".into(), plist::Value::Integer(app_id.into()));

    let mut out = Vec::new();
    plist::to_writer_xml(&mut out, &plist::Value::Dictionary(dict))?;
    Ok(out)
}

async fn purchase_with_params(
    _http: &Http,
    guid: &str,
    acc: &Account,
    app: &App,
    pricing_parameters: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let payload = purchase_payload(guid, app.id, pricing_parameters)?;
    let url = purchase_url(acc.pod.as_deref());

    let res = client
        .post(url)
        .header("Content-Type", "application/x-apple-plist")
        .header("iCloud-DSID", &acc.directory_services_id)
        .header("X-Dsid", &acc.directory_services_id)
        .header("X-Apple-Store-Front", &acc.store_front)
        .header("X-Token", &acc.password_token)
        .body(payload)
        .send()
        .await?;

    let status = res.status();
    let body = res.bytes().await?;

    if status == reqwest::StatusCode::INTERNAL_SERVER_ERROR {
        return Err(IpaToolError::Unexpected("license already exists".into()));
    }

    let normalized = normalize_plist_body(&body);
    if normalized.is_empty() {
        return Err(IpaToolError::Unexpected("empty purchase response".into()));
    }

    let parsed: PurchaseResult = plist::from_bytes(&normalized)?;

    if parsed.failure_type.as_deref() == Some(FAILURE_TYPE_TEMPORARILY_UNAVAILABLE) {
        return Err(IpaToolError::TemporarilyUnavailable);
    }
    if parsed.customer_message.as_deref() == Some(CUSTOMER_MESSAGE_SUBSCRIPTION_REQUIRED) {
        return Err(IpaToolError::SubscriptionRequired);
    }
    if parsed.failure_type.as_deref() == Some(FAILURE_TYPE_PASSWORD_TOKEN_EXPIRED) {
        return Err(IpaToolError::PasswordTokenExpired);
    }
    if parsed.failure_type.is_some() && parsed.customer_message.is_some() {
        return Err(IpaToolError::Unexpected(
            parsed
                .customer_message
                .unwrap_or_else(|| "something went wrong".into()),
        ));
    }
    if parsed.failure_type.is_some() {
        return Err(IpaToolError::Unexpected("something went wrong".into()));
    }
    if parsed.jingle_doc_type.as_deref() != Some("purchaseSuccess") || parsed.status != Some(0) {
        return Err(IpaToolError::Unexpected("failed to purchase app".into()));
    }

    Ok(())
}

pub async fn purchase(http: &Http, guid: &str, acc: &Account, app: &App) -> Result<()> {
    if app.price.unwrap_or(0.0) > 0.0 {
        return Err(IpaToolError::PaidAppsNotSupported);
    }

    match purchase_with_params(http, guid, acc, app, PRICING_PARAMETER_APPSTORE).await {
        Ok(()) => Ok(()),
        Err(IpaToolError::TemporarilyUnavailable) => {
            purchase_with_params(http, guid, acc, app, PRICING_PARAMETER_APPLE_ARCADE).await
        }
        Err(e) => Err(e),
    }
}
