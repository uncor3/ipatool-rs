use crate::{
    appstore::types::{Account, App, PurchaseResult},
    constants::{
        CUSTOMER_MESSAGE_PASSWORD_CHANGED, CUSTOMER_MESSAGE_SUBSCRIPTION_REQUIRED,
        FAILURE_TYPE_DEVICE_VERIFICATION_FAILED, FAILURE_TYPE_LICENSE_ALREADY_EXISTS,
        FAILURE_TYPE_PASSWORD_TOKEN_EXPIRED, FAILURE_TYPE_SIGN_IN_REQUIRED,
        FAILURE_TYPE_TEMPORARILY_UNAVAILABLE, PRICING_PARAMETER_APPLE_ARCADE,
        PRICING_PARAMETER_APPSTORE, PRIVATE_APPSTORE_DOMAIN, PRIVATE_PURCHASE_PATH,
    },
    error::{IpaToolError, Result},
    http::client::Http,
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

fn validate_purchase_response(status: reqwest::StatusCode, parsed: PurchaseResult) -> Result<()> {
    if parsed.failure_type.as_deref() == Some(FAILURE_TYPE_TEMPORARILY_UNAVAILABLE) {
        return Err(IpaToolError::TemporarilyUnavailable);
    }
    if parsed.customer_message.as_deref() == Some(CUSTOMER_MESSAGE_SUBSCRIPTION_REQUIRED) {
        return Err(IpaToolError::SubscriptionRequired);
    }
    if matches!(
        parsed.failure_type.as_deref(),
        Some(
            FAILURE_TYPE_PASSWORD_TOKEN_EXPIRED
                | FAILURE_TYPE_SIGN_IN_REQUIRED
                | FAILURE_TYPE_DEVICE_VERIFICATION_FAILED
        )
    ) || parsed.customer_message.as_deref() == Some(CUSTOMER_MESSAGE_PASSWORD_CHANGED)
    {
        return Err(IpaToolError::PasswordTokenExpired);
    }
    if parsed.failure_type.as_deref() == Some(FAILURE_TYPE_LICENSE_ALREADY_EXISTS)
        || status == reqwest::StatusCode::INTERNAL_SERVER_ERROR
    {
        return Err(IpaToolError::LicenseAlreadyExists);
    }
    if let Some(failure_type) = parsed.failure_type {
        return Err(IpaToolError::Unexpected(
            parsed
                .customer_message
                .unwrap_or_else(|| format!("purchase failed with failure type {failure_type}")),
        ));
    }
    if parsed.jingle_doc_type.as_deref() != Some("purchaseSuccess") || parsed.status != Some(0) {
        return Err(IpaToolError::Unexpected("failed to purchase app".into()));
    }

    Ok(())
}

async fn purchase_with_params(
    http: &Http,
    guid: &str,
    acc: &Account,
    app: &App,
    pricing_parameters: &str,
) -> Result<()> {
    let payload = purchase_payload(guid, app.id, pricing_parameters)?;
    let url = purchase_url(acc.pod.as_deref());

    let res = http
        .client()
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

    // original implementation does exactly this
    if status == reqwest::StatusCode::INTERNAL_SERVER_ERROR
    {
        return Err(IpaToolError::LicenseAlreadyExists);
    }

    let parsed: PurchaseResult = plist::from_bytes(&body)?;

    validate_purchase_response(status, parsed)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn response(failure_type: Option<&str>, customer_message: Option<&str>) -> PurchaseResult {
        PurchaseResult {
            failure_type: failure_type.map(str::to_owned),
            customer_message: customer_message.map(str::to_owned),
            jingle_doc_type: None,
            status: None,
        }
    }

    #[test]
    fn recognizes_an_existing_license() {
        let result = validate_purchase_response(
            reqwest::StatusCode::OK,
            response(
                Some(FAILURE_TYPE_LICENSE_ALREADY_EXISTS),
                Some("An unknown error has occurred"),
            ),
        );

        assert!(matches!(result, Err(IpaToolError::LicenseAlreadyExists)));
    }

    #[test]
    fn recognizes_legacy_existing_license_response() {
        let result = validate_purchase_response(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            response(None, None),
        );

        assert!(matches!(result, Err(IpaToolError::LicenseAlreadyExists)));
    }

    #[test]
    fn recognizes_authentication_failures() {
        for failure_type in [
            FAILURE_TYPE_PASSWORD_TOKEN_EXPIRED,
            FAILURE_TYPE_SIGN_IN_REQUIRED,
            FAILURE_TYPE_DEVICE_VERIFICATION_FAILED,
        ] {
            let result = validate_purchase_response(
                reqwest::StatusCode::OK,
                response(Some(failure_type), None),
            );
            assert!(matches!(result, Err(IpaToolError::PasswordTokenExpired)));
        }

        let result = validate_purchase_response(
            reqwest::StatusCode::OK,
            response(None, Some(CUSTOMER_MESSAGE_PASSWORD_CHANGED)),
        );
        assert!(matches!(result, Err(IpaToolError::PasswordTokenExpired)));
    }

    #[test]
    fn accepts_a_successful_purchase() {
        let result = validate_purchase_response(
            reqwest::StatusCode::OK,
            PurchaseResult {
                failure_type: None,
                customer_message: None,
                jingle_doc_type: Some("purchaseSuccess".into()),
                status: Some(0),
            },
        );

        assert!(result.is_ok());
    }
}
