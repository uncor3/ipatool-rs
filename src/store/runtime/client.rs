use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub type Transport = Arc<dyn Fn(reqwest::Request) -> Result<Response, ClientError> + Send + Sync>;
pub struct Response {
    pub status: reqwest::StatusCode,
    pub headers: reqwest::header::HeaderMap,
    pub body: Vec<u8>,
    pub stream: Option<reqwest::Response>,
}
pub struct Request {
    pub url: url::Url,
    pub method: reqwest::Method,
    pub operation: String,
    pub format: &'static str,
    pub headers: reqwest::header::HeaderMap,
    pub parameters: Option<plist::Dictionary>,
    pub body: Vec<u8>,
    pub bag: Option<plist::Dictionary>,
    pub hardware_id: Vec<u8>,
    pub signer: Option<Arc<dyn crate::sap::ActionSigner>>,
    pub transport: Transport,
    pub stream: bool,
    pub raw: bool,
    pub no_redirects: bool,
}

impl Runtime {
    /// Run on a blocking worker. The transport owns the actual HTTP connection.
    pub fn execute(&mut self, mut input: Request) -> Result<Response, ClientError> {
        if input.hardware_id.len() != 6 {
            return Err(failure("invalid Store hardware identity"));
        }
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| failure("Store state lock poisoned"))?;
            state.hardware_id = input.hardware_id.clone();
            state.transport = Some(input.transport);
            state.stream_response = input.stream;
            state.no_redirects = input.no_redirects;
            state.auth_request = input.operation == "authenticate";
        }
        let header = |key: &str| {
            input
                .headers
                .get(key)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
        };
        let saved = if header("X-Dsid").is_empty() {
            None
        } else {
            Some((
                header("X-Dsid"),
                header("X-Token"),
                header("X-Apple-Store-Front"),
            ))
        };
        let account = self.ephemeral_account(saved)?;
        let bag = if let Some(mut values) = input.bag.take() {
            if let Some(plist::Value::Dictionary(nested)) = values.get("urlBag").cloned() {
                values.extend(nested);
            }
            if input.operation == "purchase" {
                values.insert(
                    "buyProduct".into(),
                    plist::Value::String(input.url.to_string()),
                );
            }
            self.frozen_bag(values)?
        } else {
            0
        };
        let session = self.new_object("AMSURLSession", Value::Null)?;
        let session = self.invoke(
            session,
            "initWithConfiguration:delegate:delegateQueue:",
            &[0, 0, 0],
        )?;
        self.invoke(session, "setUseFallbackBag:", &[0])?;
        if input.operation != "authenticate" {
            let delegate = self.interactive_delegate()?;
            self.invoke(session, "setDelegate:", &[delegate])?;
        }
        if input.operation == "authenticate" {
            if input.signer.is_none() {
                return Err(failure("Store authentication requires a SAP signer"));
            }
            let original = input
                .parameters
                .as_ref()
                .ok_or_else(|| failure("Store authentication requires parameters"))?;
            let username = self.import(
                original
                    .get("appleId")
                    .ok_or_else(|| failure("missing Apple ID"))?,
            )?;
            self.invoke(account, "setUsername:", &[username])?;
            let password = original
                .get("password")
                .and_then(plist::Value::as_string)
                .ok_or_else(|| failure("missing authentication password"))?;
            let task = self.credential_task(account, bag, password)?;
            let built = self.invoke(
                task,
                "_createAuthenticateRequestParametersForAccount:",
                &[account],
            )?;
            let plist::Value::Dictionary(mut values) = self.export(built)? else {
                return Err(failure("invalid framework authentication parameters"));
            };
            let guid: String = input
                .hardware_id
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            if !values
                .get("guid")
                .and_then(plist::Value::as_string)
                .is_some_and(|v| v.eq_ignore_ascii_case(&guid))
            {
                return Err(failure("framework authentication hardware mismatch"));
            }
            for key in ["attempt", "why"] {
                if let Some(value) = original.get(key) {
                    values.insert(key.into(), value.clone());
                }
            }
            input.parameters = Some(values);
            self.invoke(session, "setDelegate:", &[task])?;
        }
        let request = if input.operation == "purchase" {
            self.purchase_request(
                account,
                bag,
                input
                    .parameters
                    .take()
                    .ok_or_else(|| failure("missing purchase parameters"))?,
            )?
        } else if let Some(parameters) = input.parameters {
            self.encode_request(account, bag, &input.method, &input.url, parameters)?
        } else {
            let request = self.new_object("AMSURLRequest", Value::Null)?;
            let url = self.new_object("NSURL", Value::String(input.url.to_string()))?;
            let request = self.invoke(
                request,
                "initWithURL:cachePolicy:timeoutInterval:",
                &[url, 0],
            )?;
            let method = self.new_object("NSString", Value::String(input.method.to_string()))?;
            self.invoke(request, "setHTTPMethod:", &[method])?;
            if !input.body.is_empty() {
                let body = self.new_object("NSData", Value::Bytes(input.body))?;
                self.invoke(request, "setHTTPBody:", &[body])?;
            }
            request
        };
        let properties = self.invoke(request, "properties", &[])?;
        if properties == 0 {
            let class = self
                .state
                .lock()
                .map_err(|_| failure("Store state lock poisoned"))?
                .receiver(request)?
                .0;
            return Err(failure(format!(
                "Store request {class} returned no properties"
            )));
        }
        for (selector, value) in [
            ("setAccount:", account),
            ("setBag:", bag),
            ("setKnownToBeTrusted:", 1),
            ("setShouldSetCookiesFromResponse:", 0),
            ("setShouldSetStorefrontFromResponse:", 0),
            ("setDisableLoadURLMetrics:", 1),
            ("setDisableBiometricsResponseHandling:", 1),
            ("setMaxRetryCount:", 0),
            (
                "setDisableResponseDecoding:",
                u64::from(input.raw || input.stream),
            ),
        ] {
            self.invoke(properties, selector, &[value])?;
        }
        for (key, value) in &input.headers {
            if key == reqwest::header::CONTENT_LENGTH {
                continue;
            }
            let key = self.new_object("NSString", Value::String(key.to_string()))?;
            let value = self.new_object(
                "NSString",
                Value::String(
                    value
                        .to_str()
                        .map_err(|_| failure("invalid Store request header"))?
                        .into(),
                ),
            )?;
            self.invoke(request, "setValue:forHTTPHeaderField:", &[value, key])?;
        }
        if let Some(signer) = input.signer {
            let body = self.invoke(request, "HTTPBody", &[])?;
            let bytes = {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| failure("Store state lock poisoned"))?;
                state.bytes(body)?
            };
            let signature = signer.sign(&bytes)?;
            let value = self.new_object("NSString", Value::String(STANDARD.encode(signature)))?;
            let key =
                self.new_object("NSString", Value::String("X-Apple-ActionSignature".into()))?;
            self.invoke(request, "setValue:forHTTPHeaderField:", &[value, key])?;
        }
        let promise = self.invoke(session, "dataTaskPromiseWithRequest:", &[request])?;
        let result = match self.resolve(promise) {
            Ok(result) => result,
            Err(ClientError::StoreFramework { .. }) if !input.stream => {
                return self
                    .state
                    .lock()
                    .map_err(|_| failure("Store state lock poisoned"))?
                    .last_response
                    .take()
                    .ok_or_else(|| failure("Store framework failed before receiving a response"));
            }
            Err(error) => return Err(error),
        };
        if !input.raw && !input.stream {
            let object = self.invoke(result, "object", &[])?;
            if object != 0 {
                let json = input.format == "json" || {
                    let state = self
                        .state
                        .lock()
                        .map_err(|_| failure("Store state lock poisoned"))?;
                    state
                        .last_response
                        .as_ref()
                        .and_then(|r| r.headers.get(reqwest::header::CONTENT_TYPE))
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|v| v.to_ascii_lowercase().contains("json"))
                };
                let mut bytes = Vec::new();
                if json {
                    let state = self
                        .state
                        .lock()
                        .map_err(|_| failure("Store state lock poisoned"))?;
                    bytes = serde_json::to_vec(&state.json_value(object, 0)?)
                        .map_err(|_| failure("failed to copy decoded Store JSON"))?;
                } else {
                    let value = self.export(object)?;
                    value.to_writer_xml(&mut bytes)?;
                }
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| failure("Store state lock poisoned"))?;
                let response = state
                    .last_response
                    .as_mut()
                    .ok_or_else(|| failure("Store session returned no HTTP response"))?;
                response.body = bytes;
                response.headers.remove(reqwest::header::CONTENT_LENGTH);
                response.headers.remove(reqwest::header::CONTENT_ENCODING);
            }
        }
        self.state
            .lock()
            .map_err(|_| failure("Store state lock poisoned"))?
            .last_response
            .take()
            .ok_or_else(|| failure("Store session returned no HTTP response"))
    }

    fn resolve(&mut self, promise: u64) -> Result<u64, ClientError> {
        let out = self
            .state
            .lock()
            .map_err(|_| failure("Store state lock poisoned"))?
            .alloc(8)?;
        let result = self.invoke(promise, "resultWithError:", &[out])?;
        let error = read64(self.engine.guest(), out)?;
        if error != 0 {
            let domain = self.invoke(error, "domain", &[])?;
            let code = self.invoke(error, "code", &[])? as i64;
            let domain = self
                .state
                .lock()
                .map_err(|_| failure("Store state lock poisoned"))?
                .string(domain)?;
            return Err(ClientError::StoreFramework { domain, code });
        }
        if result == 0 {
            return Err(failure("Store framework returned no result"));
        }
        Ok(result)
    }
    fn purchase_request(
        &mut self,
        account: u64,
        bag: u64,
        parameters: plist::Dictionary,
    ) -> Result<u64, ClientError> {
        if bag == 0 {
            return Err(failure("purchase requires a Store bag"));
        }
        validate_free_purchase(&parameters)?;
        let params = self.new_object("AMSBuyParams", Value::Null)?;
        let params = self.invoke(params, "init", &[])?;
        for (key, value) in &parameters {
            let value = self.import(value)?;
            let key = self.new_object("NSString", Value::String(key.clone()))?;
            self.invoke(params, "setParameter:forKey:", &[value, key])?;
        }
        let purchase = self.new_object("AMSPurchase", Value::Null)?;
        let purchase = self.invoke(purchase, "initWithPurchaseType:buyParams:", &[0, params])?;
        self.invoke(purchase, "setAccount:", &[account])?;
        let info = self.new_object("AMSPurchaseInfo", Value::Null)?;
        let info = self.invoke(info, "initWithPurchase:", &[purchase])?;
        self.invoke(info, "setAddKBSync:", &[0])?;
        self.invoke(info, "setHasBeenAuthedForBuy:", &[1])?;
        let encoder = self.purchase_encoder(info, bag)?;
        for (selector, value) in [
            ("setAnisetteType:", 0),
            ("setMescalType:", 0),
            ("setUrlKnownToBeTrusted:", 1),
            ("setEnableRemoteSecuritySigning:", 0),
            ("setDisableLoadURLMetrics:", 1),
            ("setCompressRequestBody:", 0),
            ("setShouldSetStorefrontHeader:", 0),
            ("setShouldSetCookieHeader:", 0),
        ] {
            self.invoke(encoder, selector, &[value])?;
        }
        let promise = self.invoke(encoder, "encodeRequest", &[])?;
        let request = self.resolve(promise)?;
        let body = self.invoke(request, "HTTPBody", &[])?;
        let bytes = self
            .state
            .lock()
            .map_err(|_| failure("Store state lock poisoned"))?
            .bytes(body)?;
        let value = plist::Value::from_reader(std::io::Cursor::new(bytes))?;
        let encoded = value
            .as_dictionary()
            .ok_or_else(|| failure("invalid encoded purchase"))?;
        validate_encoded_purchase(&parameters, encoded)?;
        Ok(request)
    }
    fn frozen_bag(&mut self, values: plist::Dictionary) -> Result<u64, ClientError> {
        let builder = self.new_object("AMSBagFrozenDataSourceBuilder", Value::Null)?;
        let data = self.import(&plist::Value::Dictionary(values))?;
        let profile = self.new_object("NSString", Value::String("AMSPurchase".into()))?;
        let version = self.new_object("NSString", Value::String("1".into()))?;
        let expiration = self.new_object("NSDate", Value::Date(now() + 300.0))?;
        for (selector, value) in [
            ("setData:", data),
            ("setProfile:", profile),
            ("setProfileVersion:", version),
            ("setExpirationDate:", expiration),
        ] {
            self.invoke(builder, selector, &[value])?;
        }
        self.invoke(builder, "createFrozenBag", &[])
    }
    fn credential_task(
        &mut self,
        account: u64,
        bag: u64,
        password: &str,
    ) -> Result<u64, ClientError> {
        let options = self.new_object("AMSAuthenticateOptions", Value::Null)?;
        let options = self.invoke(options, "init", &[])?;
        let password = self.new_object("NSString", Value::String(password.into()))?;
        for (selector, value) in [
            ("setEphemeral:", 1),
            ("setCanMakeAccountActive:", 0),
            ("setAllowServerDialogs:", 0),
            ("setPassword:", password),
            ("setCredentialSource:", 0),
        ] {
            self.invoke(options, selector, &[value])?;
        }
        let task = self.new_object("AMSVerifyCredentialsTask", Value::Null)?;
        let task = self.invoke(task, "init", &[])?;
        for (name, value) in [("_account", account), ("_options", options), ("_bag", bag)] {
            self.set_ivar(task, name, value)?;
        }
        Ok(task)
    }
    fn set_ivar(&mut self, object: u64, name: &str, value: u64) -> Result<(), ClientError> {
        let state = self
            .state
            .lock()
            .map_err(|_| failure("Store state lock poisoned"))?;
        let (mut class, _) = state.receiver(object)?;
        for _ in 0..64 {
            let index = state
                .classes
                .get(&class)
                .ok_or_else(|| failure("unknown Store ivar class"))?;
            let info = &state.class_definitions[*index];
            if let Some(offset) = info.ivars.get(name) {
                return self
                    .engine
                    .guest()
                    .mem_write(object + offset, &value.to_le_bytes());
            }
            class = info.superclass.clone();
        }
        Err(failure("Store ivar is not present in profile"))
    }
    fn encode_request(
        &mut self,
        account: u64,
        bag: u64,
        method: &reqwest::Method,
        url: &url::Url,
        parameters: plist::Dictionary,
    ) -> Result<u64, ClientError> {
        let encoder = self.new_object("AMSURLRequestEncoder", Value::Null)?;
        let encoder = self.invoke(encoder, "initWithBag:", &[bag])?;
        for (selector, value) in [
            ("setAccount:", account),
            ("setRequestEncoding:", 2),
            ("setAnisetteType:", 0),
            ("setMescalType:", 0),
            ("setEnableRemoteSecuritySigning:", 0),
            ("setUrlKnownToBeTrusted:", 1),
            ("setShouldSetCookieHeader:", 0),
            ("setShouldSetStorefrontHeader:", 0),
            ("setDisableLoadURLMetrics:", 1),
        ] {
            self.invoke(encoder, selector, &[value])?;
        }
        let method = match *method {
            reqwest::Method::GET => 2,
            reqwest::Method::POST => 4,
            reqwest::Method::PUT => 5,
            _ => return Err(failure("unsupported Store encoded request method")),
        };
        let url = self.new_object("NSURL", Value::String(url.to_string()))?;
        let parameters = self.import(&plist::Value::Dictionary(parameters))?;
        let promise = self.invoke(
            encoder,
            "requestWithMethod:URL:parameters:",
            &[method, url, parameters],
        )?;
        self.resolve(promise)
    }
}
pub(super) fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn purchase_text(value: Option<&plist::Value>) -> Result<String, ClientError> {
    Ok(match value {
        None => "<nil>".into(),
        Some(plist::Value::String(value)) => value.clone(),
        Some(plist::Value::Integer(value)) => value.as_signed().map_or_else(
            || value.as_unsigned().unwrap_or(0).to_string(),
            |v| v.to_string(),
        ),
        Some(plist::Value::Real(value)) => value.to_string(),
        Some(plist::Value::Boolean(value)) => value.to_string(),
        _ => return Err(failure("invalid Store purchase scalar")),
    })
}
fn validate_free_purchase(parameters: &plist::Dictionary) -> Result<(), ClientError> {
    if purchase_text(parameters.get("price"))? != "0"
        || parameters
            .get("productType")
            .and_then(plist::Value::as_string)
            != Some("C")
    {
        return Err(failure("purchasing paid apps is not supported"));
    }
    Ok(())
}
fn validate_encoded_purchase(
    parameters: &plist::Dictionary,
    encoded: &plist::Dictionary,
) -> Result<(), ClientError> {
    for key in ["price", "salableAdamId", "pricingParameters", "productType"] {
        if purchase_text(parameters.get(key))? != purchase_text(encoded.get(key))? {
            return Err(failure("purchase encoder changed product or price"));
        }
    }
    Ok(())
}

impl State {
    pub(super) fn bytes(&self, address: u64) -> Result<Vec<u8>, ClientError> {
        match self.objects.get(&address).map(|o| &o.value) {
            Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
            _ => Err(failure("Store object is not data")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn free_purchase_accepts_equivalent_go_scalar_types_and_rejects_changed_identity() {
        let parameters = plist::Dictionary::from_iter([
            ("price", plist::Value::Integer(0.into())),
            ("productType", plist::Value::String("C".into())),
            ("salableAdamId", plist::Value::Integer(1234.into())),
            ("pricingParameters", plist::Value::String("STDQ".into())),
        ]);
        validate_free_purchase(&parameters).unwrap();
        let mut encoded = parameters.clone();
        encoded.insert("price".into(), plist::Value::String("0".into()));
        encoded.insert("salableAdamId".into(), plist::Value::String("1234".into()));
        validate_encoded_purchase(&parameters, &encoded).unwrap();
        encoded.insert("price".into(), plist::Value::Real(0.0));
        validate_free_purchase(&encoded).unwrap();
        validate_encoded_purchase(&parameters, &encoded).unwrap();
        for (key, value) in [
            ("price", "1"),
            ("salableAdamId", "5678"),
            ("pricingParameters", "GAME"),
            ("productType", "other"),
        ] {
            let mut changed = encoded.clone();
            changed.insert(key.into(), plist::Value::String(value.into()));
            assert!(validate_encoded_purchase(&parameters, &changed).is_err());
            if key == "price" || key == "productType" {
                assert!(validate_free_purchase(&changed).is_err());
            }
        }
    }
}

