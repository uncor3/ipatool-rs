//! Foundation networking adapters. Apple guest code owns encoding and delegates;
//! the injected transport owns sockets and persistent cookie storage.
use super::*;

fn canonical(key: &str) -> String {
    key.split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    first.to_ascii_uppercase().to_string() + &chars.as_str().to_ascii_lowercase()
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}
pub(super) fn allowed_url(url: &url::Url, authenticated: bool) -> bool {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    if !authenticated {
        return matches!(url.scheme(), "https" | "http");
    }
    url.scheme() == "https"
        && (host == "apple.com"
            || host.ends_with(".apple.com")
            || host.ends_with(".mzstatic.com")
            || host.ends_with(".cdn-apple.com"))
}
impl State {
    fn sort_array(
        &mut self,
        guest: Guest<'_>,
        mut items: Vec<u64>,
        mut i: usize,
        mut j: usize,
        block: u64,
    ) -> Result<(), ClientError> {
        if i >= items.len() {
            let result = self.new_object(guest, "NSArray", Value::Array(items))?;
            return self.set(guest, result);
        }
        if j == 0 {
            i += 1;
            j = i;
            if i >= items.len() {
                let result = self.new_object(guest, "NSArray", Value::Array(items))?;
                return self.set(guest, result);
            }
        }
        self.callback_then(
            guest,
            read64(guest, block + 16)?,
            &[block, items[j - 1], items[j]],
            Box::new(move |state, guest| {
                if state.arg(guest, 0)? as i64 > 0 {
                    items.swap(j - 1, j);
                    j -= 1;
                } else {
                    i += 1;
                    j = i;
                }
                state.sort_array(guest, items, i, j, block)
            }),
        )
    }
    fn enumerate_dictionary(
        &mut self,
        guest: Guest<'_>,
        items: Arc<Vec<(String, u64)>>,
        index: usize,
        block: u64,
        stop: u64,
    ) -> Result<(), ClientError> {
        if index == items.len() || read64(guest, stop)? != 0 {
            return self.set(guest, 0);
        }
        let key = self.new_object(guest, "NSString", Value::String(items[index].0.clone()))?;
        self.callback_then(
            guest,
            read64(guest, block + 16)?,
            &[block, key, items[index].1, stop],
            Box::new(move |state, guest| {
                state.enumerate_dictionary(guest, items, index + 1, block, stop)
            }),
        )
    }
    fn format_string(&self, guest: Guest<'_>, format: &str) -> Result<String, ClientError> {
        self.format_string_at(guest, format, guest.reg_read(reg::SP)?)
    }
    fn format_string_at(
        &self,
        guest: Guest<'_>,
        format: &str,
        stack: u64,
    ) -> Result<String, ClientError> {
        let mut chars = format.chars().peekable();
        let mut result = String::new();
        let mut offset = 0;
        while let Some(c) = chars.next() {
            if c != '%' {
                result.push(c);
                continue;
            }
            if chars.peek() == Some(&'%') {
                chars.next();
                result.push('%');
                continue;
            }
            let mut width = String::new();
            while chars.peek().is_some_and(char::is_ascii_digit) {
                width.push(chars.next().unwrap());
            }
            while matches!(chars.peek(), Some('l' | 'z')) {
                chars.next();
            }
            let spec = chars
                .next()
                .ok_or_else(|| failure("incomplete Store format"))?;
            let value = read64(guest, stack + offset)?;
            offset += 8;
            let text = match spec {
                '@' => {
                    if value == 0 {
                        "(null)".into()
                    } else {
                        self.describe_value(value)?
                    }
                }
                'd' | 'i' => (value as i64).to_string(),
                'u' => value.to_string(),
                's' => self.cstring(guest, value)?,
                'x' | 'X' | 'p' => {
                    let zero = width.starts_with('0');
                    let width = width.parse::<usize>().unwrap_or(0);
                    if width > 128 {
                        return Err(failure("Store format width exceeds limit"));
                    }
                    if spec == 'p' {
                        format!("%!p(uint64={value})")
                    } else if spec == 'X' {
                        if zero {
                            format!("{value:0width$X}")
                        } else {
                            format!("{value:width$X}")
                        }
                    } else if zero {
                        format!("{value:0width$x}")
                    } else {
                        format!("{value:width$x}")
                    }
                }
                _ => return Err(failure("unsupported Store format specifier")),
            };
            result.push_str(&text);
            if result.len() > 1 << 20 {
                return Err(failure("Store formatted string exceeds limit"));
            }
        }
        Ok(result)
    }
    pub(super) fn import_value(
        &mut self,
        guest: Guest<'_>,
        value: &plist::Value,
        depth: usize,
    ) -> Result<u64, ClientError> {
        if depth > 32 {
            return Err(failure("Store import exceeds nesting limit"));
        }
        let (class, value) = match value {
            plist::Value::String(v) => ("NSString", Value::String(v.clone())),
            plist::Value::Data(v) => ("NSData", Value::Bytes(v.clone())),
            plist::Value::Boolean(v) => ("NSNumber", Value::Boolean(*v)),
            plist::Value::Integer(v) => (
                "NSNumber",
                Value::Integer(
                    v.as_signed()
                        .unwrap_or_else(|| v.as_unsigned().unwrap_or(0) as i64),
                ),
            ),
            plist::Value::Real(v) => ("NSNumber", Value::Real(*v)),
            plist::Value::Date(v) => {
                let time = std::time::SystemTime::from(*v);
                let seconds = match time.duration_since(std::time::UNIX_EPOCH) {
                    Ok(duration) => duration.as_secs_f64(),
                    Err(error) => -error.duration().as_secs_f64(),
                };
                ("NSDate", Value::Date(seconds))
            }
            plist::Value::Array(values) => {
                let items = values
                    .iter()
                    .map(|v| self.import_value(guest, v, depth + 1))
                    .collect::<Result<_, _>>()?;
                ("NSArray", Value::Array(items))
            }
            plist::Value::Dictionary(values) => {
                let items = values
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), self.import_value(guest, v, depth + 1)?)))
                    .collect::<Result<_, ClientError>>()?;
                ("NSDictionary", Value::Dictionary(items))
            }
            _ => return Err(failure("unsupported Store import type")),
        };
        self.new_object(guest, class, value)
    }
    fn dictionary(&self, address: u64) -> Result<HashMap<String, u64>, ClientError> {
        match self.objects.get(&address).map(|o| &o.value) {
            Some(Value::Dictionary(v)) => Ok(v.clone()),
            _ => Err(failure("Store object is not a dictionary")),
        }
    }
    fn property(&self, address: u64, key: &str) -> u64 {
        self.objects
            .get(&address)
            .and_then(|o| o.properties.get(key))
            .copied()
            .unwrap_or(0)
    }

    pub(super) fn network_message(
        &mut self,
        guest: Guest<'_>,
        receiver: u64,
        class: &str,
        selector: &str,
        meta: bool,
    ) -> Result<bool, ClientError> {
        if meta {
            if self.kind_of(class, "NSURLRequest") && selector == "requestWithURL:" {
                let url = self.arg(guest, 2)?;
                let request = self.new_object(guest, class, Value::Null)?;
                let method = self.new_object(guest, "NSString", Value::String("GET".into()))?;
                let headers = self.new_object(
                    guest,
                    "NSMutableDictionary",
                    Value::Dictionary(HashMap::new()),
                )?;
                self.objects.get_mut(&request).unwrap().properties.extend([
                    ("URL".into(), url),
                    ("cachePolicy".into(), 0),
                    ("HTTPMethod".into(), method),
                    ("allHTTPHeaderFields".into(), headers),
                ]);
                self.set(guest, request)?;
                return Ok(true);
            }
            let value = match (class, selector) {
                ("NSNumber", "numberWithDouble:") => self.new_object(
                    guest,
                    class,
                    Value::Real(f64::from_bits(guest.reg_read(40)?)),
                )?,
                (
                    "NSMapTable",
                    "weakToStrongObjectsMapTable"
                    | "weakToWeakObjectsMapTable"
                    | "strongToWeakObjectsMapTable"
                    | "strongToStrongObjectsMapTable",
                ) => self.new_object(guest, class, Value::Dictionary(HashMap::new()))?,
                ("NSSet", "setWithArray:") => {
                    let source = self.arg(guest, 2)?;
                    let items = if source == 0 {
                        Vec::new()
                    } else {
                        let Some(Value::Array(items)) =
                            self.objects.get(&source).map(|o| o.value.clone())
                        else {
                            return Err(failure("invalid Store set source"));
                        };
                        items
                    };
                    self.new_object(guest, class, Value::Array(items))?
                }
                ("NSSet" | "NSArray", "setWithObjects:" | "arrayWithObjects:") => {
                    let mut items = Vec::new();
                    let mut value = self.arg(guest, 2)?;
                    let stack = guest.reg_read(reg::SP)?;
                    if value != 0 {
                        items.push(value);
                        for i in 0..1024 {
                            value = read64(guest, stack + i * 8)?;
                            if value == 0 {
                                break;
                            }
                            items.push(value);
                        }
                    }
                    self.new_object(guest, class, Value::Array(items))?
                }
                ("NSNull", "null") => {
                    if self.null_object == 0 {
                        self.null_object = self.new_object(guest, class, Value::Null)?;
                    }
                    self.null_object
                }
                ("NSCharacterSet", "decimalDigitCharacterSet") => {
                    self.new_object(guest, class, Value::String("0123456789".into()))?
                }
                ("NSCharacterSet", "characterSetWithCharactersInString:") => {
                    let text = self.string(self.arg(guest, 2)?)?;
                    self.new_object(guest, class, Value::String(text))?
                }
                ("NSBundle", "bundleWithPath:") => {
                    let path = self.arg(guest, 2)?;
                    if self.string(path)? != "/System/Library/Frameworks/WebKit.framework" {
                        0
                    } else {
                        let version = self.new_object(
                            guest,
                            "NSString",
                            Value::String("22625.1.29.11.28".into()),
                        )?;
                        let info = self.new_object(
                            guest,
                            "NSDictionary",
                            Value::Dictionary(HashMap::from([("CFBundleVersion".into(), version)])),
                        )?;
                        let bundle = self.new_object(guest, "NSBundle", Value::Null)?;
                        self.objects
                            .get_mut(&bundle)
                            .unwrap()
                            .properties
                            .extend([("bundlePath".into(), path), ("infoDictionary".into(), info)]);
                        bundle
                    }
                }
                ("NSString" | "NSMutableString", "stringWithFormat:") => {
                    let format = self.string(self.arg(guest, 2)?)?;
                    let text = self.format_string(guest, &format)?;
                    self.new_object(guest, "NSString", Value::String(text))?
                }
                ("NSHTTPCookie", "cookiesWithResponseHeaderFields:forURL:") => {
                    let object = self.arg(guest, 2)?;
                    let origin = url::Url::parse(&self.string(self.arg(guest, 3)?)?)
                        .map_err(|_| failure("invalid Store cookie origin"))?;
                    let mut values = Vec::new();
                    if let Some(raw) = self.response_headers.get(&object) {
                        for value in raw.get_all(reqwest::header::SET_COOKIE) {
                            if let Ok(value) = value.to_str() {
                                values.push(value.to_owned());
                            }
                        }
                    } else {
                        for (key, value) in self.dictionary(object)? {
                            if key.eq_ignore_ascii_case("Set-Cookie") {
                                values.push(self.string(value)?);
                            }
                        }
                    }
                    let mut cookies = Vec::new();
                    for value in values {
                        if let Ok(cookie) = cookie_store::RawCookie::parse(value) {
                            let domain = cookie.domain().map_or_else(
                                || origin.host_str().unwrap_or("").to_owned(),
                                |domain| {
                                    if domain.starts_with('.') {
                                        domain.into()
                                    } else {
                                        format!(".{domain}")
                                    }
                                },
                            );
                            let mut fields = HashMap::new();
                            for (key, value) in [
                                ("Name", cookie.name()),
                                ("Value", cookie.value()),
                                ("Domain", domain.as_str()),
                                ("Path", cookie.path().unwrap_or("/")),
                            ] {
                                fields.insert(
                                    key.into(),
                                    self.new_object(
                                        guest,
                                        "NSString",
                                        Value::String(value.into()),
                                    )?,
                                );
                            }
                            if cookie.secure() == Some(true) {
                                fields.insert(
                                    "Secure".into(),
                                    self.new_object(
                                        guest,
                                        "NSString",
                                        Value::String("TRUE".into()),
                                    )?,
                                );
                            }
                            if cookie.http_only() == Some(true) {
                                fields.insert(
                                    "HttpOnly".into(),
                                    self.new_object(
                                        guest,
                                        "NSString",
                                        Value::String("TRUE".into()),
                                    )?,
                                );
                            }
                            if let Some(date) = cookie.expires_datetime() {
                                fields.insert(
                                    "Expires".into(),
                                    self.new_object(
                                        guest,
                                        "NSDate",
                                        Value::Date(date.unix_timestamp() as f64),
                                    )?,
                                );
                            }
                            cookies.push(self.new_object(
                                guest,
                                "NSHTTPCookie",
                                Value::Dictionary(fields),
                            )?);
                        }
                    }
                    self.new_object(guest, "NSArray", Value::Array(cookies))?
                }
                ("NSHTTPCookie", "cookieWithProperties:") => {
                    let fields = self.dictionary(self.arg(guest, 2)?)?;
                    self.new_object(guest, class, Value::Dictionary(fields))?
                }
                ("NSHTTPCookie", "requestHeaderFieldsWithCookies:") => {
                    let Some(Value::Array(items)) = self
                        .objects
                        .get(&self.arg(guest, 2)?)
                        .map(|o| o.value.clone())
                    else {
                        return Err(failure("invalid Store cookie array"));
                    };
                    let mut pairs = Vec::new();
                    for item in items {
                        let fields = self.dictionary(item)?;
                        let name = self.string(fields.get("Name").copied().unwrap_or(0))?;
                        let value = self.string(fields.get("Value").copied().unwrap_or(0))?;
                        pairs.push(format!("{name}={value}"));
                    }
                    let mut fields = HashMap::new();
                    if !pairs.is_empty() {
                        fields.insert(
                            "Cookie".into(),
                            self.new_object(guest, "NSString", Value::String(pairs.join("; ")))?,
                        );
                    }
                    self.new_object(guest, "NSDictionary", Value::Dictionary(fields))?
                }
                ("NSURLCache", "sharedURLCache") => 0,
                ("NSJSONSerialization", "isValidJSONObject:") => u64::from(
                    matches!(
                        self.objects.get(&self.arg(guest, 2)?).map(|o| &o.value),
                        Some(Value::Dictionary(_) | Value::Array(_))
                    ) && self.json_value(self.arg(guest, 2)?, 0).is_ok(),
                ),
                ("NSJSONSerialization", "JSONObjectWithData:options:error:") => {
                    let bytes = self.bytes(self.arg(guest, 2)?)?;
                    match serde_json::from_slice::<serde_json::Value>(&bytes) {
                        Ok(value) => self.import_json(guest, &value, 0)?,
                        Err(_) => {
                            self.parser_error(guest, self.arg(guest, 4)?)?;
                            0
                        }
                    }
                }
                ("NSURLComponents", "componentsWithURL:resolvingAgainstBaseURL:") => {
                    let text = self.string(self.arg(guest, 2)?)?;
                    if url::Url::parse(&text).is_err() {
                        0
                    } else {
                        self.new_object(guest, class, Value::String(text))?
                    }
                }
                ("NSURLQueryItem", "queryItemWithName:value:") => {
                    let name = self.arg(guest, 2)?;
                    let value = self.arg(guest, 3)?;
                    let item = self.new_object(guest, class, Value::Null)?;
                    self.objects
                        .get_mut(&item)
                        .unwrap()
                        .properties
                        .extend([("name".into(), name), ("value".into(), value)]);
                    item
                }
                ("NSURLSession", "sessionWithConfiguration:delegate:delegateQueue:") => {
                    let configuration = self.arg(guest, 2)?;
                    let delegate = self.arg(guest, 3)?;
                    let queue = self.arg(guest, 4)?;
                    let session = self.new_object(guest, class, Value::Null)?;
                    self.objects.get_mut(&session).unwrap().properties.extend([
                        ("configuration".into(), configuration),
                        ("delegate".into(), delegate),
                        ("delegateQueue".into(), queue),
                    ]);
                    session
                }
                ("NSPropertyListSerialization", "propertyList:isValidForFormat:") => u64::from(
                    self.export(self.arg(guest, 2)?, &mut HashSet::new(), 0)
                        .is_ok(),
                ),
                ("NSPropertyListSerialization", "dataWithPropertyList:format:options:error:") => {
                    let value = self.export(self.arg(guest, 2)?, &mut HashSet::new(), 0)?;
                    let mut bytes = Vec::new();
                    if self.arg(guest, 3)? == 200 {
                        value.to_writer_binary(&mut bytes)?;
                    } else {
                        value.to_writer_xml(&mut bytes)?;
                    }
                    self.new_object(guest, "NSData", Value::Bytes(bytes))?
                }
                ("NSPropertyListSerialization", "propertyListWithData:options:format:error:") => {
                    let bytes = self.bytes(self.arg(guest, 2)?)?;
                    match plist::Value::from_reader(std::io::Cursor::new(bytes)) {
                        Ok(value) => self.import_value(guest, &value, 0)?,
                        Err(_) => {
                            self.parser_error(guest, self.arg(guest, 5)?)?;
                            0
                        }
                    }
                }
                _ => return Ok(false),
            };
            self.set(guest, value)?;
            return Ok(true);
        }
        if self.kind_of(class, "NSDictionary") && selector == "enumerateKeysAndObjectsUsingBlock:" {
            let mut items = self.dictionary(receiver)?.into_iter().collect::<Vec<_>>();
            items.sort_by(|a, b| a.0.cmp(&b.0));
            let block = self.arg(guest, 2)?;
            let stop = self.alloc(8)?;
            guest.mem_write(stop, &[0; 8])?;
            self.enumerate_dictionary(guest, Arc::new(items), 0, block, stop)?;
            return Ok(true);
        }
        if self.kind_of(class, "NSArray") && selector == "addObjectsFromArray:" {
            let source = self.arg(guest, 2)?;
            let Some(Value::Array(items)) = self.objects.get(&source).map(|o| o.value.clone())
            else {
                return Err(failure("invalid Store array append"));
            };
            let object = self.objects.get_mut(&receiver).unwrap();
            if object.value == Value::Null {
                object.value = Value::Array(Vec::new());
            }
            let Value::Array(target) = &mut object.value else {
                return Err(failure("invalid Store array receiver"));
            };
            if target.len() + items.len() > 65536 {
                return Err(failure("Store array exceeds limit"));
            }
            target.extend(items);
            self.set(guest, 0)?;
            return Ok(true);
        }
        if self.kind_of(class, "NSString") && selector == "caseInsensitiveCompare:" {
            let first = self.string(receiver)?.to_lowercase();
            let other = self.string(self.arg(guest, 2)?)?.to_lowercase();
            let order = match first.cmp(&other) {
                std::cmp::Ordering::Less => -1i64,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            };
            self.set(guest, order as u64)?;
            return Ok(true);
        }
        if self.kind_of(class, "NSString")
            && ["rangeOfString:", "rangeOfString:options:"].contains(&selector)
        {
            let (mut text, mut needle) =
                (self.string(receiver)?, self.string(self.arg(guest, 2)?)?);
            let options = if selector.ends_with("options:") {
                self.arg(guest, 3)?
            } else {
                0
            };
            if options & 1 != 0 {
                text = text.to_lowercase();
                needle = needle.to_lowercase();
            }
            let index = if options & 4 != 0 {
                text.rfind(&needle)
            } else {
                text.find(&needle)
            };
            let (start, length) = index.map_or((i64::MAX as u64, 0), |i| {
                (
                    text[..i].encode_utf16().count() as u64,
                    needle.encode_utf16().count() as u64,
                )
            });
            self.set(guest, start)?;
            guest.reg_write(reg::X0 + 1, length)?;
            return Ok(true);
        }
        if self.kind_of(class, "NSString") && selector == "containsString:" {
            let text = self.string(receiver)?;
            let needle = self.string(self.arg(guest, 2)?)?;
            self.set(guest, u64::from(text.contains(&needle)))?;
            return Ok(true);
        }
        if self.kind_of(class, "NSString") && selector == "cStringUsingEncoding:" {
            let text = self.string(receiver)?;
            let out = self.alloc(text.len() as u64 + 1)?;
            guest.mem_write(out, text.as_bytes())?;
            guest.mem_write(out + text.len() as u64, &[0])?;
            self.set(guest, out)?;
            return Ok(true);
        }
        if class == "NSXPCConnection" || class == "NSXPCInterface" {
            match selector {
                "initWithMachServiceName:options:" => {
                    let name = self.arg(guest, 2)?;
                    self.objects
                        .get_mut(&receiver)
                        .unwrap()
                        .properties
                        .insert("serviceName".into(), name);
                    self.set(guest, receiver)?;
                    return Ok(true);
                }
                "_setQueue:" | "setRemoteObjectInterface:" => {
                    let value = self.arg(guest, 2)?;
                    self.objects.get_mut(&receiver).unwrap().properties.insert(
                        if selector == "_setQueue:" {
                            "queue"
                        } else {
                            "interface"
                        }
                        .into(),
                        value,
                    );
                    self.set(guest, 0)?;
                    return Ok(true);
                }
                "setInterruptionHandler:" | "setInvalidationHandler:" => {
                    let block = self.arg(guest, 2)?;
                    let key = selector.to_owned();
                    self.copy_block(
                        guest,
                        block,
                        Box::new(move |state, guest, copied| {
                            state
                                .objects
                                .get_mut(&receiver)
                                .unwrap()
                                .properties
                                .insert(key, copied);
                            state.set(guest, 0)
                        }),
                    )?;
                    return Ok(true);
                }
                "remoteObjectProxyWithErrorHandler:" => {
                    let block = self.arg(guest, 2)?;
                    self.copy_block(
                        guest,
                        block,
                        Box::new(|state, guest, copied| {
                            let proxy =
                                state.new_object(guest, "HostUnavailableProxy", Value::Null)?;
                            state
                                .objects
                                .get_mut(&proxy)
                                .unwrap()
                                .properties
                                .insert("errorBlock".into(), copied);
                            state.set(guest, proxy)
                        }),
                    )?;
                    return Ok(true);
                }
                "resume"
                | "invalidate"
                | "setClass:forSelector:argumentIndex:ofReply:"
                | "setClasses:forSelector:argumentIndex:ofReply:"
                | "setInterface:forSelector:argumentIndex:ofReply:" => {
                    self.set(guest, 0)?;
                    return Ok(true);
                }
                _ => (),
            }
        }
        if self.kind_of(class, "NSArray")
            && ["removeObjectAtIndex:", "removeLastObject"].contains(&selector)
        {
            let index = if selector == "removeLastObject" {
                None
            } else {
                Some(self.arg(guest, 2)? as usize)
            };
            let Value::Array(items) = &mut self.objects.get_mut(&receiver).unwrap().value else {
                return Err(failure("invalid Store array removal"));
            };
            let index = index.unwrap_or_else(|| items.len().saturating_sub(1));
            if index >= items.len() {
                return Err(failure("Store array removal out of range"));
            }
            items.remove(index);
            self.set(guest, 0)?;
            return Ok(true);
        }
        if self.kind_of(class, "NSString")
            && selector == "initWithBytesNoCopy:length:encoding:freeWhenDone:"
        {
            let size = self.arg(guest, 3)?;
            let encoding = self.arg(guest, 4)?;
            if size > 1 << 20 || ![1, 4].contains(&encoding) {
                return Err(failure("unsupported Store string buffer"));
            }
            let bytes = guest.mem_read(self.arg(guest, 2)?, size as usize)?;
            let text =
                String::from_utf8(bytes).map_err(|_| failure("invalid Store UTF-8 string"))?;
            self.objects.get_mut(&receiver).unwrap().value = Value::String(text);
            self.set(guest, receiver)?;
            return Ok(true);
        }
        if self.kind_of(class, "NSString")
            && [
                "substringFromIndex:",
                "substringToIndex:",
                "substringWithRange:",
            ]
            .contains(&selector)
        {
            let text = self.string(receiver)?.encode_utf16().collect::<Vec<_>>();
            let index = self.arg(guest, 2)? as usize;
            let (start, end) = match selector {
                "substringFromIndex:" => (index, text.len()),
                "substringToIndex:" => (0, index),
                _ => (
                    index,
                    index
                        .checked_add(self.arg(guest, 3)? as usize)
                        .ok_or_else(|| failure("Store substring range overflow"))?,
                ),
            };
            let range = text
                .get(start..end)
                .ok_or_else(|| failure("Store substring range exceeds string"))?;
            let value = self.new_object(
                guest,
                "NSString",
                Value::String(String::from_utf16_lossy(range)),
            )?;
            self.set(guest, value)?;
            return Ok(true);
        }
        if ["doubleValue", "floatValue"].contains(&selector) {
            let value = match &self.objects[&receiver].value {
                Value::Real(v) => *v,
                Value::Integer(v) => *v as f64,
                Value::Boolean(v) => u8::from(*v) as f64,
                Value::String(v) => v.parse::<f64>().unwrap_or(0.0),
                _ => return Err(failure("unsupported Store numeric conversion")),
            };
            guest.reg_write(
                40,
                if selector == "floatValue" {
                    (value as f32).to_bits() as u64
                } else {
                    value.to_bits()
                },
            )?;
            return Ok(true);
        }
        if class == "NSCharacterSet" && selector == "invertedSet" {
            let text = self.string(receiver)?;
            let value = self.new_object(guest, class, Value::String(text))?;
            let inverted = 1 - self.property(receiver, "inverted");
            self.objects
                .get_mut(&value)
                .unwrap()
                .properties
                .insert("inverted".into(), inverted);
            self.set(guest, value)?;
            return Ok(true);
        }
        if self.kind_of(class, "NSString") && selector == "initWithFormat:locale:arguments:" {
            let format = self.string(self.arg(guest, 2)?)?;
            let text = self.format_string_at(guest, &format, self.arg(guest, 4)?)?;
            self.objects.get_mut(&receiver).unwrap().value = Value::String(text);
            self.set(guest, receiver)?;
            return Ok(true);
        }
        if self.kind_of(class, "NSString")
            && [
                "rangeOfCharacterFromSet:",
                "rangeOfCharacterFromSet:options:",
                "stringByTrimmingCharactersInSet:",
            ]
            .contains(&selector)
        {
            let set = self.arg(guest, 2)?;
            let text = self.string(receiver)?;
            let chars = self.string(set)?;
            let inverted = self.property(set, "inverted") != 0;
            let contains = |c: char| {
                (if chars == "0123456789" {
                    super::bridge::decimal_digit(c)
                } else {
                    chars.contains(c)
                }) != inverted
            };
            if selector == "stringByTrimmingCharactersInSet:" {
                let value = self.new_object(
                    guest,
                    "NSString",
                    Value::String(text.trim_matches(contains).into()),
                )?;
                self.set(guest, value)?;
                return Ok(true);
            }
            let options = if selector.ends_with("options:") {
                self.arg(guest, 3)?
            } else {
                0
            };
            let (mut start, mut length, mut offset) = (i64::MAX as u64, 0, 0);
            for c in text.chars() {
                let size = c.len_utf16() as u64;
                if contains(c) {
                    start = offset;
                    length = size;
                    if options & 4 == 0 {
                        break;
                    }
                }
                offset += size;
            }
            self.set(guest, start)?;
            guest.reg_write(reg::X0 + 1, length)?;
            return Ok(true);
        }
        if class == "NSFileManager"
            && [
                "URLsForDirectory:inDomains:",
                "URLForDirectory:inDomain:appropriateForURL:create:error:",
            ]
            .contains(&selector)
        {
            let url = self.new_object(
                guest,
                "NSURL",
                Value::String("file:///ipatool/cache/".into()),
            )?;
            let value = if selector == "URLsForDirectory:inDomains:" {
                self.new_object(guest, "NSArray", Value::Array(vec![url]))?
            } else {
                url
            };
            self.set(guest, value)?;
            return Ok(true);
        }
        if class == "NSURL" {
            let mut url = url::Url::parse(&self.string(receiver)?)
                .map_err(|_| failure("invalid Store URL"))?;
            let value = match selector {
                "URLByAppendingPathComponent:" | "URLByAppendingPathComponent:isDirectory:" => {
                    let path = self.string(self.arg(guest, 2)?)?;
                    url.path_segments_mut()
                        .map_err(|_| failure("Store URL cannot contain path"))?
                        .pop_if_empty()
                        .push(&path);
                    self.new_object(guest, "NSURL", Value::String(url.to_string()))?
                }
                "isFileURL" => u64::from(url.scheme() == "file"),
                "scheme" | "host" | "path" | "query" | "fragment" => {
                    let text = match selector {
                        "scheme" => Some(url.scheme()),
                        "host" => url.host_str(),
                        "path" => Some(url.path()),
                        "query" => url.query(),
                        _ => url.fragment(),
                    };
                    if let Some(text) = text {
                        let text = if selector == "path" {
                            super::bridge::decoded_path(&url)
                        } else if selector == "fragment" {
                            let encoded = format!("fragment={}", text.replace('+', "%2B"));
                            url::form_urlencoded::parse(encoded.as_bytes())
                                .next()
                                .map(|(_, v)| v.into_owned())
                                .unwrap_or_default()
                        } else {
                            text.into()
                        };
                        self.new_object(guest, "NSString", Value::String(text))?
                    } else {
                        0
                    }
                }
                "fileSystemRepresentation" => {
                    let path = super::bridge::decoded_path(&url);
                    let bytes = path.as_bytes();
                    let out = self.alloc(bytes.len() as u64 + 1)?;
                    guest.mem_write(out, bytes)?;
                    guest.mem_write(out + bytes.len() as u64, &[0])?;
                    out
                }
                _ => return Ok(false),
            };
            self.set(guest, value)?;
            return Ok(true);
        }
        if selector == "compare:" {
            let other = self.arg(guest, 2)?;
            let order = match (
                &self.objects[&receiver].value,
                self.objects.get(&other).map(|o| &o.value),
            ) {
                (Value::Date(first), Some(Value::Date(second))) => first
                    .partial_cmp(second)
                    .ok_or_else(|| failure("invalid Store date comparison"))?,
                _ => self.string(receiver)?.cmp(&self.string(other)?),
            };
            self.set(
                guest,
                match order {
                    std::cmp::Ordering::Less => (-1i64) as u64,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                },
            )?;
            return Ok(true);
        }
        if self.kind_of(class, "NSArray") && selector == "sortedArrayUsingComparator:" {
            let Some(Value::Array(items)) = self.objects.get(&receiver).map(|o| o.value.clone())
            else {
                return Err(failure("invalid Store sort receiver"));
            };
            if items.len() > 4096 {
                return Err(failure("Store sort exceeds runtime budget"));
            }
            self.sort_array(guest, items, 1, 1, self.arg(guest, 2)?)?;
            return Ok(true);
        }
        if self.kind_of(class, "NSArray") && selector == "componentsJoinedByString:" {
            let separator = self.string(self.arg(guest, 2)?)?;
            let Some(Value::Array(items)) = self.objects.get(&receiver).map(|o| &o.value) else {
                return Err(failure("invalid Store string array"));
            };
            let text = items
                .iter()
                .map(|v| self.string(*v))
                .collect::<Result<Vec<_>, _>>()?
                .join(&separator);
            let value = self.new_object(guest, "NSString", Value::String(text))?;
            self.set(guest, value)?;
            return Ok(true);
        }
        if self.kind_of(class, "NSString")
            && ["initWithFormat:", "appendFormat:"].contains(&selector)
        {
            let format = self.string(self.arg(guest, 2)?)?;
            let mut text = self.format_string(guest, &format)?;
            if selector == "appendFormat:" {
                text = self.string(receiver)? + &text;
            }
            self.objects.get_mut(&receiver).unwrap().value = Value::String(text);
            self.set(
                guest,
                if selector == "appendFormat:" {
                    0
                } else {
                    receiver
                },
            )?;
            return Ok(true);
        }
        if class == "NSProcessInfo" && selector == "operatingSystemVersion" {
            let out = guest.reg_read(reg::X0 + 8)?;
            for (i, value) in [27u64, 0, 1].into_iter().enumerate() {
                guest.mem_write(out + i as u64 * 8, &value.to_le_bytes())?;
            }
            return Ok(true);
        }
        if class == "NSProcessInfo" && selector == "operatingSystemVersionString" {
            let value = self.new_object(
                guest,
                "NSString",
                Value::String("Version 27.0.1 (Build 26A434)".into()),
            )?;
            self.set(guest, value)?;
            return Ok(true);
        }
        if class == "NSURLQueryItem" && ["name", "value"].contains(&selector) {
            self.set(guest, self.property(receiver, selector))?;
            return Ok(true);
        }
        if class == "NSURLComponents" {
            if selector == "initWithURL:resolvingAgainstBaseURL:" {
                let text = self.string(self.arg(guest, 2)?)?;
                url::Url::parse(&text).map_err(|_| failure("invalid Store URL components"))?;
                self.objects.get_mut(&receiver).unwrap().value = Value::String(text);
                self.set(guest, receiver)?;
                return Ok(true);
            }
            let mut url = url::Url::parse(&self.string(receiver)?)
                .map_err(|_| failure("invalid Store URL components"))?;
            let decode = |text: &str| {
                url::form_urlencoded::parse(format!("v={}", text.replace('+', "%2B")).as_bytes())
                    .next()
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default()
            };
            let encode = |text: &str| {
                url::form_urlencoded::byte_serialize(text.as_bytes())
                    .collect::<String>()
                    .replace('+', "%20")
            };
            let value = match selector {
                "URL" => self.new_object(guest, "NSURL", Value::String(url.to_string()))?,
                "query" | "percentEncodedQuery" => {
                    if let Some(query) = url.query() {
                        self.new_object(
                            guest,
                            "NSString",
                            Value::String(if selector == "query" {
                                decode(query)
                            } else {
                                query.into()
                            }),
                        )?
                    } else {
                        0
                    }
                }
                "setFragment:" => {
                    let text = self.string(self.arg(guest, 2)?)?;
                    url.set_fragment(if text.is_empty() { None } else { Some(&text) });
                    self.objects.get_mut(&receiver).unwrap().value = Value::String(url.to_string());
                    0
                }
                "queryItems" | "percentEncodedQueryItems" => {
                    let mut items = Vec::new();
                    if let Some(query) = url.query().filter(|v| !v.is_empty()) {
                        for part in query.split('&') {
                            let (key, value) = part
                                .split_once('=')
                                .map_or((part, None), |(k, v)| (k, Some(v)));
                            let key = if selector == "queryItems" {
                                decode(key)
                            } else {
                                key.into()
                            };
                            let name = self.new_object(guest, "NSString", Value::String(key))?;
                            let item = self.new_object(guest, "NSURLQueryItem", Value::Null)?;
                            self.objects
                                .get_mut(&item)
                                .unwrap()
                                .properties
                                .insert("name".into(), name);
                            if let Some(value) = value {
                                let value = self.new_object(
                                    guest,
                                    "NSString",
                                    Value::String(if selector == "queryItems" {
                                        decode(value)
                                    } else {
                                        value.into()
                                    }),
                                )?;
                                self.objects
                                    .get_mut(&item)
                                    .unwrap()
                                    .properties
                                    .insert("value".into(), value);
                            }
                            items.push(item);
                        }
                    }
                    self.new_object(guest, "NSArray", Value::Array(items))?
                }
                "setQueryItems:" | "setPercentEncodedQueryItems:" => {
                    let address = self.arg(guest, 2)?;
                    let items = if address == 0 {
                        Vec::new()
                    } else {
                        match &self
                            .objects
                            .get(&address)
                            .ok_or_else(|| failure("invalid query item array"))?
                            .value
                        {
                            Value::Array(items) => items.clone(),
                            _ => return Err(failure("invalid query item array")),
                        }
                    };
                    let mut parts = Vec::new();
                    for item in items {
                        let key = self.string(self.property(item, "name"))?;
                        let value = self.property(item, "value");
                        let mut part = if selector == "setQueryItems:" {
                            encode(&key)
                        } else {
                            key
                        };
                        if value != 0 {
                            let text = self.string(value)?;
                            part.push('=');
                            part.push_str(&if selector == "setQueryItems:" {
                                encode(&text)
                            } else {
                                text
                            });
                        }
                        parts.push(part);
                    }
                    let query = parts.join("&");
                    url.set_query(if query.is_empty() { None } else { Some(&query) });
                    self.objects.get_mut(&receiver).unwrap().value = Value::String(url.to_string());
                    0
                }
                _ => return Ok(false),
            };
            self.set(guest, value)?;
            return Ok(true);
        }
        if class == "NSOperationQueue" && selector == "addOperationWithBlock:" {
            let block = self.arg(guest, 2)?;
            return self
                .copy_block(
                    guest,
                    block,
                    Box::new(move |state, guest, copied| {
                        state.pending.push_back((copied, receiver));
                        state.set(guest, 0)
                    }),
                )
                .map(|()| true);
        }
        if class == "AKAppleIDSession" && selector == "handleResponse:forRequest:shouldRetry:" {
            let status = self.property(self.arg(guest, 2)?, "statusCode");
            if [431, 433, 434, 441, 442, 443, 444].contains(&status) {
                return Err(failure("AuthKit anisette challenge is not supported"));
            }
            let retry = self.arg(guest, 4)?;
            if retry != 0 {
                guest.mem_write(retry, &[0])?;
            }
            self.set(guest, 0)?;
            return Ok(true);
        }
        if class == "NSURLSessionConfiguration"
            && ["_allowsTCPFastOpen", "_allowsTLSSessionTickets", "URLCache"].contains(&selector)
        {
            self.set(guest, 0)?;
            return Ok(true);
        }
        if class == "NSHTTPCookie" {
            if selector == "initWithProperties:" {
                let fields = self.dictionary(self.arg(guest, 2)?)?;
                self.objects.get_mut(&receiver).unwrap().value = Value::Dictionary(fields);
                self.set(guest, receiver)?;
                return Ok(true);
            }
            let mut fields = self.dictionary(receiver)?;
            let value = match selector {
                "name" => fields.get("Name").copied().unwrap_or(0),
                "value" => fields.get("Value").copied().unwrap_or(0),
                "domain" => fields.get("Domain").copied().unwrap_or(0),
                "path" => fields.get("Path").copied().unwrap_or(0),
                "expiresDate" => fields.get("Expires").copied().unwrap_or(0),
                "version" => 0,
                "isSessionOnly" => u64::from(!fields.contains_key("Expires")),
                "isSecure" => u64::from(fields.get("Secure").is_some_and(|a| {
                    self.string(*a)
                        .is_ok_and(|v| v.eq_ignore_ascii_case("TRUE"))
                })),
                "isHTTPOnly" => u64::from(fields.get("HttpOnly").is_some_and(|a| {
                    self.string(*a)
                        .is_ok_and(|v| v.eq_ignore_ascii_case("TRUE"))
                })),
                "properties" => {
                    fields.insert(
                        "Created".into(),
                        self.new_object(
                            guest,
                            "NSNumber",
                            Value::Integer(super::client::now() as i64 - 978307200),
                        )?,
                    );
                    if !fields.contains_key("Expires") {
                        fields.insert(
                            "Discard".into(),
                            self.new_object(guest, "NSString", Value::String("TRUE".into()))?,
                        );
                    }
                    self.new_object(guest, "NSDictionary", Value::Dictionary(fields))?
                }
                _ => return Ok(false),
            };
            self.set(guest, value)?;
            return Ok(true);
        }
        if class == "NSIndexSet" {
            if selector == "initWithIndexesInRange:" {
                let start = self.arg(guest, 2)?;
                let size = self.arg(guest, 3)?;
                self.objects
                    .get_mut(&receiver)
                    .unwrap()
                    .properties
                    .extend([("start".into(), start), ("size".into(), size)]);
                self.set(guest, receiver)?;
                return Ok(true);
            }
            if selector == "containsIndex:" {
                let index = self.arg(guest, 2)?;
                let start = self.property(receiver, "start");
                let size = self.property(receiver, "size");
                self.set(guest, u64::from(index >= start && index - start < size))?;
                return Ok(true);
            }
        }
        if class == "NSHTTPURLResponse" && selector == "_CFURLResponse" {
            self.set(guest, receiver)?;
            return Ok(true);
        }
        if class == "NSURLSessionDataTask" && selector == "_timingData" {
            self.set(guest, 0)?;
            return Ok(true);
        }
        if self.kind_of(class, "NSURLRequest") {
            match selector {
                "initWithURL:" => {
                    guest.reg_write(reg::X0 + 3, 0)?;
                    guest.reg_write(40, 60f64.to_bits())?;
                    self.message(
                        guest,
                        receiver,
                        "initWithURL:cachePolicy:timeoutInterval:",
                        false,
                    )?;
                    return Ok(true);
                }
                "initWithURL:cachePolicy:timeoutInterval:" => {
                    let url = self.arg(guest, 2)?;
                    let cache = if selector == "initWithURL:" {
                        0
                    } else {
                        self.arg(guest, 3)?
                    };
                    let method = self.new_object(guest, "NSString", Value::String("GET".into()))?;
                    let headers = self.new_object(
                        guest,
                        "NSMutableDictionary",
                        Value::Dictionary(HashMap::new()),
                    )?;
                    self.objects.get_mut(&receiver).unwrap().properties.extend([
                        ("URL".into(), url),
                        ("cachePolicy".into(), cache),
                        ("HTTPMethod".into(), method),
                        ("allHTTPHeaderFields".into(), headers),
                    ]);
                    self.set(guest, receiver)?;
                    return Ok(true);
                }
                "HTTPBody" | "HTTPBodyStream" => {
                    self.set(guest, self.property(receiver, selector))?;
                    return Ok(true);
                }
                "_CFURLRequest" => {
                    self.set(guest, receiver)?;
                    return Ok(true);
                }
                "copy"
                | "copyWithZone:"
                | "mutableCopy"
                | "mutableCopyWithZone:"
                | "_initWithCFURLRequest:" => {
                    if selector == "copy" || selector == "mutableCopy" {
                        let zone = format!("{selector}WithZone:");
                        let entry = self.lookup(class, &zone, false);
                        if entry != 0 {
                            guest.reg_write(reg::X0 + 2, 0)?;
                            self.jump(guest, entry, receiver, &zone)?;
                            return Ok(true);
                        }
                    }
                    let source = if selector == "_initWithCFURLRequest:" {
                        self.arg(guest, 2)?
                    } else {
                        receiver
                    };
                    let object = self
                        .objects
                        .get(&source)
                        .cloned()
                        .ok_or_else(|| failure("invalid Store request copy"))?;
                    let copied = if selector == "_initWithCFURLRequest:" {
                        receiver
                    } else {
                        self.new_object(guest, class, object.value.clone())?
                    };
                    let mut properties = object.properties;
                    if let Some(headers) = properties.get("allHTTPHeaderFields").copied() {
                        properties.insert(
                            "allHTTPHeaderFields".into(),
                            self.foundation_copy(guest, headers, true)?,
                        );
                    }
                    self.objects.get_mut(&copied).unwrap().properties = properties;
                    self.set(guest, copied)?;
                    return Ok(true);
                }
                "setValue:forHTTPHeaderField:" | "addValue:forHTTPHeaderField:" => {
                    let value = self.arg(guest, 2)?;
                    let key = canonical(&self.string(self.arg(guest, 3)?)?);
                    let mut header_object = self.property(receiver, "allHTTPHeaderFields");
                    if header_object == 0 {
                        header_object = self.new_object(
                            guest,
                            "NSMutableDictionary",
                            Value::Dictionary(HashMap::new()),
                        )?;
                        self.objects
                            .get_mut(&receiver)
                            .unwrap()
                            .properties
                            .insert("allHTTPHeaderFields".into(), header_object);
                    }
                    let Value::Dictionary(headers) =
                        &mut self.objects.get_mut(&header_object).unwrap().value
                    else {
                        return Err(failure("invalid Store request headers"));
                    };
                    if value == 0 {
                        headers.remove(&key);
                    } else {
                        headers.insert(key, value);
                    }
                    self.set(guest, 0)?;
                    return Ok(true);
                }
                "valueForHTTPHeaderField:" => {
                    let key = canonical(&self.string(self.arg(guest, 2)?)?);
                    let headers =
                        self.dictionary(self.property(receiver, "allHTTPHeaderFields"))?;
                    self.set(guest, headers.get(&key).copied().unwrap_or(0))?;
                    return Ok(true);
                }
                _ => (),
            }
        }
        if class == "NSHTTPURLResponse" && selector == "valueForHTTPHeaderField:" {
            let key = self.string(self.arg(guest, 2)?)?;
            let headers = self.dictionary(self.property(receiver, "allHeaderFields"))?;
            self.set(
                guest,
                headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(&key))
                    .map_or(0, |(_, v)| *v),
            )?;
            return Ok(true);
        }
        if class == "NSURLSession" && selector == "dataTaskWithRequest:" {
            let request = self.arg(guest, 2)?;
            let task = self.new_object(guest, "NSURLSessionDataTask", Value::Null)?;
            self.objects.get_mut(&task).unwrap().properties.extend([
                ("currentRequest".into(), request),
                ("originalRequest".into(), request),
                ("session".into(), receiver),
                ("taskIdentifier".into(), task),
                ("state".into(), 1),
            ]);
            self.set(guest, task)?;
            return Ok(true);
        }
        if class == "NSURLSessionDataTask" && selector == "resume" {
            if self.property(receiver, "state") != 1 {
                return Err(failure("Store task resumed twice"));
            }
            self.objects
                .get_mut(&receiver)
                .unwrap()
                .properties
                .insert("state".into(), 0);
            let block = self.host_block(
                guest,
                Arc::new(move |state, guest| state.perform_http(guest, receiver)),
            )?;
            self.pending.push_back((block, 0));
            self.set(guest, 0)?;
            return Ok(true);
        }
        if (class == "NSURLSession"
            && ["invalidateAndCancel", "finishTasksAndInvalidate"].contains(&selector))
            || (class == "NSURLSessionDataTask" && selector == "cancel")
        {
            self.set(guest, 0)?;
            return Ok(true);
        }
        if self.kind_of(class, "NSURLRequest")
            || [
                "NSURLSession",
                "NSURLSessionDataTask",
                "NSHTTPURLResponse",
                "NSURLResponse",
            ]
            .contains(&class)
        {
            if let Some(field) = selector
                .strip_prefix("set")
                .and_then(|s| s.strip_suffix(':'))
                .filter(|s| !s.contains(':') && !s.is_empty())
            {
                let first = field.chars().next().unwrap().len_utf8();
                let key = if field.as_bytes().get(1).is_some_and(u8::is_ascii_uppercase) {
                    field.into()
                } else {
                    field[..first].to_lowercase() + &field[first..]
                };
                let value = self.arg(guest, 2)?;
                self.objects
                    .get_mut(&receiver)
                    .unwrap()
                    .properties
                    .insert(key, value);
                self.set(guest, 0)?;
                return Ok(true);
            }
            if let Some(value) = self.objects[&receiver].properties.get(selector).copied() {
                self.set(guest, value)?;
                return Ok(true);
            }
        }
        if class == "NSData" || class == "NSMutableData" {
            match selector {
                "bytes" => {
                    let data = self.bytes(receiver)?;
                    let pointer = self.alloc(data.len() as u64)?;
                    guest.mem_write(pointer, &data)?;
                    self.set(guest, pointer)?;
                    return Ok(true);
                }
                "appendBytes:length:" | "appendData:" => {
                    let other = if selector == "appendData:" {
                        self.bytes(self.arg(guest, 2)?)?
                    } else {
                        let size = self.arg(guest, 3)?;
                        if size > 32 << 20 {
                            return Err(failure("Store data append exceeds limit"));
                        }
                        guest.mem_read(self.arg(guest, 2)?, size as usize)?
                    };
                    let object = self.objects.get_mut(&receiver).unwrap();
                    if object.value == Value::Null {
                        object.value = Value::Bytes(Vec::new());
                    }
                    let Value::Bytes(bytes) = &mut object.value else {
                        return Err(failure("invalid Store data receiver"));
                    };
                    if bytes.len() + other.len() > 32 << 20 {
                        return Err(failure("Store data exceeds limit"));
                    }
                    bytes.extend_from_slice(&other);
                    self.set(guest, 0)?;
                    return Ok(true);
                }
                _ => (),
            }
        }
        Ok(false)
    }

    fn parser_error(&mut self, guest: Guest<'_>, out: u64) -> Result<(), ClientError> {
        if out == 0 {
            return Ok(());
        }
        let domain = self.new_object(
            guest,
            "NSString",
            Value::String("NSCocoaErrorDomain".into()),
        )?;
        let code = self.new_object(guest, "NSNumber", Value::Integer(3840))?;
        let info = self.new_object(guest, "NSDictionary", Value::Dictionary(HashMap::new()))?;
        let error = self.new_object(
            guest,
            "NSError",
            Value::Dictionary(HashMap::from([
                ("domain".into(), domain),
                ("code".into(), code),
                ("userInfo".into(), info),
            ])),
        )?;
        guest.mem_write(out, &error.to_le_bytes())
    }
    pub(super) fn json_value(
        &self,
        address: u64,
        depth: usize,
    ) -> Result<serde_json::Value, ClientError> {
        if depth > 64 {
            return Err(failure("Store JSON exceeds nesting limit"));
        }
        let object = self
            .objects
            .get(&address)
            .ok_or_else(|| failure("unknown Store JSON object"))?;
        Ok(match &object.value {
            Value::String(v) => serde_json::Value::String(v.clone()),
            Value::Integer(v) => (*v).into(),
            Value::Boolean(v) => (*v).into(),
            Value::Real(v) => serde_json::Number::from_f64(*v)
                .map(serde_json::Value::Number)
                .ok_or_else(|| failure("nonfinite Store JSON number"))?,
            Value::Array(v) if object.class.contains("Array") => serde_json::Value::Array(
                v.iter()
                    .map(|a| self.json_value(*a, depth + 1))
                    .collect::<Result<_, _>>()?,
            ),
            Value::Dictionary(v) => serde_json::Value::Object(
                v.iter()
                    .map(|(k, a)| Ok((k.clone(), self.json_value(*a, depth + 1)?)))
                    .collect::<Result<_, ClientError>>()?,
            ),
            Value::Null if object.class == "NSNull" => serde_json::Value::Null,
            _ => return Err(failure("invalid Store JSON object type")),
        })
    }
    fn import_json(
        &mut self,
        guest: Guest<'_>,
        value: &serde_json::Value,
        depth: usize,
    ) -> Result<u64, ClientError> {
        if depth > 64 {
            return Err(failure("Store JSON exceeds nesting limit"));
        }
        let (class, value) = match value {
            serde_json::Value::Null => ("NSNull", Value::Null),
            serde_json::Value::String(v) => ("NSString", Value::String(v.clone())),
            serde_json::Value::Bool(v) => ("NSNumber", Value::Boolean(*v)),
            serde_json::Value::Number(v) => (
                "NSNumber",
                if let Some(v) = v.as_i64() {
                    Value::Integer(v)
                } else {
                    Value::Real(
                        v.as_f64()
                            .ok_or_else(|| failure("invalid Store JSON number"))?,
                    )
                },
            ),
            serde_json::Value::Array(v) => {
                let items = v
                    .iter()
                    .map(|v| self.import_json(guest, v, depth + 1))
                    .collect::<Result<_, _>>()?;
                ("NSArray", Value::Array(items))
            }
            serde_json::Value::Object(v) => {
                let items = v
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), self.import_json(guest, v, depth + 1)?)))
                    .collect::<Result<_, ClientError>>()?;
                ("NSDictionary", Value::Dictionary(items))
            }
        };
        self.new_object(guest, class, value)
    }
    pub(super) fn delegate_call(
        &mut self,
        guest: Guest<'_>,
        receiver: u64,
        selector: &str,
        args: Vec<u64>,
        after: Completion,
    ) -> Result<(), ClientError> {
        let (class, _) = self.receiver(receiver).map_err(|_| {
            failure(format!(
                "unknown Store delegate receiver {receiver:#x} for {selector}"
            ))
        })?;
        let entry = self.lookup(&class, selector, false);
        if entry == 0 {
            let forward = self.lookup(&class, "forwardingTargetForSelector:", false);
            if forward == 0 {
                return Err(failure(format!("missing Store delegate method {selector}")));
            }
            let method = self.selector(guest, "forwardingTargetForSelector:")?;
            let target = self.selector(guest, selector)?;
            let selector = selector.to_owned();
            return self.callback_then(
                guest,
                forward,
                &[receiver, method, target],
                Box::new(move |state, guest| {
                    let target = state.arg(guest, 0)?;
                    if target == 0 || target == receiver {
                        return Err(failure("Store delegate cannot forward request"));
                    }
                    state.delegate_call(guest, target, &selector, args, after)
                }),
            );
        }
        let method = self.selector(guest, selector)?;
        let mut all = vec![receiver, method];
        all.extend(args);
        self.callback_then(guest, entry, &all, after)
    }
    fn perform_http(&mut self, guest: Guest<'_>, task: u64) -> Result<(), ClientError> {
        let request = self.property(task, "currentRequest");
        let url = self.string(self.property(request, "URL"))?;
        let url = url::Url::parse(&url).map_err(|_| failure("invalid Store transport URL"))?;
        if !allowed_url(&url, self.auth_request || !self.stream_response) {
            return Err(failure("unsupported Store transport URL"));
        }
        let method = self
            .string(self.property(request, "HTTPMethod"))?
            .parse::<reqwest::Method>()
            .map_err(|_| failure("invalid Store HTTP method"))?;
        let mut http = reqwest::Request::new(method, url.clone());
        let body = self.property(request, "HTTPBody");
        if body != 0 {
            *http.body_mut() = Some(self.bytes(body)?.into());
        }
        let headers = self.property(request, "allHTTPHeaderFields");
        if headers != 0 {
            for (key, value) in self.dictionary(headers)? {
                let key = key
                    .parse::<reqwest::header::HeaderName>()
                    .map_err(|_| failure("invalid Store header name"))?;
                let value = self
                    .string(value)?
                    .parse()
                    .map_err(|_| failure("invalid Store header value"))?;
                http.headers_mut().insert(key, value);
            }
        }
        let transport = self
            .transport
            .as_ref()
            .cloned()
            .ok_or_else(|| failure("Store transport not configured"))?;
        let response = transport(http)?;
        if response.body.len() > 32 << 20 {
            return Err(failure("Store response exceeds size limit"));
        }
        let status = response.status;
        let body = response.body.clone();
        let mut headers = HashMap::new();
        let destination = response
            .headers
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| url.join(v).ok());
        let expected_length = response
            .headers
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(if response.stream.is_some() {
                u64::MAX
            } else {
                body.len() as u64
            });
        for (key, value) in &response.headers {
            headers.insert(
                canonical(key.as_str()),
                self.new_object(
                    guest,
                    "NSString",
                    Value::String(
                        value
                            .to_str()
                            .map_err(|_| failure("invalid Store response header"))?
                            .into(),
                    ),
                )?,
            );
        }
        let content_type = response
            .headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .to_owned();
        let mime = self.new_object(guest, "NSString", Value::String(content_type))?;
        let headers = self.new_object(guest, "NSDictionary", Value::Dictionary(headers))?;
        self.response_headers
            .insert(headers, response.headers.clone());
        let result = self.new_object(guest, "NSHTTPURLResponse", Value::Null)?;
        let request_url = self.property(request, "URL");
        self.objects.get_mut(&result).unwrap().properties.extend([
            ("statusCode".into(), status.as_u16() as u64),
            ("allHeaderFields".into(), headers),
            ("URL".into(), request_url),
            ("MIMEType".into(), mime),
            ("expectedContentLength".into(), expected_length),
        ]);
        self.last_response = Some(response);
        self.objects
            .get_mut(&task)
            .unwrap()
            .properties
            .insert("response".into(), result);
        let session = self.property(task, "session");
        let delegate = self.property(session, "delegate");
        let completion = self.host_block(
            guest,
            Arc::new(move |state, guest| {
                if state.arg(guest, 1)? != 1 {
                    return Err(failure("Store framework rejected HTTP response"));
                }
                let bytes = body.clone();
                let block = state.host_block(
                    guest,
                    Arc::new(move |state, guest| {
                        let data =
                            state.new_object(guest, "NSData", Value::Bytes(bytes.clone()))?;
                        state.delegate_call(
                            guest,
                            delegate,
                            "URLSession:dataTask:didReceiveData:",
                            vec![session, task, data],
                            Box::new(move |state, guest| {
                                let block = state.host_block(
                                    guest,
                                    Arc::new(move |state, guest| {
                                        state
                                            .objects
                                            .get_mut(&task)
                                            .unwrap()
                                            .properties
                                            .insert("state".into(), 3);
                                        state.delegate_call(
                                            guest,
                                            delegate,
                                            "URLSession:task:didCompleteWithError:",
                                            vec![session, task, 0],
                                            Box::new(|state, guest| state.set(guest, 0)),
                                        )
                                    }),
                                )?;
                                state.pending.push_back((block, 0));
                                state.set(guest, 0)
                            }),
                        )
                    }),
                )?;
                state.pending.push_back((block, 0));
                state.set(guest, 0)
            }),
        )?;
        if [301, 302, 303, 307, 308].contains(&status.as_u16())
            && !self.no_redirects
            && let Some(destination) = destination
        {
            let count = self.property(task, "redirectCount");
            if count >= 4 {
                return Err(failure("Store redirect limit exceeded"));
            }
            if !allowed_url(&destination, self.auth_request || !self.stream_response)
                || (self.auth_request
                    && (status.as_u16() == 303
                        || destination.port().is_some_and(|p| p != 443)
                        || !destination
                            .host_str()
                            .unwrap_or("")
                            .ends_with("buy.itunes.apple.com")
                        || destination.path().trim_end_matches('/')
                            != "/WebObjects/MZFinance.woa/wa/authenticate"
                        || destination.path().contains('%')))
            {
                return Err(failure("invalid Store redirect destination"));
            }
            let proposed = self.new_object(guest, "NSMutableURLRequest", Value::Null)?;
            let mut properties = self.objects[&request].properties.clone();
            properties.insert(
                "URL".into(),
                self.new_object(guest, "NSURL", Value::String(destination.to_string()))?,
            );
            let original_headers = self.property(request, "allHTTPHeaderFields");
            let mut fields = if original_headers == 0 {
                HashMap::new()
            } else {
                self.dictionary(original_headers)?
            };
            if destination.host_str() != url.host_str() {
                fields.retain(|k, _| {
                    ![
                        "authorization",
                        "cookie",
                        "x-token",
                        "x-dsid",
                        "icloud-dsid",
                    ]
                    .contains(&k.to_ascii_lowercase().as_str())
                });
            }
            if status.as_u16() == 303
                || ([301, 302].contains(&status.as_u16())
                    && self.string(self.property(request, "HTTPMethod"))? == "POST")
            {
                properties.insert(
                    "HTTPMethod".into(),
                    self.new_object(guest, "NSString", Value::String("GET".into()))?,
                );
                properties.insert("HTTPBody".into(), 0);
                fields.retain(|k, _| {
                    !k.eq_ignore_ascii_case("Content-Length")
                        && !k.eq_ignore_ascii_case("Content-Type")
                });
            }
            properties.insert(
                "allHTTPHeaderFields".into(),
                self.new_object(guest, "NSMutableDictionary", Value::Dictionary(fields))?,
            );
            self.objects.get_mut(&proposed).unwrap().properties = properties;
            let redirected = self.host_block(
                guest,
                Arc::new(move |state, guest| {
                    let next = state.arg(guest, 1)?;
                    if next == 0 {
                        return state.delegate_call(
                            guest,
                            delegate,
                            "URLSession:dataTask:didReceiveResponse:completionHandler:",
                            vec![session, task, result, completion],
                            Box::new(|state, guest| state.set(guest, 0)),
                        );
                    }
                    if !state.objects.contains_key(&next) {
                        return Err(failure("invalid redirected Store request"));
                    }
                    state.objects.get_mut(&task).unwrap().properties.extend([
                        ("currentRequest".into(), next),
                        ("redirectCount".into(), count + 1),
                    ]);
                    let block = state.host_block(
                        guest,
                        Arc::new(move |state, guest| state.perform_http(guest, task)),
                    )?;
                    state.pending.push_back((block, 0));
                    state.set(guest, 0)
                }),
            )?;
            return self.delegate_call(
                guest,
                delegate,
                "URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:",
                vec![session, task, result, proposed, redirected],
                Box::new(|state, guest| state.set(guest, 0)),
            );
        }
        self.delegate_call(
            guest,
            delegate,
            "URLSession:dataTask:didReceiveResponse:completionHandler:",
            vec![session, task, result, completion],
            Box::new(|state, guest| state.set(guest, 0)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_urls_are_restricted() {
        for url in [
            "https://apple.com/a",
            "https://buy.itunes.apple.com/a",
            "https://a.mzstatic.com/a",
        ] {
            assert!(allowed_url(&url.parse().unwrap(), true));
        }
        for url in [
            "https://apple.com.evil.test/a",
            "http://apple.com/a",
            "https://u:p@apple.com/a",
            "https://apple.com/a#fragment",
        ] {
            assert!(!allowed_url(&url.parse().unwrap(), true));
        }
        assert!(allowed_url(
            &"https://cdn.example.test/file".parse().unwrap(),
            false
        ));
    }
}
