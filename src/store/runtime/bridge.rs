//! Remaining services from the pinned upstream emulator/bridge.go.
use super::*;

pub(super) fn decoded_path(url: &url::Url) -> String {
    let encoded = format!("path={}", url.path().replace('+', "%2B"));
    url::form_urlencoded::parse(encoded.as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

pub(super) fn clean_path(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => (),
            ".." => {
                if parts.last().is_some_and(|p| *p != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push(part);
                }
            }
            _ => parts.push(part),
        }
    }
    let mut result = if absolute { "/".into() } else { String::new() };
    result.push_str(&parts.join("/"));
    if result.is_empty() {
        result.push('.');
    }
    result
}

// Unicode Nd decimal blocks, matching Go's unicode.IsDigit (Unicode 17).
pub(super) fn decimal_digit(c: char) -> bool {
    let value = c as u32;
    [
        0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66,
        0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90,
        0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0,
        0xff10, 0x104a0, 0x10d30, 0x10d40, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450,
        0x114d0, 0x11650, 0x116c0, 0x116d0, 0x116da, 0x11730, 0x118e0, 0x11950, 0x11bf0, 0x11c50,
        0x11d50, 0x11da0, 0x11de0, 0x11f50, 0x16130, 0x16a60, 0x16ac0, 0x16b50, 0x16d70, 0x1ccf0,
        0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140, 0x1e2f0, 0x1e4f0, 0x1e5f1, 0x1e950,
        0x1fbf0,
    ]
    .into_iter()
    .any(|start| value >= start && value < start + 10)
}

impl State {
    pub(super) fn describe_value(&self, address: u64) -> Result<String, ClientError> {
        let value = &self
            .objects
            .get(&address)
            .ok_or_else(|| failure("unknown Store format object"))?
            .value;
        Ok(match value {
            Value::Null => "<nil>".into(),
            Value::String(v) => v.clone(),
            Value::Integer(v) => v.to_string(),
            Value::Boolean(v) => v.to_string(),
            Value::Real(v) => v.to_string(),
            Value::Array(v) => format!(
                "[{}]",
                v.iter().map(u64::to_string).collect::<Vec<_>>().join(" ")
            ),
            Value::Bytes(v) => format!(
                "[{}]",
                v.iter().map(u8::to_string).collect::<Vec<_>>().join(" ")
            ),
            Value::Dictionary(v) => {
                let mut entries = v.iter().collect::<Vec<_>>();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                format!(
                    "map[{}]",
                    entries
                        .into_iter()
                        .map(|(k, v)| format!("{k}:{v}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
            Value::Date(v) => {
                let date = time::OffsetDateTime::from_unix_timestamp_nanos((*v * 1e9) as i128)
                    .map_err(|_| failure("invalid Store format date"))?;
                let description = time::format_description::parse(
                    "[year]-[month]-[day] [hour]:[minute]:[second]",
                )
                .map_err(|_| failure("invalid Store date format"))?;
                let mut text = date
                    .format(&description)
                    .map_err(|_| failure("invalid Store date"))?;
                if date.nanosecond() != 0 {
                    text.push('.');
                    text.push_str(format!("{:09}", date.nanosecond()).trim_end_matches('0'));
                }
                text.push_str(" +0000 UTC");
                text
            }
        })
    }
    pub(super) fn bridge_message(
        &mut self,
        guest: Guest<'_>,
        receiver: u64,
        class: &str,
        selector: &str,
        meta: bool,
    ) -> Result<bool, ClientError> {
        if meta {
            let value = match selector {
                "fileURLWithPath:" | "fileURLWithPath:isDirectory:" => {
                    let path = self.string(self.arg(guest, 2)?)?;
                    let mut url = url::Url::parse("file:///").unwrap();
                    url.set_path(&path);
                    self.new_object(guest, "NSURL", Value::String(url.to_string()))?
                }
                "preferredLanguages" => {
                    let language =
                        self.new_object(guest, "NSString", Value::String("en-US".into()))?;
                    self.new_object(guest, "NSArray", Value::Array(vec![language]))?
                }
                "numberWithFloat:" => self.new_object(
                    guest,
                    "NSNumber",
                    Value::Real(f32::from_bits(guest.reg_read(40)? as u32) as f64),
                )?,
                _ => return Ok(false),
            };
            self.set(guest, value)?;
            return Ok(true);
        }
        match selector {
            "removeObjectsInArray:" | "removeObject:" => {
                let argument = self.arg(guest, 2)?;
                if argument == 0 {
                    self.set(guest, 0)?;
                    return Ok(true);
                }
                let remove = if selector == "removeObject:" {
                    vec![argument]
                } else {
                    self.array_values(argument)?
                };
                let mut result = Vec::new();
                for item in self.array_values(receiver)? {
                    let mut found = false;
                    for other in &remove {
                        if self.foundation_equal(item, *other, 0)? {
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        result.push(item);
                    }
                }
                self.objects.get_mut(&receiver).unwrap().value = Value::Array(result);
                self.set(guest, 0)?;
            }
            "initWithDictionary:copyItems:" => {
                let source = self.arg(guest, 2)?;
                let copy = self.arg(guest, 3)? != 0;
                let Some(Value::Dictionary(values)) =
                    self.objects.get(&source).map(|o| o.value.clone())
                else {
                    return Err(failure("invalid Store dictionary initializer"));
                };
                let mut keys = values.keys().cloned().collect::<Vec<_>>();
                keys.sort();
                self.objects.get_mut(&receiver).unwrap().value = Value::Dictionary(values);
                if copy {
                    self.copy_dictionary_items(guest, receiver, Arc::new(keys), 0)?;
                } else {
                    self.set(guest, receiver)?;
                }
            }
            "setObject:forKey:cost:" => {
                let value = self.arg(guest, 2)?;
                let key = self.collection_key(self.arg(guest, 3)?);
                let Value::Dictionary(values) = &mut self.objects.get_mut(&receiver).unwrap().value
                else {
                    return Err(failure("invalid Store cache mutation"));
                };
                if value == 0 {
                    values.remove(&key);
                } else {
                    values.insert(key, value);
                }
                self.set(guest, 0)?;
            }
            "appendString:" => {
                let text = self.string(receiver)? + &self.string(self.arg(guest, 2)?)?;
                self.objects.get_mut(&receiver).unwrap().value = Value::String(text);
                self.set(guest, 0)?;
            }
            "isEqualToDate:" => {
                self.set(
                    guest,
                    u64::from(self.foundation_equal(receiver, self.arg(guest, 2)?, 0)?),
                )?;
            }
            "dataUsingEncoding:" => {
                let text = self.string(receiver)?;
                let bytes = match self.arg(guest, 2)? {
                    4 => text.into_bytes(),
                    10 => {
                        let mut bytes = vec![0xff, 0xfe];
                        for word in text.encode_utf16() {
                            bytes.extend_from_slice(&word.to_le_bytes());
                        }
                        bytes
                    }
                    _ => return Err(failure("unsupported Store string encoding")),
                };
                let data = self.new_object(guest, "NSData", Value::Bytes(bytes))?;
                self.set(guest, data)?;
            }
            "initWithTimeIntervalSince1970:" => {
                if class != "NSDate" {
                    return Err(failure("invalid Store date initializer"));
                }
                let seconds = f64::from_bits(guest.reg_read(40)?);
                if !seconds.is_finite() || seconds <= i64::MIN as f64 || seconds >= i64::MAX as f64
                {
                    return Err(failure("invalid Store date interval"));
                }
                self.objects.get_mut(&receiver).unwrap().value = Value::Date(seconds);
                self.set(guest, receiver)?;
            }
            "localizedStringForKey:value:table:" => {
                if class != "NSBundle" {
                    return Err(failure("invalid Store localization receiver"));
                }
                let value = self.arg(guest, 3)?;
                self.set(
                    guest,
                    if value != 0 && !self.string(value)?.is_empty() {
                        value
                    } else {
                        self.arg(guest, 2)?
                    },
                )?;
            }
            "createDirectoryAtURL:withIntermediateDirectories:attributes:error:"
            | "createDirectoryAtPath:withIntermediateDirectories:attributes:error:" => {
                let out = self.arg(guest, 5)?;
                if out != 0 {
                    let domain = self.new_object(
                        guest,
                        "NSString",
                        Value::String("NSCocoaErrorDomain".into()),
                    )?;
                    let code = self.new_object(guest, "NSNumber", Value::Integer(513))?;
                    let info =
                        self.new_object(guest, "NSDictionary", Value::Dictionary(HashMap::new()))?;
                    let error = self.new_object(
                        guest,
                        "NSError",
                        Value::Dictionary(HashMap::from([
                            ("domain".into(), domain),
                            ("code".into(), code),
                            ("userInfo".into(), info),
                        ])),
                    )?;
                    guest.mem_write(out, &error.to_le_bytes())?;
                }
                self.set(guest, 0)?;
            }
            "isWritableFileAtPath:" | "fileExistsAtPath:" | "fileExistsAtPath:isDirectory:" => {
                if selector == "fileExistsAtPath:isDirectory:" && self.arg(guest, 3)? != 0 {
                    guest.mem_write(self.arg(guest, 3)?, &[0])?;
                }
                self.set(guest, 0)?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
    fn array_values(&self, address: u64) -> Result<Vec<u64>, ClientError> {
        match self.objects.get(&address).map(|o| &o.value) {
            Some(Value::Array(values)) => Ok(values.clone()),
            _ => Err(failure("invalid Store array receiver")),
        }
    }
    fn copy_dictionary_items(
        &mut self,
        guest: Guest<'_>,
        receiver: u64,
        keys: Arc<Vec<String>>,
        mut index: usize,
    ) -> Result<(), ClientError> {
        while index < keys.len() {
            let key = keys[index].clone();
            index += 1;
            let Value::Dictionary(values) = &self.objects[&receiver].value else {
                return Err(failure("invalid Store dictionary copy"));
            };
            let value = values[&key];
            let class = &self
                .objects
                .get(&value)
                .ok_or_else(|| failure("invalid Store dictionary value"))?
                .class;
            let entry = self.lookup(class, "copyWithZone:", false);
            if entry != 0 {
                let selector = self.selector(guest, "copyWithZone:")?;
                return self.callback_then(
                    guest,
                    entry,
                    &[value, selector, 0],
                    Box::new(move |state, guest| {
                        let copied = state.arg(guest, 0)?;
                        let Value::Dictionary(values) =
                            &mut state.objects.get_mut(&receiver).unwrap().value
                        else {
                            unreachable!()
                        };
                        values.insert(key, copied);
                        state.copy_dictionary_items(guest, receiver, keys, index)
                    }),
                );
            }
            let copied = self.foundation_copy(guest, value, false)?;
            let Value::Dictionary(values) = &mut self.objects.get_mut(&receiver).unwrap().value
            else {
                unreachable!()
            };
            values.insert(key, copied);
        }
        self.set(guest, receiver)
    }
}
