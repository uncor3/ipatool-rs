use super::*;

impl State {
    pub(super) fn responds(&self, receiver: u64, selector: &str) -> bool {
        let Ok((class, meta)) = self.receiver(receiver) else {
            return false;
        };
        if self.lookup(&class, selector, meta) != 0 {
            return true;
        }
        if meta {
            return ["class", "alloc", "new"].contains(&selector);
        }
        if [
            "class",
            "retain",
            "release",
            "autorelease",
            "copy",
            "mutableCopy",
            "isKindOfClass:",
            "isEqual:",
            "respondsToSelector:",
        ]
        .contains(&selector)
        {
            return true;
        }
        let number = [
            "integerValue",
            "intValue",
            "longLongValue",
            "unsignedIntegerValue",
            "unsignedLongLongValue",
            "boolValue",
        ];
        match self.objects.get(&receiver).map(|o| &o.value) {
            Some(Value::String(_)) => {
                number.contains(&selector)
                    || ["length", "isEqualToString:", "hasPrefix:", "UTF8String"]
                        .contains(&selector)
            }
            Some(Value::Integer(_)) => number.contains(&selector),
            Some(Value::Dictionary(_)) => [
                "count",
                "objectForKey:",
                "objectForKeyedSubscript:",
                "allKeys",
                "setObject:forKey:",
                "setObject:forKeyedSubscript:",
            ]
            .contains(&selector),
            Some(Value::Array(_) | Value::Bytes(_)) => ["count", "length"].contains(&selector),
            _ => false,
        }
    }
    pub(super) fn message(
        &mut self,
        guest: Guest<'_>,
        receiver: u64,
        selector: &str,
        superclass: bool,
    ) -> Result<(), ClientError> {
        if receiver == 0 {
            guest.reg_write(reg::X0 + 1, 0)?;
            for register in 40..44 {
                guest.reg_write(register, 0)?;
            }
            return self.set(guest, 0);
        }
        if !self.objects.contains_key(&receiver)
            && !self.class_names.contains_key(&receiver)
            && selector == "copy"
            && (HEAP_BASE..STACK_BASE + STACK_SIZE).contains(&receiver)
        {
            return self.copy_block(
                guest,
                receiver,
                Box::new(|state, guest, copied| state.set(guest, copied)),
            );
        }
        let (class, meta) = self.receiver(receiver)?;
        if class == "HostUnavailableProxy" {
            let domain = self.new_object(
                guest,
                "NSString",
                Value::String("NSCocoaErrorDomain".into()),
            )?;
            let code = self.new_object(guest, "NSNumber", Value::Integer(4099))?;
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
            let block = self.objects[&receiver].properties["errorBlock"];
            return self.callback_then(
                guest,
                read64(guest, block + 16)?,
                &[block, error],
                Box::new(|state, guest| state.set(guest, 0)),
            );
        }
        if class == "AMSLogConfig"
            || (class == "AMSConcurrency"
                && selector == "logFaultFromSwiftConcurrencyOnInternalBuild")
        {
            return self.set(guest, 0);
        }
        let entry = self.lookup(&class, selector, meta);
        if entry != 0 && !superclass {
            return self.jump(guest, entry, receiver, selector);
        }
        if self.account_message(guest, receiver, &class, selector, meta)? {
            return Ok(());
        }
        if self.network_message(guest, receiver, &class, selector, meta)? {
            return Ok(());
        }
        if self.notification_message(guest, receiver, &class, selector, meta)? {
            return Ok(());
        }
        if self.bridge_message(guest, receiver, &class, selector, meta)? {
            return Ok(());
        }
        if selector == "initWithObjectsAndKeys:"
            || (meta && selector == "dictionaryWithObjectsAndKeys:")
        {
            let mut values = HashMap::new();
            let mut value = self.arg(guest, 2)?;
            let stack = guest.reg_read(reg::SP)?;
            let mut index = 0u64;
            while value != 0 {
                if index > 1024 {
                    return Err(failure("Store dictionary varargs exceeds limit"));
                }
                let key = self.collection_key(read64(guest, stack + index * 16)?);
                values.insert(key, value);
                value = read64(guest, stack + index * 16 + 8)?;
                index += 1;
            }
            let object = if meta {
                self.new_object(guest, &class, Value::Dictionary(values))?
            } else {
                self.objects.get_mut(&receiver).unwrap().value = Value::Dictionary(values);
                receiver
            };
            return self.set(guest, object);
        }
        if meta {
            let value = match selector {
                "errorWithDomain:code:userInfo:" => {
                    let domain = self.arg(guest, 2)?;
                    let code = self.new_object(
                        guest,
                        "NSNumber",
                        Value::Integer(self.arg(guest, 3)? as i64),
                    )?;
                    let info = self.arg(guest, 4)?;
                    self.new_object(
                        guest,
                        "NSError",
                        Value::Dictionary(HashMap::from([
                            ("domain".into(), domain),
                            ("code".into(), code),
                            ("userInfo".into(), info),
                        ])),
                    )?
                }
                "instanceMethodForSelector:" => {
                    let selector = self.cstring(guest, self.arg(guest, 2)?)?;
                    self.lookup(&class, &selector, false)
                }
                "isSubclassOfClass:" => {
                    let target = self
                        .class_names
                        .get(&self.arg(guest, 2)?)
                        .cloned()
                        .unwrap_or_default();
                    u64::from(self.kind_of(&class, &target))
                }
                "respondsToSelector:" => {
                    let selector = self.cstring(guest, self.arg(guest, 2)?)?;
                    u64::from(
                        self.lookup(&class, &selector, true) != 0
                            || ["class", "alloc", "new"].contains(&selector.as_str()),
                    )
                }
                "UUID" => {
                    let mut bytes = [0; 16];
                    getrandom::fill(&mut bytes).map_err(|_| failure("Store UUID source failed"))?;
                    bytes[6] = (bytes[6] & 15) | 64;
                    bytes[8] = (bytes[8] & 63) | 128;
                    let text = format!(
                        "{:08X}-{:04X}-{:04X}-{:04X}-{:012X}",
                        u32::from_be_bytes(bytes[..4].try_into().unwrap()),
                        u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
                        u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
                        u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
                        u64::from_be_bytes([
                            0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
                        ])
                    );
                    self.new_object(guest, "NSUUID", Value::String(text))?
                }
                "alloc" | "allocWithZone:" => self.new_object(guest, &class, Value::Null)?,
                "new" => {
                    let object = self.new_object(guest, &class, Value::Null)?;
                    return self.message(guest, object, "init", false);
                }
                "class" => receiver,
                "dictionary" | "dictionaryWithCapacity:" => {
                    self.new_object(guest, &class, Value::Dictionary(HashMap::new()))?
                }
                "defaultSessionConfiguration" | "ephemeralSessionConfiguration" => {
                    let object =
                        self.new_object(guest, "NSURLSessionConfiguration", Value::Null)?;
                    let protocols = self.new_object(guest, "NSArray", Value::Array(Vec::new()))?;
                    self.objects.get_mut(&object).unwrap().properties.extend([
                        ("usesClassicLoadingMode".into(), 1),
                        ("protocolClasses".into(), protocols),
                        ("HTTPShouldSetCookies".into(), 1),
                        ("HTTPMaximumConnectionsPerHost".into(), 6),
                    ]);
                    object
                }
                "currentThread" => self.new_object(guest, "NSThread", Value::Null)?,
                "isMainThread" => 1,
                "interfaceWithProtocol:" => {
                    self.new_object(guest, "NSXPCInterface", Value::Null)?
                }
                "date" | "now" => {
                    self.new_object(guest, "NSDate", Value::Date(super::client::now()))?
                }
                "distantPast" => self.new_object(guest, "NSDate", Value::Date(-62135769600.0))?,
                "distantFuture" => self.new_object(guest, "NSDate", Value::Date(64092211200.0))?,
                "dateWithTimeIntervalSinceNow:" | "dateWithTimeIntervalSince1970:" => {
                    let mut seconds = f64::from_bits(guest.reg_read(40)?);
                    if !seconds.is_finite() {
                        return Err(failure("invalid Store date interval"));
                    }
                    if selector == "dateWithTimeIntervalSinceNow:" {
                        seconds += super::client::now();
                    }
                    if seconds <= i64::MIN as f64 || seconds >= i64::MAX as f64 {
                        return Err(failure("Store date interval exceeds supported range"));
                    }
                    self.new_object(guest, "NSDate", Value::Date(seconds))?
                }
                "array" | "set" | "arrayWithCapacity:" | "setWithCapacity:" => {
                    self.new_object(guest, &class, Value::Array(Vec::new()))?
                }
                "mainBundle" | "bundleForClass:" => {
                    let bundle = self.bundle(guest)?;
                    let identifier = if selector == "bundleForClass:"
                        && self
                            .class_names
                            .get(&self.arg(guest, 2)?)
                            .is_some_and(|c| c.contains("AMS"))
                    {
                        "com.apple.AppleMediaServices"
                    } else {
                        "me.majd.ipatool"
                    };
                    let identifier =
                        self.new_object(guest, "NSString", Value::String(identifier.into()))?;
                    let path =
                        self.new_object(guest, "NSString", Value::String("/ipatool".into()))?;
                    self.objects.get_mut(&bundle).unwrap().properties.extend([
                        ("bundleIdentifier".into(), identifier),
                        ("bundlePath".into(), path),
                    ]);
                    bundle
                }
                "processInfo" => {
                    let process = self.new_object(guest, "NSProcessInfo", Value::Null)?;
                    let name =
                        self.new_object(guest, "NSString", Value::String("ipatool".into()))?;
                    let environment =
                        self.new_object(guest, "NSDictionary", Value::Dictionary(HashMap::new()))?;
                    self.objects.get_mut(&process).unwrap().properties.extend([
                        ("processName".into(), name),
                        ("environment".into(), environment),
                    ]);
                    process
                }
                "standardUserDefaults" => {
                    self.new_object(guest, "NSUserDefaults", Value::Dictionary(HashMap::new()))?
                }
                "currentLocale" | "systemLocale" => {
                    self.new_object(guest, "NSLocale", Value::String("en_US".into()))?
                }
                "defaultManager" => self.new_object(guest, "NSFileManager", Value::Null)?,
                "stringWithUTF8String:" => {
                    let text = self.cstring(guest, self.arg(guest, 2)?)?;
                    self.new_object(guest, "NSString", Value::String(text))?
                }
                "dictionaryWithDictionary:" => {
                    let source = self.arg(guest, 2)?;
                    let values = self
                        .objects
                        .get(&source)
                        .map(|o| o.value.clone())
                        .ok_or_else(|| failure("invalid dictionary source"))?;
                    self.new_object(guest, &class, values)?
                }
                "dictionaryWithObjects:forKeys:count:" => {
                    let values = self.arg(guest, 2)?;
                    let keys = self.arg(guest, 3)?;
                    let count = self.arg(guest, 4)?;
                    if count > 65536 {
                        return Err(failure("Store dictionary exceeds limit"));
                    }
                    let mut dictionary = HashMap::new();
                    for i in 0..count {
                        dictionary.insert(
                            self.string(read64(guest, keys + i * 8)?)?,
                            read64(guest, values + i * 8)?,
                        );
                    }
                    self.new_object(guest, "NSDictionary", Value::Dictionary(dictionary))?
                }
                "arrayWithObjects:count:" | "setWithObjects:count:" => {
                    let values = self.arg(guest, 2)?;
                    let count = self.arg(guest, 3)?;
                    if count > 65536 {
                        return Err(failure("Store array exceeds limit"));
                    }
                    let values = (0..count)
                        .map(|i| read64(guest, values + i * 8))
                        .collect::<Result<_, _>>()?;
                    self.new_object(guest, &class, Value::Array(values))?
                }
                "URLWithString:" | "stringWithString:" => self.new_object(
                    guest,
                    &class,
                    Value::String(self.string(self.arg(guest, 2)?)?),
                )?,
                "numberWithBool:" => {
                    self.new_object(guest, &class, Value::Boolean(self.arg(guest, 2)? != 0))?
                }
                "numberWithInteger:"
                | "numberWithInt:"
                | "numberWithLongLong:"
                | "numberWithUnsignedLongLong:"
                | "numberWithUnsignedInteger:" => {
                    self.new_object(guest, &class, Value::Integer(self.arg(guest, 2)? as i64))?
                }
                "arrayWithObject:" | "setWithObject:" => {
                    self.new_object(guest, &class, Value::Array(vec![self.arg(guest, 2)?]))?
                }
                _ => {
                    return Err(failure(format!(
                        "unimplemented Store class method {class}::{selector}"
                    )));
                }
            };
            return self.set(guest, value);
        }
        // Host-backed properties exist only on the per-request objects.
        if let Some(value) = self
            .objects
            .get(&receiver)
            .and_then(|o| o.properties.get(selector))
            .copied()
        {
            return self.set(guest, value);
        }
        if ([
            "NSURLSessionConfiguration",
            "NSOperationQueue",
            "NSCache",
            "ACAccountType",
            "ACAccountCredential",
        ]
        .contains(&class.as_str())
            || self.kind_of(&class, "ACAccount"))
            && selector.starts_with("set")
            && selector.ends_with(':')
            && selector.matches(':').count() == 1
        {
            let field = &selector[3..selector.len() - 1];
            if field.is_empty() {
                return Err(failure("invalid Store property setter"));
            }
            let key = if field.as_bytes().get(1).is_some_and(u8::is_ascii_uppercase) {
                field.to_owned()
            } else {
                let first = field.chars().next().unwrap().len_utf8();
                format!("{}{}", field[..first].to_lowercase(), &field[first..])
            };
            let value = self.arg(guest, 2)?;
            self.objects
                .get_mut(&receiver)
                .unwrap()
                .properties
                .insert(key, value);
            return self.set(guest, 0);
        }
        match selector {
            "initWithDomain:code:userInfo:" => {
                let domain = self.arg(guest, 2)?;
                let code = self.new_object(
                    guest,
                    "NSNumber",
                    Value::Integer(self.arg(guest, 3)? as i64),
                )?;
                let info = self.arg(guest, 4)?;
                self.objects.get_mut(&receiver).unwrap().value =
                    Value::Dictionary(HashMap::from([
                        ("domain".into(), domain),
                        ("code".into(), code),
                        ("userInfo".into(), info),
                    ]));
                self.set(guest, receiver)
            }
            "domain" | "code" | "userInfo" if self.kind_of(&class, "NSError") => {
                let Value::Dictionary(values) = &self.objects[&receiver].value else {
                    return Err(failure("invalid Store error"));
                };
                let value = values.get(selector).copied().unwrap_or(0);
                if selector == "code" {
                    let Some(Value::Integer(code)) = self.objects.get(&value).map(|o| &o.value)
                    else {
                        return Err(failure("invalid Store error code"));
                    };
                    self.set(guest, *code as u64)
                } else {
                    self.set(guest, value)
                }
            }
            "localizedDescription" | "localizedFailureReason" | "localizedRecoverySuggestion"
                if self.kind_of(&class, "NSError") =>
            {
                let Value::Dictionary(fields) = &self.objects[&receiver].value else {
                    return Err(failure("invalid Store error"));
                };
                let key = match selector {
                    "localizedDescription" => "NSLocalizedDescription",
                    "localizedFailureReason" => "NSLocalizedFailureReason",
                    _ => "NSLocalizedRecoverySuggestion",
                };
                let mut value = fields
                    .get("userInfo")
                    .and_then(|a| self.objects.get(a))
                    .and_then(|o| {
                        if let Value::Dictionary(v) = &o.value {
                            v.get(key).copied()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                if value == 0 && selector == "localizedDescription" {
                    let domain = self.string(fields.get("domain").copied().unwrap_or(0))?;
                    let code = fields
                        .get("code")
                        .and_then(|a| self.objects.get(a))
                        .and_then(|o| {
                            if let Value::Integer(v) = o.value {
                                Some(v)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    value = self.new_object(
                        guest,
                        "NSString",
                        Value::String(format!("{domain} error {code}")),
                    )?;
                }
                self.set(guest, value)
            }
            "firstObject" | "lastObject" => {
                let Value::Array(values) = &self.objects[&receiver].value else {
                    return Err(failure("invalid Store array"));
                };
                self.set(
                    guest,
                    if selector == "firstObject" {
                        values.first()
                    } else {
                        values.last()
                    }
                    .copied()
                    .unwrap_or(0),
                )
            }
            "initWithArray:" | "initWithDictionary:" => {
                let source = self.arg(guest, 2)?;
                let value = self
                    .objects
                    .get(&source)
                    .map(|o| o.value.clone())
                    .ok_or_else(|| failure("invalid Store collection source"))?;
                self.objects.get_mut(&receiver).unwrap().value = value;
                self.set(guest, receiver)
            }
            "allKeys" | "allValues" => {
                let Value::Dictionary(values) = &self.objects[&receiver].value else {
                    return Err(failure("invalid Store dictionary"));
                };
                let mut entries: Vec<_> = values.iter().map(|(k, v)| (k.clone(), *v)).collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                let mut items = Vec::new();
                for (key, value) in entries {
                    items.push(if selector == "allKeys" {
                        self.new_object(guest, "NSString", Value::String(key))?
                    } else {
                        value
                    });
                }
                let array = self.new_object(guest, "NSArray", Value::Array(items))?;
                self.set(guest, array)
            }
            "addEntriesFromDictionary:" => {
                let source = self.arg(guest, 2)?;
                let Some(Value::Dictionary(other)) =
                    self.objects.get(&source).map(|o| o.value.clone())
                else {
                    return Err(failure("invalid Store dictionary source"));
                };
                let Value::Dictionary(values) = &mut self.objects.get_mut(&receiver).unwrap().value
                else {
                    return Err(failure("invalid Store dictionary receiver"));
                };
                values.extend(other);
                self.set(guest, 0)
            }
            "removeAllObjects" => {
                match &mut self.objects.get_mut(&receiver).unwrap().value {
                    Value::Dictionary(v) => v.clear(),
                    Value::Array(v) => v.clear(),
                    _ => return Err(failure("invalid Store collection")),
                };
                self.set(guest, 0)
            }
            "countByEnumeratingWithState:objects:count:" => {
                let state = self.arg(guest, 2)?;
                let buffer = self.arg(guest, 3)?;
                let limit = self.arg(guest, 4)?.min(65536);
                let items = match self.objects[&receiver].value.clone() {
                    Value::Array(v) => v,
                    Value::Dictionary(v) => {
                        let mut keys: Vec<_> = v.into_keys().collect();
                        keys.sort();
                        keys.into_iter()
                            .map(|key| self.new_object(guest, "NSString", Value::String(key)))
                            .collect::<Result<Vec<_>, _>>()?
                    }
                    _ => return Err(failure("invalid Store enumeration receiver")),
                };
                let index = read64(guest, state)?;
                if index >= items.len() as u64 {
                    return self.set(guest, 0);
                }
                let count = limit.min(items.len() as u64 - index);
                for i in 0..count {
                    guest.mem_write(buffer + i * 8, &items[(index + i) as usize].to_le_bytes())?;
                }
                let mut mutation = self.objects[&receiver]
                    .properties
                    .get("mutationCounter")
                    .copied()
                    .unwrap_or(0);
                if mutation == 0 {
                    mutation = self.alloc(8)?;
                    self.objects
                        .get_mut(&receiver)
                        .unwrap()
                        .properties
                        .insert("mutationCounter".into(), mutation);
                }
                guest.mem_write(state, &(index + count).to_le_bytes())?;
                guest.mem_write(state + 8, &buffer.to_le_bytes())?;
                guest.mem_write(state + 16, &mutation.to_le_bytes())?;
                self.set(guest, count)
            }
            "init" => {
                if self.objects[&receiver].value != Value::Null {
                    return self.set(guest, receiver);
                }
                let value = if ["NSDictionary", "NSMutableDictionary", "NSCache"]
                    .contains(&class.as_str())
                {
                    Value::Dictionary(HashMap::new())
                } else if [
                    "NSArray",
                    "NSMutableArray",
                    "NSSet",
                    "NSMutableSet",
                    "NSOrderedSet",
                    "NSMutableOrderedSet",
                ]
                .contains(&class.as_str())
                {
                    Value::Array(Vec::new())
                } else if ["NSString", "NSMutableString"].contains(&class.as_str()) {
                    Value::String(String::new())
                } else if ["NSData", "NSMutableData"].contains(&class.as_str()) {
                    Value::Bytes(Vec::new())
                } else {
                    Value::Null
                };
                self.objects.get_mut(&receiver).unwrap().value = value;
                self.set(guest, receiver)
            }
            "retain" | "autorelease" | "self" => self.set(guest, receiver),
            "copyWithZone:" => self.set(guest, receiver),
            "copy" => {
                let entry = self.lookup(&class, "copyWithZone:", false);
                if entry != 0 {
                    guest.reg_write(reg::X0 + 2, 0)?;
                    self.jump(guest, entry, receiver, "copyWithZone:")
                } else {
                    let copied = self.foundation_copy(guest, receiver, false)?;
                    self.set(guest, copied)
                }
            }
            "mutableCopy" | "mutableCopyWithZone:" => {
                let object = self.objects[&receiver].clone();
                let copied = self.new_object(
                    guest,
                    if matches!(object.value, Value::Dictionary(_)) {
                        "NSMutableDictionary"
                    } else {
                        &class
                    },
                    object.value,
                )?;
                self.set(guest, copied)
            }
            "release" | "dealloc" | "lock" | "unlock" | "signal" | "broadcast" => {
                self.set(guest, 0)
            }
            "wait" | "waitUntilDate:" if class == "NSCondition" => {
                self.run_pending(guest, Box::new(|state, guest| state.set(guest, 1)))
            }
            "class" => self.set(
                guest,
                self.classes
                    .get(&class)
                    .map_or(0, |i| self.class_definitions[*i].address),
            ),
            "count" | "length" => {
                let count = match &self.objects[&receiver].value {
                    Value::Array(v) => v.len(),
                    Value::Dictionary(v) => v.len(),
                    Value::Bytes(v) => v.len(),
                    Value::String(v) => v.len(),
                    _ => return Err(failure("Store length receiver is not a collection")),
                };
                self.set(guest, count as u64)
            }
            "objectForKey:"
            | "objectForKeyedSubscript:"
            | "valueForKey:"
            | "__swift_objectForKeyedSubscript:" => {
                let key = self.collection_key(self.arg(guest, 2)?);
                let Value::Dictionary(values) = &self.objects[&receiver].value else {
                    return Err(failure(format!(
                        "Store dictionary receiver mismatch: {class}::{selector}"
                    )));
                };
                self.set(guest, values.get(&key).copied().unwrap_or(0))
            }
            "setObject:forKey:" | "setObject:forKeyedSubscript:" | "setValue:forKey:" => {
                let key = self.collection_key(self.arg(guest, 3)?);
                let value = self.arg(guest, 2)?;
                let Value::Dictionary(values) = &mut self.objects.get_mut(&receiver).unwrap().value
                else {
                    return Err(failure(format!(
                        "Store dictionary receiver mismatch: {class}::{selector}"
                    )));
                };
                if value == 0 {
                    values.remove(&key);
                } else {
                    values.insert(key, value);
                }
                self.set(guest, 0)
            }
            "removeObjectForKey:" => {
                let key = self.collection_key(self.arg(guest, 2)?);
                let Value::Dictionary(values) = &mut self.objects.get_mut(&receiver).unwrap().value
                else {
                    return Err(failure(format!(
                        "Store dictionary receiver mismatch: {class}::{selector}"
                    )));
                };
                values.remove(&key);
                self.set(guest, 0)
            }
            "objectAtIndex:" | "objectAtIndexedSubscript:" => {
                let index = self.arg(guest, 2)? as usize;
                let Value::Array(values) = &self.objects[&receiver].value else {
                    return Err(failure("Store array receiver mismatch"));
                };
                self.set(
                    guest,
                    *values
                        .get(index)
                        .ok_or_else(|| failure("Store array index out of bounds"))?,
                )
            }
            "addObject:" => {
                let value = self.arg(guest, 2)?;
                let Value::Array(values) = &mut self.objects.get_mut(&receiver).unwrap().value
                else {
                    return Err(failure("Store array receiver mismatch"));
                };
                values.push(value);
                self.set(guest, 0)
            }
            "containsObject:" => {
                let value = self.arg(guest, 2)?;
                let Value::Array(values) = &self.objects[&receiver].value else {
                    return Err(failure("Store set receiver mismatch"));
                };
                let found = values.iter().any(|item| {
                    *item == value
                        || self
                            .objects
                            .get(item)
                            .zip(self.objects.get(&value))
                            .is_some_and(|_| {
                                self.describe_value(*item).ok() == self.describe_value(value).ok()
                            })
                });
                self.set(guest, u64::from(found))
            }
            "allObjects" => {
                let value = self.objects[&receiver].value.clone();
                let value = self.new_object(guest, "NSArray", value)?;
                self.set(guest, value)
            }
            "boolValue"
            | "integerValue"
            | "intValue"
            | "longLongValue"
            | "unsignedLongLongValue"
            | "unsignedIntegerValue" => {
                let value = match &self.objects[&receiver].value {
                    Value::Boolean(v) => u64::from(*v),
                    Value::Integer(v) => *v as u64,
                    Value::Real(v) => {
                        if selector == "boolValue" {
                            u64::from(*v != 0.0)
                        } else {
                            (*v as i64) as u64
                        }
                    }
                    Value::String(v) => v.parse::<i64>().unwrap_or(0) as u64,
                    _ => 0,
                };
                self.set(guest, value)
            }
            "UTF8String" => {
                let value = self.string(receiver)?;
                let address = self.alloc(value.len() as u64 + 1)?;
                let mut bytes = value.into_bytes();
                bytes.push(0);
                guest.mem_write(address, &bytes)?;
                self.set(guest, address)
            }
            "lowercaseString" | "uppercaseString" => {
                let text = self.string(receiver)?;
                let text = if selector == "lowercaseString" {
                    text.to_lowercase()
                } else {
                    text.to_uppercase()
                };
                let value = self.new_object(guest, "NSString", Value::String(text))?;
                self.set(guest, value)
            }
            "stringValue" => {
                let text = self.describe_value(receiver)?;
                let value = self.new_object(guest, "NSString", Value::String(text))?;
                self.set(guest, value)
            }
            "stringByAppendingString:" | "stringByAppendingPathComponent:" => {
                let text = self.string(receiver)?;
                let suffix = self.string(self.arg(guest, 2)?)?;
                let text = if selector == "stringByAppendingString:" {
                    text + &suffix
                } else {
                    super::bridge::clean_path(&if text.is_empty() {
                        suffix
                    } else {
                        format!(
                            "{}/{}",
                            text.trim_end_matches('/'),
                            suffix.trim_start_matches('/')
                        )
                    })
                };
                let value = self.new_object(guest, "NSString", Value::String(text))?;
                self.set(guest, value)
            }
            "componentsSeparatedByString:" => {
                let text = self.string(receiver)?;
                let delimiter = self.string(self.arg(guest, 2)?)?;
                let mut values = Vec::new();
                let parts = if delimiter.is_empty() {
                    text.chars().map(|c| c.to_string()).collect::<Vec<_>>()
                } else {
                    text.split(&delimiter).map(str::to_owned).collect()
                };
                for part in parts {
                    values.push(self.new_object(guest, "NSString", Value::String(part))?);
                }
                let value = self.new_object(guest, "NSArray", Value::Array(values))?;
                self.set(guest, value)
            }
            "initWithString:" => {
                let text = self.string(self.arg(guest, 2)?)?;
                self.objects.get_mut(&receiver).unwrap().value = Value::String(text);
                self.set(guest, receiver)
            }
            "isEqual:" | "isEqualToString:" | "isEqualToDictionary:" | "isEqualToArray:" => {
                let other = self.arg(guest, 2)?;
                let equal = self.foundation_equal(receiver, other, 0)?;
                self.set(guest, u64::from(equal))
            }
            "hasPrefix:" | "hasSuffix:" => {
                let value = self.string(receiver)?;
                let other = self.string(self.arg(guest, 2)?)?;
                self.set(
                    guest,
                    u64::from(if selector == "hasPrefix:" {
                        value.starts_with(&other)
                    } else {
                        value.ends_with(&other)
                    }),
                )
            }
            "description" => self.set(guest, receiver),
            "absoluteString" => {
                let text = self.string(receiver)?;
                let value = self.new_object(guest, "NSString", Value::String(text))?;
                self.set(guest, value)
            }
            "UUIDString" => {
                let text = self.string(receiver)?;
                let value = self.new_object(guest, "NSString", Value::String(text))?;
                self.set(guest, value)
            }
            "respondsToSelector:" => {
                let selector = self.cstring(guest, self.arg(guest, 2)?)?;
                let implemented = self.responds(receiver, &selector);
                self.set(guest, u64::from(implemented))
            }
            "isKindOfClass:" => {
                let target = self
                    .class_names
                    .get(&self.arg(guest, 2)?)
                    .cloned()
                    .unwrap_or_default();
                self.set(guest, u64::from(self.kind_of(&class, &target)))
            }
            "timeIntervalSince1970" | "timeIntervalSinceReferenceDate" | "timeIntervalSinceNow" => {
                let Value::Date(mut seconds) = self.objects[&receiver].value else {
                    return Err(failure("invalid Store date receiver"));
                };
                if selector == "timeIntervalSinceReferenceDate" {
                    seconds -= 978307200.0;
                } else if selector == "timeIntervalSinceNow" {
                    seconds -= super::client::now();
                    seconds = seconds.clamp(i64::MIN as f64 / 1e9, i64::MAX as f64 / 1e9);
                }
                guest.reg_write(40, seconds.to_bits())
            }
            "timeIntervalSinceDate:" => {
                let other = self.arg(guest, 2)?;
                let (Value::Date(first), Value::Date(second)) = (
                    &self.objects[&receiver].value,
                    &self
                        .objects
                        .get(&other)
                        .ok_or_else(|| failure("missing Store date"))?
                        .value,
                ) else {
                    return Err(failure("invalid Store date receiver"));
                };
                guest.reg_write(
                    40,
                    (first - second)
                        .clamp(i64::MIN as f64 / 1e9, i64::MAX as f64 / 1e9)
                        .to_bits(),
                )
            }
            "threadDictionary" => {
                let existing = self.objects[&receiver]
                    .properties
                    .get(selector)
                    .copied()
                    .unwrap_or(0);
                let value = if existing != 0 {
                    existing
                } else {
                    let value = self.new_object(
                        guest,
                        "NSMutableDictionary",
                        Value::Dictionary(HashMap::new()),
                    )?;
                    self.objects
                        .get_mut(&receiver)
                        .unwrap()
                        .properties
                        .insert(selector.into(), value);
                    value
                };
                self.set(guest, value)
            }
            "boolForKey:" => {
                let key = self.string(self.arg(guest, 2)?)?;
                let Value::Dictionary(values) = &self.objects[&receiver].value else {
                    return Err(failure("invalid Store defaults receiver"));
                };
                let value = values.get(&key).copied().unwrap_or(0);
                if value == 0 {
                    self.set(guest, 0)
                } else {
                    self.message(guest, value, "boolValue", false)
                }
            }
            "bundleURL" | "executableURL" => {
                let value =
                    self.new_object(guest, "NSURL", Value::String("file:///ipatool".into()))?;
                self.set(guest, value)
            }
            "path" => {
                let text = self.string(receiver)?;
                let value = if class == "NSURL" {
                    super::bridge::decoded_path(
                        &url::Url::parse(&text).map_err(|_| failure("invalid Store URL"))?,
                    )
                } else {
                    text
                };
                let value = self.new_object(guest, "NSString", Value::String(value))?;
                self.set(guest, value)
            }
            "lastPathComponent" | "pathExtension" => {
                let text = self.string(receiver)?;
                let path = if class == "NSURL" {
                    super::bridge::decoded_path(
                        &url::Url::parse(&text).map_err(|_| failure("invalid Store URL"))?,
                    )
                } else {
                    text
                };
                let path = super::bridge::clean_path(&path);
                let last = if path == "/" {
                    "/"
                } else {
                    path.rsplit('/').next().unwrap_or(".")
                };
                let value = if selector == "pathExtension" {
                    last.rsplit_once('.').map_or("", |(_, suffix)| suffix)
                } else {
                    last
                };
                let value = self.new_object(guest, "NSString", Value::String(value.into()))?;
                self.set(guest, value)
            }
            "stringByDeletingPathExtension" => {
                let text = self.string(receiver)?;
                let slash = text.rfind('/').map_or(0, |i| i + 1);
                let text = if let Some(dot) = text[slash..].rfind('.') {
                    text[..slash + dot].to_owned()
                } else {
                    text
                };
                let value = self.new_object(guest, "NSString", Value::String(text))?;
                self.set(guest, value)
            }
            "bundleIdentifier" | "bundlePath" | "processName" | "environment" => self.set(
                guest,
                self.objects[&receiver]
                    .properties
                    .get(selector)
                    .copied()
                    .unwrap_or(0),
            ),
            "localeIdentifier" => {
                let value = self.new_object(guest, "NSString", Value::String("en_US".into()))?;
                self.set(guest, value)
            }
            "languageCode" => {
                let value = self.new_object(guest, "NSString", Value::String("en".into()))?;
                self.set(guest, value)
            }
            "infoDictionary" => {
                let value = if let Some(value) = self.objects[&receiver]
                    .properties
                    .get("infoDictionary")
                    .copied()
                {
                    value
                } else {
                    self.bundle_info(guest)?
                };
                self.set(guest, value)
            }
            "objectForInfoDictionaryKey:" => {
                let key = self.string(self.arg(guest, 2)?)?;
                let info = if let Some(value) = self.objects[&receiver]
                    .properties
                    .get("infoDictionary")
                    .copied()
                {
                    value
                } else {
                    self.bundle_info(guest)?
                };
                let Value::Dictionary(values) = &self.objects[&info].value else {
                    unreachable!()
                };
                self.set(guest, values.get(&key).copied().unwrap_or(0))
            }
            "initWithCapacity:" => {
                self.objects.get_mut(&receiver).unwrap().value = if class.contains("String") {
                    Value::String(String::new())
                } else if class.contains("Array") {
                    Value::Array(Vec::new())
                } else {
                    Value::Dictionary(HashMap::new())
                };
                self.set(guest, receiver)
            }
            _ => Err(failure(format!(
                "unimplemented Store instance method {class}::{selector}"
            ))),
        }
    }

    pub(super) fn bundle_info(&mut self, guest: Guest<'_>) -> Result<u64, ClientError> {
        let mut info = HashMap::new();
        for (key, value) in [
            ("CFBundleIdentifier", "me.majd.ipatool"),
            ("CFBundleVersion", "1.0"),
            ("CFBundleExecutable", "ipatool"),
            ("CFBundleName", "ipatool"),
        ] {
            info.insert(
                key.into(),
                self.new_object(guest, "NSString", Value::String(value.into()))?,
            );
        }
        self.new_object(guest, "NSDictionary", Value::Dictionary(info))
    }
    pub(super) fn collection_key(&self, address: u64) -> String {
        match self.objects.get(&address).map(|o| &o.value) {
            Some(Value::String(v)) => v.clone(),
            Some(Value::Integer(v)) => format!("#number:{v}"),
            _ => format!("#object:{address:x}"),
        }
    }
    pub(super) fn bundle(&mut self, guest: Guest<'_>) -> Result<u64, ClientError> {
        let object = self.new_object(guest, "NSBundle", Value::Null)?;
        let identifier =
            self.new_object(guest, "NSString", Value::String("me.majd.ipatool".into()))?;
        let path = self.new_object(guest, "NSString", Value::String("/ipatool".into()))?;
        self.objects.get_mut(&object).unwrap().properties.extend([
            ("bundleIdentifier".into(), identifier),
            ("bundlePath".into(), path),
        ]);
        Ok(object)
    }
    pub(super) fn foundation_equal(
        &self,
        first: u64,
        second: u64,
        depth: usize,
    ) -> Result<bool, ClientError> {
        if first == second {
            return Ok(true);
        }
        if depth > 32 {
            return Err(failure("Foundation comparison exceeds nesting limit"));
        }
        let Some((a, b)) = self.objects.get(&first).zip(self.objects.get(&second)) else {
            return Ok(false);
        };
        Ok(match (&a.value, &b.value) {
            (Value::Boolean(a), Value::Integer(b)) | (Value::Integer(b), Value::Boolean(a)) => {
                i64::from(*a) == *b
            }
            (Value::Array(a), Value::Array(b)) => {
                if a.len() != b.len() {
                    return Ok(false);
                }
                for (a, b) in a.iter().zip(b) {
                    if !self.foundation_equal(*a, *b, depth + 1)? {
                        return Ok(false);
                    }
                }
                true
            }
            (Value::Dictionary(a), Value::Dictionary(b)) => {
                if a.len() != b.len() {
                    return Ok(false);
                }
                for (key, a) in a {
                    let Some(b) = b.get(key) else {
                        return Ok(false);
                    };
                    if !self.foundation_equal(*a, *b, depth + 1)? {
                        return Ok(false);
                    }
                }
                true
            }
            (Value::String(a), Value::String(b)) => a == b,
            (Value::Bytes(a), Value::Bytes(b)) => a == b,
            (Value::Integer(a), Value::Integer(b)) => a == b,
            (Value::Boolean(a), Value::Boolean(b)) => a == b,
            (Value::Date(a), Value::Date(b)) => a == b,
            _ => false,
        })
    }
}
