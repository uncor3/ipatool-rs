//! Scoped Swift ABI services. Guest references remain valid until VM drop.
use super::*;
use unicode_normalization::UnicodeNormalization;

impl State {
    pub(super) fn swift_symbol(
        &mut self,
        guest: Guest<'_>,
        name: &str,
    ) -> Result<bool, ClientError> {
        if self.task_symbol(guest, name)? {
            return Ok(true);
        }
        match name {
            "$ss11AnyHashableVwcp" | "$ss11AnyHashableVwca" => {
                let source = self.arg(guest, 1)?;
                if self.data.metadata.bridges.get("anyHashableStringMetadata")
                    != Some(&read64(guest, source + 24)?)
                {
                    return Err(failure("unsupported Swift AnyHashable copy"));
                }
                guest.mem_write(self.arg(guest, 0)?, &guest.mem_read(source, 40)?)?;
            }
            "swift_dynamicCast" => {
                let destination = self.arg(guest, 0)?;
                let source = self.arg(guest, 1)?;
                let mut source_type = self.arg(guest, 2)?;
                let target = self.arg(guest, 3)?;
                let symbols = &self.data.metadata.symbols;
                if symbols.get("$ss11AnyHashableVN") == Some(&source_type)
                    && symbols.get("$sSSN") == Some(&target)
                {
                    if self.data.metadata.bridges.get("anyHashableStringMetadata")
                        != Some(&read64(guest, source + 24)?)
                    {
                        return Err(failure("unsupported AnyHashable cast box"));
                    }
                    source_type = target;
                } else if symbols.get("$sypN").map(|v| v + 8) == Some(source_type) {
                    source_type = read64(guest, source + 24)?;
                }
                if source_type == target {
                    let size = read64(guest, read64(guest, source_type - 8)? + 64)?;
                    if size > 24 {
                        return Err(failure("Swift cast value exceeds limit"));
                    }
                    guest.mem_write(destination, &guest.mem_read(source, size as usize)?)?;
                    self.set(guest, 1)?;
                } else if symbols.get("$sSSN") == Some(&target)
                    && ["$sSiN", "$sSbN", "$sSdN"]
                        .iter()
                        .any(|k| symbols.get(*k) == Some(&source_type))
                    && self.arg(guest, 4)? & 1 == 0
                {
                    self.set(guest, 0)?;
                } else {
                    return Err(failure("unsupported Swift cast metadata"));
                }
            }
            "$ss18_DictionaryStorageC6resize8original8capacity4moveAByxq_Gs05__RawaB0C_SiSbtFZ" => {
                let storage_type = self.arg(guest, 3)?;
                let metadata = self
                    .data
                    .metadata
                    .swift_dictionaries
                    .iter()
                    .find(|(_, layout)| layout.metadata == storage_type)
                    .and_then(|(key, _)| key.parse::<u64>().ok())
                    .ok_or_else(|| failure("unprepared Swift dictionary storage"))?;
                let empty = *self
                    .data
                    .metadata
                    .symbols
                    .get("_swiftEmptyDictionarySingleton")
                    .ok_or_else(|| failure("missing Swift empty dictionary"))?;
                let slot = self.alloc(8)?;
                guest.mem_write(slot, &empty.to_le_bytes())?;
                self.unique_dictionary(guest, slot, false, self.arg(guest, 1)?, metadata)?;
                self.set(guest, read64(guest, slot)?)?;
            }
            "$ss9_typeName_9qualifiedSSypXp_SbtF" => {
                let metadata = self.arg(guest, 0)?;
                let mut name = self.class_names.get(&metadata).cloned();
                if name.is_none() && read64(guest, metadata)? == 0x305 {
                    name = self.class_names.get(&read64(guest, metadata + 8)?).cloned();
                }
                let name = name.ok_or_else(|| failure("unprepared Swift type name"))?;
                self.return_swift_string(guest, &name)?;
            }
            "$sScPwst" => {
                if self.arg(guest, 2)? != 1 || self.arg(guest, 1)? > 1 {
                    return Err(failure("unsupported Swift task priority tag"));
                }
                let size = read64(guest, read64(guest, self.arg(guest, 3)? - 8)? + 64)?;
                if size != 1 {
                    return Err(failure("invalid Swift task priority size"));
                }
                guest.mem_write(self.arg(guest, 0)? + size, &[self.arg(guest, 1)? as u8])?;
            }
            "$sScPwet" => {
                let size = read64(guest, read64(guest, self.arg(guest, 2)? - 8)? + 64)?;
                self.set(
                    guest,
                    guest.mem_read(self.arg(guest, 0)? + size, 1)?[0] as u64,
                )?;
            }
            "$s10Foundation10URLRequestV8setValue_18forHTTPHeaderFieldySSSg_SStF" => {
                let pointer = guest.reg_read(reg::X0 + 20)?;
                let source = read64(guest, pointer)?;
                let object = self
                    .objects
                    .get(&source)
                    .cloned()
                    .ok_or_else(|| failure("invalid Swift request storage"))?;
                let copied = self.new_object(guest, &object.class, object.value)?;
                if let Some(index) = self.classes.get(&object.class) {
                    let size = self.class_definitions[*index].size;
                    guest.mem_write(copied, &guest.mem_read(source, size as usize)?)?;
                }
                let mut properties = object.properties;
                let fields = properties.get("allHTTPHeaderFields").copied().unwrap_or(0);
                let fields = if fields == 0 {
                    self.new_object(
                        guest,
                        "NSMutableDictionary",
                        Value::Dictionary(HashMap::new()),
                    )?
                } else {
                    self.foundation_copy(guest, fields, true)?
                };
                let key = self.swift_string(guest, self.arg(guest, 2)?, self.arg(guest, 3)?)?;
                let key = key
                    .split('-')
                    .map(|part| {
                        let mut c = part.chars();
                        c.next().map_or(String::new(), |first| {
                            first.to_ascii_uppercase().to_string()
                                + &c.as_str().to_ascii_lowercase()
                        })
                    })
                    .collect::<Vec<_>>()
                    .join("-");
                let value = if self.arg(guest, 1)? == 0 {
                    0
                } else {
                    let text =
                        self.swift_string(guest, self.arg(guest, 0)?, self.arg(guest, 1)?)?;
                    self.new_object(guest, "NSString", Value::String(text))?
                };
                let Value::Dictionary(values) = &mut self.objects.get_mut(&fields).unwrap().value
                else {
                    return Err(failure("invalid Swift request headers"));
                };
                if value == 0 {
                    values.remove(&key);
                } else {
                    values.insert(key, value);
                }
                properties.insert("allHTTPHeaderFields".into(), fields);
                self.objects.get_mut(&copied).unwrap().properties = properties;
                guest.mem_write(pointer, &copied.to_le_bytes())?;
            }
            "$s10Foundation3URLV14absoluteStringSSvg" => {
                let pointer = guest.reg_read(reg::X0 + 20)?;
                let text = self.string(read64(guest, pointer)?)?;
                self.return_swift_string(guest, &text)?;
            }
            "$s10Foundation10URLRequestV3urlAA3URLVSgvg" => {
                let pointer = guest.reg_read(reg::X0 + 20)?;
                let object = self
                    .objects
                    .get(&read64(guest, pointer)?)
                    .ok_or_else(|| failure("invalid Swift request"))?;
                let url = object.properties.get("URL").copied().unwrap_or(0);
                let out = guest.reg_read(reg::X0 + 8)?;
                guest.mem_write(out, &url.to_le_bytes())?;
                guest.mem_write(out + 8, &0u64.to_le_bytes())?;
            }
            "$ss38_bridgeAnythingNonVerbatimToObjectiveCyyXlxnlF" => {
                let source = self.arg(guest, 0)?;
                let metadata = self.arg(guest, 1)?;
                let (class, value) = if self.data.metadata.symbols.get("$sSSN") == Some(&metadata) {
                    (
                        "NSString",
                        Value::String(self.swift_string(
                            guest,
                            read64(guest, source)?,
                            read64(guest, source + 8)?,
                        )?),
                    )
                } else if self.data.metadata.symbols.get("$sSiN") == Some(&metadata) {
                    ("NSNumber", Value::Integer(read64(guest, source)? as i64))
                } else {
                    return Err(failure("unsupported nonverbatim Swift bridge"));
                };
                let object = self.new_object(guest, class, value)?;
                self.set(guest, object)?;
            }
            "swift_allocError" => {
                let metadata = self.arg(guest, 0)?;
                let witness = self.arg(guest, 1)?;
                let source = self.arg(guest, 2)?;
                let size = read64(guest, read64(guest, metadata - 8)? + 64)?;
                if size > 1 << 20 {
                    return Err(failure("Swift error exceeds limit"));
                }
                let value = self.alloc(size)?;
                if source != 0 {
                    guest.mem_write(value, &guest.mem_read(source, size as usize)?)?;
                }
                let object = self.new_object(guest, "HostSwiftError", Value::Null)?;
                self.objects.get_mut(&object).unwrap().properties.extend([
                    ("metadata".into(), metadata),
                    ("witness".into(), witness),
                    ("value".into(), value),
                ]);
                self.set(guest, object)?;
                guest.reg_write(reg::X0 + 1, value)?;
            }
            "swift_getErrorValue" => {
                let object = self
                    .objects
                    .get(&self.arg(guest, 0)?)
                    .filter(|o| o.class == "HostSwiftError")
                    .ok_or_else(|| failure("invalid Swift error box"))?;
                let out = self.arg(guest, 2)?;
                for (i, key) in ["value", "metadata", "witness"].into_iter().enumerate() {
                    guest.mem_write(out + i as u64 * 8, &object.properties[key].to_le_bytes())?;
                }
            }
            "$s10Foundation22_convertErrorToNSErrorySo0E0Cs0C0_pF" => {
                let mut value = self.arg(guest, 0)?;
                for _ in 0..16 {
                    let object = self
                        .objects
                        .get(&value)
                        .ok_or_else(|| failure("unknown Swift error"))?;
                    if self.kind_of(&object.class, "NSError") {
                        self.set(guest, value)?;
                        return Ok(true);
                    }
                    if object.class != "HostSwiftError"
                        || self
                            .data
                            .metadata
                            .swift_types
                            .get(&0x1a2e1c7fau64.to_string())
                            != object.properties.get("metadata")
                    {
                        return Err(failure("unsupported Swift error bridge"));
                    }
                    value = read64(guest, object.properties["value"])?;
                }
                return Err(failure("recursive Swift error box"));
            }
            "$s10Foundation3URLV9appending10components13directoryHintACxd_AC09DirectoryF0OtSyRzlF"
            | "$s10Foundation3URLV6append10components13directoryHintyxd_AC09DirectoryF0OtSyRzlF" => {
                let mut pointer = guest.reg_read(reg::X0 + 20)?;
                let array = self.arg(guest, 0)?;
                let count = read64(guest, array + 16)?;
                if count > 32 {
                    return Err(failure("Store URL component count exceeds limit"));
                }
                let mut url = url::Url::parse(&self.string(read64(guest, pointer)?)?)
                    .map_err(|_| failure("invalid Swift URL"))?;
                for i in 0..count {
                    let item = array + 32 + i * 16;
                    let component =
                        self.swift_string(guest, read64(guest, item)?, read64(guest, item + 8)?)?;
                    for part in component.split('/').filter(|v| !v.is_empty()) {
                        url.path_segments_mut()
                            .map_err(|_| failure("invalid Swift URL path"))?
                            .pop_if_empty()
                            .push(part);
                    }
                }
                if name.contains("9appending") {
                    pointer = guest.reg_read(reg::X0 + 8)?;
                }
                let value = self.new_object(guest, "NSURL", Value::String(url.to_string()))?;
                guest.mem_write(pointer, &value.to_le_bytes())?;
                guest.mem_write(pointer + 8, &0u64.to_le_bytes())?;
            }
            "$s10Foundation3URLV06isFileB0Sbvg" => {
                let pointer = guest.reg_read(reg::X0 + 20)?;
                let url = url::Url::parse(&self.string(read64(guest, pointer)?)?)
                    .map_err(|_| failure("invalid Swift URL"))?;
                self.set(guest, u64::from(url.scheme() == "file"))?;
            }
            "$s10Foundation3URLVwst" => {
                if self.arg(guest, 2)? != 1 || self.arg(guest, 1)? > 1 {
                    return Err(failure("unsupported Swift URL optional tag"));
                }
                if self.arg(guest, 1)? == 1 {
                    guest.mem_write(self.arg(guest, 0)?, &[0; 16])?;
                }
            }
            "$s10Foundation3URLVwet" => {
                if self.arg(guest, 1)? != 1 {
                    return Err(failure("unsupported Swift URL optional tag"));
                }
                self.set(guest, u64::from(read64(guest, self.arg(guest, 0)?)? == 0))?;
            }
            "$s10ObjectiveC8SelectorV2eeoiySbAC_ACtFZ" => {
                self.set(guest, u64::from(self.arg(guest, 0)? == self.arg(guest, 1)?))?
            }
            "swift_arrayInitWithCopy"
            | "swift_arrayInitWithTakeFrontToBack"
            | "swift_arrayInitWithTakeBackToFront" => {
                let destination = self.arg(guest, 0)?;
                let source = self.arg(guest, 1)?;
                let count = self.arg(guest, 2)?;
                let metadata = self.arg(guest, 3)?;
                if count == 0 {
                    self.set(guest, destination)?;
                    return Ok(true);
                }
                let witnesses = read64(guest, metadata - 8)?;
                let stride = read64(guest, witnesses + 72)?;
                if count > 65536 || stride > 1 << 20 {
                    return Err(failure("Swift array copy exceeds limit"));
                }
                let entry = read64(
                    guest,
                    witnesses
                        + if name == "swift_arrayInitWithCopy" {
                            16
                        } else {
                            32
                        },
                )?;
                self.copy_swift_elements(
                    guest,
                    (
                        destination,
                        source,
                        count,
                        metadata,
                        stride,
                        entry,
                        name == "swift_arrayInitWithTakeBackToFront",
                    ),
                    0,
                )?;
            }
            "$ss17_NativeDictionaryV12ensureUnique02isD08capacityS2b_SitF" => {
                let pointer = guest.reg_read(reg::general(20).unwrap())?;
                self.unique_dictionary(
                    guest,
                    pointer,
                    self.arg(guest, 0)? != 0,
                    self.arg(guest, 1)?,
                    self.arg(guest, 2)?,
                )?;
            }
            "$sSD10FoundationE36_unconditionallyBridgeFromObjectiveCySDyxq_GSo12NSDictionaryCSgFZ" =>
            {
                let key_type = self.arg(guest, 1)?;
                let value_type = self.arg(guest, 2)?;
                if ![
                    self.data
                        .metadata
                        .symbols
                        .get("$sSSN")
                        .copied()
                        .unwrap_or(0),
                    self.data
                        .metadata
                        .symbols
                        .get("$ss11AnyHashableVN")
                        .copied()
                        .unwrap_or(0),
                ]
                .contains(&key_type)
                    || ![
                        self.data
                            .metadata
                            .symbols
                            .get("$sypN")
                            .copied()
                            .unwrap_or(0)
                            + 8,
                        self.data
                            .metadata
                            .symbols
                            .get("$sSSN")
                            .copied()
                            .unwrap_or(0),
                    ]
                    .contains(&value_type)
                {
                    return Err(failure("unsupported Swift dictionary bridge metadata"));
                }
                let value =
                    self.dictionary_to_swift(guest, self.arg(guest, 0)?, key_type, value_type)?;
                self.set(guest, value)?;
            }
            "$sSD10FoundationE19_bridgeToObjectiveCSo12NSDictionaryCyF" => {
                let value = self.dictionary_to_objc(
                    guest,
                    self.arg(guest, 0)?,
                    self.arg(guest, 1)?,
                    self.arg(guest, 2)?,
                )?;
                self.set(guest, value)?;
            }
            "$ss6HasherV5_seedABSi_tcfC" => {
                let out = guest.reg_read(reg::general(8).unwrap())?;
                self.init_hasher(guest, out, self.arg(guest, 0)?)?;
            }
            "$ss6HasherV8_combineyySuF" => {
                let pointer = guest.reg_read(reg::general(20).unwrap())?;
                self.hash_word(guest, pointer, self.arg(guest, 0)?)?;
            }
            "$ss6HasherV9_finalizeSiyF" => {
                let pointer = guest.reg_read(reg::general(20).unwrap())?;
                let result = self.hash_compress(guest, pointer, read64(guest, pointer)?, true)?;
                self.set(guest, result)?;
            }
            "$s10ObjectiveC8SelectorV4hash4intoys6HasherVz_tF" => {
                self.hash_word(guest, self.arg(guest, 0)?, self.arg(guest, 1)?)?
            }
            "$sSS4hash4intoys6HasherVz_tF" => {
                let text = self.swift_string(guest, self.arg(guest, 1)?, self.arg(guest, 2)?)?;
                let mut bytes = text.nfc().collect::<String>().into_bytes();
                bytes.push(255);
                self.hash_bytes(guest, self.arg(guest, 0)?, &bytes)?;
            }
            "$ss27_stringCompareWithSmolCheck__9expectingSbs11_StringGutsV_ADs01_G16ComparisonResultOtF" =>
            {
                let first = self
                    .swift_string(guest, self.arg(guest, 0)?, self.arg(guest, 1)?)?
                    .nfc()
                    .collect::<String>();
                let second = self
                    .swift_string(guest, self.arg(guest, 2)?, self.arg(guest, 3)?)?
                    .nfc()
                    .collect::<String>();
                let value = match self.arg(guest, 4)? {
                    0 => first == second,
                    1 => first < second,
                    _ => return Err(failure("unsupported Swift string comparison")),
                };
                self.set(guest, u64::from(value))?;
            }
            "swift_defaultActor_initialize" => {
                self.objects.insert(
                    self.arg(guest, 0)?,
                    Object {
                        class: "HostSwiftActor".into(),
                        value: Value::Null,
                        properties: HashMap::new(),
                    },
                );
            }
            "$ss9TaskLocalC12wrappedValueAByxGx_tcfc" => {
                let pointer = guest.reg_read(reg::general(20).unwrap())?;
                let metadata = read64(guest, pointer)?;
                let value_type = read64(guest, metadata + 80)?;
                let size = read64(guest, read64(guest, value_type - 8)? + 64)?;
                let allocation = self
                    .allocations
                    .get(&pointer)
                    .copied()
                    .ok_or_else(|| failure("unknown Swift TaskLocal allocation"))?;
                if size > allocation.saturating_sub(16) {
                    return Err(failure("Swift TaskLocal exceeds allocation"));
                }
                guest.mem_write(
                    pointer + 16,
                    &guest.mem_read(self.arg(guest, 0)?, size as usize)?,
                )?;
                self.objects.insert(
                    pointer,
                    Object {
                        class: "HostSwiftTaskLocal".into(),
                        value: Value::Null,
                        properties: HashMap::from([
                            ("valueSize".into(), size),
                            ("defaultValue".into(), pointer + 16),
                        ]),
                    },
                );
                self.set(guest, pointer)?;
            }
            "$ss9TaskLocalC3getxyF" | "$ss9TaskLocalC12wrappedValuexvg" => {
                let pointer = guest.reg_read(reg::general(20).unwrap())?;
                let object = self
                    .objects
                    .get(&pointer)
                    .ok_or_else(|| failure("unknown Swift TaskLocal"))?;
                let source = self
                    .task_locals
                    .get(&self.current_task)
                    .and_then(|v| v.iter().rev().find(|(k, _)| *k == pointer))
                    .map_or(object.properties["defaultValue"], |(_, v)| *v);
                guest.mem_write(
                    guest.reg_read(reg::general(8).unwrap())?,
                    &guest.mem_read(source, object.properties["valueSize"] as usize)?,
                )?;
            }
            "$s8Dispatch0A3QoSV11unspecifiedACvgZ" => {
                let out = guest.reg_read(reg::general(8).unwrap())?;
                guest.mem_write(out, &5u64.to_le_bytes())?;
                guest.mem_write(out + 8, &0u64.to_le_bytes())?;
            }
            "$sSo17OS_dispatch_queueC8DispatchE5label3qos10attributes20autoreleaseFrequency6targetABSS_AC0D3QoSVAbCE10AttributesVAbCE011AutoreleaseI0OABSgtcfC"
            | "$sSo24OS_dispatch_queue_serialC8DispatchE5label3qos10attributes20autoreleaseFrequency6targetABSS_AC0E3QoSVAbCE10AttributesVSo0a1_b1_C0CACE011AutoreleaseJ0OANSgtcfC" =>
            {
                let target = self.arg(guest, 5)?;
                let label = self.swift_string(guest, self.arg(guest, 0)?, self.arg(guest, 1)?)?;
                let queue = self.new_object(guest, "HostQueue", Value::String(label))?;
                self.objects
                    .get_mut(&queue)
                    .unwrap()
                    .properties
                    .insert("targetQueue".into(), target);
                self.set(guest, queue)?;
            }
            "$sSo17OS_dispatch_queueC8DispatchE5async5group3qos5flags7executeySo0a1_b1_F0CSg_AC0D3QoSVAC0D13WorkItemFlagsVyyXBtF" =>
            {
                if self.arg(guest, 0)? != 0 {
                    return Err(failure("Swift dispatch group is unsupported"));
                }
                let queue = guest.reg_read(reg::general(20).unwrap())?;
                let block = self.arg(guest, 3)?;
                self.copy_block(
                    guest,
                    block,
                    Box::new(move |state, guest, block| {
                        state.pending.push_back((block, queue));
                        state.set(guest, 0)
                    }),
                )?;
            }
            "$ss10SetAlgebraPyxqd__ncSTRd__7ElementQyd__ACRtzlufCTj" => {
                let accessor = self.arg(guest, 3)?;
                let allowed = [
                    "$sSo24OS_dispatch_queue_serialC8DispatchE10AttributesVMa",
                    "$sSo17OS_dispatch_queueC8DispatchE10AttributesVMa",
                    "$s8Dispatch0A13WorkItemFlagsVMa",
                ]
                .iter()
                .any(|name| self.data.metadata.swift_accessors.get(*name) == Some(&accessor));
                if !allowed || read64(guest, read64(guest, self.arg(guest, 0)?)? + 16)? != 0 {
                    return Err(failure("unsupported Swift SetAlgebra initializer"));
                }
                guest.mem_write(
                    guest.reg_read(reg::general(8).unwrap())?,
                    &0u64.to_le_bytes(),
                )?;
            }
            "swift_getTypeByMangledNameInContext2" => {
                let key = self.arg(guest, 0)?.to_string();
                let value = self
                    .data
                    .metadata
                    .swift_types
                    .get(&key)
                    .copied()
                    .filter(|_| {
                        self.arg(guest, 2).ok() == Some(0) && self.arg(guest, 3).ok() == Some(0)
                    })
                    .ok_or_else(|| failure("unprepared Swift type metadata"))?;
                self.set(guest, value)?;
            }
            "swift_getSingletonMetadata" => {
                let key = self.arg(guest, 1)?.to_string();
                let value = self
                    .data
                    .metadata
                    .swift_singletons
                    .get(&key)
                    .copied()
                    .ok_or_else(|| failure("unprepared Swift singleton metadata"))?;
                self.set(guest, value)?;
                guest.reg_write(reg::X0 + 1, 0)?;
            }
            "swift_getWitnessTable" => {
                let key = profile::format::witness_key(self.arg(guest, 0)?, self.arg(guest, 1)?);
                let value = self
                    .data
                    .metadata
                    .swift_witnesses
                    .get(&key)
                    .copied()
                    .ok_or_else(|| failure("unprepared Swift witness metadata"))?;
                self.set(guest, value)?;
            }
            "swift_getForeignTypeMetadata" => {
                let candidate = self.arg(guest, 1)?;
                let value = self
                    .data
                    .metadata
                    .swift_foreign
                    .get(&candidate.to_string())
                    .copied()
                    .or_else(|| {
                        (candidate == 0x1eaa52f08 && read64(guest, candidate).ok() == Some(0x201))
                            .then_some(candidate)
                    })
                    .ok_or_else(|| failure("unsupported Swift foreign metadata"))?;
                self.set(guest, value)?;
                guest.reg_write(reg::X0 + 1, 0)?;
            }
            "swift_getObjectType" => self.set(guest, read64(guest, self.arg(guest, 0)?)?)?,
            "swift_getObjCClassMetadata" => (),
            "swift_getObjCClassFromMetadata" => {
                let metadata = self.arg(guest, 0)?;
                if !self.class_names.contains_key(&metadata) {
                    if read64(guest, metadata)? != 0x305 {
                        return Err(failure("unknown Swift Objective-C class metadata"));
                    }
                    self.set(guest, read64(guest, metadata + 8)?)?;
                }
            }
            "swift_allocObject" => {
                let metadata = self.arg(guest, 0)?;
                let size = self.arg(guest, 1)?;
                if size < 16 {
                    return Err(failure("invalid Swift object size"));
                }
                let object = self.alloc(size)?;
                guest.mem_write(object, &metadata.to_le_bytes())?;
                guest.mem_write(object + 8, &3u64.to_le_bytes())?;
                self.set(guest, object)?;
            }
            "swift_isUniquelyReferenced_nonNull_native"
            | "swift_isUniquelyReferenced_nonNull_bridgeObject" => self.set(guest, 0)?,
            "swift_retain_n"
            | "swift_bridgeObjectRetain_n"
            | "swift_retain"
            | "swift_bridgeObjectRetain"
            | "swift_unknownObjectRetain"
            | "swift_destroy_strong"
            | "$ss15CollectionOfOneV8IteratorVwxx"
            | "swift_pod_destroy"
            | "swift_arrayDestroy"
            | "swift_deallocPartialClassInstance"
            | "swift_cvw_destroy"
            | "swift_noop_void_return"
            | "swift_release_n"
            | "swift_bridgeObjectRelease_n"
            | "swift_release"
            | "swift_bridgeObjectRelease"
            | "swift_unknownObjectRelease"
            | "swift_deallocObject"
            | "swift_errorRetain"
            | "swift_errorRelease"
            | "swift_willThrow"
            | "$ss11AnyHashableVwxx"
            | "$sSSwxx" => (),
            "swift_initWithCopy_strong"
            | "swift_initWithTake_strong"
            | "swift_assignWithCopy_strong"
            | "swift_assignWithTake_strong" => guest.mem_write(
                self.arg(guest, 0)?,
                &read64(guest, self.arg(guest, 1)?)?.to_le_bytes(),
            )?,
            "$ss17CodingUserInfoKeyVwCP" | "$sSSwCP" | "$sSSwcp" | "$sSSwca" => guest.mem_write(
                self.arg(guest, 0)?,
                &guest.mem_read(self.arg(guest, 1)?, 16)?,
            )?,
            "$sSqwta"
            | "$sSqwca"
            | "$sSqwcp"
            | "$sSqwtk"
            | "swift_cvw_initWithCopy"
            | "swift_cvw_assignWithCopy"
            | "swift_cvw_initWithTake"
            | "swift_cvw_assignWithTake" => {
                let metadata = self.arg(guest, 2)?;
                let size = read64(guest, read64(guest, metadata - 8)? + 64)?;
                if size > 1024 {
                    return Err(failure("Swift value copy exceeds limit"));
                }
                guest.mem_write(
                    self.arg(guest, 0)?,
                    &guest.mem_read(self.arg(guest, 1)?, size as usize)?,
                )?;
            }
            "$sSS10FoundationE36_unconditionallyBridgeFromObjectiveCySSSo8NSStringCSgFZ" => {
                let text = self.string(self.arg(guest, 0)?)?;
                self.return_swift_string(guest, &text)?;
            }
            "$sSS10FoundationE19_bridgeToObjectiveCSo8NSStringCyF" => {
                let text = self.swift_string(guest, self.arg(guest, 0)?, self.arg(guest, 1)?)?;
                let value = self.new_object(guest, "NSString", Value::String(text))?;
                self.set(guest, value)?;
            }
            "$sSS6appendyySSF" => {
                let pointer = guest.reg_read(reg::general(20).unwrap())?;
                let mut text =
                    self.swift_string(guest, read64(guest, pointer)?, read64(guest, pointer + 8)?)?;
                text.push_str(&self.swift_string(
                    guest,
                    self.arg(guest, 0)?,
                    self.arg(guest, 1)?,
                )?);
                self.return_swift_string(guest, &text)?;
                guest.mem_write(pointer, &self.arg(guest, 0)?.to_le_bytes())?;
                guest.mem_write(pointer + 8, &self.arg(guest, 1)?.to_le_bytes())?;
            }
            "$sSo9OS_os_logC0B0E9subsystem8categoryABSS_SStcfC" => {
                let value = self.new_object(guest, "HostOSLog", Value::Null)?;
                self.set(guest, value)?;
            }
            "$sSo13os_log_type_ta0A0E5errorABvgZ" => self.set(guest, 16)?,
            "$sSo13os_log_type_ta0A0E5faultABvgZ" => self.set(guest, 17)?,
            "$sSo13os_log_type_ta0A0E4infoABvgZ" => self.set(guest, 1)?,
            "$sSo13os_log_type_ta0A0E5debugABvgZ" => self.set(guest, 2)?,
            "$sSo13os_log_type_ta0A0E7defaultABvgZ" => self.set(guest, 0)?,
            "$sSD17dictionaryLiteralSDyxq_Gx_q_td_tcfC" => {
                if read64(guest, self.arg(guest, 0)? + 16)? != 0 {
                    return Err(failure("nonempty Swift dictionary literal is unsupported"));
                }
                let empty = self
                    .data
                    .metadata
                    .symbols
                    .get("_swiftEmptyDictionarySingleton")
                    .copied()
                    .ok_or_else(|| failure("missing Swift empty dictionary"))?;
                self.set(guest, empty)?;
            }
            "$s10Foundation10URLRequestV36_unconditionallyBridgeFromObjectiveCyACSo12NSURLRequestCSgFZ"
            | "$s10Foundation3URLV36_unconditionallyBridgeFromObjectiveCyACSo5NSURLCSgFZ" => {
                let value = self.arg(guest, 0)?;
                let object = self
                    .objects
                    .get(&value)
                    .ok_or_else(|| failure("invalid Swift Foundation bridge"))?;
                if !(self.kind_of(&object.class, "NSURLRequest") || object.class == "NSURL") {
                    return Err(failure("invalid Swift Foundation bridge"));
                }
                let out = guest.reg_read(reg::general(8).unwrap())?;
                guest.mem_write(out, &value.to_le_bytes())?;
                if name.contains("3URLV") {
                    guest.mem_write(out + 8, &0u64.to_le_bytes())?;
                }
            }
            "$s10Foundation10URLRequestV19_bridgeToObjectiveCSo12NSURLRequestCyF"
            | "$s10Foundation3URLV19_bridgeToObjectiveCSo5NSURLCyF" => {
                let pointer = guest.reg_read(reg::general(20).unwrap())?;
                self.set(guest, read64(guest, pointer)?)?;
            }
            _ => {
                if (name.starts_with("$sSo17OS_dispatch_queueC8DispatchE")
                    || name.starts_with("$s10Foundation3URLV13DirectoryHintO"))
                    && name.ends_with("Owui")
                {
                    let metadata = self.arg(guest, 2)?;
                    if read64(guest, read64(guest, metadata - 8)? + 64)? != 1 {
                        return Err(failure("unexpected Swift dispatch enum size"));
                    }
                    guest.mem_write(self.arg(guest, 0)?, &[self.arg(guest, 1)? as u8])?;
                    return Ok(true);
                }
                if let Some(value) = self.data.metadata.swift_globals.get(name).copied() {
                    self.set(guest, value)?;
                    return Ok(true);
                }
                if let Some(value) = self.data.metadata.swift_accessors.get(name).copied() {
                    self.set(guest, value)?;
                    guest.reg_write(reg::X0 + 1, 0)?;
                    return Ok(true);
                }
                if let Some(size) = name
                    .strip_prefix("swift_memcpy")
                    .and_then(|s| s.split_once('_'))
                    .and_then(|(size, _)| size.parse::<usize>().ok())
                    .filter(|size| *size <= 1024)
                {
                    guest.mem_write(
                        self.arg(guest, 0)?,
                        &guest.mem_read(self.arg(guest, 1)?, size)?,
                    )?;
                    return Ok(true);
                }
                if (name.contains("NativeBoxIyLm8ELm8ELm8E") || name.contains("SwiftRetainableBox"))
                    && name.contains("initializeBufferWithCopyOfBuffer")
                    || name.contains("BridgeObjectBox")
                        && (name.contains("initializeWithCopy") || name.contains("assignWithCopy"))
                {
                    guest.mem_write(
                        self.arg(guest, 0)?,
                        &read64(guest, self.arg(guest, 1)?)?.to_le_bytes(),
                    )?;
                    return Ok(true);
                }
                if name.contains("BridgeObjectBox") && name.contains("destroy")
                    || name.contains("SwiftRetainableBox") && name.contains("7destroy")
                {
                    return Ok(true);
                }
                if name.contains("tuple_initializeWithCopy")
                    || name.contains("tuple_assignWithCopy")
                {
                    let size = read64(guest, read64(guest, self.arg(guest, 2)? - 8)? + 64)?;
                    if size > 1024 {
                        return Err(failure("Swift tuple copy exceeds limit"));
                    }
                    guest.mem_write(
                        self.arg(guest, 0)?,
                        &guest.mem_read(self.arg(guest, 1)?, size as usize)?,
                    )?;
                    return Ok(true);
                }
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub(super) fn return_swift_string(
        &mut self,
        guest: Guest<'_>,
        text: &str,
    ) -> Result<(), ClientError> {
        if text.len() <= 15 {
            let mut words = [0; 16];
            words[..text.len()].copy_from_slice(text.as_bytes());
            words[15] = 0xa0 | text.len() as u8;
            if text.is_ascii() {
                words[15] |= 0x40;
            }
            self.set(guest, u64::from_le_bytes(words[..8].try_into().unwrap()))?;
            guest.reg_write(
                reg::X0 + 1,
                u64::from_le_bytes(words[8..].try_into().unwrap()),
            )
        } else {
            if text.len() > 1 << 20 {
                return Err(failure("Swift string exceeds limit"));
            }
            let pointer = self.alloc(text.len() as u64 + 33)?;
            let mut bytes = text.as_bytes().to_vec();
            bytes.push(0);
            guest.mem_write(pointer + 32, &bytes)?;
            let mut flags = text.len() as u64 | 0x3000000000000000;
            if text.is_ascii() {
                flags |= 0xc000000000000000;
            }
            self.set(guest, flags)?;
            guest.reg_write(reg::X0 + 1, pointer | 0x8000000000000000)
        }
    }
    pub(super) fn swift_string(
        &self,
        guest: Guest<'_>,
        first: u64,
        second: u64,
    ) -> Result<String, ClientError> {
        if second & (1 << 61) != 0 {
            let mut bytes = Vec::from(first.to_le_bytes());
            bytes.extend_from_slice(&second.to_le_bytes());
            return String::from_utf8(bytes[..((second >> 56) & 15) as usize].to_vec())
                .map_err(|_| failure("invalid Swift UTF-8 string"));
        }
        let pointer = second & 0x0fffffffffffffff;
        if second & (1 << 60) != 0 {
            return self.string(pointer);
        }
        if second & (1 << 63) == 0 {
            return Err(failure("unsupported mortal Swift string"));
        }
        let size = first & 0x0000ffffffffffff;
        if size > 1 << 20 {
            return Err(failure("Swift string exceeds limit"));
        }
        String::from_utf8(guest.mem_read(pointer + 32, size as usize)?)
            .map_err(|_| failure("invalid Swift UTF-8 string"))
    }
    fn copy_swift_elements(
        &mut self,
        guest: Guest<'_>,
        layout: (u64, u64, u64, u64, u64, u64, bool),
        index: u64,
    ) -> Result<(), ClientError> {
        let (destination, source, count, metadata, stride, entry, backward) = layout;
        if index == count {
            return self.set(guest, destination);
        }
        let element = if backward { count - index - 1 } else { index };
        let offset = element
            .checked_mul(stride)
            .ok_or_else(|| failure("Swift array copy overflow"))?;
        self.callback_then(
            guest,
            entry,
            &[
                destination
                    .checked_add(offset)
                    .ok_or_else(|| failure("Swift array destination overflow"))?,
                source
                    .checked_add(offset)
                    .ok_or_else(|| failure("Swift array source overflow"))?,
                metadata,
            ],
            Box::new(move |state, guest| state.copy_swift_elements(guest, layout, index + 1)),
        )
    }
}
