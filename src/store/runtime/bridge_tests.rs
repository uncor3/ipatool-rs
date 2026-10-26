//! Semantic fixtures for the pinned Go bridge, using only synthetic guest data.
use super::*;

fn value(runtime: &Runtime, address: u64) -> Value {
    runtime.state.lock().unwrap().objects[&address]
        .value
        .clone()
}
fn string(runtime: &mut Runtime, text: &str) -> u64 {
    runtime
        .new_object("NSString", Value::String(text.into()))
        .unwrap()
}
fn call_symbol(runtime: &mut Runtime, name: &str, args: &[u64]) -> u64 {
    let guest = runtime.engine.guest();
    let mut state = runtime.state.lock().unwrap();
    for (index, value) in args.iter().enumerate() {
        guest
            .reg_write(reg::general(index as u32).unwrap(), *value)
            .unwrap();
    }
    state.symbol(guest, name).unwrap();
    guest.reg_read(reg::X0).unwrap()
}

#[tokio::test]
#[ignore = "requires pinned assets and ARM64 Unicorn; no account or network requests"]
async fn live_store_bridge_collections_strings_dates_and_virtual_services() {
    let bundle = crate::sap::assets::macos27::load_verified(
        &crate::sap::assets::macos27::cache_directory().unwrap(),
    )
    .unwrap();
    let mut runtime = Runtime::open(&AppleClient::for_tests(), &bundle.apple_media_services)
        .await
        .unwrap();
    let a = string(&mut runtime, "a");
    let equal_a = string(&mut runtime, "a");
    let b = string(&mut runtime, "b");
    let array = runtime
        .new_object("NSMutableArray", Value::Array(vec![a, b, equal_a]))
        .unwrap();
    let remove = runtime
        .new_object("NSArray", Value::Array(vec![equal_a]))
        .unwrap();
    runtime
        .invoke(array, "removeObjectsInArray:", &[remove])
        .unwrap();
    assert!(value(&runtime, array) == Value::Array(vec![b]));
    runtime.invoke(array, "removeObject:", &[0]).unwrap();
    assert!(value(&runtime, array) == Value::Array(vec![b]));
    let equal_b = string(&mut runtime, "b");
    runtime.invoke(array, "removeObject:", &[equal_b]).unwrap();
    assert!(value(&runtime, array) == Value::Array(vec![]));
    let nested = runtime
        .new_object("NSArray", Value::Array(vec![a]))
        .unwrap();
    let equal_nested = runtime
        .new_object("NSArray", Value::Array(vec![equal_a]))
        .unwrap();
    let array = runtime
        .new_object("NSMutableArray", Value::Array(vec![nested, b, nested]))
        .unwrap();
    runtime
        .invoke(array, "removeObject:", &[equal_nested])
        .unwrap();
    assert!(value(&runtime, array) == Value::Array(vec![b]));

    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    let native = runtime.new_object("FixtureCopy", Value::Null).unwrap();
    {
        let mut state = runtime.state.lock().unwrap();
        let guest = runtime.engine.guest();
        let block = state
            .host_block(
                guest,
                Arc::new(move |state, guest| {
                    observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let copied =
                        state.new_object(guest, "NSString", Value::String("copied".into()))?;
                    state.set(guest, copied)
                }),
            )
            .unwrap();
        state.methods.insert(
            ("FixtureCopy".into(), "copyWithZone:".into(), false),
            read64(guest, block + 16).unwrap(),
        );
    }
    let mutable = runtime
        .new_object("NSMutableArray", Value::Array(vec![a]))
        .unwrap();
    let source = runtime
        .new_object(
            "NSDictionary",
            Value::Dictionary(HashMap::from([
                ("native".into(), native),
                ("array".into(), mutable),
            ])),
        )
        .unwrap();
    for copy in [0, 1] {
        let target = runtime.new_object("NSDictionary", Value::Null).unwrap();
        assert_eq!(
            runtime
                .invoke(target, "initWithDictionary:copyItems:", &[source, copy])
                .unwrap(),
            target
        );
        let Value::Dictionary(values) = value(&runtime, target) else {
            panic!()
        };
        if copy == 0 {
            assert_eq!(values["native"], native);
            assert_eq!(values["array"], mutable);
        } else {
            assert!(value(&runtime, values["native"]) == Value::String("copied".into()));
            assert_ne!(values["array"], mutable);
            assert!(value(&runtime, values["array"]) == Value::Array(vec![a]));
        }
    }
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let cache = runtime.new_object("NSCache", Value::Null).unwrap();
    runtime.invoke(cache, "init", &[]).unwrap();
    runtime
        .invoke(cache, "setObject:forKey:cost:", &[b, a, 5])
        .unwrap();
    assert_eq!(
        runtime.invoke(cache, "objectForKey:", &[equal_a]).unwrap(),
        b
    );

    let text = string(&mut runtime, "é😀");
    let bytes = runtime.invoke(text, "dataUsingEncoding:", &[10]).unwrap();
    assert!(value(&runtime, bytes) == Value::Bytes(vec![0xff, 0xfe, 0xe9, 0, 0x3d, 0xd8, 0, 0xde]));
    let bytes = runtime.invoke(text, "dataUsingEncoding:", &[4]).unwrap();
    assert!(value(&runtime, bytes) == Value::Bytes("é😀".as_bytes().into()));
    assert_eq!(runtime.invoke(text, "length", &[]).unwrap(), 6);
    let mutable = runtime
        .new_object("NSMutableString", Value::String("hello".into()))
        .unwrap();
    runtime.invoke(mutable, "appendString:", &[text]).unwrap();
    assert!(value(&runtime, mutable) == Value::String("helloé😀".into()));
    let empty = string(&mut runtime, "");
    let parts = runtime
        .invoke(text, "componentsSeparatedByString:", &[empty])
        .unwrap();
    let Value::Array(parts) = value(&runtime, parts) else {
        panic!()
    };
    assert_eq!(parts.len(), 2);
    let set = runtime
        .invoke(
            runtime.class_address("NSCharacterSet").unwrap(),
            "decimalDigitCharacterSet",
            &[],
        )
        .unwrap();
    let arabic = string(&mut runtime, "x١y");
    assert_eq!(
        runtime
            .invoke(arabic, "rangeOfCharacterFromSet:", &[set])
            .unwrap(),
        1
    );

    let date = runtime.new_object("NSDate", Value::Null).unwrap();
    runtime
        .engine
        .guest()
        .reg_write(40, (-0.5f64).to_bits())
        .unwrap();
    runtime
        .invoke(date, "initWithTimeIntervalSince1970:", &[])
        .unwrap();
    assert!(value(&runtime, date) == Value::Date(-0.5));
    let second = runtime.new_object("NSDate", Value::Date(-0.5)).unwrap();
    assert_eq!(
        runtime.invoke(date, "isEqualToDate:", &[second]).unwrap(),
        1
    );
    let locale = runtime.class_address("NSLocale").unwrap();
    let languages = runtime.invoke(locale, "preferredLanguages", &[]).unwrap();
    let Value::Array(languages) = value(&runtime, languages) else {
        panic!()
    };
    assert!(value(&runtime, languages[0]) == Value::String("en-US".into()));
    let number_class = runtime.class_address("NSNumber").unwrap();
    runtime
        .engine
        .guest()
        .reg_write(40, 1.25f32.to_bits() as u64)
        .unwrap();
    let number = runtime
        .invoke(number_class, "numberWithFloat:", &[])
        .unwrap();
    assert!(value(&runtime, number) == Value::Real(1.25));
    let null_class = runtime.class_address("NSNull").unwrap();
    assert_eq!(
        runtime.invoke(null_class, "null", &[]).unwrap(),
        runtime.invoke(null_class, "null", &[]).unwrap()
    );
    let path = string(&mut runtime, "/ipatool/test file");
    let url = runtime
        .invoke(
            runtime.class_address("NSURL").unwrap(),
            "fileURLWithPath:isDirectory:",
            &[path, 0],
        )
        .unwrap();
    assert!(value(&runtime, url) == Value::String("file:///ipatool/test%20file".into()));
    let decoded = runtime.invoke(url, "path", &[]).unwrap();
    assert!(value(&runtime, decoded) == Value::String("/ipatool/test file".into()));
    let component = runtime.invoke(url, "lastPathComponent", &[]).unwrap();
    assert!(value(&runtime, component) == Value::String("test file".into()));
    let parent = string(&mut runtime, "/ipatool/a/..");
    let child = string(&mut runtime, "b");
    let joined = runtime
        .invoke(parent, "stringByAppendingPathComponent:", &[child])
        .unwrap();
    assert!(value(&runtime, joined) == Value::String("/ipatool/b".into()));
    let joined = runtime
        .invoke(empty, "stringByAppendingPathComponent:", &[child])
        .unwrap();
    assert!(value(&runtime, joined) == Value::String("b".into()));
    let true_value = runtime
        .new_object("NSNumber", Value::Boolean(true))
        .unwrap();
    let representation = runtime.invoke(true_value, "stringValue", &[]).unwrap();
    assert!(value(&runtime, representation) == Value::String("true".into()));
    let format_string = string(&mut runtime, "%@ %04x %4x");
    let mut state = runtime.state.lock().unwrap();
    let args = state.alloc(24).unwrap();
    drop(state);
    runtime
        .engine
        .guest()
        .mem_write(args, &true_value.to_le_bytes())
        .unwrap();
    runtime
        .engine
        .guest()
        .mem_write(args + 8, &15u64.to_le_bytes())
        .unwrap();
    runtime
        .engine
        .guest()
        .mem_write(args + 16, &15u64.to_le_bytes())
        .unwrap();
    let formatted = runtime.new_object("NSString", Value::Null).unwrap();
    runtime
        .invoke(
            formatted,
            "initWithFormat:locale:arguments:",
            &[format_string, 0, args],
        )
        .unwrap();
    assert!(value(&runtime, formatted) == Value::String("true 000f    f".into()));
    let bundle = runtime
        .invoke(
            runtime.class_address("NSBundle").unwrap(),
            "mainBundle",
            &[],
        )
        .unwrap();
    let fallback = string(&mut runtime, "fallback");
    assert_eq!(
        runtime
            .invoke(
                bundle,
                "localizedStringForKey:value:table:",
                &[a, fallback, 0]
            )
            .unwrap(),
        fallback
    );
    assert_eq!(
        runtime
            .invoke(bundle, "localizedStringForKey:value:table:", &[a, empty, 0])
            .unwrap(),
        a
    );
    let manager = runtime
        .invoke(
            runtime.class_address("NSFileManager").unwrap(),
            "defaultManager",
            &[],
        )
        .unwrap();
    let out = runtime.state.lock().unwrap().alloc(8).unwrap();
    runtime.engine.guest().mem_write(out, &[0xff; 8]).unwrap();
    assert_eq!(
        runtime
            .invoke(manager, "fileExistsAtPath:isDirectory:", &[path, out])
            .unwrap(),
        0
    );
    assert_eq!(runtime.engine.guest().mem_read(out, 1).unwrap(), vec![0]);
    assert_eq!(
        runtime
            .invoke(manager, "isWritableFileAtPath:", &[path])
            .unwrap(),
        0
    );
    for selector in [
        "createDirectoryAtPath:withIntermediateDirectories:attributes:error:",
        "createDirectoryAtURL:withIntermediateDirectories:attributes:error:",
    ] {
        assert_eq!(
            runtime
                .invoke(manager, selector, &[path, 1, 0, out])
                .unwrap(),
            0
        );
        let error = read64(runtime.engine.guest(), out).unwrap();
        assert_eq!(runtime.invoke(error, "code", &[]).unwrap(), 513);
    }

    let guest = runtime.engine.guest();
    let mut state = runtime.state.lock().unwrap();
    let input = state.alloc(128).unwrap();
    let format = state.alloc(64).unwrap();
    let tm = state.alloc(56).unwrap();
    let output = state.alloc(128).unwrap();
    drop(state);
    let stamp = b"Wed, 31 Dec 1969 23:59:59 GMT";
    guest.mem_write(input, stamp).unwrap();
    guest
        .mem_write(format, b"%a, %d %b %Y %H:%M:%S GMT\0")
        .unwrap();
    assert_eq!(
        call_symbol(&mut runtime, "strptime", &[input, format, tm]),
        input + stamp.len() as u64
    );
    assert_eq!(call_symbol(&mut runtime, "timegm", &[tm]), u64::MAX);
    assert_eq!(
        call_symbol(&mut runtime, "strftime", &[output, 128, format, tm]),
        stamp.len() as u64
    );
    assert_eq!(
        runtime
            .engine
            .guest()
            .mem_read(output, stamp.len())
            .unwrap(),
        stamp
    );
    assert_eq!(
        call_symbol(&mut runtime, "strftime", &[output, 2, format, tm]),
        0
    );
    runtime
        .engine
        .guest()
        .mem_write(input, b"invalid date\0")
        .unwrap();
    assert_eq!(
        call_symbol(&mut runtime, "strptime", &[input, format, tm]),
        0
    );
}

#[test]
fn unicode_decimal_digits_exclude_other_numbers() {
    for c in ['0', '١', '９', '\u{1d7ff}'] {
        assert!(super::bridge::decimal_digit(c));
    }
    for c in ['x', '²', 'Ⅳ', '¼'] {
        assert!(!super::bridge::decimal_digit(c));
    }
}
