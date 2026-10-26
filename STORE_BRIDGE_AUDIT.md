# Store bridge audit

Reference: `majd/ipatool` commit `d9c0247daea564d3ec7d04a9b015d0a29af66b04`,
`internal/store/emulator/bridge.go`. This audit covers that file, not every
other Go emulator module or transport behavior.

| Go bridge responsibility | Rust implementation |
| --- | --- |
| C/Objective-C imports, properties, weak references, blocks, memory | `src/store/runtime/symbols.rs`, `callbacks.rs` |
| Virtual device identity, dates, CF/IOKit services | `src/store/runtime/system.rs` |
| Dispatch queues, once, timers, semaphores | `src/store/runtime/dispatch.rs`, `symbols.rs` |
| Objective-C message dispatch, Foundation values, bundles, equality | `src/store/runtime/foundation.rs` |
| Formatting, sorting, enumeration, URL/string adapters | `src/store/runtime/network.rs` |
| Array removal, dictionary item-copy callbacks, encodings, localization, virtual filesystem | `src/store/runtime/bridge.rs` |
| `kindOf`, UUIDs, collection keys, copies and character sets | `mod.rs`, `foundation.rs`, `callbacks.rs`, `bridge.rs` |

The audit added the previously missing handlers rather than substituting generic
success/no-op responses. In particular, the virtual filesystem reports absent
files and returns Go's `NSCocoaErrorDomain/513` directory-creation error. It does
not read or write the host filesystem. `initWithDictionary:copyItems:` copies
immediate values through native `copyWithZone:` callbacks where available and
keeps nested collection contents shared. Array removal uses Foundation equality.

Behavior corrections include NSString UTF-8 length (as implemented by Go), empty
delimiter splitting, date equality, Unicode decimal character sets, singleton
NSNull identity, class-specific Foundation copies, mutable-copy behavior,
formatting, normalized paths, decoded URL paths, cached bundle information,
numeric conversions and the return value of an already-completed `dispatch_once`.
Date bridges include `strptime`, `timegm`, pre-epoch `strftime`, normalized tm
fields, and Go-duration saturation for relative intervals.

Inventory command (the checkout is only a development input):

```shell
python3 tools/audit_store_bridge.py /path/to/go/ipatool
```

It reads the exact pinned Git object and checks 164 symbol case labels and 206
message case labels against Rust source. Some message labels identify classes or
nested cases; the counts are not counts of independently tested APIs. This check
detects absent names; it does **not** establish semantic parity by itself.

Behavior checks:

```shell
cargo test --lib live_store_bridge_collections_strings_dates_and_virtual_services -- --ignored
cargo test --lib live_store_vm_comparator_sort_is_stable_and_preserves_source -- --ignored
cargo test --lib live_store_ -- --ignored --test-threads=1
cargo test --all-targets
```

The fixtures exercise real ARM64 guest callback entry/return, stable sorting,
structural array removal, nil removal, shallow/native dictionary copying, UTF-16
BOM/surrogates, Unicode digits, formatting, virtual filesystem errors, and C date
round-trips including a negative Unix timestamp. The wider Store tests cover
public bag/catalog requests, encoded requests, finance errors, gzip, redirects,
and local ranged streaming. None uses saved credentials. A real-account IPA
download is still a separate verification step, not something these tests prove.
