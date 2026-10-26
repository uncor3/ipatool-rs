# Upstream port status

Reference: `majd/ipatool` commit `d9c0247daea564d3ec7d04a9b015d0a29af66b04`.
Earlier protocol changes were compared with `3411d57f451f` (2026-10-01).

## Implemented

- `f9aa6536cd2d`: normalize the validated initial authentication URL to a
  trailing slash, preserving its host and query.
- `93b527a83910`: phone-number Apple Account storefront routing for China and
  India without modifying the signed Apple ID.
- `e3932cec3176`: iOS public catalog fallback after all MDM catalogs return no
  listing/offer, including identity/platform/version validation for Arcade apps.
- `7578671482fb`: allow unpinned redownloads only for confirmed iOS catalog 404s;
  keep app/bundle identity checks and bound download requests. Numeric-ID
  downloads avoid requiring a publicly listed bundle ID.
- `1b9ff28eb467`: package platform validation with the legacy iOS exception for
  a missing (not empty/malformed/conflicting) platform declaration.
- `4484b55d366e`: watchOS search/lookup filtering, version selection, download,
  and package-platform validation. New platform-selectable APIs preserve the
  existing iDescriptor iPhone-default interface.
- ARM64 Unicorn engine foundation from `0259df3c09bd`: register layout,
  128-bit vector access, CPU model, invalid-instruction hooks, and CASAL/SWPAL/
  EOR3 compatibility. x86-64 execution remains available for the existing signer.
- Explicit Unicorn timeout reporting via `UC_QUERY_TIMEOUT`.
- Preferred `ent/download` protocol with account/device-bound kbsync, Go-compatible
  `kbsync-v1` cache items, one fresh retry after cached-blob rejection, and legacy
  fallback.
- Production SAP signing and fresh kbsync generation now use Go's macOS 27.0.1
  (`26A434`) ARM64e profile, including exact asset sizes/digests, shared-cache
  function/slot mappings, chained fixups, pointer-authentication rewrites, ARM64
  arguments and callbacks, sparse segment mapping, and StoreAgent global cleanup.
  Reads the same verified asset cache as Go under the OS cache directory:
  `ipatool/sap/apple-assets-macos-27-26A434-arm64-v1/`.
- Native IPSW range/AEA readers:
  seekable HTTP range reader with strict Content-Range validation, three attempts
  resuming truncated bodies, bounded ZIP sections, and the exact two pinned AEA
  member sizes. Authenticated AEA profile-1 indexing/random access, Apple FCS
  P-256/HPKE image-key resolution, HKDF/AES-CTR/HMAC-SHA256, bounded LZFSE output,
  segment SHA-256 checks, and a 64-segment decoded cache.
- Store profile import and native loader: committed
  metadata/pages/plugin from the reference revision, bounded Zstandard decoding,
  exact decoded sizes/digests, image UUID/page index validation, shared immutable
  process cache, and the Go JSON schema. The import script reads the exact Git
  object, not modified checkout files. No Go build/runtime dependency is added.
- APFS reader implementation: container/checkpoint and object-map traversal,
  sealed filesystem child hashes, path/inode/xattr resolution, physical extents,
  resource-fork compression indexes, bounded LZVN/LZFSE/LZBITMAP decoding and
  random-access file reads. Native extraction of commerce, CoreFP and CoreFP.icxs
  has matched the exact pinned Go sizes and hashes in a live IPSW test.
- Dyld reader implementation: arm64e member/subcache tables, UUID checks,
  virtual-address mapping, image lookup and v5 slide-chain decoding. Standalone
  Mach-O segment/linkedit/symbol reconstruction matches the exact pinned
  AppleMediaServices hash. A live native IPSW extraction run passed for all
  four assets, without reading Go's cached asset bytes or running Go.
- Cache-miss extraction is connected to SAP signing and kbsync generation,
  serialized with a file lock. All four hashes are required before installation;
  private temporary files are synced and renamed atomically per asset.
- Initial Store VM: isolated image/profile loading, grouped mappings, code-range
  checks, bounded guest heap/stack/calls, Objective-C dispatch, block/byref copies,
  Foundation object import/export and ephemeral Accounts values, dispatch queues,
  semaphore waits and callback continuations. Actual Apple AMSBuyParams operations,
  a synthetic account/DSID round-trip, and queued callback return/queue restoration
  pass locally.

- Production Store-framework HTTP executor: per-request ARM64 guests run Apple's
  AMSURLRequestEncoder, AMSPurchaseRequestEncoder, AMSVerifyCredentialsTask,
  AMSURLSession and response decoding. Rust supplies scoped Foundation/Swift,
  dispatch/task, notification, virtual device and unavailable-XPC adapters.
  The purchase subclass reapplies Go's signing policy and validates product/price
  after encoding. Native UI requests return to the CLI through the same declining
  delegate policy as Go. Framework finance errors preserve the original response
  for existing 2FA/license handling; bridge and transport errors remain errors.
- Shared reqwest sockets and Go-compatible cookie persistence sit underneath the
  framework, with framework-controlled redirects, fresh authentication connections,
  bounded API bodies and gzip decoding, and unbuffered package/range responses.
  Authentication, purchase, download metadata, catalog, bag, and package transfer
  entry points now use this executor. No Go subprocess or runtime dependency.
- Caller cancellation now reaches guest preparation, CPU execution, Swift task
  cancellation checks, and pending HTTP header/body reads. A dropped async caller
  cancels its blocking worker cooperatively. The verified AppleMediaServices
  image is initialized once per AppleClient and shared by concurrent requests;
  guests remain isolated. Each call supplies response format, redirect policy,
  and streaming explicitly. Authentication permits framework redirects;
  ent/download explicitly returns redirects to its compatibility layer.
- Purchase validation compares Go-style scalar representations, accepting
  equivalent numeric/string zero and product identifiers while rejecting paid
  purchases and changed product/price/pricing parameters after native encoding.
- Store connections explicitly retain Go's 90-second idle pool timeout and a
  30-second deadline for receiving response headers. One transport distinction
  remains: reqwest's headers future includes connect/upload, so this deadline
  starts earlier than Go's ResponseHeaderTimeout (which starts after writing).
  It does not impose a 30-second limit on streamed package bodies. Explicit
  request timeouts still apply, and header timeouts participate in auth retries.

## Remaining verification and separate upstream scope

The complete pinned `bridge.go` handler inventory and the corresponding behavior
audit are documented in [STORE_BRIDGE_AUDIT.md](STORE_BRIDGE_AUDIT.md), including
collection removal, dictionary copy callbacks, strings, dates, and virtual services.

- Go's optional strict profile-page test guard (not enabled by Go production).
- MCP command/tool server additions and the later legacy-macOS metadata fixes.
- The user confirmed a successful real-account download after completing the
  bridge handlers. The later cancellation/cache/options changes have synthetic
  regression coverage and public bag/catalog verification, not a fresh automated
  real-account sign-in/download. Tests do not read saved accounts.
- Windows/macOS runtime verification of the ARM64 engine additions.

The production signing/generation path now uses macOS 27 and attempts native
IPSW extraction on a cache miss. The HTTP path now runs through the pinned Store
framework executor; reqwest owns sockets/cookies. No silent fallback to a direct
protocol implementation or OS X 10.9 generation is used. Go
account/cookie persistence formats and native backends are unchanged.

## Verification

Run unit/CLI checks:

```shell
cargo test --all-targets
cargo clippy --all-targets
```

With Unicorn 2.1 containing both x86 and ARM64 guest support installed:

```shell
cargo test --lib sap::unicorn::tests::live_ -- --ignored
```

These emulator tests do not authenticate with Apple or read saved credentials.

To test fresh kbsync generation with a synthetic DSID, verified Apple assets and
the packaged Unicorn library (no saved credentials or live account requests):

```shell
cargo test --lib live_macos27_kbsync_generates_fresh_blob -- --ignored
```

Verified locally: fresh macOS 27 kbsync generation using a synthetic DSID, and a
real SAP handshake followed by two distinct signatures, without saved accounts.
This does not verify a real account sign-in or package download.

The new range/AEA tests use local HTTP responses and synthetic authenticated
archives, including truncated-body resumption and corruption rejection. Store
profile tests decode and verify all three committed artifacts. Flatpak testing
is explicitly outside the requested scope.

Additional live checks, none using saved account credentials:

```shell
cargo test --lib live_pinned_aea_images_are_readable -- --ignored
cargo test --lib live_extract_matches_go_assets -- --ignored
cargo test --lib live_cache_install_round_trip -- --ignored
cargo test --lib live_store_vm_ -- --ignored --test-threads=1
cargo test --lib live_store_framework_ -- --ignored --test-threads=1
cargo test --lib live_store_backend_preserves_streamed_range -- --ignored
cargo test --lib live_store_backend_public_bag_and_catalog -- --ignored
cargo test --lib live_store_vm_cancellation_stops_guest_execution -- --ignored
cargo test --lib live_store_framework_authentication_redirect_keeps_signed_post -- --ignored
```

The complete native IPSW extraction test passed in approximately 133 seconds
on this machine. This is an observed test duration, not a download-time guarantee.
The temporary-cache installation/read-back test also passed, including Unix
directory/file permissions and the absence of leftover temporary files.

Store executor checks passed locally: real guest GET and encoded POST, plain/gzip
plist decoding, JSON including null values, framework-controlled redirect,
authentication and purchase with synthetic credentials, original finance-error
bodies, and a local HTTP ranged package stream preserving status/headers/bytes.
The production wrapper also fetched Apple's public bag and Spotify catalog entry
successfully without saved credentials. These checks do not establish real-account
sign-in or download success after this executor switch.
