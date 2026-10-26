These Zstandard artifacts are imported without regeneration from
`majd/ipatool` commit `d9c0247daea564d3ec7d04a9b015d0a29af66b04`,
`internal/store/profile/data_generated.go`.

Pinned inputs: `macos-27-26A434-unicorn-3-11d75d28e8c328de`.
The loader verifies decoded sizes, SHA-256 hashes, image UUIDs and page indexes.
Run `python3 tools/import_store_profile.py /path/to/pinned/go/checkout` to
reproduce the compressed files. Go is not needed to build or run this crate.

The profile format and ported code are derived from upstream's MIT-licensed
implementation. See `THIRD_PARTY_NOTICES.md` at the repository root.
