This is a rust rewrite of ipatool https://github.com/majd/ipatool

Upstream will refer to the original ipatool repository at https://github.com/majd/ipatool

Persisted state in `~/.ipatool` is a compatibility boundary. Account credentials and
cookies must use the formats and platform backends used by the current Go ipatool so
both programs can share the same files and native keychain entries. Never log account
payloads, passwords, password tokens, cookies, or keyring passphrases.

In particular, use the macOS Keychain and Linux Secret Service account entries created
by Go ipatool. Do not use Windows Credential Manager as the ipatool account backend:
Go ipatool excludes WinCred and uses its passphrase-encrypted `~/.ipatool/account`
file on Windows. Use that same encrypted file when Linux Secret Service is unavailable.
The encrypted account is a compact JWE using `PBES2-HS256+A128KW` and `A256GCM`, and
its plaintext is the JSON-serialized Go keyring item whose `Data` field contains the
base64-encoded Go account JSON. Cookie files are Go persistent-cookiejar JSON arrays,
not the JSON representation produced by Rust's `cookie_store` crate.
