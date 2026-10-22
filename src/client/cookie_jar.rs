use std::collections::HashMap;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cookie_store::{CookieDomain, CookieExpiration, CookieStore, RawCookie};
use fs2::FileExt;
use reqwest_cookie_store::CookieStoreMutex;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::error::ClientError;

const GO_ZERO_TIME: &str = "0001-01-01T00:00:00Z";
type CookieId = (String, String, String);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoCookieEntry {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: bool,
    http_only: bool,
    persistent: bool,
    host_only: bool,
    expires: String,
    creation: String,
    last_access: String,
    updated: String,
    canonical_host: String,
}

impl GoCookieEntry {
    fn id(&self) -> CookieId {
        (self.domain.clone(), self.path.clone(), self.name.clone())
    }

    fn updated_at(&self) -> Result<OffsetDateTime, ClientError> {
        parse_go_time("Updated", &self.name, &self.updated)
    }

    fn expires_at(&self) -> Result<OffsetDateTime, ClientError> {
        parse_go_time("Expires", &self.name, &self.expires)
    }

    fn is_expired_at(&self, now: OffsetDateTime) -> Result<bool, ClientError> {
        if !self.persistent || self.expires == GO_ZERO_TIME {
            return Ok(false);
        }

        Ok(self.expires_at()? <= now)
    }

    fn validate_times(&self) -> Result<(), ClientError> {
        self.expires_at()?;
        parse_go_time("Creation", &self.name, &self.creation)?;
        parse_go_time("LastAccess", &self.name, &self.last_access)?;
        self.updated_at()?;
        Ok(())
    }

    fn same_cookie(&self, other: &Self) -> bool {
        self.name == other.name
            && self.value == other.value
            && self.domain == other.domain
            && self.path == other.path
            && self.secure == other.secure
            && self.http_only == other.http_only
            && self.persistent == other.persistent
            && self.host_only == other.host_only
            && self.expires == other.expires
            && self.canonical_host == other.canonical_host
    }
}

pub struct GoCookieJar {
    store: Arc<CookieStoreMutex>,
    /// Go keeps expired entries briefly as deletion markers so another
    /// process cannot resurrect a cookie while merging the shared file.
    known_entries: Mutex<HashMap<CookieId, GoCookieEntry>>,
}

impl GoCookieJar {
    pub fn provider(&self) -> Arc<CookieStoreMutex> {
        self.store.clone()
    }
}

pub fn new_cookie_store(path: Option<&Path>) -> Result<GoCookieJar, ClientError> {
    let mut store = CookieStore::default();
    let mut known_entries = HashMap::new();
    if let Some(path) = path.filter(|path| path.exists()) {
        let lock = open_lock_file(path)?;
        FileExt::lock_shared(&lock).map_err(|error| {
            ClientError::CookieStore(format!("could not lock cookies: {error}"))
        })?;
        let result = read_go_cookies(path);
        let _ = FileExt::unlock(&lock);
        let now = OffsetDateTime::now_utc();
        for entry in result? {
            entry.validate_times()?;
            if entry.persistent {
                known_entries.insert(entry.id(), entry.clone());
            }

            // Go's persistent-cookiejar keeps expired entries for 24 hours as
            // deletion markers. Preserve them for compatible file merging, but
            // never add them to the request jar or send them back to Apple.
            if entry.is_expired_at(now)? {
                continue;
            }
            insert_go_cookie(entry, &mut store)?;
        }
    }
    Ok(GoCookieJar {
        store: Arc::new(CookieStoreMutex::new(store)),
        known_entries: Mutex::new(known_entries),
    })
}

fn read_go_cookies(path: &Path) -> Result<Vec<GoCookieEntry>, ClientError> {
    let file = std::fs::File::open(path)
        .map_err(|error| ClientError::CookieStore(format!("could not open cookies: {error}")))?;
    if file
        .metadata()
        .map_err(|error| ClientError::CookieStore(format!("could not inspect cookies: {error}")))?
        .len()
        == 0
    {
        return Ok(Vec::new());
    }
    serde_json::from_reader(std::io::BufReader::new(file)).map_err(|error| {
        ClientError::CookieStore(format!("invalid Go ipatool cookie JSON: {error}"))
    })
}

fn insert_go_cookie(entry: GoCookieEntry, store: &mut CookieStore) -> Result<(), ClientError> {
    let cookie_name = entry.name.clone();
    let host = if entry.canonical_host.is_empty() {
        entry.domain.trim_start_matches('.')
    } else {
        entry.canonical_host.as_str()
    };
    if host.is_empty() {
        return Err(ClientError::CookieStore(format!(
            "cookie {} has no domain",
            entry.name
        )));
    }
    let scheme = if entry.secure { "https" } else { "http" };
    let request_url = Url::parse(&format!("{scheme}://{host}{}", normalize_path(&entry.path)))
        .map_err(|error| {
            ClientError::CookieStore(format!("invalid cookie origin for {}: {error}", entry.name))
        })?;

    let mut builder = RawCookie::build((entry.name, entry.value))
        .path(normalize_path(&entry.path))
        .secure(entry.secure)
        .http_only(entry.http_only);
    if !entry.host_only {
        builder = builder.domain(entry.domain);
    }
    if entry.persistent && entry.expires != GO_ZERO_TIME {
        builder = builder.expires(parse_go_time("Expires", &cookie_name, &entry.expires)?);
    }

    store
        .insert_raw(&builder.build(), &request_url)
        .map_err(|error| {
            ClientError::CookieStore(format!("invalid cookie from Go ipatool: {error}"))
        })?;
    Ok(())
}

pub fn save_cookie_store(jar: &GoCookieJar, path: &Path) -> Result<(), ClientError> {
    let lock = open_lock_file(path)?;
    lock.lock_exclusive()
        .map_err(|error| ClientError::CookieStore(format!("could not lock cookies: {error}")))?;
    let result = save_go_cookies(jar, path);
    let _ = FileExt::unlock(&lock);
    result
}

fn save_go_cookies(jar: &GoCookieJar, path: &Path) -> Result<(), ClientError> {
    let guard = jar
        .store
        .lock()
        .map_err(|_| ClientError::CookieStore("cookie store lock was poisoned".into()))?;
    let mut known = jar
        .known_entries
        .lock()
        .map_err(|_| ClientError::CookieStore("cookie metadata lock was poisoned".into()))?;
    let now_value = OffsetDateTime::now_utc();
    let now = format_go_time(now_value)?;

    let current = guard
        .iter_unexpired()
        .filter(|cookie| cookie.is_persistent())
        .map(|cookie| {
            let domain = cookie
                .domain
                .as_cow()
                .map(|domain| domain.into_owned())
                .unwrap_or_default();
            let host_only = matches!(cookie.domain, CookieDomain::HostOnly(_));
            let expires = match cookie.expires {
                CookieExpiration::AtUtc(expires) => format_go_time(expires)?,
                CookieExpiration::SessionEnd => GO_ZERO_TIME.to_string(),
            };
            let entry = GoCookieEntry {
                name: cookie.name().to_string(),
                value: cookie.value().to_string(),
                domain: domain.clone(),
                path: cookie.path.as_ref().to_string(),
                secure: cookie.secure().unwrap_or(false),
                http_only: cookie.http_only().unwrap_or(false),
                persistent: true,
                host_only,
                expires,
                creation: now.clone(),
                last_access: now.clone(),
                updated: now.clone(),
                canonical_host: domain,
            };
            Ok((entry.id(), entry))
        })
        .collect::<Result<HashMap<_, _>, ClientError>>()?;

    let mut merged = known.clone();
    for (id, mut entry) in current
        .iter()
        .map(|(id, entry)| (id.clone(), entry.clone()))
    {
        if let Some(previous) = known.get(&id) {
            entry.creation.clone_from(&previous.creation);
            entry.canonical_host.clone_from(&previous.canonical_host);
            if entry.same_cookie(previous) {
                entry.last_access.clone_from(&previous.last_access);
                entry.updated.clone_from(&previous.updated);
            }
        }
        merged.insert(id, entry);
    }

    // Missing cookies that were loaded by this process are deletions. Keep a
    // Go-compatible tombstone for 24 hours so a stale writer cannot restore it.
    for (id, previous) in known.iter() {
        if !current.contains_key(id) && previous.expires_at()? > now_value {
            let mut tombstone = previous.clone();
            tombstone.value.clear();
            tombstone.expires = format_go_time(now_value - Duration::SECOND)?;
            tombstone.last_access = now.clone();
            tombstone.updated = now.clone();
            merged.insert(id.clone(), tombstone);
        }
    }

    // Match persistent-cookiejar's Save behavior: merge changes written by a
    // second process after this jar was loaded, preferring the latest update.
    if path.exists() {
        if let Ok(on_disk) = read_go_cookies(path) {
            for entry in on_disk.into_iter().filter(|entry| entry.persistent) {
                entry.validate_times()?;
                let replace = merged
                    .get(&entry.id())
                    .map(|existing| {
                        existing
                            .updated_at()
                            .and_then(|old| entry.updated_at().map(|new| new > old))
                    })
                    .transpose()?
                    .unwrap_or(true);
                if replace {
                    merged.insert(entry.id(), entry);
                }
            }
        }
    }

    let expired_ids = merged
        .iter()
        .filter_map(|(id, entry)| {
            let expires = entry.expires_at().ok()?;
            let updated = entry.updated_at().ok()?;
            (expires <= now_value && updated + Duration::DAY <= now_value).then(|| id.clone())
        })
        .collect::<Vec<_>>();
    for id in expired_ids {
        merged.remove(&id);
    }

    let mut entries = merged.values().cloned().collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left.canonical_host
            .cmp(&right.canonical_host)
            .then_with(|| right.path.len().cmp(&left.path.len()))
            .then_with(|| left.creation.cmp(&right.creation))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.value.cmp(&right.value))
    });

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| ClientError::CookieStore(format!("could not create cookies: {error}")))?;
    serde_json::to_writer(&mut file, &entries)
        .map_err(|error| ClientError::CookieStore(format!("could not save cookies: {error}")))?;
    use std::io::Write;
    file.write_all(b"\n")
        .map_err(|error| ClientError::CookieStore(format!("could not save cookies: {error}")))?;
    *known = merged;
    Ok(())
}

fn open_lock_file(cookie_path: &Path) -> Result<std::fs::File, ClientError> {
    let lock_path = PathBuf::from(format!("{}.lock", cookie_path.display()));
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(lock_path)
        .map_err(|error| ClientError::CookieStore(format!("could not open cookie lock: {error}")))
}

fn normalize_path(path: &str) -> &str {
    if path.starts_with('/') { path } else { "/" }
}

fn parse_go_time(
    field: &str,
    cookie_name: &str,
    value: &str,
) -> Result<OffsetDateTime, ClientError> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).map_err(|error| {
        ClientError::CookieStore(format!(
            "invalid {field} time for cookie {cookie_name}: {error}"
        ))
    })
}

fn format_go_time(value: OffsetDateTime) -> Result<String, ClientError> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| ClientError::CookieStore(format!("could not format cookie time: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_go_cookie_array() {
        let path =
            std::env::temp_dir().join(format!("ipatool-cookie-test-{}.json", std::process::id()));
        let data = r#"[{"Name":"mz_at0","Value":"token","Domain":"itunes.apple.com","Path":"/","Secure":true,"HttpOnly":true,"Persistent":true,"HostOnly":false,"Expires":"2099-01-01T00:00:00Z","Creation":"2026-01-01T00:00:00Z","LastAccess":"2026-01-01T00:00:00Z","Updated":"2026-01-01T00:00:00Z","CanonicalHost":"itunes.apple.com"}]"#;
        std::fs::write(&path, data).unwrap();
        let jar = new_cookie_store(Some(&path)).unwrap();
        assert_eq!(jar.store.lock().unwrap().iter_unexpired().count(), 1);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    }

    #[test]
    fn loads_live_cookie_and_retains_expired_deletion_marker() {
        let path = std::env::temp_dir().join(format!(
            "ipatool-cookie-tombstone-test-{}.json",
            std::process::id()
        ));
        let data = r#"[
            {"Name":"mz_at0","Value":"token","Domain":"itunes.apple.com","Path":"/","Secure":true,"HttpOnly":true,"Persistent":true,"HostOnly":false,"Expires":"2099-01-01T00:00:00Z","Creation":"2026-01-01T00:00:00Z","LastAccess":"2026-01-01T00:00:00Z","Updated":"2026-01-01T00:00:00Z","CanonicalHost":"itunes.apple.com"},
            {"Name":"mzf_dr","Value":"","Domain":".apple.com","Path":"/WebObjects","Secure":false,"HttpOnly":false,"Persistent":true,"HostOnly":false,"Expires":"1970-01-01T00:00:00Z","Creation":"2026-01-01T00:00:00Z","LastAccess":"2026-10-04T08:49:00Z","Updated":"2026-10-04T08:49:00Z","CanonicalHost":"buy.itunes.apple.com"}
        ]"#;
        std::fs::write(&path, data).unwrap();

        let jar = new_cookie_store(Some(&path)).unwrap();

        assert_eq!(jar.store.lock().unwrap().iter_unexpired().count(), 1);
        assert_eq!(jar.known_entries.lock().unwrap().len(), 2);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    }

    #[test]
    fn only_persistent_cookies_are_saved() {
        let path = std::env::temp_dir().join(format!(
            "ipatool-cookie-save-test-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let jar = new_cookie_store(None).unwrap();
        let url = Url::parse("https://itunes.apple.com/").unwrap();
        {
            let mut store = jar.store.lock().unwrap();
            store
                .insert_raw(&RawCookie::new("session", "temporary"), &url)
                .unwrap();
            store
                .insert_raw(
                    &RawCookie::build(("saved", "durable"))
                        .expires(OffsetDateTime::now_utc() + Duration::DAY)
                        .build(),
                    &url,
                )
                .unwrap();
        }
        save_cookie_store(&jar, &path).unwrap();
        let entries = read_go_cookies(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "saved");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    }
}
