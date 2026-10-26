use std::path::{Path, PathBuf};
use std::sync::RwLock;

use base64::Engine;
use jose4rs::jwa::{AlgorithmConstraints, ConstraintType};
use jose4rs::jwe::{ContentEncryptionAlgorithm, JsonWebEncryption, KeyManagementAlgorithm};
use jose4rs::jwk::{JsonWebKey, oct::OctetSequenceJsonWebKey};
use jose4rs::jwx::{HeaderParameter, JsonWebStructure};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::error::IpaToolError;
use crate::model::account::Account;

const SERVICE_NAME: &str = "ipatool-auth.service";
const ACCOUNT_KEY: &str = "account";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialBackend {
    Native,
    EncryptedFile,
}

pub struct CredentialStore {
    state_dir: PathBuf,
    backend: CredentialBackend,
    passphrase: RwLock<Option<SecretString>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoKeyringItem {
    key: String,
    data: String,
    label: String,
    description: String,
    keychain_not_trust_application: bool,
    keychain_not_synchronizable: bool,
}

impl GoKeyringItem {
    #[cfg(test)]
    fn from_account(account: &Account) -> Result<Self, IpaToolError> {
        Ok(Self::from_data(ACCOUNT_KEY, &serde_json::to_vec(account)?))
    }

    fn from_data(key: &str, data: &[u8]) -> Self {
        Self {
            key: key.to_string(),
            data: base64::engine::general_purpose::STANDARD.encode(data),
            label: SERVICE_NAME.to_string(),
            description: String::new(),
            keychain_not_trust_application: false,
            keychain_not_synchronizable: false,
        }
    }

    fn decode_data(&self) -> Result<Vec<u8>, IpaToolError> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.data)
            .map_err(|error| IpaToolError::InvalidEncryptedAccount(error.to_string()))
    }
}

impl CredentialStore {
    pub fn new(state_dir: PathBuf, passphrase: Option<String>) -> Self {
        Self {
            state_dir,
            backend: platform_backend(),
            passphrase: RwLock::new(passphrase.map(SecretString::from)),
        }
    }

    pub fn backend(&self) -> CredentialBackend {
        self.backend
    }

    pub fn requires_passphrase(&self) -> bool {
        self.backend == CredentialBackend::EncryptedFile
            && self.account_path().is_file()
            && self
                .passphrase
                .read()
                .map(|passphrase| passphrase.is_none())
                .unwrap_or(true)
    }

    pub fn set_passphrase(&self, passphrase: String) -> Result<(), IpaToolError> {
        if passphrase.is_empty() {
            return Err(IpaToolError::KeyringPassphraseRequired);
        }
        *self
            .passphrase
            .write()
            .map_err(|_| IpaToolError::AccountStore("passphrase lock was poisoned".into()))? =
            Some(SecretString::from(passphrase));
        Ok(())
    }

    pub fn store_account(&self, account: &Account) -> Result<(), IpaToolError> {
        match self.backend {
            CredentialBackend::Native => {
                store_native_data(ACCOUNT_KEY, &serde_json::to_vec(account)?)
            }
            CredentialBackend::EncryptedFile => {
                self.store_file_data(ACCOUNT_KEY, &serde_json::to_vec(account)?)
            }
        }
    }

    pub fn load_account(&self) -> Result<Option<Account>, IpaToolError> {
        match self.backend {
            CredentialBackend::Native => load_native_data(ACCOUNT_KEY)?
                .map(|data| serde_json::from_slice(&data).map_err(Into::into))
                .transpose(),
            CredentialBackend::EncryptedFile => self
                .load_file_data(ACCOUNT_KEY)?
                .map(|data| serde_json::from_slice(&data).map_err(Into::into))
                .transpose(),
        }
    }

    pub fn delete_account(&self) -> Result<(), IpaToolError> {
        match self.backend {
            CredentialBackend::Native => delete_native_data(ACCOUNT_KEY),
            CredentialBackend::EncryptedFile => match std::fs::remove_file(self.account_path()) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(IpaToolError::Io(error)),
            },
        }
    }

    /// Separate Go-compatible keyring item; never included in account output.
    pub(crate) fn load_kbsync(&self) -> Result<Option<Vec<u8>>, IpaToolError> {
        match self.backend {
            CredentialBackend::Native => load_native_data("kbsync-v1"),
            CredentialBackend::EncryptedFile => self.load_file_data("kbsync-v1"),
        }
    }

    pub(crate) fn store_kbsync(&self, data: &[u8]) -> Result<(), IpaToolError> {
        match self.backend {
            CredentialBackend::Native => store_native_data("kbsync-v1", data),
            CredentialBackend::EncryptedFile => self.store_file_data("kbsync-v1", data),
        }
    }

    pub(crate) fn delete_kbsync(&self) -> Result<(), IpaToolError> {
        match self.backend {
            CredentialBackend::Native => delete_native_data("kbsync-v1"),
            CredentialBackend::EncryptedFile => {
                match std::fs::remove_file(self.state_dir.join("kbsync-v1")) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(error.into()),
                }
            }
        }
    }

    fn account_path(&self) -> PathBuf {
        self.state_dir.join(ACCOUNT_KEY)
    }

    fn with_passphrase<T>(
        &self,
        operation: impl FnOnce(&str) -> Result<T, IpaToolError>,
    ) -> Result<T, IpaToolError> {
        let passphrase = self
            .passphrase
            .read()
            .map_err(|_| IpaToolError::AccountStore("passphrase lock was poisoned".into()))?;
        let passphrase = passphrase
            .as_ref()
            .ok_or(IpaToolError::KeyringPassphraseRequired)?;
        operation(passphrase.expose_secret())
    }

    fn load_file_data(&self, key_name: &str) -> Result<Option<Vec<u8>>, IpaToolError> {
        let path = self.state_dir.join(key_name);
        let token = match std::fs::read_to_string(&path) {
            Ok(token) => token,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(IpaToolError::Io(error)),
        };

        self.with_passphrase(|passphrase| {
            let constraints = pbes2_constraints();
            let key = password_key(passphrase);
            let mut jwe = JsonWebEncryption::new();
            jwe.set_algorithm_constraints(&constraints);
            jwe.set_compact_serialization(token.trim())
                .map_err(|error| IpaToolError::InvalidEncryptedAccount(error.to_string()))?;
            if jwe.algorithm() != Some("PBES2-HS256+A128KW")
                || jwe.encryption_method() != Some("A256GCM")
            {
                return Err(IpaToolError::InvalidEncryptedAccount(
                    "expected PBES2-HS256+A128KW with A256GCM".into(),
                ));
            }
            let payload = jwe
                .payload(&key)
                .map_err(|_| IpaToolError::IncorrectKeyringPassphrase)?;
            let item: GoKeyringItem = serde_json::from_slice(payload)
                .map_err(|error| IpaToolError::InvalidEncryptedAccount(error.to_string()))?;
            if item.key != key_name {
                return Err(IpaToolError::AccountStore(
                    "keyring item key does not match".into(),
                ));
            }
            item.decode_data().map(Some)
        })
    }

    fn store_file_data(&self, key_name: &str, data: &[u8]) -> Result<(), IpaToolError> {
        std::fs::create_dir_all(&self.state_dir)?;
        self.with_passphrase(|passphrase| {
            let item = GoKeyringItem::from_data(key_name, data);
            let payload = serde_json::to_vec(&item)?;
            let constraints = pbes2_constraints();
            let key = password_key(passphrase);
            let mut jwe = JsonWebEncryption::new();
            jwe.set_algorithm_constraints(&constraints);
            jwe.set_algorithm(KeyManagementAlgorithm::Pbes2Hs256A128Kw);
            jwe.set_header(
                HeaderParameter::EncryptionMethod,
                ContentEncryptionAlgorithm::Aes256Gcm.name(),
            );
            jwe.set_header_name(
                "created",
                time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|error| IpaToolError::AccountStore(error.to_string()))?,
            );
            jwe.set_payload(payload);
            jwe.encrypt(&key)
                .map_err(|error| IpaToolError::AccountStore(error.to_string()))?;
            let token = jwe
                .compact_serialization()
                .map_err(|error| IpaToolError::AccountStore(error.to_string()))?;
            write_private_file(&self.state_dir.join(key_name), token.as_bytes())
        })
    }
}

fn pbes2_constraints() -> AlgorithmConstraints<KeyManagementAlgorithm> {
    AlgorithmConstraints::new(
        ConstraintType::Permit,
        [KeyManagementAlgorithm::Pbes2Hs256A128Kw],
    )
}

fn password_key(passphrase: &str) -> JsonWebKey {
    JsonWebKey::Oct(OctetSequenceJsonWebKey::from_bytes(passphrase.as_bytes()))
}

fn write_private_file(path: &Path, data: &[u8]) -> Result<(), IpaToolError> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn platform_backend() -> CredentialBackend {
    use dbus_secret_service::{EncryptionType, SecretService};
    if SecretService::connect_with_max_prompt_timeout(EncryptionType::Dh, 0).is_ok() {
        CredentialBackend::Native
    } else {
        CredentialBackend::EncryptedFile
    }
}

#[cfg(target_os = "macos")]
fn platform_backend() -> CredentialBackend {
    CredentialBackend::Native
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_backend() -> CredentialBackend {
    CredentialBackend::EncryptedFile
}

#[cfg(target_os = "macos")]
fn store_native_data(key_name: &str, data: &[u8]) -> Result<(), IpaToolError> {
    let entry = keyring::Entry::new(SERVICE_NAME, key_name)?;
    entry.set_secret(data)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn load_native_data(key_name: &str) -> Result<Option<Vec<u8>>, IpaToolError> {
    let entry = keyring::Entry::new(SERVICE_NAME, key_name)?;
    match entry.get_secret() {
        Ok(data) => Ok(Some(data)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "macos")]
fn delete_native_data(key_name: &str) -> Result<(), IpaToolError> {
    let entry = keyring::Entry::new(SERVICE_NAME, key_name)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn secret_service() -> Result<dbus_secret_service::SecretService, IpaToolError> {
    use dbus_secret_service::{EncryptionType, SecretService};
    SecretService::connect(EncryptionType::Dh)
        .map_err(|error| IpaToolError::AccountStore(error.to_string()))
}

#[cfg(target_os = "linux")]
fn find_collection<'a>(
    service: &'a dbus_secret_service::SecretService,
) -> Result<Option<dbus_secret_service::Collection<'a>>, IpaToolError> {
    let expected_path = format!("/org/freedesktop/secrets/collection/{SERVICE_NAME}");
    let collections = service
        .get_all_collections()
        .map_err(|error| IpaToolError::AccountStore(error.to_string()))?;
    for collection in collections {
        let collection_path = collection.path.to_string();
        if decode_secret_service_path(collection_path.as_bytes()) == expected_path {
            collection
                .ensure_unlocked()
                .map_err(|error| IpaToolError::AccountStore(error.to_string()))?;
            return Ok(Some(collection));
        }
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
fn decode_secret_service_path(path: &[u8]) -> String {
    let mut decoded = Vec::with_capacity(path.len());
    let mut index = 0;
    while index < path.len() {
        if path[index] == b'_' && index + 2 < path.len() {
            let digits = &path[index + 1..index + 3];
            if let Ok(hex) = std::str::from_utf8(digits)
                && let Ok(byte) = u8::from_str_radix(hex, 16)
            {
                decoded.push(byte);
                index += 3;
                continue;
            }
        }
        decoded.push(path[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

#[cfg(target_os = "linux")]
fn store_native_data(key_name: &str, data: &[u8]) -> Result<(), IpaToolError> {
    use std::collections::HashMap;
    let service = secret_service()?;
    let collection = match find_collection(&service)? {
        Some(collection) => collection,
        None => service
            .create_collection(SERVICE_NAME, "")
            .map_err(|error| IpaToolError::AccountStore(error.to_string()))?,
    };
    collection
        .ensure_unlocked()
        .map_err(|error| IpaToolError::AccountStore(error.to_string()))?;
    let item = GoKeyringItem::from_data(key_name, data);
    let secret = serde_json::to_vec(&item)?;
    collection
        .create_item(
            key_name,
            HashMap::from([("profile", key_name)]),
            &secret,
            true,
            "application/json",
        )
        .map_err(|error| IpaToolError::AccountStore(error.to_string()))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn load_native_data(key_name: &str) -> Result<Option<Vec<u8>>, IpaToolError> {
    use std::collections::HashMap;
    let service = secret_service()?;
    let Some(collection) = find_collection(&service)? else {
        return Ok(None);
    };
    let items = collection
        .search_items(HashMap::from([("profile", key_name)]))
        .map_err(|error| IpaToolError::AccountStore(error.to_string()))?;
    let Some(item) = items.into_iter().next() else {
        return Ok(None);
    };
    item.ensure_unlocked()
        .map_err(|error| IpaToolError::AccountStore(error.to_string()))?;
    let secret = item
        .get_secret()
        .map_err(|error| IpaToolError::AccountStore(error.to_string()))?;
    let item: GoKeyringItem = serde_json::from_slice(&secret)?;
    item.decode_data().map(Some)
}

#[cfg(target_os = "linux")]
fn delete_native_data(key_name: &str) -> Result<(), IpaToolError> {
    use std::collections::HashMap;
    let service = secret_service()?;
    let Some(collection) = find_collection(&service)? else {
        return Ok(());
    };
    let items = collection
        .search_items(HashMap::from([("profile", key_name)]))
        .map_err(|error| IpaToolError::AccountStore(error.to_string()))?;
    if let Some(item) = items.into_iter().next() {
        item.ensure_unlocked()
            .map_err(|error| IpaToolError::AccountStore(error.to_string()))?;
        item.delete()
            .map_err(|error| IpaToolError::AccountStore(error.to_string()))?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn store_native_data(_key_name: &str, _data: &[u8]) -> Result<(), IpaToolError> {
    unreachable!()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn load_native_data(key_name: &str) -> Result<Option<Vec<u8>>, IpaToolError> {
    unreachable!()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn delete_native_data(key_name: &str) -> Result<(), IpaToolError> {
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> Account {
        Account {
            email: "person@example.com".into(),
            password_token: "token".into(),
            directory_services_id: "1234".into(),
            name: "Person".into(),
            store_front: "143441-1,29".into(),
            pod: Some("42".into()),
            password: Some("apple-password".into()),
        }
    }

    #[test]
    fn go_account_and_item_field_names_are_preserved() {
        let account_json = serde_json::to_value(account()).unwrap();
        assert_eq!(account_json["directoryServicesIdentifier"], "1234");
        assert!(account_json.get("directory_services_id").is_none());

        let item_json =
            serde_json::to_value(GoKeyringItem::from_account(&account()).unwrap()).unwrap();
        assert_eq!(item_json["Key"], ACCOUNT_KEY);
        assert!(item_json["Data"].is_string());
    }

    #[test]
    fn encrypted_file_round_trip_uses_compact_jwe() {
        let state_dir =
            std::env::temp_dir().join(format!("ipatool-rs-credential-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state_dir);
        std::fs::create_dir_all(&state_dir).unwrap();
        let store = CredentialStore {
            state_dir: state_dir.clone(),
            backend: CredentialBackend::EncryptedFile,
            passphrase: RwLock::new(Some(SecretString::from("correct horse"))),
        };
        store.store_account(&account()).unwrap();
        let token = std::fs::read_to_string(state_dir.join("account")).unwrap();
        assert_eq!(token.split('.').count(), 5);
        assert_eq!(
            store.load_account().unwrap().unwrap().email,
            "person@example.com"
        );
        let cache = br#"{"dsid":1234,"guid":"AABBCCDDEEFF","data":"YmxvYg=="}"#;
        store.store_kbsync(cache).unwrap();
        assert_eq!(store.load_kbsync().unwrap().unwrap(), cache);
        let encrypted = std::fs::read_to_string(state_dir.join("kbsync-v1")).unwrap();
        let constraints = pbes2_constraints();
        let key = password_key("correct horse");
        let mut jwe = JsonWebEncryption::new();
        jwe.set_algorithm_constraints(&constraints);
        jwe.set_compact_serialization(&encrypted).unwrap();
        let item: GoKeyringItem = serde_json::from_slice(jwe.payload(&key).unwrap()).unwrap();
        assert_eq!(item.key, "kbsync-v1");
        assert_eq!(item.decode_data().unwrap(), cache);
        assert_eq!(
            store.load_account().unwrap().unwrap().email,
            "person@example.com"
        );
        store.delete_kbsync().unwrap();
        assert!(store.load_kbsync().unwrap().is_none());
        assert!(store.load_account().unwrap().is_some());
        std::fs::remove_dir_all(state_dir).unwrap();
    }

    #[test]
    fn decrypts_a_jose2go_encrypted_keyring_item() {
        const GO_TOKEN: &str = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjo4MTkyLCJwMnMiOiJvdldzbUxaWUJ6WUNlb1VpIn0.zWWP-pnIiET9Vb1q4iQGkMFS4Lr4UoYSLG6T1eEII-K5_zHq7yzN8A.tarEVV9bUHwLWwy_.ZcauiBw5HBILSVc1jGL0c_biGpOTIpEEDCLaquJAoW8T84wiAmm4RywJwP6FbPiFKMJnfDd1U3ZAqelj2lp0EPCXFl-oy96hXWoTXmJOk_3qCvYBCX_UpR4M3KdolEbOrzyaIatJQwb9EYXcJQ8NkGgeSaWuiCMz4l8P306Ac6mlUqSkgn0wgEnURUUHF99lmFB_DUppOYIwvbbVqQ.B_B54mpsP6_ddH6-h-CsZg";
        const GO_PAYLOAD: &[u8] = br#"{"Key":"account","Data":"ZXhhbXBsZQ==","Label":"ipatool-auth.service","Description":"","KeychainNotTrustApplication":false,"KeychainNotSynchronizable":false}"#;

        let constraints = pbes2_constraints();
        let key = password_key("correct horse");
        let mut jwe = JsonWebEncryption::new();
        jwe.set_algorithm_constraints(&constraints);
        jwe.set_compact_serialization(GO_TOKEN).unwrap();
        assert_eq!(jwe.payload(&key).unwrap(), GO_PAYLOAD);
    }
}
