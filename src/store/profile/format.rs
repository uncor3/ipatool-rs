//! Go's committed profile JSON schema; addresses remain guest virtual addresses.
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Method {
    pub selector: String,
    pub address: u64,
    pub class_method: bool,
    pub types: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Class {
    pub meta_address: u64,
    pub name: String,
    pub address: u64,
    #[serde(rename = "Super")]
    pub superclass: String,
    pub size: u64,
    #[serde(default, deserialize_with = "null_default")]
    pub ivars: HashMap<String, u64>,
    #[serde(default, deserialize_with = "null_default")]
    pub methods: Vec<Method>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Call {
    pub address: u64,
    pub symbol: String,
    pub selector: String,
    pub selector_address: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Page {
    pub address: u64,
    pub offset: u64,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Constant {
    pub is_boolean: bool,
    pub boolean: bool,
    pub kind: String,
    pub text: String,
    pub number: i64,
    #[serde(deserialize_with = "null_default")]
    pub entries: HashMap<String, u64>,
    #[serde(deserialize_with = "null_default")]
    pub items: Vec<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DictionaryLayout {
    pub metadata: u64,
    pub key_stride: u64,
    pub value_stride: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MetadataPatch {
    pub address: u64,
    #[serde(deserialize_with = "base64_bytes")]
    pub data: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Profile {
    pub bridges: HashMap<String, u64>,
    #[serde(rename = "ObjCMetadata")]
    pub objc_metadata: HashMap<String, u64>,
    pub swift_singletons: HashMap<String, u64>,
    #[serde(default, deserialize_with = "null_default")]
    pub metadata_patches: Vec<MetadataPatch>,
    pub swift_foreign: HashMap<String, u64>,
    #[serde(rename = "PluginUUID")]
    pub plugin_uuid: String,
    pub swift_dictionaries: HashMap<String, DictionaryLayout>,
    pub swift_globals: HashMap<String, u64>,
    pub swift_types: HashMap<String, u64>,
    pub swift_witnesses: HashMap<String, u64>,
    pub swift_accessors: HashMap<String, u64>,
    pub symbols: HashMap<String, u64>,
    pub features: HashMap<String, bool>,
    pub constants: HashMap<String, Constant>,
    #[serde(rename = "UUID")]
    pub uuid: String,
    pub classes: Vec<Class>,
    pub calls: Vec<Call>,
    pub strings: HashMap<String, String>,
    pub pages: Vec<Page>,
}

fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn base64_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use base64::Engine;
    let value = Option::<String>::deserialize(deserializer)?;
    base64::engine::general_purpose::STANDARD
        .decode(value.unwrap_or_default())
        .map_err(serde::de::Error::custom)
}

pub fn witness_key(descriptor: u64, metadata: u64) -> String {
    format!("{descriptor}:{metadata}")
}
