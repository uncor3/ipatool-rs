use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    #[serde(rename = "trackId")]
    pub id: i64,
    #[serde(rename = "bundleId")]
    pub bundle_id: String,
    #[serde(rename = "trackName")]
    pub name: String,
    pub version: Option<String>,
    #[serde(default)]
    pub price: f64,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct SearchResponse {
    #[serde(rename = "resultCount")]
    pub count: u32,
    pub results: Vec<App>,
}

impl App {
    pub(crate) fn supports_watchos(&self) -> bool {
        self.extra
            .get("supportedDevices")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|devices| {
                devices
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .any(|device| device.starts_with("Watch"))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_search_requires_a_watch_device_in_metadata() {
        let mut app: App = serde_json::from_value(serde_json::json!({
            "trackId": 42, "bundleId": "com.test.app", "trackName": "App",
            "supportedDevices": ["iPhone15-iPhone15", "iPadAir-iPadAir"]
        }))
        .unwrap();
        assert!(!app.supports_watchos());
        app.extra.insert(
            "supportedDevices".into(),
            serde_json::json!(["Watch7-Watch7"]),
        );
        assert!(app.supports_watchos());
    }
}
