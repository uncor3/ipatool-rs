use crate::error::{IpaToolError, Result};
use owo_colors::OwoColorize;
use owo_colors::colors::*;
use regex::Regex;

pub fn guid_from_mac() -> Result<String> {
    let add = mac_address::get_mac_address()?;

    match add {
        Some(a) => {
            let s = a.to_string().replace(':', "").to_uppercase();
            if !s.is_empty() {
                return Ok(s);
            } else {
                return Err(IpaToolError::EmptyMacAddress);
            }
        }
        None => return Err(IpaToolError::EmptyMacAddress),
    }
}

fn re_document() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<Document\b[^>]*>(.*)</Document>").unwrap())
}

fn re_plist() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<plist\b[^>]*>.*?</plist>").unwrap())
}

fn re_dict() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<dict\b[^>]*>.*</dict>").unwrap())
}

pub fn normalize_plist_body(body: &[u8]) -> Vec<u8> {
    let mut s = String::from_utf8_lossy(body).trim().to_string();
    if s.is_empty() {
        return vec![];
    }

    if let Some(caps) = re_document().captures(&s) {
        if let Some(inner) = caps.get(1) {
            let t = inner.as_str().trim();
            if !t.is_empty() {
                s = t.to_string();
            }
        }
    }

    if let Some(m) = re_plist().find(&s) {
        s = m.as_str().trim().to_string();
    }

    if let Some(m) = re_dict().find(&s) {
        return m.as_str().trim().as_bytes().to_vec();
    }

    if s.contains("<key>") {
        return format!("<dict>{}</dict>", s).into_bytes();
    }

    s.into_bytes()
}

pub fn with_success_style(text: String) -> String {
    format!("[SUCCESS]: {}", text.fg::<Black>().bg::<Green>())
}

pub fn with_error_style(text: String) -> String {
    format!("[ERROR]: {}", text.fg::<White>().bg::<Red>())
}
