use std::io::Read;
use std::path::Path;

use crate::error::IpaToolError;
use crate::model::Platform;

/// Upstream accepts pre-platform-declaration iOS packages, but never an
/// explicit empty declaration or a package for a different Apple platform.
pub fn validate_package(path: &Path, platform: Platform) -> Result<(), IpaToolError> {
    let expected = match platform {
        Platform::IPhone | Platform::IPad => "iPhoneOS",
        Platform::AppleTV => "AppleTVOS",
        Platform::WatchOS => "WatchOS",
    };
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let parts = entry.name().split('/').collect::<Vec<_>>();
        if parts.len() != 3
            || parts[0] != "Payload"
            || !parts[1].ends_with(".app")
            || parts[2] != "Info.plist"
        {
            continue;
        }
        let mut body = Vec::new();
        entry
            .by_ref()
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut body)?;
        if body.len() > 8 * 1024 * 1024 {
            return Err(IpaToolError::Unexpected(
                "package Info.plist exceeds 8 MiB".into(),
            ));
        }
        let info: plist::Dictionary = plist::from_bytes(&body)?;
        if declares_platform(&info, expected) {
            return Ok(());
        }
    }
    Err(IpaToolError::Unexpected(format!(
        "downloaded package does not declare {expected} support"
    )))
}

fn declares_platform(info: &plist::Dictionary, expected: &str) -> bool {
    match info.get("CFBundleSupportedPlatforms") {
        None => expected == "iPhoneOS",
        Some(plist::Value::Array(platforms)) => platforms
            .iter()
            .any(|platform| platform.as_string() == Some(expected)),
        Some(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_missing_declarations_qualify_as_legacy_ios() {
        let mut info = plist::Dictionary::new();
        assert!(declares_platform(&info, "iPhoneOS"));
        assert!(!declares_platform(&info, "AppleTVOS"));
        info.insert(
            "CFBundleSupportedPlatforms".into(),
            plist::Value::Array(vec![]),
        );
        assert!(!declares_platform(&info, "iPhoneOS"));
        info.insert(
            "CFBundleSupportedPlatforms".into(),
            plist::Value::Array(vec![plist::Value::String("AppleTVOS".into())]),
        );
        assert!(!declares_platform(&info, "iPhoneOS"));
        assert!(declares_platform(&info, "AppleTVOS"));
    }
}
