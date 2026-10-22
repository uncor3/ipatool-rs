use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    #[serde(rename = "iphone")]
    IPhone,
    #[serde(rename = "ipad")]
    IPad,
    #[serde(rename = "appletv")]
    AppleTV,
    #[serde(rename = "watchos")]
    WatchOS,
}

impl Platform {
    pub fn search_entity(&self) -> &'static str {
        match self {
            Self::IPhone => "software",
            Self::IPad => "iPadSoftware",
            Self::AppleTV => "tvSoftware",
            Self::WatchOS => "software,watchSoftware",
        }
    }

    pub fn lookup_entity(&self) -> &'static str {
        match self {
            Self::WatchOS => "watchSoftware",
            _ => self.search_entity(),
        }
    }

    pub fn bundle_platform_name(&self) -> Option<&'static str> {
        match self {
            Self::AppleTV => Some("AppleTVOS"),
            Self::WatchOS => Some("WatchOS"),
            _ => None,
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IPhone => write!(f, "iphone"),
            Self::IPad => write!(f, "ipad"),
            Self::AppleTV => write!(f, "appletv"),
            Self::WatchOS => write!(f, "watchos"),
        }
    }
}

impl std::str::FromStr for Platform {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "iphone" | "ios" => Ok(Self::IPhone),
            "ipad" | "ipados" => Ok(Self::IPad),
            "appletv" | "apple_tv" | "apple-tv" | "tvos" => Ok(Self::AppleTV),
            "watch" | "watchos" | "applewatch" | "apple-watch" => Ok(Self::WatchOS),
            other => Err(format!("unknown platform: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_aliases_use_watch_lookup_and_shared_search() {
        for alias in ["watch", "watchos", "applewatch", "apple-watch"] {
            assert_eq!(alias.parse::<Platform>().unwrap(), Platform::WatchOS);
        }
        assert_eq!(Platform::WatchOS.lookup_entity(), "watchSoftware");
        assert_eq!(Platform::WatchOS.search_entity(), "software,watchSoftware");
        assert_eq!(Platform::WatchOS.bundle_platform_name(), Some("WatchOS"));
    }
}
