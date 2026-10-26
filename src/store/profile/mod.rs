//! Immutable upstream profile; no Go installation or runtime profile generation.
pub mod format;

use crate::{error::IpaToolError, sap::hex_digest};
use std::{
    collections::HashSet,
    io::Read,
    sync::{Arc, OnceLock},
};

pub const FRAMEWORK_UUID: &str = "5DFC37A5-4689-3F9D-9655-D4774E1D8D08";
pub const PLUGIN_UUID: &str = "B8C07F94-4868-3CD7-A59A-F01E8C24C1B7";

pub struct Data {
    pub metadata: format::Profile,
    pub pages: Vec<u8>,
    pub plugin: Vec<u8>,
}

struct Artifact {
    name: &'static str,
    compressed: &'static [u8],
    size: usize,
    limit: usize,
    sha256: &'static str,
}

const METADATA: Artifact = Artifact {
    name: "Store metadata",
    compressed: include_bytes!("data/metadata.zst"),
    size: 4_807_917,
    limit: 128 << 20,
    sha256: "5e92717743272aa84343bd25f6bab6401155f88ade51b704ec535d3e6b5bd421",
};
const PAGES: Artifact = Artifact {
    name: "Store pages",
    compressed: include_bytes!("data/pages.zst"),
    size: 20_893_696,
    limit: 256 << 20,
    sha256: "4fd8cf193ca6e71d52a2d6e68d9ca76907332ff33dade332351c97efe5f0caed",
};
const PLUGIN: Artifact = Artifact {
    name: "Store plugin",
    compressed: include_bytes!("data/plugin.zst"),
    size: 138_088,
    limit: 64 << 20,
    sha256: "e33fff05a6e6593dd91e33fd103b5d3068b62a787c680df33b859f19b3acc4ea",
};

fn failure(message: impl Into<String>) -> IpaToolError {
    IpaToolError::Sap(message.into())
}

fn decode(artifact: &Artifact) -> Result<Vec<u8>, IpaToolError> {
    if artifact.size == 0 || artifact.size > artifact.limit {
        return Err(failure(format!("invalid compiled {} size", artifact.name)));
    }
    let decoder = ruzstd::decoding::StreamingDecoder::new_with_max_window_size(
        artifact.compressed,
        artifact.limit as u64,
    )
    .map_err(|_| failure(format!("cannot open compiled {}", artifact.name)))?;
    let mut bytes = Vec::with_capacity(artifact.size + 1);
    decoder
        .take(artifact.size as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure(format!("cannot decode compiled {}", artifact.name)))?;
    if bytes.len() != artifact.size || hex_digest(&bytes) != artifact.sha256 {
        return Err(failure(format!(
            "compiled {} failed integrity verification",
            artifact.name
        )));
    }
    Ok(bytes)
}

fn validate(metadata: &format::Profile, pages: &[u8], plugin: &[u8]) -> Result<(), IpaToolError> {
    if metadata.uuid != FRAMEWORK_UUID || metadata.plugin_uuid != PLUGIN_UUID {
        return Err(failure("Store profile uses unexpected Apple images"));
    }
    if metadata.pages.is_empty()
        || !pages.len().is_multiple_of(4096)
        || metadata.pages.len() != pages.len() / 4096
        || plugin.is_empty()
    {
        return Err(failure("incomplete compiled Store profile"));
    }
    let mut addresses = HashSet::with_capacity(metadata.pages.len());
    for (i, page) in metadata.pages.iter().enumerate() {
        if page.address % 4096 != 0
            || page.offset != i as u64 * 4096
            || !addresses.insert(page.address)
        {
            return Err(failure("invalid Store page index"));
        }
    }
    Ok(())
}

static DATA: OnceLock<Result<Arc<Data>, String>> = OnceLock::new();

/// Decode and verify once per process. Call on a blocking worker on first use.
pub fn load() -> Result<Arc<Data>, IpaToolError> {
    DATA.get_or_init(|| {
        let load = || -> Result<Data, IpaToolError> {
            let metadata: format::Profile = serde_json::from_slice(&decode(&METADATA)?)
                .map_err(|error| failure(format!("invalid Store metadata: {error}")))?;
            let pages = decode(&PAGES)?;
            let plugin = decode(&PLUGIN)?;
            validate(&metadata, &pages, &plugin)?;
            Ok(Data {
                metadata,
                pages,
                plugin,
            })
        };
        load().map(Arc::new).map_err(|error| error.to_string())
    })
    .as_ref()
    .map(Arc::clone)
    .map_err(|message| failure(message.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_upstream_profile_decodes_and_is_shared() {
        let first = load().unwrap();
        assert!(Arc::ptr_eq(&first, &load().unwrap()));
        assert_eq!(first.pages.len(), PAGES.size);
        assert!(!first.metadata.classes.is_empty());
        assert!(!first.metadata.bridges.is_empty());
        assert_eq!(&first.plugin[..4], &[0xcf, 0xfa, 0xed, 0xfe]);
    }
    #[test]
    fn rejects_wrong_size_and_digest() {
        assert!(
            decode(&Artifact {
                size: METADATA.size - 1,
                ..METADATA
            })
            .is_err()
        );
        assert!(
            decode(&Artifact {
                sha256: "00",
                ..METADATA
            })
            .is_err()
        );
    }
    #[test]
    fn rejects_duplicate_or_unaligned_guest_pages() {
        let mut metadata: format::Profile =
            serde_json::from_slice(&decode(&METADATA).unwrap()).unwrap();
        metadata.pages[1].address = metadata.pages[0].address;
        assert!(validate(&metadata, &vec![0; PAGES.size], &[1]).is_err());
        metadata.pages[1].address = 1;
        assert!(validate(&metadata, &vec![0; PAGES.size], &[1]).is_err());
    }
}
