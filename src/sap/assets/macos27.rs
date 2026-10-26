//! Exact framework profile used by Go ipatool's macOS 27 SAP runtime.
use crate::{error::ClientError, sap::hex_digest};
use fs2::FileExt;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
enum AssetError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Client(#[from] ClientError),
}
impl From<AssetError> for ClientError {
    fn from(error: AssetError) -> Self {
        match error {
            AssetError::Client(error) => error,
            AssetError::Io(error) => ClientError::Sap(format!("Apple asset extraction: {error}")),
        }
    }
}

pub const CACHE_DIRECTORY: &str = "apple-assets-macos-27-26A434-arm64-v1";
pub const VERSION: &str = "27.0.1";
pub const BUILD: &str = "26A434";

pub struct Bundle {
    pub apple_media_services: Vec<u8>,
    pub commerce: Vec<u8>,
    pub core_fp: Vec<u8>,
    pub core_fp_icxs: Vec<u8>,
}

const FILES: &[(&str, usize, &str)] = &[
    (
        "AppleMediaServices",
        14_813_888,
        "95f4558aa2c0ccd9f96ed479e336b630b46bf4b4e0baabc1c1ac8c7d55e21ab4",
    ),
    (
        "commerce",
        8_092_640,
        "76de40a4a32f691947cb926ce3b128d2fc446f7cac9755f831c406cf5a316ac9",
    ),
    (
        "CoreFP",
        94_842_464,
        "2c30fa2b5f695fd66c0360dce72f54757d03ddb7107549715c12cb359a003b46",
    ),
    (
        "CoreFP.icxs",
        7_365_344,
        "cb8f55330ec567da3e692dab5f5388bed0312dd9093340477c5759078cc2aa7b",
    ),
];

pub fn cache_directory() -> Result<PathBuf, ClientError> {
    dirs::cache_dir()
        .map(|root| root.join("ipatool/sap").join(CACHE_DIRECTORY))
        .ok_or_else(|| ClientError::Sap("cannot locate the macOS 27 asset cache".into()))
}

pub fn load_verified(directory: &Path) -> Result<Bundle, ClientError> {
    let mut contents = Vec::new();
    for &(name, size, digest) in FILES {
        let path = directory.join(name);
        let metadata = std::fs::metadata(&path).map_err(|_| {
            ClientError::Sap(format!(
                "macOS {VERSION} ({BUILD}) asset {name} is unavailable"
            ))
        })?;
        if metadata.len() != size as u64 {
            return Err(ClientError::Sap(format!(
                "macOS 27 asset {name} has unexpected size"
            )));
        }
        let bytes = std::fs::read(path)
            .map_err(|_| ClientError::Sap(format!("cannot read macOS 27 asset {name}")))?;
        if bytes.len() != size || hex_digest(&bytes) != digest {
            return Err(ClientError::Sap(format!(
                "macOS 27 asset {name} failed integrity verification"
            )));
        }
        contents.push(bytes);
    }
    let mut contents = contents.into_iter();
    Ok(Bundle {
        apple_media_services: contents.next().unwrap(),
        commerce: contents.next().unwrap(),
        core_fp: contents.next().unwrap(),
        core_fp_icxs: contents.next().unwrap(),
    })
}

/// Resolve the shared Go-compatible cache, extracting missing assets on a worker.
pub async fn load() -> Result<Bundle, ClientError> {
    tokio::task::spawn_blocking(|| load_at(&cache_directory()?))
        .await
        .map_err(|error| ClientError::Sap(format!("Apple asset worker failed: {error}")))?
        .map_err(Into::into)
}

fn load_at(directory: &Path) -> Result<Bundle, AssetError> {
    if let Ok(bundle) = load_verified(directory) {
        return Ok(bundle);
    }
    private_directory(directory)?;
    let lock_path = directory.join(".extract.lock");
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(lock_path)?;
    FileExt::lock_exclusive(&lock)?;
    if let Ok(bundle) = load_verified(directory) {
        return Ok(bundle);
    }
    tracing::info!(
        version = VERSION,
        build = BUILD,
        "extracting pinned Apple frameworks from restore image"
    );
    let bundle = extract()?;
    install(directory, &bundle)?;
    Ok(bundle)
}

fn private_directory(directory: &Path) -> Result<(), AssetError> {
    std::fs::create_dir_all(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn validate(name: &str, data: &[u8]) -> Result<(), ClientError> {
    let (_, size, digest) = FILES
        .iter()
        .find(|(n, _, _)| *n == name)
        .ok_or_else(|| ClientError::Sap("unknown Apple asset".into()))?;
    if data.len() != *size || hex_digest(data) != *digest {
        return Err(ClientError::Sap(format!(
            "extracted macOS 27 asset {name} failed integrity verification"
        )));
    }
    Ok(())
}

fn install(directory: &Path, bundle: &Bundle) -> Result<(), AssetError> {
    let contents = [
        &bundle.apple_media_services,
        &bundle.commerce,
        &bundle.core_fp,
        &bundle.core_fp_icxs,
    ];
    for ((name, _, _), data) in FILES.iter().zip(contents) {
        validate(name, data)?;
    }
    for ((name, _, _), data) in FILES.iter().zip(contents) {
        let mut random = [0; 8];
        getrandom::fill(&mut random)
            .map_err(|_| ClientError::Sap("cannot generate asset temporary filename".into()))?;
        let temporary = directory.join(format!(".{name}.{:016x}.tmp", u64::from_le_bytes(random)));
        let write = || -> Result<(), AssetError> {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(data)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temporary, directory.join(name))?;
            Ok(())
        };
        let result = write();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result?;
    }
    #[cfg(unix)]
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
}

fn extract() -> Result<Bundle, AssetError> {
    use super::{aea, apfs, dyld, remote};
    let source = remote::RemoteFile::open_restore_image()?;
    let (filesystem, system_os) = remote::restore_members(&source)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(ClientError::from)?;
    let image = aea::Reader::open(filesystem, 11_274_289_152, &client)?;
    if image.len() != 14_189_330_432 {
        return Err(ClientError::Sap("unexpected macOS filesystem size".into()).into());
    }
    let volume = apfs::Volume::open(image, 14_189_330_432)?;
    let paths = [
        (
            "commerce",
            "/System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Resources/commerce",
        ),
        (
            "CoreFP",
            "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP",
        ),
        (
            "CoreFP.icxs",
            "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/Resources/CoreFP.icxs",
        ),
    ];
    let mut files = Vec::new();
    for (name, path) in paths {
        let file = volume.open_file(path)?;
        let expected = FILES.iter().find(|(n, _, _)| *n == name).unwrap().1;
        if file.len() != expected as u64 {
            return Err(ClientError::Sap(format!("extracted {name} has unexpected size")).into());
        }
        let mut bytes = vec![0; expected];
        file.read_exact_at(0, &mut bytes)?;
        validate(name, &bytes)?;
        files.push(bytes);
        tracing::debug!(asset = name, "verified extracted Apple framework");
    }
    drop(volume);
    let image = aea::Reader::open(system_os, 2_415_919_104, &client)?;
    if image.len() != 2_879_389_696 {
        return Err(ClientError::Sap("unexpected SystemOS image size".into()).into());
    }
    let volume = apfs::Volume::open(image, 2_879_389_696)?;
    let cache = dyld::Cache::open(|suffix| {
        volume.open_file(&format!(
            "/System/Library/dyld/dyld_shared_cache_arm64e{suffix}"
        ))
    })?;
    let apple_media_services = cache.export_image("/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices")?;
    validate("AppleMediaServices", &apple_media_services)?;
    let mut files = files.into_iter();
    Ok(Bundle {
        apple_media_services,
        commerce: files.next().unwrap(),
        core_fp: files.next().unwrap(),
        core_fp_icxs: files.next().unwrap(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_assets_never_replace_cache_files() {
        let directory =
            std::env::temp_dir().join(format!("ipatool-invalid-assets-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("AppleMediaServices");
        std::fs::write(&path, b"existing").unwrap();
        let bundle = Bundle {
            apple_media_services: vec![],
            commerce: vec![],
            core_fp: vec![],
            core_fp_icxs: vec![],
        };
        assert!(install(&directory, &bundle).is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"existing");
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    #[ignore = "extracts pinned public IPSW ranges and verifies exact Go framework hashes"]
    fn live_extract_matches_go_assets() {
        let bundle = extract().unwrap();
        assert_eq!(bundle.apple_media_services.len(), FILES[0].1);
    }
    #[test]
    #[ignore = "requires local verified macOS 27 assets; writes only a temporary cache"]
    fn live_cache_install_round_trip() {
        let bundle = load_verified(&cache_directory().unwrap()).unwrap();
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "ipatool-asset-install-{:016x}",
            u64::from_le_bytes(random)
        ));
        private_directory(&directory).unwrap();
        install(&directory, &bundle).unwrap();
        let installed = load_at(&directory).unwrap();
        assert_eq!(hex_digest(&installed.apple_media_services), FILES[0].2);
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 4);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for (name, _, _) in FILES {
                assert_eq!(
                    std::fs::metadata(directory.join(name))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
