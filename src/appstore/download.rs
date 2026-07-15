use std::{
    collections::HashSet,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    appstore::types::{Account, App, DownloadItem, DownloadResult},
    constants::{
        FAILURE_TYPE_LICENSE_NOT_FOUND, FAILURE_TYPE_PASSWORD_TOKEN_EXPIRED,
        PRIVATE_APPSTORE_DOMAIN, PRIVATE_DOWNLOAD_PATH,
    },
    error::{IpaToolError, Result},
    http::client::Http,
};
use tokio::io::AsyncWriteExt;

fn download_url(pod: Option<&str>, guid: &str) -> String {
    let pod_prefix = match pod {
        Some(p) if !p.is_empty() => format!("p{}-", p),
        _ => String::new(),
    };
    format!(
        "https://{}{}{}?guid={}",
        pod_prefix, PRIVATE_APPSTORE_DOMAIN, PRIVATE_DOWNLOAD_PATH, guid
    )
}

fn download_payload(guid: &str, app_id: u64, external_version_id: Option<&str>) -> Result<Vec<u8>> {
    let mut dict = plist::Dictionary::new();
    dict.insert("creditDisplay".into(), plist::Value::String(String::new()));
    dict.insert("guid".into(), plist::Value::String(guid.to_string()));
    dict.insert("salableAdamId".into(), plist::Value::Integer(app_id.into()));
    if let Some(v) = external_version_id.filter(|s| !s.is_empty()) {
        dict.insert(
            "externalVersionId".into(),
            plist::Value::String(v.to_string()),
        );
    }

    let mut out = Vec::new();
    plist::to_writer_xml(&mut out, &plist::Value::Dictionary(dict))?;
    Ok(out)
}

fn item_version(item: &DownloadItem) -> String {
    let Some(meta) = &item.metadata else {
        return "unknown".into();
    };
    let Some(v) = meta.get("bundleShortVersionString") else {
        return "unknown".into();
    };
    match v {
        plist::Value::String(s) if !s.is_empty() => s.clone(),
        plist::Value::Integer(i) => i.to_string(),
        plist::Value::Real(f) => f.to_string(),
        plist::Value::Boolean(b) => b.to_string(),
        _ => "unknown".into(),
    }
}

fn file_name(app: &App, version: &str) -> String {
    let mut parts = Vec::new();
    if let Some(bundle_id) = app.bundle_id.as_ref().filter(|s| !s.is_empty()) {
        parts.push(bundle_id.clone());
    }
    if app.id != 0 {
        parts.push(app.id.to_string());
    }
    if !version.is_empty() {
        parts.push(version.to_string());
    }
    format!("{}.ipa", parts.join("_"))
}

fn resolve_destination_path(app: &App, version: &str, path: Option<&str>) -> Result<PathBuf> {
    let file = file_name(app, version);
    match path {
        None | Some("") => Ok(std::env::current_dir()?.join(file)),
        Some(p) => {
            let candidate = PathBuf::from(p);
            if candidate.exists() && candidate.is_dir() {
                Ok(candidate.join(file))
            } else {
                Ok(candidate)
            }
        }
    }
}

async fn download_file<F>(src: &str, dst: &Path, progress: &mut F) -> Result<()>
where
    F: FnMut(u64, Option<u64>) + Send,
{
    let client = reqwest::Client::new();
    let mut res = client.get(src).send().await?;
    if !res.status().is_success() {
        return Err(IpaToolError::HttpStatus {
            status: res.status(),
        });
    }

    let total = res.content_length();
    let mut downloaded = 0u64;
    progress(downloaded, total);

    let mut f = tokio::fs::File::create(dst).await?;
    while let Some(chunk) = res.chunk().await? {
        f.write_all(&chunk).await?;
        downloaded += chunk.len() as u64;
        progress(downloaded, total);
    }
    f.flush().await?;
    Ok(())
}

#[derive(Debug, Clone, serde::Deserialize)]
struct PackageManifest {
    #[serde(rename = "SinfPaths")]
    sinf_paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct PackageInfo {
    #[serde(rename = "CFBundleExecutable")]
    bundle_executable: Option<String>,
}

fn extract_bundle_name(info_plist_path: &str) -> Option<String> {
    let relative = info_plist_path
        .strip_prefix("Payload/")?
        .strip_suffix(".app/Info.plist")?;
    if relative.is_empty() || relative.contains('/') {
        return None;
    }
    Some(relative.to_string())
}

fn zip_opts() -> zip::write::SimpleFileOptions {
    zip::write::SimpleFileOptions::default()
}

fn read_plist_entry<T>(archive: &mut zip::ZipArchive<File>, name: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let mut entry = archive.by_name(name)?;
    let mut data = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut data)?;
    Ok(plist::from_bytes(&data)?)
}

fn read_package_metadata(
    archive: &mut zip::ZipArchive<File>,
) -> Result<(String, PackageInfo, Option<PackageManifest>)> {
    let info_path = archive
        .file_names()
        .find(|name| extract_bundle_name(name).is_some())
        .map(str::to_owned)
        .ok_or_else(|| IpaToolError::MissingData {
            thing: "main app Info.plist".into(),
        })?;
    let bundle_name = extract_bundle_name(&info_path).expect("validated Info.plist path");
    let info = read_plist_entry(archive, &info_path)?;

    let manifest_path = format!("Payload/{bundle_name}.app/SC_Info/Manifest.plist");
    let has_manifest = archive.file_names().any(|name| name == manifest_path);
    let manifest = if has_manifest {
        Some(read_plist_entry(archive, &manifest_path)?)
    } else {
        None
    };

    Ok((bundle_name, info, manifest))
}

fn resolve_sinf_targets(
    item: &DownloadItem,
    bundle_name: &str,
    info: &PackageInfo,
    manifest: Option<&PackageManifest>,
) -> Result<Vec<String>> {
    let sinfs = item
        .sinfs
        .as_ref()
        .filter(|sinfs| !sinfs.is_empty())
        .ok_or_else(|| IpaToolError::MissingData {
            thing: "SINF data".into(),
        })?;
    if sinfs.iter().any(|sinf| sinf.data.is_none()) {
        return Err(IpaToolError::MissingData {
            thing: "SINF data".into(),
        });
    }

    if let Some(manifest) = manifest {
        let paths = manifest.sinf_paths.as_deref().unwrap_or_default();
        if sinfs.len() != paths.len() {
            return Err(IpaToolError::SinfCountMismatch {
                sinfs: sinfs.len(),
                targets: paths.len(),
            });
        }
        return Ok(paths
            .iter()
            .map(|path| format!("Payload/{bundle_name}.app/{path}"))
            .collect());
    }

    if sinfs.len() != 1 {
        return Err(IpaToolError::SinfCountMismatch {
            sinfs: sinfs.len(),
            targets: 1,
        });
    }
    let executable = info
        .bundle_executable
        .as_deref()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| IpaToolError::MissingData {
            thing: "CFBundleExecutable".into(),
        })?;
    Ok(vec![format!(
        "Payload/{bundle_name}.app/SC_Info/{executable}.sinf"
    )])
}

fn write_sinfs(
    dst_zip: &mut zip::ZipWriter<File>,
    item: &DownloadItem,
    targets: &[String],
) -> Result<()> {
    let sinfs = item
        .sinfs
        .as_deref()
        .ok_or_else(|| IpaToolError::MissingData {
            thing: "SINF data".into(),
        })?;
    for (sinf, target) in sinfs.iter().zip(targets) {
        let data = sinf
            .data
            .as_ref()
            .ok_or_else(|| IpaToolError::MissingData {
                thing: "SINF data".into(),
            })?;
        dst_zip.start_file(target, zip_opts())?;
        dst_zip.write_all(data.as_ref())?;
    }
    Ok(())
}

fn write_patched_archive(item: &DownloadItem, acc: &Account, src: &Path, dst: &Path) -> Result<()> {
    let src_file = File::open(src)?;
    let mut src_zip = zip::ZipArchive::new(src_file)?;

    let (bundle_name, info, manifest) = read_package_metadata(&mut src_zip)?;
    let sinf_targets = resolve_sinf_targets(item, &bundle_name, &info, manifest.as_ref())?;
    let mut replaced_entries = sinf_targets.iter().cloned().collect::<HashSet<_>>();
    replaced_entries.insert("iTunesMetadata.plist".into());

    let dst_file = File::create(dst)?;
    let mut dst_zip = zip::ZipWriter::new(dst_file);

    for i in 0..src_zip.len() {
        let entry = src_zip.by_index(i)?;
        let name = entry.name().to_string();
        if replaced_entries.contains(&name) {
            continue;
        }
        dst_zip.raw_copy_file(entry)?;
    }

    let mut metadata = plist::Dictionary::new();
    if let Some(m) = &item.metadata {
        for (k, v) in m {
            metadata.insert(k.clone(), v.clone());
        }
    }
    metadata.insert("apple-id".into(), plist::Value::String(acc.email.clone()));
    metadata.insert("userName".into(), plist::Value::String(acc.email.clone()));

    dst_zip.start_file("iTunesMetadata.plist", zip_opts())?;
    plist::to_writer_binary(&mut dst_zip, &plist::Value::Dictionary(metadata))?;

    write_sinfs(&mut dst_zip, item, &sinf_targets)?;

    let output = dst_zip.finish()?;
    output.sync_all()?;
    Ok(())
}

fn apply_patches(item: &DownloadItem, acc: &Account, src: &Path, dst: &Path) -> Result<()> {
    let patched = PathBuf::from(format!("{}.patch.tmp", dst.display()));
    let result = write_patched_archive(item, acc, src, &patched);
    if let Err(error) = result {
        let _ = std::fs::remove_file(&patched);
        return Err(error);
    }

    if let Err(error) = std::fs::rename(&patched, dst) {
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            let _ = std::fs::remove_file(&patched);
            return Err(error.into());
        }
        std::fs::remove_file(dst)?;
        std::fs::rename(&patched, dst)?;
    }
    Ok(())
}

pub async fn download_ipa<F>(
    http: &Http,
    guid: &str,
    acc: &Account,
    app: &App,
    output_path: Option<&str>,
    external_version_id: Option<&str>,
    progress: &mut F,
) -> Result<String>
where
    F: FnMut(u64, Option<u64>) + Send,
{
    let payload = download_payload(guid, app.id, external_version_id)?;
    let url = download_url(acc.pod.as_deref(), guid);

    let res = http
        .client()
        .post(url)
        .header("Content-Type", "application/x-apple-plist")
        .header("iCloud-DSID", &acc.directory_services_id)
        .header("X-Dsid", &acc.directory_services_id)
        .body(payload)
        .send()
        .await?;

    let body = res.bytes().await?;

    let parsed: DownloadResult = plist::from_bytes(&body)?;

    if parsed.failure_type.as_deref() == Some(FAILURE_TYPE_PASSWORD_TOKEN_EXPIRED) {
        return Err(IpaToolError::PasswordTokenExpired);
    }
    if parsed.failure_type.as_deref() == Some(FAILURE_TYPE_LICENSE_NOT_FOUND) {
        return Err(IpaToolError::LicenseRequired);
    }
    if parsed.failure_type.is_some() && parsed.customer_message.is_some() {
        return Err(IpaToolError::Unexpected(
            parsed
                .customer_message
                .unwrap_or_else(|| "received error".into()),
        ));
    }
    if parsed.failure_type.is_some() {
        return Err(IpaToolError::Unexpected(
            parsed
                .failure_type
                .unwrap_or_else(|| "received error".into()),
        ));
    }

    let item = parsed
        .items
        .as_ref()
        .and_then(|items| items.first())
        .ok_or_else(|| IpaToolError::Unexpected("invalid response".into()))?;

    let url = item
        .url
        .as_ref()
        .ok_or_else(|| IpaToolError::Unexpected("missing download URL".into()))?;

    let version = item_version(item);
    let destination = resolve_destination_path(app, &version, output_path)?;
    let tmp = PathBuf::from(format!("{}.tmp", destination.display()));

    download_file(url, &tmp, progress).await?;
    let patch_item = item.clone();
    let patch_account = acc.clone();
    let patch_source = tmp.clone();
    let patch_destination = destination.clone();
    tokio::task::spawn_blocking(move || {
        apply_patches(
            &patch_item,
            &patch_account,
            &patch_source,
            &patch_destination,
        )
    })
    .await??;
    tokio::fs::remove_file(&tmp).await?;

    Ok(destination.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appstore::types::Sinf;
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT_TEST_FILE: AtomicUsize = AtomicUsize::new(0);

    fn test_path(name: &str) -> PathBuf {
        let id = NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("ipatool-{name}-{}-{id}", std::process::id()))
    }

    fn download_item(sinfs: Vec<Vec<u8>>) -> DownloadItem {
        DownloadItem {
            md5: None,
            url: None,
            metadata: Some(BTreeMap::new()),
            sinfs: Some(
                sinfs
                    .into_iter()
                    .map(|data| Sinf {
                        id: None,
                        data: Some(plist::Data::new(data)),
                    })
                    .collect(),
            ),
        }
    }

    #[test]
    fn only_recognizes_the_main_app_info_plist() {
        assert_eq!(
            extract_bundle_name("Payload/Telegram.app/Info.plist").as_deref(),
            Some("Telegram")
        );
        assert!(extract_bundle_name("Payload/Telegram.app/Watch/Watch.app/Info.plist").is_none());
        assert!(
            extract_bundle_name("Payload/Telegram.app/PlugIns/Share.appex/Info.plist").is_none()
        );
    }

    #[test]
    fn rejects_mismatched_manifest_and_sinf_counts() {
        let item = download_item(vec![vec![1]]);
        let info = PackageInfo {
            bundle_executable: Some("Telegram".into()),
        };
        let manifest = PackageManifest {
            sinf_paths: Some(vec!["SC_Info/One.sinf".into(), "SC_Info/Two.sinf".into()]),
        };

        let result = resolve_sinf_targets(&item, "Telegram", &info, Some(&manifest));

        assert!(matches!(
            result,
            Err(IpaToolError::SinfCountMismatch {
                sinfs: 1,
                targets: 2
            })
        ));
    }

    #[test]
    fn raw_copies_files_and_replaces_metadata_and_sinf() {
        let source = test_path("source.ipa");
        let destination = test_path("destination.ipa");
        let original_data = vec![b'a'; 128 * 1024];

        let source_file = File::create(&source).unwrap();
        let mut source_zip = zip::ZipWriter::new(source_file);
        let compressed = zip_opts().compression_method(zip::CompressionMethod::Deflated);
        source_zip
            .start_file("Payload/Telegram.app/Telegram", compressed)
            .unwrap();
        source_zip.write_all(&original_data).unwrap();

        source_zip
            .start_file("Payload/Telegram.app/Info.plist", compressed)
            .unwrap();
        let mut info = plist::Dictionary::new();
        info.insert(
            "CFBundleExecutable".into(),
            plist::Value::String("Telegram".into()),
        );
        plist::to_writer_xml(&mut source_zip, &plist::Value::Dictionary(info)).unwrap();

        source_zip
            .start_file("iTunesMetadata.plist", zip_opts())
            .unwrap();
        source_zip.write_all(b"old metadata").unwrap();
        source_zip
            .start_file("Payload/Telegram.app/SC_Info/Telegram.sinf", zip_opts())
            .unwrap();
        source_zip.write_all(b"old sinf").unwrap();
        source_zip.finish().unwrap();

        let mut source_zip = zip::ZipArchive::new(File::open(&source).unwrap()).unwrap();
        let original_compressed_size = source_zip
            .by_name("Payload/Telegram.app/Telegram")
            .unwrap()
            .compressed_size();
        drop(source_zip);

        let item = download_item(vec![b"new sinf".to_vec()]);
        let account = Account {
            email: "test@example.com".into(),
            ..Account::default()
        };
        apply_patches(&item, &account, &source, &destination).unwrap();

        let mut patched = zip::ZipArchive::new(File::open(&destination).unwrap()).unwrap();
        let names = patched.file_names().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            names
                .iter()
                .filter(|name| name.as_str() == "iTunesMetadata.plist")
                .count(),
            1
        );
        assert_eq!(
            names
                .iter()
                .filter(|name| { name.as_str() == "Payload/Telegram.app/SC_Info/Telegram.sinf" })
                .count(),
            1
        );

        let mut executable = patched.by_name("Payload/Telegram.app/Telegram").unwrap();
        assert_eq!(executable.compression(), zip::CompressionMethod::Deflated);
        assert_eq!(executable.compressed_size(), original_compressed_size);
        let mut copied_data = Vec::new();
        executable.read_to_end(&mut copied_data).unwrap();
        assert_eq!(copied_data, original_data);
        drop(executable);

        let mut sinf = patched
            .by_name("Payload/Telegram.app/SC_Info/Telegram.sinf")
            .unwrap();
        let mut sinf_data = Vec::new();
        sinf.read_to_end(&mut sinf_data).unwrap();
        assert_eq!(sinf_data, b"new sinf");
        drop(sinf);

        let metadata: plist::Value = {
            let mut metadata = patched.by_name("iTunesMetadata.plist").unwrap();
            let mut data = Vec::new();
            metadata.read_to_end(&mut data).unwrap();
            plist::from_bytes(&data).unwrap()
        };
        assert_eq!(
            metadata
                .as_dictionary()
                .and_then(|dict| dict.get("apple-id"))
                .and_then(plist::Value::as_string),
            Some("test@example.com")
        );

        drop(patched);
        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(destination);
    }
}
