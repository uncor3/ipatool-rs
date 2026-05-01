use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    appstore::{
        purchase,
        types::{Account, App, DownloadItem, DownloadResult, Sinf},
    },
    constants::{
        FAILURE_TYPE_LICENSE_NOT_FOUND, FAILURE_TYPE_PASSWORD_TOKEN_EXPIRED,
        PRIVATE_APPSTORE_DOMAIN, PRIVATE_DOWNLOAD_PATH,
    },
    error::{IpaToolError, Result},
    http::client::Http,
    util::normalize_plist_body,
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

async fn download_file(
    src: &str,
    dst: &Path,
    progress: &mut dyn FnMut(u64, Option<u64>),
) -> Result<()> {
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
    let prefix = info_plist_path.strip_suffix(".app/Info.plist")?;
    prefix.rsplit('/').next().map(|s| s.to_string())
}

fn zip_opts() -> zip::write::SimpleFileOptions {
    zip::write::SimpleFileOptions::default()
}

fn replicate_sinf_from_manifest(
    dst_zip: &mut zip::ZipWriter<File>,
    sinfs: &[Sinf],
    bundle_name: &str,
    manifest: &PackageManifest,
) -> Result<()> {
    let paths = manifest.sinf_paths.as_ref().cloned().unwrap_or_default();
    for (sinf, rel_path) in sinfs.iter().zip(paths.iter()) {
        let data = sinf
            .data
            .as_ref()
            .ok_or_else(|| IpaToolError::MissingData {
                thing: "sinf".into(),
            })?;
        let target = format!("Payload/{}.app/{}", bundle_name, rel_path);
        dst_zip.start_file(target, zip_opts())?;
        dst_zip.write_all(data.as_ref())?;
    }
    Ok(())
}

fn replicate_sinf_from_info(
    dst_zip: &mut zip::ZipWriter<File>,
    sinfs: &[Sinf],
    bundle_name: &str,
    info: &PackageInfo,
) -> Result<()> {
    let exec = info
        .bundle_executable
        .as_ref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| IpaToolError::MissingData {
            thing: "CFBundleExecutable".into(),
        })?;
    let first = sinfs.first().ok_or_else(|| IpaToolError::MissingData {
        thing: "sinf data".into(),
    })?;
    let data = first
        .data
        .as_ref()
        .ok_or_else(|| IpaToolError::MissingData {
            thing: "sinf data".into(),
        })?;

    let target = format!("Payload/{}.app/SC_Info/{}.sinf", bundle_name, exec);
    dst_zip.start_file(target, zip_opts())?;
    dst_zip.write_all(data.as_ref())?;
    Ok(())
}

fn replicate_sinf(
    dst_zip: &mut zip::ZipWriter<File>,
    item: &DownloadItem,
    bundle_name: Option<&str>,
    manifest: Option<&PackageManifest>,
    info: Option<&PackageInfo>,
) -> Result<()> {
    let sinfs = match item.sinfs.as_ref() {
        Some(v) if !v.is_empty() => v,
        _ => return Ok(()),
    };

    let bundle =
        bundle_name
            .filter(|s| !s.is_empty())
            .ok_or_else(|| IpaToolError::MissingData {
                thing: "bundle name".into(),
            })?;

    if let Some(m) = manifest {
        if m.sinf_paths
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        {
            return replicate_sinf_from_manifest(dst_zip, sinfs, bundle, m);
        }
    }

    if let Some(i) = info {
        return replicate_sinf_from_info(dst_zip, sinfs, bundle, i);
    }

    Err(IpaToolError::NoSinfTarget)
}

fn apply_patches(item: &DownloadItem, acc: &Account, src: &Path, dst: &Path) -> Result<()> {
    let src_file = File::open(src)?;
    let mut src_zip = zip::ZipArchive::new(src_file)?;

    let dst_file = File::create(dst)?;
    let mut dst_zip = zip::ZipWriter::new(dst_file);

    let mut bundle_name: Option<String> = None;
    let mut manifest: Option<PackageManifest> = None;
    let mut info: Option<PackageInfo> = None;

    for i in 0..src_zip.len() {
        let mut entry = src_zip.by_index(i)?;
        let name = entry.name().to_string();

        if entry.is_dir() {
            dst_zip.add_directory(name, zip_opts())?;
            continue;
        }

        let mut options: zip::write::SimpleFileOptions =
            zip_opts().compression_method(entry.compression());
        if let Some(mode) = entry.unix_mode() {
            options = options.unix_permissions(mode);
        }

        dst_zip.start_file(name.clone(), options)?;

        let is_info = name.contains(".app/Info.plist");
        let is_manifest = name.ends_with(".app/SC_Info/Manifest.plist");

        if is_info || is_manifest {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            dst_zip.write_all(&buf)?;

            if is_info && !name.contains("/Watch/") && bundle_name.is_none() {
                bundle_name = extract_bundle_name(&name);
            }

            if is_manifest && manifest.is_none() {
                manifest = plist::from_bytes::<PackageManifest>(&buf).ok();
            }

            if is_info && info.is_none() {
                info = plist::from_bytes::<PackageInfo>(&buf).ok();
            }
        } else {
            io::copy(&mut entry, &mut dst_zip)?;
        }
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

    replicate_sinf(
        &mut dst_zip,
        item,
        bundle_name.as_deref(),
        manifest.as_ref(),
        info.as_ref(),
    )?;

    dst_zip.finish()?;
    Ok(())
}

pub async fn download_ipa(
    http: &Http,
    guid: &str,
    acc: &mut Account,
    app: &App,
    output_path: Option<&str>,
    external_version_id: Option<&str>,
    acquire_license: bool,
    progress: &mut dyn FnMut(u64, Option<u64>),
) -> Result<String> {
    if acquire_license {
        purchase::purchase(http, guid, acc, app).await?;
    }

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
    let normalized = normalize_plist_body(&body);
    if normalized.is_empty() {
        return Err(IpaToolError::EmptyResponse);
    }

    let parsed: DownloadResult = plist::from_bytes(&normalized)?;

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
    apply_patches(item, acc, &tmp, &destination)?;
    let _ = std::fs::remove_file(&tmp);

    Ok(destination.to_string_lossy().to_string())
}
