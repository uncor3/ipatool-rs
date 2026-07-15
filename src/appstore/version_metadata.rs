use std::io::{Cursor, Read};

use reqwest::header::{ACCEPT_ENCODING, CONTENT_RANGE, RANGE};
use time::{
    Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset,
    format_description::well_known::Rfc3339, macros::format_description,
};

use crate::{
    VersionMetadata,
    appstore::types::{Account, App, DownloadItem, DownloadResult},
    constants::{
        DEFAULT_USER_AGENT, FAILURE_TYPE_LICENSE_NOT_FOUND, FAILURE_TYPE_PASSWORD_TOKEN_EXPIRED,
        FAILURE_TYPE_SIGN_IN_REQUIRED, PRIVATE_APPSTORE_DOMAIN, PRIVATE_DOWNLOAD_PATH,
    },
    error::{IpaToolError, Result},
    http::client::Http,
};

/*
    golang ipatool implement the io.ReaderAt for eocd etc..
    however is rust, there isn't a similar api
    as far as I know, so we have to parse the zip ourselfs here
*/ 

const ZIP_EOCD_SIZE: u64 = 22;
const ZIP_MAX_COMMENT_SIZE: u64 = u16::MAX as u64;
const ZIP_CENTRAL_HEADER_SIZE: usize = 46;
const ZIP_LOCAL_HEADER_SIZE: usize = 30;


struct RemoteZip {
    client: reqwest::blocking::Client,
    url: String,
    size: u64,
}

impl RemoteZip {
    fn open(url: String) -> Result<Self> {
        if url.is_empty() {
            return Err(IpaToolError::MissingData {
                thing: "download URL".into(),
            });
        }
        let client = reqwest::blocking::Client::builder()
            .user_agent(DEFAULT_USER_AGENT)
            .build()?;
        let response = client
            .get(&url)
            .header(ACCEPT_ENCODING, "identity")
            .header(RANGE, "bytes=0-0")
            .send()?;
        if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(IpaToolError::Unexpected(format!(
                "expected partial content response, got HTTP {}",
                response.status()
            )));
        }
        let content_range = response
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| IpaToolError::MissingData {
                thing: "Content-Range header".into(),
            })?;
        let size = parse_content_range_size(content_range)?;

        Ok(Self { client, url, size })
    }

    fn range(&self, start: u64, end: u64) -> Result<Vec<u8>> {
        if start > end || end >= self.size {
            return Err(IpaToolError::Unexpected(format!(
                "invalid IPA byte range {start}-{end} for {} byte file",
                self.size
            )));
        }
        let response = self
            .client
            .get(&self.url)
            .header(ACCEPT_ENCODING, "identity")
            .header(RANGE, format!("bytes={start}-{end}"))
            .send()?;
        if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(IpaToolError::Unexpected(format!(
                "expected partial content response, got HTTP {}",
                response.status()
            )));
        }
        let bytes = response.bytes()?.to_vec();
        let expected = usize::try_from(end - start + 1)
            .map_err(|_| IpaToolError::Unexpected("IPA byte range is too large".into()))?;
        if bytes.len() != expected {
            return Err(IpaToolError::Unexpected(format!(
                "short IPA byte range: expected {expected} bytes, got {}",
                bytes.len()
            )));
        }
        Ok(bytes)
    }
}

#[derive(Debug)]
struct RemoteZipEntry {
    local_header_offset: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    crc32: u32,
    modified: zip::DateTime,
    unix_modified: Option<i64>,
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| IpaToolError::Unexpected("truncated ZIP data".into()))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| IpaToolError::Unexpected("truncated ZIP data".into()))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or_else(|| IpaToolError::Unexpected("truncated ZIP data".into()))?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn find_eocd(data: &[u8]) -> Result<usize> {
    data.windows(4)
        .enumerate()
        .rev()
        .find_map(|(offset, window)| {
            if window != [0x50, 0x4b, 0x05, 0x06] || offset + ZIP_EOCD_SIZE as usize > data.len() {
                return None;
            }
            let comment_len = u16::from_le_bytes([data[offset + 20], data[offset + 21]]) as usize;
            (offset + ZIP_EOCD_SIZE as usize + comment_len == data.len()).then_some(offset)
        })
        .ok_or_else(|| IpaToolError::Unexpected("ZIP end record not found".into()))
}

fn zip64_value(extra: &[u8], field_offset: usize) -> Result<u64> {
    let mut offset = 0;
    while offset + 4 <= extra.len() {
        let kind = read_u16(extra, offset)?;
        let len = read_u16(extra, offset + 2)? as usize;
        let body = extra
            .get(offset + 4..offset + 4 + len)
            .ok_or_else(|| IpaToolError::Unexpected("truncated ZIP extra field".into()))?;
        if kind == 0x0001 {
            return read_u64(body, field_offset);
        }
        offset += 4 + len;
    }
    Err(IpaToolError::Unexpected(
        "missing ZIP64 extended information".into(),
    ))
}

fn extended_timestamp(extra: &[u8]) -> Option<i64> {
    let mut offset = 0;
    while offset + 4 <= extra.len() {
        let kind = u16::from_le_bytes(extra[offset..offset + 2].try_into().ok()?);
        let len = u16::from_le_bytes(extra[offset + 2..offset + 4].try_into().ok()?) as usize;
        let body = extra.get(offset + 4..offset + 4 + len)?;
        if kind == 0x5455 && body.len() >= 5 && body[0] & 1 != 0 {
            return Some(u32::from_le_bytes(body[1..5].try_into().ok()?) as i64);
        }
        offset += 4 + len;
    }
    None
}

fn find_info_entry(directory: &[u8], entry_count: u64) -> Result<RemoteZipEntry> {
    let mut offset = 0;
    for _ in 0..entry_count {
        let header = directory
            .get(offset..offset + ZIP_CENTRAL_HEADER_SIZE)
            .ok_or_else(|| IpaToolError::Unexpected("truncated ZIP central directory".into()))?;
        if read_u32(header, 0)? != 0x0201_4b50 {
            return Err(IpaToolError::Unexpected(
                "invalid ZIP central directory header".into(),
            ));
        }
        let name_len = read_u16(header, 28)? as usize;
        let extra_len = read_u16(header, 30)? as usize;
        let comment_len = read_u16(header, 32)? as usize;
        let record_len = ZIP_CENTRAL_HEADER_SIZE + name_len + extra_len + comment_len;
        let record = directory
            .get(offset..offset + record_len)
            .ok_or_else(|| IpaToolError::Unexpected("truncated ZIP central entry".into()))?;
        let name_bytes = &record[ZIP_CENTRAL_HEADER_SIZE..ZIP_CENTRAL_HEADER_SIZE + name_len];
        let name = String::from_utf8_lossy(name_bytes);
        let extra_start = ZIP_CENTRAL_HEADER_SIZE + name_len;
        let extra = &record[extra_start..extra_start + extra_len];

        if is_main_app_info_plist(&name) {
            let compressed32 = read_u32(header, 20)?;
            let uncompressed32 = read_u32(header, 24)?;
            let local_offset32 = read_u32(header, 42)?;
            let mut zip64_offset = 0;
            let uncompressed_size = if uncompressed32 == u32::MAX {
                let value = zip64_value(extra, zip64_offset)?;
                zip64_offset += 8;
                value
            } else {
                uncompressed32 as u64
            };
            let compressed_size = if compressed32 == u32::MAX {
                let value = zip64_value(extra, zip64_offset)?;
                zip64_offset += 8;
                value
            } else {
                compressed32 as u64
            };
            let local_header_offset = if local_offset32 == u32::MAX {
                zip64_value(extra, zip64_offset)?
            } else {
                local_offset32 as u64
            };
            let modified =
                zip::DateTime::try_from_msdos(read_u16(header, 14)?, read_u16(header, 12)?)
                    .map_err(|_| {
                        IpaToolError::Unexpected("invalid ZIP modification date".into())
                    })?;
            return Ok(RemoteZipEntry {
                local_header_offset,
                compressed_size,
                uncompressed_size,
                crc32: read_u32(header, 16)?,
                modified,
                unix_modified: extended_timestamp(extra),
            });
        }
        offset += record_len;
    }
    Err(IpaToolError::MissingData {
        thing: "main app Info.plist".into(),
    })
}

fn parse_content_range_size(header: &str) -> Result<u64> {
    let size = header
        .rsplit_once('/')
        .map(|(_, size)| size)
        .filter(|size| !size.is_empty() && *size != "*")
        .ok_or_else(|| IpaToolError::Unexpected(format!("invalid Content-Range: {header}")))?;
    size.parse::<u64>()
        .map_err(|_| IpaToolError::Unexpected(format!("invalid Content-Range size: {size}")))
}

fn is_main_app_info_plist(name: &str) -> bool {
    let mut parts = name.split('/');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("Payload"), Some(app), Some("Info.plist"), None) if app.ends_with(".app")
    )
}

fn display_version(metadata: &plist::Dictionary) -> Result<String> {
    for key in ["CFBundleShortVersionString", "bundleShortVersionString"] {
        let Some(value) = metadata.get(key) else {
            continue;
        };
        let value = match value {
            plist::Value::String(value) => value.clone(),
            plist::Value::Integer(value) => value.to_string(),
            plist::Value::Real(value) => value.to_string(),
            plist::Value::Boolean(value) => value.to_string(),
            _ => String::new(),
        };
        let value = value.trim().to_string();
        if value.is_empty() {
            return Err(IpaToolError::MissingData { thing: key.into() });
        }
        return Ok(value);
    }
    Err(IpaToolError::MissingData {
        thing: "Info.plist display version".into(),
    })
}

fn parse_release_date_string(value: &str) -> Result<OffsetDateTime> {
    let value = value.trim();
    if let Ok(date) = OffsetDateTime::parse(value, &Rfc3339) {
        return Ok(date.to_offset(UtcOffset::UTC));
    }
    let long_date =
        format_description!("[weekday repr:long], [month repr:long] [day padding:none], [year]");
    if let Ok(date) = Date::parse(value, long_date) {
        return Ok(PrimitiveDateTime::new(date, Time::MIDNIGHT).assume_utc());
    }
    let short_date = format_description!("[year]-[month]-[day]");
    if let Ok(date) = Date::parse(value, short_date) {
        return Ok(PrimitiveDateTime::new(date, Time::MIDNIGHT).assume_utc());
    }
    Err(IpaToolError::Unexpected(format!(
        "invalid release date: {value}"
    )))
}

fn release_date_from_value(value: &plist::Value) -> Result<OffsetDateTime> {
    match value {
        plist::Value::Date(value) => parse_release_date_string(&value.to_xml_format()),
        plist::Value::String(value) => parse_release_date_string(value),
        plist::Value::Integer(value) => value
            .as_signed()
            .or_else(|| {
                value
                    .as_unsigned()
                    .and_then(|value| i64::try_from(value).ok())
            })
            .and_then(|timestamp| OffsetDateTime::from_unix_timestamp(timestamp).ok())
            .ok_or_else(|| IpaToolError::Unexpected("invalid release date timestamp".into())),
        plist::Value::Real(value) if value.is_finite() => {
            OffsetDateTime::from_unix_timestamp(*value as i64)
                .map_err(|_| IpaToolError::Unexpected("invalid release date timestamp".into()))
        }
        _ => Err(IpaToolError::Unexpected(
            "unsupported release date value".into(),
        )),
    }
}

fn zip_modified_date(value: zip::DateTime) -> Result<OffsetDateTime> {
    let month = Month::try_from(value.month())
        .map_err(|_| IpaToolError::Unexpected("invalid ZIP modification month".into()))?;
    let date = Date::from_calendar_date(value.year() as i32, month, value.day())
        .map_err(|_| IpaToolError::Unexpected("invalid ZIP modification date".into()))?;
    let time = Time::from_hms(value.hour(), value.minute(), value.second())
        .map_err(|_| IpaToolError::Unexpected("invalid ZIP modification time".into()))?;
    Ok(PrimitiveDateTime::new(date, time).assume_utc())
}

fn central_directory(remote: &RemoteZip) -> Result<(Vec<u8>, u64)> {
    let tail_len = remote.size.min(ZIP_EOCD_SIZE + ZIP_MAX_COMMENT_SIZE);
    let tail_start = remote.size - tail_len;
    let tail = remote.range(tail_start, remote.size - 1)?;
    let eocd = find_eocd(&tail)?;
    let comment_len = read_u16(&tail, eocd + 20)? as usize;
    if eocd + ZIP_EOCD_SIZE as usize + comment_len > tail.len() {
        return Err(IpaToolError::Unexpected("truncated ZIP end record".into()));
    }

    let entries32 = read_u16(&tail, eocd + 10)?;
    let directory_size32 = read_u32(&tail, eocd + 12)?;
    let directory_offset32 = read_u32(&tail, eocd + 16)?;
    let (entry_count, directory_size, directory_offset) = if entries32 == u16::MAX
        || directory_size32 == u32::MAX
        || directory_offset32 == u32::MAX
    {
        let locator = eocd
            .checked_sub(20)
            .ok_or_else(|| IpaToolError::Unexpected("missing ZIP64 end record locator".into()))?;
        if read_u32(&tail, locator)? != 0x0706_4b50 {
            return Err(IpaToolError::Unexpected(
                "invalid ZIP64 end record locator".into(),
            ));
        }
        let zip64_offset = read_u64(&tail, locator + 8)?;
        let zip64 = remote.range(zip64_offset, zip64_offset + 55)?;
        if read_u32(&zip64, 0)? != 0x0606_4b50 {
            return Err(IpaToolError::Unexpected("invalid ZIP64 end record".into()));
        }
        (
            read_u64(&zip64, 32)?,
            read_u64(&zip64, 40)?,
            read_u64(&zip64, 48)?,
        )
    } else {
        (
            entries32 as u64,
            directory_size32 as u64,
            directory_offset32 as u64,
        )
    };
    if directory_size == 0 {
        return Err(IpaToolError::Unexpected(
            "ZIP central directory is empty".into(),
        ));
    }
    let directory_end = directory_offset
        .checked_add(directory_size - 1)
        .ok_or_else(|| IpaToolError::Unexpected("invalid ZIP central directory size".into()))?;
    Ok((remote.range(directory_offset, directory_end)?, entry_count))
}

fn read_remote_entry(remote: &RemoteZip, entry: &RemoteZipEntry) -> Result<Vec<u8>> {
    // A local header can have a different extra field than its central entry.
    // Fetch enough for the maximum legal name + extra fields and the compressed
    // Info.plist so this remains one CDN request in the common case.
    let maximum_header_size = ZIP_LOCAL_HEADER_SIZE as u64 + 2 * u16::MAX as u64;
    let requested_size = maximum_header_size
        .checked_add(entry.compressed_size)
        .ok_or_else(|| IpaToolError::Unexpected("ZIP entry is too large".into()))?;
    let end = entry
        .local_header_offset
        .saturating_add(requested_size - 1)
        .min(remote.size - 1);
    let mut bytes = remote.range(entry.local_header_offset, end)?;
    if read_u32(&bytes, 0)? != 0x0403_4b50 {
        return Err(IpaToolError::Unexpected(
            "invalid ZIP local file header".into(),
        ));
    }
    let name_len = read_u16(&bytes, 26)? as usize;
    let extra_len = read_u16(&bytes, 28)? as usize;
    let entry_len = ZIP_LOCAL_HEADER_SIZE
        .checked_add(name_len)
        .and_then(|value| value.checked_add(extra_len))
        .and_then(|value| value.checked_add(usize::try_from(entry.compressed_size).ok()?))
        .ok_or_else(|| IpaToolError::Unexpected("ZIP entry is too large".into()))?;
    if bytes.len() < entry_len {
        return Err(IpaToolError::Unexpected("truncated ZIP entry".into()));
    }
    bytes.truncate(entry_len);

    // Apple archives may use a data descriptor, leaving sizes out of the local
    // header. The central directory is authoritative, so populate those fields
    // before passing this isolated entry to zip's streaming decoder.
    let compressed_size = u32::try_from(entry.compressed_size)
        .map_err(|_| IpaToolError::Unexpected("Info.plist ZIP entry is too large".into()))?;
    let uncompressed_size = u32::try_from(entry.uncompressed_size)
        .map_err(|_| IpaToolError::Unexpected("Info.plist ZIP entry is too large".into()))?;
    let flags = read_u16(&bytes, 6)? & !0x0008;
    bytes[6..8].copy_from_slice(&flags.to_le_bytes());
    bytes[14..18].copy_from_slice(&entry.crc32.to_le_bytes());
    bytes[18..22].copy_from_slice(&compressed_size.to_le_bytes());
    bytes[22..26].copy_from_slice(&uncompressed_size.to_le_bytes());

    let mut cursor = Cursor::new(bytes);
    let mut file = zip::read::read_zipfile_from_stream(&mut cursor)?
        .ok_or_else(|| IpaToolError::Unexpected("invalid Info.plist ZIP entry".into()))?;
    let mut data = Vec::with_capacity(entry.uncompressed_size as usize);
    file.read_to_end(&mut data)?;
    Ok(data)
}

fn read_metadata_from_ipa(url: String) -> Result<VersionMetadata> {
    let remote = RemoteZip::open(url)?;
    let (directory, entry_count) = central_directory(&remote)?;
    let entry = find_info_entry(&directory, entry_count)?;
    let data = read_remote_entry(&remote, &entry)?;
    let value: plist::Value = plist::from_bytes(&data)?;
    let metadata = value
        .as_dictionary()
        .ok_or_else(|| IpaToolError::Unexpected("Info.plist is not a dictionary".into()))?;

    let display_version = display_version(metadata)?;
    let release_date = if let Some(value) = ["releaseDate", "ReleaseDate"]
        .iter()
        .find_map(|key| metadata.get(key))
    {
        release_date_from_value(value)?
    } else if let Some(timestamp) = entry.unix_modified {
        OffsetDateTime::from_unix_timestamp(timestamp)
            .map_err(|_| IpaToolError::Unexpected("invalid ZIP modification timestamp".into()))?
    } else {
        zip_modified_date(entry.modified)?
    };

    Ok(VersionMetadata {
        display_version,
        release_date: release_date
            .to_offset(UtcOffset::UTC)
            .format(&Rfc3339)
            .map_err(|error| IpaToolError::Unexpected(error.to_string()))?,
    })
}

async fn download_item(
    http: &Http,
    guid: &str,
    account: &Account,
    app: &App,
    version_id: &str,
) -> Result<DownloadItem> {
    let pod_prefix = account
        .pod
        .as_deref()
        .filter(|pod| !pod.is_empty())
        .map(|pod| format!("p{pod}-"))
        .unwrap_or_default();
    let url =
        format!("https://{pod_prefix}{PRIVATE_APPSTORE_DOMAIN}{PRIVATE_DOWNLOAD_PATH}?guid={guid}");
    let mut payload = plist::Dictionary::new();
    payload.insert("creditDisplay".into(), plist::Value::String(String::new()));
    payload.insert("guid".into(), plist::Value::String(guid.into()));
    payload.insert("salableAdamId".into(), plist::Value::Integer(app.id.into()));
    payload.insert(
        "externalVersionId".into(),
        plist::Value::String(version_id.into()),
    );
    let mut body = Vec::new();
    plist::to_writer_xml(&mut body, &plist::Value::Dictionary(payload))?;

    let response = http
        .client()
        .post(url)
        .header("Content-Type", "application/x-apple-plist")
        .header("iCloud-DSID", &account.directory_services_id)
        .header("X-Dsid", &account.directory_services_id)
        .body(body)
        .send()
        .await?;
    let status = response.status();
    let body = response.bytes().await?;
    let parsed: DownloadResult = plist::from_bytes(&body)?;

    if matches!(
        parsed.failure_type.as_deref(),
        Some(FAILURE_TYPE_PASSWORD_TOKEN_EXPIRED | FAILURE_TYPE_SIGN_IN_REQUIRED)
    ) {
        return Err(IpaToolError::PasswordTokenExpired);
    }
    if parsed.failure_type.as_deref() == Some(FAILURE_TYPE_LICENSE_NOT_FOUND) {
        return Err(IpaToolError::LicenseRequired);
    }
    if let Some(failure_type) = parsed.failure_type {
        return Err(IpaToolError::Unexpected(
            parsed.customer_message.unwrap_or(failure_type),
        ));
    }
    parsed
        .items
        .and_then(|items| items.into_iter().next())
        .ok_or_else(|| IpaToolError::Unexpected("invalid response".into()))
}

pub async fn get(
    http: &Http,
    guid: &str,
    account: &Account,
    app: &App,
    version_id: &str,
) -> Result<VersionMetadata> {
    let item = download_item(http, guid, account, app, version_id).await?;
    let url = item.url.ok_or_else(|| IpaToolError::MissingData {
        thing: "download URL".into(),
    })?;
    tokio::task::spawn_blocking(move || read_metadata_from_ipa(url)).await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_range_size() {
        assert_eq!(
            parse_content_range_size("bytes 0-0/197440775").unwrap(),
            197440775
        );
        assert!(parse_content_range_size("bytes 0-0/*").is_err());
    }

    #[test]
    fn finds_eocd_without_mistaking_comment_contents_for_a_record() {
        let mut eocd = vec![0; ZIP_EOCD_SIZE as usize + 8];
        eocd[0..4].copy_from_slice(&0x0605_4b50_u32.to_le_bytes());
        eocd[20..22].copy_from_slice(&8_u16.to_le_bytes());
        eocd[24..28].copy_from_slice(&0x0605_4b50_u32.to_le_bytes());
        assert_eq!(find_eocd(&eocd).unwrap(), 0);
    }

    #[test]
    fn finds_info_plist_from_central_directory() {
        let name = b"Payload/Test.app/Info.plist";
        let mut directory = vec![0; ZIP_CENTRAL_HEADER_SIZE + name.len()];
        directory[0..4].copy_from_slice(&0x0201_4b50_u32.to_le_bytes());
        directory[12..14].copy_from_slice(&0_u16.to_le_bytes());
        directory[14..16].copy_from_slice(&0x0021_u16.to_le_bytes());
        directory[16..20].copy_from_slice(&123_u32.to_le_bytes());
        directory[20..24].copy_from_slice(&456_u32.to_le_bytes());
        directory[24..28].copy_from_slice(&789_u32.to_le_bytes());
        directory[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
        directory[42..46].copy_from_slice(&42_u32.to_le_bytes());
        directory[ZIP_CENTRAL_HEADER_SIZE..].copy_from_slice(name);

        let entry = find_info_entry(&directory, 1).unwrap();
        assert_eq!(entry.local_header_offset, 42);
        assert_eq!(entry.compressed_size, 456);
        assert_eq!(entry.uncompressed_size, 789);
        assert_eq!(entry.crc32, 123);
    }

    #[test]
    fn reads_extended_zip_timestamp() {
        let timestamp = 1_342_633_342_u32;
        let mut extra = vec![0x55, 0x54, 5, 0, 1];
        extra.extend_from_slice(&timestamp.to_le_bytes());
        assert_eq!(extended_timestamp(&extra), Some(timestamp as i64));
    }

    #[test]
    fn identifies_only_main_app_info_plist() {
        assert!(is_main_app_info_plist("Payload/Test.app/Info.plist"));
        assert!(!is_main_app_info_plist(
            "Payload/Test.app/PlugIns/Share.appex/Info.plist"
        ));
        assert!(!is_main_app_info_plist(
            "Payload/Test.app/Watch/Watch.app/Info.plist"
        ));
    }

    #[test]
    fn reads_display_version_variants() {
        let mut metadata = plist::Dictionary::new();
        metadata.insert(
            "CFBundleShortVersionString".into(),
            plist::Value::String(" 2.4.1 ".into()),
        );
        assert_eq!(display_version(&metadata).unwrap(), "2.4.1");
    }

    #[test]
    fn parses_supported_release_dates() {
        assert_eq!(
            parse_release_date_string("2024-05-06")
                .unwrap()
                .format(&Rfc3339)
                .unwrap(),
            "2024-05-06T00:00:00Z"
        );
        assert!(parse_release_date_string("not a date").is_err());
    }
}
