//! Seekable, bounded HTTP range access to the pinned restore image.
//!
//! This reader belongs on a blocking worker. It never downloads the IPSW as a
//! whole, and rejects servers that ignore Range rather than consuming their body.
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::{StatusCode, blocking::Client, header};

pub const RESTORE_URL: &str = "https://updates.cdn-apple.com/2026FallFCS/59241290-5d51-4ca8-9df4-31624b9a4eac/UniversalMac_27.0.1_26A434_Restore.ipsw";

type ReadWindow = Arc<Mutex<Option<(u64, Vec<u8>)>>>;

#[derive(Clone)]
pub struct RemoteFile {
    client: Client,
    url: String,
    size: u64,
    position: u64,
    window: ReadWindow,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn content_range(value: &str) -> io::Result<(u64, u64, u64)> {
    let (range, total) = value
        .strip_prefix("bytes ")
        .and_then(|s| s.split_once('/'))
        .ok_or_else(|| invalid("invalid image Content-Range"))?;
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| invalid("invalid image Content-Range"))?;
    let decimal = |s: &str| -> io::Result<u64> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid("invalid image Content-Range number"));
        }
        s.parse()
            .map_err(|_| invalid("image Content-Range overflow"))
    };
    let (start, end, total) = (decimal(start)?, decimal(end)?, decimal(total)?);
    if start > end || end >= total || total > i64::MAX as u64 {
        return Err(invalid("image Content-Range is out of bounds"));
    }
    Ok((start, end, total))
}

impl RemoteFile {
    pub fn open_restore_image() -> io::Result<Self> {
        Self::open(RESTORE_URL)
    }

    fn open(url: &str) -> io::Result<Self> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(io::Error::other)?;
        let response = client
            .get(url)
            .header(header::RANGE, "bytes=0-0")
            .header(header::ACCEPT_ENCODING, "identity")
            .send()
            .map_err(io::Error::other)?;
        if response.status() != StatusCode::PARTIAL_CONTENT {
            return Err(invalid("restore server does not support byte ranges"));
        }
        let (start, end, size) = response_range(&response)?;
        if start != 0 || end != 0 {
            return Err(invalid("restore server returned the wrong initial range"));
        }
        Ok(Self {
            client,
            url: url.into(),
            size,
            position: 0,
            window: Arc::new(Mutex::new(None)),
        })
    }

    pub fn len(&self) -> u64 {
        self.size
    }
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn read_at(&self, data: &mut [u8], offset: u64) -> io::Result<usize> {
        if data.is_empty() || offset >= self.size {
            return Ok(0);
        }
        let wanted = (data.len() as u64).min(self.size - offset) as usize;
        let end = offset + wanted as u64 - 1;
        let mut done = 0;
        let mut last_error = None;
        for _ in 0..3 {
            let start = offset + done as u64;
            let response = self
                .client
                .get(&self.url)
                .header(header::RANGE, format!("bytes={start}-{end}"))
                .header(header::ACCEPT_ENCODING, "identity")
                .send();
            let mut response = match response {
                Ok(response) => response,
                Err(error) => {
                    last_error = Some(io::Error::other(error));
                    continue;
                }
            };
            if response.status() != StatusCode::PARTIAL_CONTENT {
                return Err(invalid("restore server ignored the requested byte range"));
            }
            if response_range(&response)? != (start, end, self.size) {
                return Err(invalid("restore server returned an unexpected byte range"));
            }
            while done < wanted {
                match response.read(&mut data[done..wanted]) {
                    Ok(0) => {
                        last_error = Some(io::ErrorKind::UnexpectedEof.into());
                        break;
                    }
                    Ok(count) => done += count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        last_error = Some(error);
                        break;
                    }
                }
            }
            if done == wanted {
                return Ok(done);
            }
        }
        Err(last_error.unwrap_or_else(|| io::ErrorKind::UnexpectedEof.into()))
    }

    pub fn section(&self, offset: u64, size: u64) -> io::Result<Section> {
        if offset > self.size || size > self.size - offset {
            return Err(invalid("restore member is outside the archive"));
        }
        Ok(Section {
            source: self.clone(),
            offset,
            size,
            position: 0,
        })
    }

    // ZIP's central-directory decoder performs many tiny sequential reads.
    // Coalesce only those reads; explicit large/range reads retain exact bounds.
    fn read_cached(&self, data: &mut [u8], offset: u64) -> io::Result<usize> {
        if data.is_empty() || offset >= self.size {
            return Ok(0);
        }
        if data.len() >= 65536 {
            return self.read_at(data, offset);
        }
        let mut window = self
            .window
            .lock()
            .map_err(|_| invalid("restore read cache poisoned"))?;
        if let Some((start, bytes)) = window.as_ref()
            && offset >= *start
            && offset - *start < bytes.len() as u64
        {
            let inside = (offset - *start) as usize;
            let count = data.len().min(bytes.len() - inside);
            data[..count].copy_from_slice(&bytes[inside..inside + count]);
            return Ok(count);
        }
        let start = offset & !65535;
        let mut bytes = vec![0; (self.size - start).min(65536) as usize];
        self.read_at(&mut bytes, start)?;
        let inside = (offset - start) as usize;
        let count = data.len().min(bytes.len() - inside);
        data[..count].copy_from_slice(&bytes[inside..inside + count]);
        *window = Some((start, bytes));
        Ok(count)
    }
}

fn response_range(response: &reqwest::blocking::Response) -> io::Result<(u64, u64, u64)> {
    content_range(
        response
            .headers()
            .get(header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| invalid("restore response has no Content-Range"))?,
    )
}

impl Read for RemoteFile {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        let count = self.read_cached(data, self.position)?;
        self.position += count as u64;
        Ok(count)
    }
}
impl Seek for RemoteFile {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.position = seek_position(self.position, self.size, from)?;
        Ok(self.position)
    }
}

pub struct Section {
    source: RemoteFile,
    offset: u64,
    size: u64,
    position: u64,
}

/// Locate the two exact, uncompressed AEA members without reading their bodies.
pub fn restore_members(source: &RemoteFile) -> io::Result<(Section, Section)> {
    let entries = zip_members(source.len(), |offset, size| {
        let mut data = vec![0; size];
        if source.read_at(&mut data, offset)? != size {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(data)
    })?;
    let filesystem = source.section(entries[0].0, entries[0].1)?;
    let system_os = source.section(entries[1].0, entries[1].1)?;
    Ok((filesystem, system_os))
}

// zip 2.x eagerly probes every local header while loading the directory. An
// IPSW has thousands of unrelated entries; only probe our two selected members.
fn zip_members(
    total: u64,
    mut read: impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
) -> io::Result<[(u64, u64); 2]> {
    fn word(data: &[u8], offset: usize, size: usize) -> io::Result<u64> {
        let value = data
            .get(offset..offset + size)
            .ok_or_else(|| invalid("truncated ZIP record"))?;
        let mut bytes = [0; 8];
        bytes[..size].copy_from_slice(value);
        Ok(u64::from_le_bytes(bytes))
    }
    if total < 22 {
        return Err(invalid("restore ZIP is too small"));
    }
    let tail_offset = total.saturating_sub(65_557);
    let tail = read(tail_offset, (total - tail_offset) as usize)?;
    let end = (0..=tail.len() - 22)
        .rev()
        .find(|i| {
            tail[*i..].starts_with(b"PK\x05\x06")
                && word(&tail, *i + 20, 2).is_ok_and(|size| *i + 22 + size as usize == tail.len())
        })
        .ok_or_else(|| invalid("restore ZIP has no end record"))?;
    if word(&tail, end + 4, 2)? != 0 || word(&tail, end + 6, 2)? != 0 {
        return Err(invalid("split restore ZIP is unsupported"));
    }
    let mut count = word(&tail, end + 10, 2)?;
    let mut size = word(&tail, end + 12, 4)?;
    let mut offset = word(&tail, end + 16, 4)?;
    if count == 0xffff || size == 0xffff_ffff || offset == 0xffff_ffff {
        let locator_offset = (tail_offset + end as u64)
            .checked_sub(20)
            .ok_or_else(|| invalid("missing ZIP64 locator"))?;
        let locator = read(locator_offset, 20)?;
        if !locator.starts_with(b"PK\x06\x07")
            || word(&locator, 4, 4)? != 0
            || word(&locator, 16, 4)? != 1
        {
            return Err(invalid("invalid ZIP64 locator"));
        }
        let header_offset = word(&locator, 8, 8)?;
        let header = read(header_offset, 56)?;
        if !header.starts_with(b"PK\x06\x06")
            || word(&header, 4, 8)? < 44
            || word(&header, 16, 4)? != 0
            || word(&header, 20, 4)? != 0
            || word(&header, 24, 8)? != word(&header, 32, 8)?
        {
            return Err(invalid("invalid ZIP64 end record"));
        }
        count = word(&header, 32, 8)?;
        size = word(&header, 40, 8)?;
        offset = word(&header, 48, 8)?;
    }
    if count == 0 || count > 100_000 || size > 32 << 20 || offset > total || size > total - offset {
        return Err(invalid("invalid restore ZIP directory bounds"));
    }
    let directory = read(offset, size as usize)?;
    let names = [
        ("043-70867-640.dmg.aea", 11_274_289_152u64),
        ("043-70701-651.dmg.aea", 2_415_919_104u64),
    ];
    let mut found = [None, None];
    let mut position = 0usize;
    for _ in 0..count {
        let header = directory
            .get(position..position + 46)
            .filter(|h| h.starts_with(b"PK\x01\x02"))
            .ok_or_else(|| invalid("invalid ZIP directory entry"))?;
        let name_size = word(header, 28, 2)? as usize;
        let extra_size = word(header, 30, 2)? as usize;
        let comment_size = word(header, 32, 2)? as usize;
        let end = position
            .checked_add(46 + name_size + extra_size + comment_size)
            .filter(|e| *e <= directory.len())
            .ok_or_else(|| invalid("truncated ZIP directory entry"))?;
        let name = &directory[position + 46..position + 46 + name_size];
        if let Some(index) = names
            .iter()
            .position(|(expected, _)| name == expected.as_bytes())
        {
            if found[index].is_some() {
                return Err(invalid("duplicate pinned ZIP member"));
            }
            let mut compressed = word(header, 20, 4)?;
            let mut decoded = word(header, 24, 4)?;
            let mut local = word(header, 42, 4)?;
            let mut extra =
                &directory[position + 46 + name_size..position + 46 + name_size + extra_size];
            while !extra.is_empty() {
                let kind = word(extra, 0, 2)?;
                let length = word(extra, 2, 2)? as usize;
                let payload = extra
                    .get(4..4 + length)
                    .ok_or_else(|| invalid("truncated ZIP extra field"))?;
                if kind == 1 {
                    let mut cursor = 0;
                    for value in [&mut decoded, &mut compressed, &mut local] {
                        if *value == 0xffff_ffff {
                            *value = word(payload, cursor, 8)?;
                            cursor += 8;
                        }
                    }
                }
                extra = &extra[4 + length..];
            }
            if word(header, 8, 2)? & 1 != 0
                || word(header, 10, 2)? != 0
                || word(header, 34, 2)? != 0
                || compressed != names[index].1
                || decoded != names[index].1
            {
                return Err(invalid("restore member does not match pinned image"));
            }
            if local > total || total - local < 30 {
                return Err(invalid("invalid ZIP local header offset"));
            }
            let local_header = read(local, 30)?;
            if !local_header.starts_with(b"PK\x03\x04")
                || word(&local_header, 6, 2)? & 1 != 0
                || word(&local_header, 8, 2)? != 0
            {
                return Err(invalid("invalid pinned ZIP local header"));
            }
            let local_name_size = word(&local_header, 26, 2)?;
            if local_name_size != name_size as u64 || read(local + 30, name_size)? != name {
                return Err(invalid("ZIP local member name mismatch"));
            }
            let data = local
                .checked_add(30 + local_name_size + word(&local_header, 28, 2)?)
                .ok_or_else(|| invalid("ZIP data offset overflow"))?;
            if data > total || compressed > total - data {
                return Err(invalid("ZIP member exceeds restore archive"));
            }
            found[index] = Some((data, compressed));
        }
        position = end;
    }
    Ok([
        found[0].ok_or_else(|| invalid("restore filesystem member is absent"))?,
        found[1].ok_or_else(|| invalid("restore SystemOS member is absent"))?,
    ])
}
impl Read for Section {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        let wanted = (data.len() as u64).min(self.size.saturating_sub(self.position)) as usize;
        if wanted == 0 {
            return Ok(0);
        }
        let count = self
            .source
            .read_cached(&mut data[..wanted], self.offset + self.position)?;
        self.position += count as u64;
        Ok(count)
    }
}
impl Seek for Section {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.position = seek_position(self.position, self.size, from)?;
        Ok(self.position)
    }
}

fn seek_position(position: u64, size: u64, from: SeekFrom) -> io::Result<u64> {
    let value = match from {
        SeekFrom::Start(value) => i128::from(value),
        SeekFrom::Current(delta) => i128::from(position) + i128::from(delta),
        SeekFrom::End(delta) => i128::from(size) + i128::from(delta),
    };
    u64::try_from(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid image seek"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip64_reader_probes_only_selected_local_headers() {
        fn put(bytes: &mut [u8], offset: usize, value: u64, size: usize) {
            bytes[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
        }
        let total = 26_637_307_067u64;
        let members = [
            ("043-70867-640.dmg.aea", 11_274_289_152u64, 4096u64),
            ("043-70701-651.dmg.aea", 2_415_919_104u64, 12_000_000_000u64),
        ];
        let directory_offset = total - 65557 + 512;
        let mut directory = Vec::new();
        let mut ranges = Vec::new();
        for (name, size, local) in members {
            let mut extra = vec![1, 0, 24, 0];
            extra.extend_from_slice(&size.to_le_bytes());
            extra.extend_from_slice(&size.to_le_bytes());
            extra.extend_from_slice(&local.to_le_bytes());
            let mut header = vec![0; 46];
            header[..4].copy_from_slice(b"PK\x01\x02");
            put(&mut header, 20, 0xffff_ffff, 4);
            put(&mut header, 24, 0xffff_ffff, 4);
            put(&mut header, 42, 0xffff_ffff, 4);
            put(&mut header, 28, name.len() as u64, 2);
            put(&mut header, 30, extra.len() as u64, 2);
            directory.extend_from_slice(&header);
            directory.extend_from_slice(name.as_bytes());
            directory.extend_from_slice(&extra);
            let mut header = vec![0; 30];
            header[..4].copy_from_slice(b"PK\x03\x04");
            put(&mut header, 26, name.len() as u64, 2);
            header.extend_from_slice(name.as_bytes());
            ranges.push((local, header));
        }
        let zip64_offset = total - 98;
        let mut footer = vec![0; 98];
        footer[..4].copy_from_slice(b"PK\x06\x06");
        put(&mut footer, 4, 44, 8);
        put(&mut footer, 24, 2, 8);
        put(&mut footer, 32, 2, 8);
        put(&mut footer, 40, directory.len() as u64, 8);
        put(&mut footer, 48, directory_offset, 8);
        footer[56..60].copy_from_slice(b"PK\x06\x07");
        put(&mut footer, 64, zip64_offset, 8);
        put(&mut footer, 72, 1, 4);
        footer[76..80].copy_from_slice(b"PK\x05\x06");
        put(&mut footer, 84, 65535, 2);
        put(&mut footer, 86, 65535, 2);
        put(&mut footer, 88, 0xffff_ffff, 4);
        put(&mut footer, 92, 0xffff_ffff, 4);
        ranges.push((directory_offset, directory));
        ranges.push((zip64_offset, footer));
        let mut requests = Vec::new();
        let offsets = zip_members(total, |offset, size| {
            requests.push((offset, size));
            let mut bytes = vec![0; size];
            for (start, data) in &ranges {
                let left = offset.max(*start);
                let right = (offset + size as u64).min(*start + data.len() as u64);
                if right > left {
                    bytes[(left - offset) as usize..(right - offset) as usize]
                        .copy_from_slice(&data[(left - start) as usize..(right - start) as usize]);
                }
            }
            Ok(bytes)
        })
        .unwrap();
        for (index, (name, size, local)) in members.iter().enumerate() {
            assert_eq!(offsets[index], (local + 30 + name.len() as u64, *size));
        }
        assert_eq!(requests.len(), 8);
        assert!(requests.iter().map(|(_, size)| *size).sum::<usize>() < 70_000);
    }

    #[test]
    #[ignore = "reads pinned public Apple IPSW ranges, without account credentials"]
    fn live_pinned_aea_images_are_readable() {
        eprintln!("opening pinned IPSW range reader");
        let source = RemoteFile::open_restore_image().unwrap();
        eprintln!("locating pinned ZIP members");
        let (filesystem, system_os) = restore_members(&source).unwrap();
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap();
        for (section, encrypted_size, expected) in [
            (filesystem, 11_274_289_152, 14_189_330_432),
            (system_os, 2_415_919_104, 2_879_389_696),
        ] {
            eprintln!("opening AEA image with expected decoded size {expected}");
            let mut image =
                super::super::aea::Reader::open(section, encrypted_size, &client).unwrap();
            assert_eq!(image.len(), expected);
            let mut header = [0; 36];
            image.read_exact(&mut header).unwrap();
            eprintln!("decrypted image header: {header:02x?}");
        }
    }
    #[test]
    fn strict_content_range() {
        assert_eq!(content_range("bytes 3-7/10").unwrap(), (3, 7, 10));
        for value in [
            "bytes 0-0/*",
            "bytes 2-1/4",
            "bytes 0-4/4",
            "bytes +0-0/1",
            "bytes 0-0/0",
            "items 0-0/1",
            "bytes 0-0/18446744073709551615",
        ] {
            assert!(content_range(value).is_err(), "{value}");
        }
    }
    #[test]
    fn seek_bounds() {
        assert!(seek_position(0, 10, SeekFrom::Current(-1)).is_err());
        assert_eq!(seek_position(2, 10, SeekFrom::End(-1)).unwrap(), 9);
        assert_eq!(seek_position(2, 10, SeekFrom::Start(12)).unwrap(), 12);
    }

    fn server(responses: Vec<&'static str>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/image", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            use std::io::Write;
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                requests.push(String::from_utf8(request).unwrap());
                stream.write_all(response.as_bytes()).unwrap();
            }
            requests
        });
        (url, worker)
    }

    #[test]
    fn resumes_partial_body_at_first_missing_byte() {
        let (url, worker) = server(vec![
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-0/5\r\nContent-Length: 1\r\nConnection: close\r\n\r\na",
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 1-4/5\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbc",
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 3-4/5\r\nContent-Length: 2\r\nConnection: close\r\n\r\nde",
        ]);
        let reader = RemoteFile::open(&url).unwrap();
        let mut bytes = [0; 8];
        assert_eq!(reader.read_at(&mut bytes, 1).unwrap(), 4);
        assert_eq!(&bytes[..4], b"bcde");
        let requests = worker.join().unwrap();
        assert!(
            requests[2]
                .to_ascii_lowercase()
                .contains("range: bytes=3-4")
        );
    }

    #[test]
    fn refuses_full_image_or_incorrect_range() {
        let (url, worker) = server(vec![
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ]);
        assert!(RemoteFile::open(&url).is_err());
        worker.join().unwrap();
        let (url, worker) = server(vec![
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-0/5\r\nContent-Length: 1\r\nConnection: close\r\n\r\na",
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-2/5\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",
        ]);
        let reader = RemoteFile::open(&url).unwrap();
        assert!(reader.read_at(&mut [0; 3], 1).is_err());
        worker.join().unwrap();
    }
}
