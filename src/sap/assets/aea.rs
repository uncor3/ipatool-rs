//! Authenticated random access to the pinned profile-1 Apple Encrypted Archive.
//! Derived from upstream `internal/sap/assets/aea.go`; keys here are Apple's
//! public restore-image keys, never account credentials.
use aes::cipher::{KeyIvInit, StreamCipher};
use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hpke::{Deserializable, Kem, OpModeR, aead::AesGcm256, kdf::HkdfSha256, kem::DhP256HkdfSha256};
use p256::pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    io::{self, Read, Seek, SeekFrom},
};

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn u32le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}
fn u64le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}
fn read_at<R: Read + Seek>(source: &mut R, offset: u64, count: usize) -> io::Result<Vec<u8>> {
    source.seek(SeekFrom::Start(offset))?;
    let mut data = vec![0; count];
    source.read_exact(&mut data)?;
    Ok(data)
}

pub fn metadata(data: &[u8]) -> io::Result<HashMap<String, Vec<u8>>> {
    let mut rest = data;
    let mut result = HashMap::new();
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(bad("truncated AEA metadata length"));
        }
        let size = u32le(rest) as usize;
        if size < 5 || size > rest.len() {
            return Err(bad("invalid AEA metadata length"));
        }
        let record = &rest[4..size];
        let split = record
            .iter()
            .position(|b| *b == 0)
            .filter(|i| *i != 0)
            .ok_or_else(|| bad("invalid AEA metadata key"))?;
        let key =
            std::str::from_utf8(&record[..split]).map_err(|_| bad("invalid AEA metadata key"))?;
        if result
            .insert(key.into(), record[split + 1..].into())
            .is_some()
        {
            return Err(bad("duplicate AEA metadata key"));
        }
        rest = &rest[size..];
    }
    Ok(result)
}

fn restore_key(
    client: &reqwest::blocking::Client,
    metadata: &HashMap<String, Vec<u8>>,
) -> io::Result<Vec<u8>> {
    let url = metadata
        .get("com.apple.wkms.fcs-key-url")
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|v| url::Url::parse(v).ok())
        .filter(|url| {
            url.scheme() == "https"
                && url.host_str() == Some("wkms-public.apple.com")
                && url.username().is_empty()
                && url.password().is_none()
                && url.port_or_known_default() == Some(443)
        })
        .ok_or_else(|| bad("invalid Apple FCS key URL"))?;
    let response = client.get(url).send().map_err(io::Error::other)?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Apple FCS key request failed (HTTP {})", response.status()),
        ));
    }
    let mut pem = Vec::new();
    response.take(65_537).read_to_end(&mut pem)?;
    if pem.len() > 65_536 {
        return Err(bad("Apple FCS key is too large"));
    }
    let pem = std::str::from_utf8(&pem).map_err(|_| bad("invalid Apple FCS PEM"))?;
    let secret =
        p256::SecretKey::from_pkcs8_pem(pem).map_err(|_| bad("invalid Apple FCS P-256 key"))?;
    #[derive(serde::Deserialize)]
    struct Wrapped {
        #[serde(rename = "enc-request")]
        encapsulation: String,
        #[serde(rename = "wrapped-key")]
        ciphertext: String,
    }
    let wrapped: Wrapped = serde_json::from_slice(
        metadata
            .get("com.apple.wkms.fcs-response")
            .ok_or_else(|| bad("missing AEA FCS response"))?,
    )
    .map_err(|_| bad("invalid AEA FCS response"))?;
    let enc = STANDARD
        .decode(&wrapped.encapsulation)
        .map_err(|_| bad("invalid AEA encapsulation"))?;
    let ciphertext = STANDARD
        .decode(&wrapped.ciphertext)
        .map_err(|_| bad("invalid AEA wrapped key"))?;
    let key = <DhP256HkdfSha256 as Kem>::PrivateKey::from_bytes(&secret.to_bytes())
        .map_err(|_| bad("invalid AEA recipient key"))?;
    let enc = <DhP256HkdfSha256 as Kem>::EncappedKey::from_bytes(&enc)
        .map_err(|_| bad("invalid AEA encapsulation key"))?;
    let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
        &OpModeR::Base,
        &key,
        &enc,
        &[],
    )
    .map_err(|_| bad("cannot initialize AEA recipient"))?;
    let key = receiver
        .open(&ciphertext, &[])
        .map_err(|_| bad("cannot unwrap AEA image key"))?;
    if key.len() != 32 {
        return Err(bad("invalid AEA image key size"));
    }
    Ok(key)
}

fn derive<const N: usize>(key: &[u8], salt: &[u8], info: &[u8]) -> io::Result<[u8; N]> {
    let mut output = [0; N];
    Hkdf::<Sha256>::new(Some(salt), key)
        .expand(info, &mut output)
        .map_err(|_| bad("invalid AEA key expansion"))?;
    Ok(output)
}
fn indexed(label: &[u8], index: u32) -> Vec<u8> {
    let mut info = label.to_vec();
    info.extend_from_slice(&index.to_le_bytes());
    info
}
fn authenticate(key: &[u8; 80], ciphertext: &[u8], salt: &[u8], expected: &[u8]) -> io::Result<()> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key[..32]).unwrap();
    mac.update(salt);
    mac.update(ciphertext);
    mac.update(&(salt.len() as u64).to_le_bytes());
    mac.verify_slice(expected)
        .map_err(|_| bad("AEA authentication failed"))
}
fn decrypt(key: &[u8; 80], mut data: Vec<u8>) -> Vec<u8> {
    let mut cipher =
        ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&key[32..64], &key[64..]).unwrap();
    cipher.apply_keystream(&mut data);
    data
}

struct Segment {
    offset: u64,
    compressed: usize,
    decoded: usize,
    checksum: [u8; 32],
    mac: [u8; 32],
    cluster: u32,
    index: u32,
}

pub struct Reader<R> {
    source: R,
    size: u64,
    position: u64,
    segment_size: u32,
    key: [u8; 32],
    segments: Vec<Segment>,
    cache: VecDeque<(usize, Vec<u8>)>,
}

impl<R: Read + Seek> Reader<R> {
    pub fn open(
        mut source: R,
        source_size: u64,
        client: &reqwest::blocking::Client,
    ) -> io::Result<Self> {
        let header = read_at(&mut source, 0, 12)?;
        let auth_size = validate_header(&header)?;
        let auth = read_at(&mut source, 12, auth_size)?;
        let key = restore_key(client, &metadata(&auth)?)?;
        Self::with_key(source, source_size, &header, &auth, &key)
    }

    fn with_key(
        mut source: R,
        source_size: u64,
        header: &[u8],
        auth: &[u8],
        image_key: &[u8],
    ) -> io::Result<Self> {
        validate_header(header)?;
        let salt_offset = 12 + auth.len() as u64;
        let salt = read_at(&mut source, salt_offset, 32)?;
        let key = derive(image_key, &salt, &indexed(b"AEA_AMK", u32le(&header[4..])))?;
        let root_offset = salt_offset + 32;
        let root = read_at(&mut source, root_offset, 112)?;
        let root_key = derive(&key, &[], b"AEA_RHEK")?;
        let mut mac_salt = root[80..112].to_vec();
        mac_salt.extend_from_slice(auth);
        authenticate(&root_key, &root[32..80], &mac_salt, &root[..32])?;
        let plain = decrypt(&root_key, root[32..80].into());
        let size = u64le(&plain);
        let segment_size = u32le(&plain[16..]);
        let per_cluster = u32le(&plain[20..]);
        if size == 0
            || size > i64::MAX as u64
            || u64le(&plain[8..]) != source_size
            || segment_size == 0
            || segment_size > 64 << 20
            || per_cluster == 0
            || per_cluster > 16_384
            || plain[24] != b'e'
            || plain[25] != 2
        {
            return Err(bad("unsupported or invalid AEA root layout"));
        }
        let count = size.div_ceil(segment_size as u64);
        if count > 1_000_000 {
            return Err(bad("AEA segment count exceeds limit"));
        }
        let mut reader = Self {
            source,
            size,
            position: 0,
            segment_size,
            key,
            segments: Vec::with_capacity(count as usize),
            cache: VecDeque::new(),
        };
        reader.index(
            root_offset + 112,
            root[80..112].try_into().unwrap(),
            source_size,
            per_cluster,
        )?;
        Ok(reader)
    }

    fn index(
        &mut self,
        mut offset: u64,
        mut mac: [u8; 32],
        source_size: u64,
        per_cluster: u32,
    ) -> io::Result<()> {
        let mut output = 0u64;
        let mut cluster = 0u32;
        let encrypted_size = per_cluster as usize * 40;
        let header_size = encrypted_size + 32 + per_cluster as usize * 32;
        while output < self.size {
            if offset > source_size || header_size as u64 > source_size - offset {
                return Err(bad("AEA cluster header exceeds image"));
            }
            let raw = read_at(&mut self.source, offset, header_size)?;
            let cluster_key: [u8; 32] = derive(&self.key, &[], &indexed(b"AEA_CK", cluster))?;
            let key = derive(&cluster_key, &[], b"AEA_CHEK")?;
            authenticate(&key, &raw[..encrypted_size], &raw[encrypted_size..], &mac)?;
            let headers = decrypt(&key, raw[..encrypted_size].into());
            let mut data_offset = offset + header_size as u64;
            let mut saw_empty = false;
            for index in 0..per_cluster {
                let segment = &headers[index as usize * 40..][..40];
                let decoded = u32le(segment) as usize;
                let compressed = u32le(&segment[4..]) as usize;
                if decoded == 0 {
                    if compressed != 0 {
                        return Err(bad("AEA empty segment has encrypted data"));
                    }
                    saw_empty = true;
                    continue;
                }
                let expected = (self.size - output).min(self.segment_size as u64) as usize;
                if saw_empty
                    || decoded != expected
                    || compressed == 0
                    || compressed > (64 << 20)
                    || data_offset > source_size
                    || compressed as u64 > source_size - data_offset
                {
                    return Err(bad("invalid AEA segment layout"));
                }
                self.segments.push(Segment {
                    offset: data_offset,
                    decoded,
                    compressed,
                    checksum: segment[8..40].try_into().unwrap(),
                    mac: raw[encrypted_size + 32 + index as usize * 32..][..32]
                        .try_into()
                        .unwrap(),
                    cluster,
                    index,
                });
                output += decoded as u64;
                data_offset += compressed as u64;
                if output > self.size {
                    return Err(bad("AEA segments exceed output"));
                }
            }
            if saw_empty && output != self.size {
                return Err(bad("missing AEA output segments"));
            }
            mac.copy_from_slice(&raw[encrypted_size..encrypted_size + 32]);
            offset = data_offset;
            cluster += 1;
        }
        if self.segments.len() as u64 != self.size.div_ceil(self.segment_size as u64) {
            return Err(bad("incomplete AEA segment index"));
        }
        Ok(())
    }

    fn segment(&mut self, index: usize) -> io::Result<&[u8]> {
        if let Some(position) = self.cache.iter().position(|(i, _)| *i == index) {
            // FIFO matches the upstream bounded decoded-segment cache.
            return Ok(&self.cache[position].1);
        }
        let segment = self
            .segments
            .get(index)
            .ok_or_else(|| bad("missing AEA segment"))?;
        let encrypted = read_at(&mut self.source, segment.offset, segment.compressed)?;
        let cluster_key: [u8; 32] = derive(&self.key, &[], &indexed(b"AEA_CK", segment.cluster))?;
        let key = derive(&cluster_key, &[], &indexed(b"AEA_SK", segment.index))?;
        authenticate(&key, &encrypted, &[], &segment.mac)?;
        let compressed = decrypt(&key, encrypted);
        let decoded = if segment.compressed == segment.decoded {
            compressed
        } else {
            let mut result = Vec::with_capacity(segment.decoded);
            let mut writer = BoundedOutput {
                bytes: &mut result,
                maximum: segment.decoded,
            };
            lzfse_rust::LzfseRingDecoder::default()
                .decode(&mut compressed.as_slice(), &mut writer)
                .map_err(|_| bad("invalid AEA LZFSE segment"))?;
            result
        };
        if decoded.len() != segment.decoded
            || Sha256::digest(&decoded).as_slice() != segment.checksum
        {
            return Err(bad("AEA segment failed checksum verification"));
        }
        if self.cache.len() == 64 {
            self.cache.pop_front();
        }
        self.cache.push_back((index, decoded));
        Ok(&self.cache.back().unwrap().1)
    }

    pub fn len(&self) -> u64 {
        self.size
    }
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

fn validate_header(header: &[u8]) -> io::Result<usize> {
    if header.len() != 12 || &header[..4] != b"AEA1" || u32le(&header[4..]) & 0xffffff != 1 {
        return Err(bad("unsupported AEA header/profile"));
    }
    let length = u32le(&header[8..]) as usize;
    if length > 1 << 20 {
        return Err(bad("AEA authentication metadata exceeds limit"));
    }
    Ok(length)
}

struct BoundedOutput<'a> {
    bytes: &'a mut Vec<u8>,
    maximum: usize,
}
impl io::Write for BoundedOutput<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(bad("AEA decoded segment exceeds declared size"));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<R: Read + Seek> Read for Reader<R> {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        let wanted = (data.len() as u64).min(self.size.saturating_sub(self.position)) as usize;
        let mut done = 0;
        while done < wanted {
            let index = (self.position / self.segment_size as u64) as usize;
            let inside = (self.position % self.segment_size as u64) as usize;
            let segment = self.segment(index)?;
            let count = (wanted - done).min(segment.len() - inside);
            data[done..done + count].copy_from_slice(&segment[inside..inside + count]);
            done += count;
            self.position += count as u64;
        }
        Ok(done)
    }
}
impl<R: Read + Seek> Seek for Reader<R> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(v) => i128::from(v),
            SeekFrom::Current(v) => i128::from(self.position) + i128::from(v),
            SeekFrom::End(v) => i128::from(self.size) + i128::from(v),
        };
        self.position = u64::try_from(position).map_err(|_| bad("invalid AEA seek"))?;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_records_are_bounded_and_unique() {
        assert_eq!(metadata(&[7, 0, 0, 0, b'a', 0, b'b']).unwrap()["a"], b"b");
        for data in [
            vec![0],
            vec![4, 0, 0, 0],
            vec![8, 0, 0, 0, b'a', 0, b'b'],
            vec![7, 0, 0, 0, b'a', 0, b'b', 7, 0, 0, 0, b'a', 0, b'c'],
        ] {
            assert!(metadata(&data).is_err());
        }
    }
    #[test]
    fn authentication_covers_salt_and_ciphertext() {
        let key = derive(&[1; 32], &[], b"test").unwrap();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key[..32]).unwrap();
        mac.update(b"salt");
        mac.update(b"data");
        mac.update(&4u64.to_le_bytes());
        let tag = mac.finalize().into_bytes();
        assert!(authenticate(&key, b"data", b"salt", &tag).is_ok());
        assert!(authenticate(&key, b"Data", b"salt", &tag).is_err());
        assert!(authenticate(&key, b"data", b"Salt", &tag).is_err());
    }

    fn tag(key: &[u8; 80], ciphertext: &[u8], salt: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key[..32]).unwrap();
        mac.update(salt);
        mac.update(ciphertext);
        mac.update(&(salt.len() as u64).to_le_bytes());
        mac.finalize().into_bytes().into()
    }

    fn fixture() -> Vec<u8> {
        let key: [u8; 32] = derive(&[7; 32], &[3; 32], &indexed(b"AEA_AMK", 1)).unwrap();
        let mut clusters = Vec::new();
        let mut next_mac = [0; 32];
        for cluster in (0..2).rev() {
            let cluster_key: [u8; 32] = derive(&key, &[], &indexed(b"AEA_CK", cluster)).unwrap();
            let segment_key = derive(&cluster_key, &[], &indexed(b"AEA_SK", 0)).unwrap();
            let plain = if cluster == 0 { b"abcd" } else { b"efgh" };
            let ciphertext = decrypt(&segment_key, plain.to_vec());
            let segment_mac = tag(&segment_key, &ciphertext, &[]);
            let mut header = Vec::new();
            header.extend_from_slice(&4u32.to_le_bytes());
            header.extend_from_slice(&4u32.to_le_bytes());
            header.extend_from_slice(&Sha256::digest(plain));
            let header_key = derive(&cluster_key, &[], b"AEA_CHEK").unwrap();
            let encrypted = decrypt(&header_key, header);
            let mut salt = next_mac.to_vec();
            salt.extend_from_slice(&segment_mac);
            next_mac = tag(&header_key, &encrypted, &salt);
            let mut data = encrypted;
            data.extend_from_slice(&salt);
            data.extend_from_slice(&ciphertext);
            clusters.insert(0, data);
        }
        let total = 12 + 32 + 112 + clusters.iter().map(Vec::len).sum::<usize>();
        let mut root = vec![0; 48];
        root[..8].copy_from_slice(&8u64.to_le_bytes());
        root[8..16].copy_from_slice(&(total as u64).to_le_bytes());
        root[16..20].copy_from_slice(&4u32.to_le_bytes());
        root[20..24].copy_from_slice(&1u32.to_le_bytes());
        root[24] = b'e';
        root[25] = 2;
        let root_key = derive(&key, &[], b"AEA_RHEK").unwrap();
        let root = decrypt(&root_key, root);
        let mut archive = b"AEA1".to_vec();
        archive.extend_from_slice(&1u32.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&[3; 32]);
        archive.extend_from_slice(&tag(&root_key, &root, &next_mac));
        archive.extend_from_slice(&root);
        archive.extend_from_slice(&next_mac);
        for data in clusters {
            archive.extend_from_slice(&data);
        }
        archive
    }

    fn open_fixture(bytes: Vec<u8>) -> io::Result<Reader<std::io::Cursor<Vec<u8>>>> {
        let size = bytes.len() as u64;
        let header = bytes[..12].to_vec();
        Reader::with_key(std::io::Cursor::new(bytes), size, &header, &[], &[7; 32])
    }

    #[test]
    fn authenticated_random_access_across_clusters() {
        let mut reader = open_fixture(fixture()).unwrap();
        reader.seek(SeekFrom::Start(2)).unwrap();
        let mut bytes = [0; 5];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"cdefg");
        reader.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(&bytes, b"abcdefgh");
        reader.seek(SeekFrom::End(3)).unwrap();
        assert_eq!(reader.read(&mut [0; 1]).unwrap(), 0);
    }

    #[test]
    fn rejects_corrupted_root_cluster_and_segment() {
        for position in [44, 156] {
            let mut bytes = fixture();
            bytes[position] ^= 1;
            assert!(open_fixture(bytes).is_err());
        }
        let mut bytes = fixture();
        *bytes.last_mut().unwrap() ^= 1;
        let mut reader = open_fixture(bytes).unwrap();
        let mut output = Vec::new();
        assert!(reader.read_to_end(&mut output).is_err());
    }
}
