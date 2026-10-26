//! Read-only sealed APFS traversal for the pinned restore images.
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    io::{self, Read, Seek, SeekFrom},
    rc::Rc,
};

const BLOCK: u64 = 4096;
fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn u16le(v: &[u8]) -> u16 {
    u16::from_le_bytes(v[..2].try_into().unwrap())
}
fn u32le(v: &[u8]) -> u32 {
    u32::from_le_bytes(v[..4].try_into().unwrap())
}
fn u64le(v: &[u8]) -> u64 {
    u64::from_le_bytes(v[..8].try_into().unwrap())
}
fn part(data: &[u8], offset: usize, size: usize) -> io::Result<&[u8]> {
    data.get(
        offset
            ..offset
                .checked_add(size)
                .ok_or_else(|| bad("APFS range overflow"))?,
    )
    .ok_or_else(|| bad("truncated APFS record"))
}

pub trait ReadAt {
    fn read_exact_at(&self, offset: u64, data: &mut [u8]) -> io::Result<()>;
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
pub type File = Rc<dyn ReadAt>;
struct Device<R> {
    source: RefCell<R>,
    size: u64,
    blocks: RefCell<VecDeque<(u64, Vec<u8>)>>,
}
impl<R: Read + Seek> ReadAt for Device<R> {
    fn read_exact_at(&self, offset: u64, data: &mut [u8]) -> io::Result<()> {
        if offset > self.size || data.len() as u64 > self.size - offset {
            return Err(bad("APFS read exceeds image"));
        }
        let mut source = self.source.borrow_mut();
        source.seek(SeekFrom::Start(offset))?;
        source.read_exact(data)
    }
    fn len(&self) -> u64 {
        self.size
    }
}
impl<R: Read + Seek> Device<R> {
    fn block(&self, address: u64, hash: Option<&[u8]>) -> io::Result<Vec<u8>> {
        if let Some((_, data)) = self.blocks.borrow().iter().find(|(a, _)| *a == address) {
            if hash.is_some_and(|h| h != Sha256::digest(data).as_slice()) {
                return Err(bad("sealed APFS node hash mismatch"));
            }
            return Ok(data.clone());
        }
        let offset = address
            .checked_mul(BLOCK)
            .ok_or_else(|| bad("APFS block overflow"))?;
        let mut data = vec![0; BLOCK as usize];
        self.read_exact_at(offset, &mut data)?;
        if let Some(hash) = hash {
            if hash != Sha256::digest(&data).as_slice() {
                return Err(bad("sealed APFS node hash mismatch"));
            }
        } else if data[..32].iter().any(|b| *b != 0) && !checksum(&data) {
            return Err(bad("APFS object checksum mismatch"));
        }
        let mut cache = self.blocks.borrow_mut();
        if cache.len() == 128 {
            cache.pop_front();
        }
        cache.push_back((address, data.clone()));
        Ok(data)
    }
}

fn checksum(data: &[u8]) -> bool {
    let mut sum1 = 0u64;
    let mut sum2 = 0u64;
    for word in data[8..].chunks_exact(4) {
        sum1 = (sum1 + u32le(word) as u64) % 0xffff_ffff;
        sum2 = (sum2 + sum1) % 0xffff_ffff;
    }
    let first = 0xffff_ffff - ((sum1 + sum2) % 0xffff_ffff);
    let second = 0xffff_ffff - ((sum1 + first) % 0xffff_ffff);
    u64le(data) == (second << 32) | first
}

struct Node {
    leaf: bool,
    records: Vec<(Vec<u8>, Vec<u8>)>,
}
impl Node {
    fn parse(data: &[u8], fixed_key: usize, fixed_value: usize) -> io::Result<Self> {
        if data.len() != BLOCK as usize {
            return Err(bad("invalid APFS tree block size"));
        }
        let flags = u16le(&data[32..]);
        let leaf = flags & 2 != 0;
        let count = u32le(&data[36..]) as usize;
        let table = 56 + u16le(&data[40..]) as usize;
        let table_size = u16le(&data[42..]) as usize;
        let keys = table
            .checked_add(table_size)
            .ok_or_else(|| bad("APFS key offset overflow"))?;
        let end = data.len() - if flags & 1 != 0 { 40 } else { 0 };
        let stride = if flags & 4 != 0 { 4 } else { 8 };
        if count > 1000 || count * stride > table_size || keys > end {
            return Err(bad("invalid APFS node table"));
        }
        let mut records = Vec::with_capacity(count);
        for i in 0..count {
            let record = part(data, table + i * stride, stride)?;
            let key_offset = u16le(record) as usize;
            let (key_size, value_offset, value_size) = if stride == 4 {
                (
                    fixed_key,
                    u16le(&record[2..]) as usize,
                    if leaf { fixed_value } else { 8 },
                )
            } else {
                (
                    u16le(&record[2..]) as usize,
                    u16le(&record[4..]) as usize,
                    u16le(&record[6..]) as usize,
                )
            };
            if value_offset > end {
                return Err(bad("invalid APFS value offset"));
            }
            records.push((
                part(data, keys + key_offset, key_size)?.into(),
                part(data, end - value_offset, value_size)?.into(),
            ));
        }
        Ok(Self { leaf, records })
    }
}

pub struct Volume<R> {
    device: Rc<Device<R>>,
    omap: u64,
    xid: u64,
    root: u64,
    root_oid: u64,
    fext: u64,
}
impl<R: Read + Seek + 'static> Volume<R> {
    pub fn open(source: R, size: u64) -> io::Result<Self> {
        let device = Rc::new(Device {
            source: RefCell::new(source),
            size,
            blocks: RefCell::new(VecDeque::new()),
        });
        let mut nx = device.block(0, None)?;
        if &nx[32..36] != b"NXSB" || u32le(&nx[36..]) as u64 != BLOCK {
            return Err(bad("expected a 4096-byte APFS container"));
        }
        let count = u32le(&nx[104..]) as u64;
        let base = u64le(&nx[112..]);
        if count > 65_536 || count & 0x8000_0000 != 0 {
            return Err(bad("unsupported APFS checkpoint layout"));
        }
        for index in 0..count {
            let block = device.block(
                base.checked_add(index)
                    .ok_or_else(|| bad("APFS checkpoint overflow"))?,
                None,
            );
            if let Ok(candidate) = block
                && &candidate[32..36] == b"NXSB"
                && u64le(&candidate[16..]) > u64le(&nx[16..])
            {
                nx = candidate;
            }
        }
        let container_map = device.block(u64le(&nx[160..]), None)?;
        let volume_oid = nx[184..984]
            .chunks_exact(8)
            .map(u64le)
            .find(|id| *id != 0)
            .ok_or_else(|| bad("APFS container has no volume"))?;
        let volume_address = omap_lookup(
            &device,
            u64le(&container_map[48..]),
            volume_oid,
            u64le(&nx[16..]),
        )?;
        let volume = device.block(volume_address, None)?;
        if &volume[32..36] != b"APSB" {
            return Err(bad("invalid APFS volume superblock"));
        }
        let map = device.block(u64le(&volume[128..]), None)?;
        let omap = u64le(&map[48..]);
        let xid = u64le(&map[16..]);
        let root_oid = u64le(&volume[136..]);
        let root = omap_lookup(&device, omap, root_oid, xid)?;
        Ok(Self {
            device,
            omap,
            xid,
            root,
            root_oid,
            fext: u64le(&volume[1032..]),
        })
    }

    fn records(&self, object: u64) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut result = Vec::new();
        self.collect(
            self.root,
            None,
            object,
            false,
            &mut HashSet::new(),
            0,
            &mut result,
        )?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn collect(
        &self,
        address: u64,
        hash: Option<&[u8]>,
        object: u64,
        physical: bool,
        visited: &mut HashSet<u64>,
        depth: usize,
        result: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> io::Result<()> {
        if depth > 32 || !visited.insert(address) {
            return Err(bad("cyclic or excessive APFS tree depth"));
        }
        let data = self.device.block(address, hash)?;
        let node = Node::parse(&data, 16, 16)?;
        let object_id = |key: &[u8]| -> io::Result<u64> {
            let id = u64le(part(key, 0, 8)?);
            Ok(if physical {
                id
            } else {
                id & 0x0fff_ffff_ffff_ffff
            })
        };
        if node.leaf {
            for (key, value) in node.records {
                if object_id(&key)? == object {
                    result.push((key, value));
                }
            }
            return Ok(());
        }
        for (i, (key, value)) in node.records.iter().enumerate() {
            let lower = object_id(key)?;
            let upper = if i + 1 < node.records.len() {
                object_id(&node.records[i + 1].0)?
            } else {
                u64::MAX
            };
            if object < lower || object > upper {
                continue;
            }
            let child = u64le(part(value, 0, 8)?);
            let hash = if !physical && value.len() == 40 {
                Some(&value[8..40])
            } else {
                None
            };
            let child = if physical {
                child
            } else {
                let oid = if hash.is_some() {
                    self.root_oid
                        .checked_add(child)
                        .ok_or_else(|| bad("APFS child overflow"))?
                } else {
                    child
                };
                omap_lookup(&self.device, self.omap, oid, self.xid)?
            };
            self.collect(child, hash, object, physical, visited, depth + 1, result)?;
        }
        Ok(())
    }

    fn extents(&self, object: u64) -> io::Result<Vec<Extent>> {
        let records = if self.fext == 0 {
            self.records(object)?
        } else {
            let mut records = Vec::new();
            self.collect(
                self.fext,
                None,
                object,
                true,
                &mut HashSet::new(),
                0,
                &mut records,
            )?;
            records
        };
        let mut extents = Vec::new();
        for (key, value) in records {
            if self.fext == 0 && u64le(&key) >> 60 != 8 {
                continue;
            }
            let logical = u64le(part(&key, 8, 8)?);
            let length = u64le(part(&value, 0, 8)?) & 0x00ff_ffff_ffff_ffff;
            let physical = u64le(part(&value, 8, 8)?)
                .checked_mul(BLOCK)
                .ok_or_else(|| bad("APFS extent overflow"))?;
            extents.push(Extent {
                logical,
                physical,
                length,
            });
        }
        extents.sort_by_key(|e| e.logical);
        Ok(extents)
    }

    pub fn open_file(&self, path: &str) -> io::Result<File> {
        let mut object = 2;
        for name in path.trim_matches('/').split('/') {
            let mut found = None;
            for (key, value) in self.records(object)? {
                if u64le(&key) >> 60 != 9 {
                    continue;
                }
                let length = (u32le(part(&key, 8, 4)?) & 0x3ff) as usize;
                let bytes = part(&key, 12, length)?;
                if bytes.strip_suffix(&[0]).unwrap_or(bytes) == name.as_bytes() {
                    found = Some(u64le(part(&value, 0, 8)?));
                    break;
                }
            }
            object = found.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("APFS path component {name} not found"),
                )
            })?;
        }
        let records = self.records(object)?;
        let inode = records
            .iter()
            .find(|(key, _)| u64le(key) >> 60 == 3)
            .map(|(_, value)| value)
            .ok_or_else(|| bad("APFS file has no inode"))?;
        let private = u64le(part(inode, 8, 8)?);
        let mut size = u64le(part(inode, 84, 8)?);
        if inode.len() >= 96 {
            let count = u16le(&inode[92..]) as usize;
            let mut offset = 96 + count * 4;
            for i in 0..count {
                let field = part(inode, 96 + i * 4, 4)?;
                let length = u16le(&field[2..]) as usize;
                if field[0] == 8 {
                    size = u64le(part(inode, offset, 8)?);
                }
                offset = offset
                    .checked_add((length + 7) & !7)
                    .ok_or_else(|| bad("APFS inode field overflow"))?;
            }
        }
        let mut attrs = HashMap::new();
        for (key, value) in &records {
            if u64le(key) >> 60 == 4 {
                let len = u16le(part(key, 8, 2)?) as usize;
                let name = part(key, 10, len)?;
                attrs.insert(name.strip_suffix(&[0]).unwrap_or(name).to_vec(), value);
            }
        }
        if let Some(attr) = attrs.get(b"com.apple.decmpfs".as_slice()) {
            let header = part(attr, 4, 16)?;
            if &header[..4] != b"fpmc" {
                return Err(bad("invalid APFS compression header"));
            }
            let method = u32le(&header[4..]);
            size = u64le(&header[8..]);
            if ![8, 12, 14].contains(&method) {
                return Err(bad("unsupported APFS compression method"));
            }
            let resource = attrs
                .get(b"com.apple.ResourceFork".as_slice())
                .ok_or_else(|| bad("compressed APFS file has no resource fork"))?;
            if u16le(part(resource, 0, 2)?) & 1 == 0 {
                return Err(bad("expected APFS resource data stream"));
            }
            let object = u64le(part(resource, 4, 8)?);
            let resource_size = u64le(part(resource, 12, 8)?);
            let fork: File = Rc::new(Fork::new(
                self.device.clone(),
                self.extents(object)?,
                resource_size,
            )?);
            return Ok(Rc::new(Compressed::open(fork, size, method)?));
        }
        Ok(Rc::new(Fork::new(
            self.device.clone(),
            self.extents(private)?,
            size,
        )?))
    }
}

fn omap_lookup<R: Read + Seek>(
    device: &Device<R>,
    mut root: u64,
    object: u64,
    xid: u64,
) -> io::Result<u64> {
    let mut visited = HashSet::new();
    for _ in 0..32 {
        if !visited.insert(root) {
            return Err(bad("cyclic APFS object map"));
        }
        let node = Node::parse(&device.block(root, None)?, 16, 16)?;
        let mut best = None;
        for (key, value) in &node.records {
            let candidate = (u64le(part(key, 0, 8)?), u64le(part(key, 8, 8)?));
            if candidate <= (object, xid) {
                best = Some((candidate, value));
            } else {
                break;
            }
        }
        let (candidate, value) = best.ok_or_else(|| bad("APFS object is unmapped"))?;
        if node.leaf {
            if candidate.0 != object || u32le(part(value, 0, 4)?) & 1 != 0 {
                return Err(bad("APFS object is absent or deleted"));
            }
            return Ok(u64le(part(value, 8, 8)?));
        }
        root = u64le(part(value, 0, 8)?);
    }
    Err(bad("APFS object map exceeds maximum depth"))
}

struct Extent {
    logical: u64,
    physical: u64,
    length: u64,
}
struct Fork {
    source: File,
    extents: Vec<Extent>,
    size: u64,
}
impl Fork {
    fn new(source: File, extents: Vec<Extent>, size: u64) -> io::Result<Self> {
        let mut position = 0;
        for extent in &extents {
            if extent.logical != position
                || extent.physical == 0
                || extent.length == 0
                || extent.physical > source.len()
                || extent.length > source.len() - extent.physical
            {
                return Err(bad("invalid or sparse APFS extents"));
            }
            position = position
                .checked_add(extent.length)
                .ok_or_else(|| bad("APFS extent overflow"))?;
        }
        if position < size {
            return Err(bad("APFS extents do not cover file"));
        }
        Ok(Self {
            source,
            extents,
            size,
        })
    }
}
impl ReadAt for Fork {
    fn len(&self) -> u64 {
        self.size
    }
    fn read_exact_at(&self, mut offset: u64, mut output: &mut [u8]) -> io::Result<()> {
        if offset > self.size || output.len() as u64 > self.size - offset {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        while !output.is_empty() {
            let index = self
                .extents
                .partition_point(|e| e.logical + e.length <= offset);
            let extent = self
                .extents
                .get(index)
                .ok_or_else(|| bad("missing APFS extent"))?;
            let count = (output.len() as u64).min(extent.logical + extent.length - offset) as usize;
            self.source.read_exact_at(
                extent.physical + offset - extent.logical,
                &mut output[..count],
            )?;
            output = &mut output[count..];
            offset += count as u64;
        }
        Ok(())
    }
}

struct Compressed {
    source: File,
    size: u64,
    method: u32,
    offsets: Vec<u32>,
    cache: RefCell<VecDeque<(usize, Vec<u8>)>>,
}
impl Compressed {
    fn open(source: File, size: u64, method: u32) -> io::Result<Self> {
        let count = size
            .div_ceil(65536)
            .checked_add(1)
            .ok_or_else(|| bad("APFS compression index overflow"))?;
        if count > 1_000_000 || count * 4 > source.len() {
            return Err(bad("invalid APFS compression index size"));
        }
        let mut table = vec![0; (count * 4) as usize];
        source.read_exact_at(0, &mut table)?;
        let offsets: Vec<u32> = table.chunks_exact(4).map(u32le).collect();
        if offsets[0] as u64 != count * 4
            || offsets.last().copied().unwrap() as u64 != source.len()
            || offsets
                .windows(2)
                .any(|w| w[1] <= w[0] || w[1] - w[0] > 65537)
        {
            return Err(bad("invalid APFS compression block bounds"));
        }
        Ok(Self {
            source,
            size,
            method,
            offsets,
            cache: RefCell::new(VecDeque::new()),
        })
    }
    fn block(&self, index: usize) -> io::Result<Vec<u8>> {
        if let Some((_, data)) = self.cache.borrow().iter().find(|(i, _)| *i == index) {
            return Ok(data.clone());
        }
        let offsets = self
            .offsets
            .get(index..index + 2)
            .ok_or_else(|| bad("missing APFS compressed block"))?;
        let mut encoded = vec![0; (offsets[1] - offsets[0]) as usize];
        self.source.read_exact_at(offsets[0] as u64, &mut encoded)?;
        let expected = (self.size - index as u64 * 65536).min(65536) as usize;
        let decoded =
            super::compression::decode(&encoded, self.method, expected).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "APFS codec {} block {index} ({} encoded, {expected} decoded): {error}",
                        self.method,
                        encoded.len()
                    ),
                )
            })?;
        if decoded.len() != expected {
            return Err(bad("APFS decompressed block has wrong size"));
        }
        let mut cache = self.cache.borrow_mut();
        if cache.len() == 128 {
            cache.pop_front();
        }
        cache.push_back((index, decoded.clone()));
        Ok(decoded)
    }
}
impl ReadAt for Compressed {
    fn len(&self) -> u64 {
        self.size
    }
    fn read_exact_at(&self, mut offset: u64, mut output: &mut [u8]) -> io::Result<()> {
        if offset > self.size || output.len() as u64 > self.size - offset {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        while !output.is_empty() {
            let block = self.block((offset / 65536) as usize)?;
            let inside = (offset % 65536) as usize;
            let count = output.len().min(block.len() - inside);
            output[..count].copy_from_slice(&block[inside..inside + count]);
            output = &mut output[count..];
            offset += count as u64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Bytes(Vec<u8>);
    impl ReadAt for Bytes {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, offset: u64, data: &mut [u8]) -> io::Result<()> {
            data.copy_from_slice(part(&self.0, offset as usize, data.len())?);
            Ok(())
        }
    }
    #[test]
    fn rejects_sparse_overlapping_and_out_of_image_extents() {
        let source: File = Rc::new(Bytes(vec![0; 16384]));
        for extents in [
            vec![Extent {
                logical: 1,
                physical: 4096,
                length: 4,
            }],
            vec![Extent {
                logical: 0,
                physical: 0,
                length: 4,
            }],
            vec![Extent {
                logical: 0,
                physical: 16382,
                length: 4,
            }],
            vec![
                Extent {
                    logical: 0,
                    physical: 4096,
                    length: 4,
                },
                Extent {
                    logical: 3,
                    physical: 8192,
                    length: 4,
                },
            ],
        ] {
            assert!(Fork::new(source.clone(), extents, 4).is_err());
        }
    }
    #[test]
    fn fork_reads_across_physical_extents() {
        let mut bytes = vec![0; 16384];
        bytes[4096..4100].copy_from_slice(b"abcd");
        bytes[8192..8196].copy_from_slice(b"efgh");
        let fork = Fork::new(
            Rc::new(Bytes(bytes)),
            vec![
                Extent {
                    logical: 0,
                    physical: 4096,
                    length: 4,
                },
                Extent {
                    logical: 4,
                    physical: 8192,
                    length: 4,
                },
            ],
            8,
        )
        .unwrap();
        let mut output = [0; 5];
        fork.read_exact_at(2, &mut output).unwrap();
        assert_eq!(&output, b"cdefg");
        assert!(fork.read_exact_at(7, &mut output).is_err());
    }
    #[test]
    fn compressed_fork_validates_index_and_decoded_size() {
        let source: File = Rc::new(Bytes(vec![8, 0, 0, 0, 11, 0, 0, 0, 255, b'a', b'b']));
        let fork = Compressed::open(source, 2, 12).unwrap();
        let mut output = [0; 2];
        fork.read_exact_at(0, &mut output).unwrap();
        assert_eq!(&output, b"ab");
        let source: File = Rc::new(Bytes(vec![8, 0, 0, 0, 7, 0, 0, 0]));
        assert!(Compressed::open(source, 2, 12).is_err());
    }
    #[test]
    fn node_rejects_invalid_table_and_value_ranges() {
        let mut block = vec![0; 4096];
        block[36..40].copy_from_slice(&1001u32.to_le_bytes());
        assert!(Node::parse(&block, 16, 16).is_err());
        block[36..40].copy_from_slice(&1u32.to_le_bytes());
        block[42..44].copy_from_slice(&8u16.to_le_bytes());
        block[60..62].copy_from_slice(&65535u16.to_le_bytes());
        assert!(Node::parse(&block, 16, 16).is_err());
    }
}
