//! Bounded arm64e shared-cache mapping and v5 slide decoding.
use super::apfs::File;
use std::io;

mod export;

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}
fn u64le(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}
fn read(file: &File, offset: u64, size: usize) -> io::Result<Vec<u8>> {
    if offset > file.len() || size as u64 > file.len() - offset {
        return Err(bad("dyld range exceeds member"));
    }
    let mut bytes = vec![0; size];
    file.read_exact_at(offset, &mut bytes)?;
    Ok(bytes)
}

pub struct Mapping {
    pub address: u64,
    pub size: u64,
    pub offset: u64,
    slide_offset: u64,
    slide_size: u64,
}
struct Member {
    file: File,
    uuid: [u8; 16],
    mappings: Vec<Mapping>,
    header: Vec<u8>,
}
pub struct Cache {
    members: Vec<Member>,
}
impl Member {
    fn open(file: File) -> io::Result<Self> {
        let header = read(&file, 0, 568)?;
        let magic_end = header[..16]
            .iter()
            .rposition(|b| *b != 0)
            .map_or(0, |i| i + 1);
        if &header[..magic_end] != b"dyld_v1  arm64e" {
            return Err(bad("unsupported dyld shared-cache format"));
        }
        let offset = u32le(&header[312..]) as u64;
        let count = u32le(&header[316..]) as usize;
        if count == 0 || count > 64 {
            return Err(bad("invalid dyld mapping count"));
        }
        let encoded = read(&file, offset, count * 56)?;
        let mut mappings = Vec::new();
        for entry in encoded.chunks_exact(56) {
            let mapping = Mapping {
                address: u64le(entry),
                size: u64le(&entry[8..]),
                offset: u64le(&entry[16..]),
                slide_offset: u64le(&entry[24..]),
                slide_size: u64le(&entry[32..]),
            };
            if mapping.size == 0
                || mapping.address.checked_add(mapping.size).is_none()
                || mapping.offset > file.len()
                || mapping.size > file.len() - mapping.offset
                || mapping.slide_offset > file.len()
                || mapping.slide_size > file.len() - mapping.slide_offset
            {
                return Err(bad("invalid dyld mapping"));
            }
            mappings.push(mapping);
        }
        Ok(Self {
            uuid: header[88..104].try_into().unwrap(),
            file,
            mappings,
            header,
        })
    }
}
impl Cache {
    pub fn open(mut opener: impl FnMut(&str) -> io::Result<File>) -> io::Result<Self> {
        let primary = Member::open(opener("")?)?;
        let offset = u32le(&primary.header[392..]) as u64;
        let count = u32le(&primary.header[396..]) as usize;
        if count > 128 {
            return Err(bad("invalid dyld subcache count"));
        }
        let entries = read(&primary.file, offset, count * 56)?;
        let mut members = vec![primary];
        for entry in entries.chunks_exact(56) {
            let suffix = std::str::from_utf8(&entry[24..56])
                .map_err(|_| bad("invalid dyld suffix"))?
                .trim_end_matches('\0');
            if suffix.is_empty() || suffix.contains(['/', '\\']) {
                return Err(bad("invalid dyld suffix"));
            }
            let member = Member::open(opener(suffix)?)?;
            if member.uuid != entry[..16] {
                return Err(bad("dyld subcache UUID mismatch"));
            }
            members.push(member);
        }
        let mut common = None;
        for member in &members {
            for mapping in &member.mappings {
                if mapping.slide_size == 0 {
                    continue;
                }
                let slide = Slide::open(&member.file, mapping)?;
                if common.is_some_and(|layout| layout != (slide.page_size, slide.value_add)) {
                    return Err(bad("incompatible dyld slide layouts"));
                }
                common = Some((slide.page_size, slide.value_add));
            }
        }
        if common.is_none() {
            return Err(bad("dyld cache contains no slide information"));
        }
        Ok(Self { members })
    }

    fn mapping(&self, address: u64) -> io::Result<(&Member, &Mapping)> {
        for member in &self.members {
            for mapping in &member.mappings {
                if address >= mapping.address && address - mapping.address < mapping.size {
                    return Ok((member, mapping));
                }
            }
        }
        Err(bad("address is outside dyld cache"))
    }

    pub fn read_address(&self, mut address: u64, mut output: &mut [u8]) -> io::Result<()> {
        while !output.is_empty() {
            let (member, mapping) = self.mapping(address)?;
            let count =
                (output.len() as u64).min(mapping.size - (address - mapping.address)) as usize;
            member.file.read_exact_at(
                mapping.offset + address - mapping.address,
                &mut output[..count],
            )?;
            address = address
                .checked_add(count as u64)
                .ok_or_else(|| bad("dyld address overflow"))?;
            output = &mut output[count..];
        }
        Ok(())
    }

    pub fn image_address(&self, path: &str) -> io::Result<u64> {
        let primary = &self.members[0];
        let count = u32le(&primary.header[452..]) as usize;
        if count == 0 || count > 100_000 {
            return Err(bad("invalid dyld image table"));
        }
        let entries = read(
            &primary.file,
            u32le(&primary.header[448..]) as u64,
            count * 32,
        )?;
        for entry in entries.chunks_exact(32) {
            if cstring(&primary.file, u32le(&entry[24..]) as u64)? == path {
                let address = u64le(entry);
                self.mapping(address)?;
                return Ok(address);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "image absent from dyld cache",
        ))
    }

    pub fn rebases(&self, address: u64, size: u64) -> io::Result<Vec<(u64, u64)>> {
        let (member, mapping) = self.mapping(address)?;
        if size > mapping.size - (address - mapping.address) {
            return Err(bad("dyld slide range crosses mapping"));
        }
        if mapping.slide_size == 0 {
            return Ok(Vec::new());
        }
        let slide = Slide::open(&member.file, mapping)?;
        let start = (address - mapping.address) / slide.page_size as u64;
        let end = (address - mapping.address + size)
            .div_ceil(slide.page_size as u64)
            .min(slide.starts.len() as u64);
        let mut rebases = Vec::new();
        for page in start..end {
            let mut offset = slide.starts[page as usize] as u64;
            if offset == 0xffff {
                continue;
            }
            for _ in 0..65_536 {
                if offset + 8 > slide.page_size as u64 {
                    return Err(bad("dyld slide chain leaves page"));
                }
                let file_offset = mapping.offset + page * slide.page_size as u64 + offset;
                let raw = u64le(&read(&member.file, file_offset, 8)?);
                let pointer_address = mapping.address + page * slide.page_size as u64 + offset;
                if pointer_address >= address && pointer_address - address < size {
                    rebases.push((pointer_address, slide.decode(raw)?));
                }
                let next = (raw >> 52) & 0x7ff;
                if next == 0 {
                    break;
                }
                offset += next * 8;
            }
        }
        Ok(rebases)
    }
}

fn cstring(file: &File, offset: u64) -> io::Result<String> {
    if offset >= file.len() {
        return Err(bad("invalid dyld string offset"));
    }
    let data = read(file, offset, (file.len() - offset).min(4096) as usize)?;
    let end = data
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| bad("unterminated dyld string"))?;
    String::from_utf8(data[..end].into()).map_err(|_| bad("invalid dyld string"))
}

struct Slide {
    page_size: u32,
    value_add: u64,
    starts: Vec<u16>,
}
impl Slide {
    fn open(file: &File, mapping: &Mapping) -> io::Result<Self> {
        if mapping.slide_size < 24 {
            return Err(bad("truncated dyld slide header"));
        }
        let header = read(file, mapping.slide_offset, 24)?;
        let page_size = u32le(&header[4..]);
        let count = u32le(&header[8..]) as u64;
        if u32le(&header) != 5
            || !page_size.is_power_of_two()
            || page_size > 65536
            || count * 2 > mapping.slide_size - 24
            || count > mapping.size.div_ceil(page_size as u64)
        {
            return Err(bad("invalid dyld v5 slide layout"));
        }
        let encoded = read(file, mapping.slide_offset + 24, (count * 2) as usize)?;
        let starts = encoded
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
            .collect();
        Ok(Self {
            page_size,
            value_add: u64le(&header[16..]),
            starts,
        })
    }
    fn decode(&self, pointer: u64) -> io::Result<u64> {
        if pointer == 0 {
            return Ok(0);
        }
        let mut target = pointer & ((1 << 34) - 1);
        if pointer >> 63 == 0 {
            target |= ((pointer >> 34) & 255) << 56;
        }
        self.value_add
            .checked_add(target)
            .ok_or_else(|| bad("dyld pointer overflow"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v5_authentication_bits_and_chain_bits_are_removed() {
        let slide = Slide {
            page_size: 16384,
            value_add: 0x180000000,
            starts: Vec::new(),
        };
        assert_eq!(slide.decode(0).unwrap(), 0);
        assert_eq!(
            slide.decode((1 << 63) | (17 << 52) | 0x1234).unwrap(),
            0x180001234
        );
        assert_eq!(
            slide.decode((0xab << 34) | 0x1234).unwrap(),
            0xab00000180001234
        );
    }
}
