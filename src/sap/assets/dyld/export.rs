//! Reconstruct the standalone Mach-O layout used by upstream go-macho Export.
use super::*;

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn align(value: usize, boundary: usize) -> io::Result<usize> {
    value
        .checked_add(boundary - 1)
        .map(|v| v & !(boundary - 1))
        .ok_or_else(|| bad("Mach-O size overflow"))
}
fn name(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len())]
}
struct Segment {
    command: usize,
    address: u64,
    memory: u64,
    original: usize,
    offset: usize,
    size: usize,
}

impl Cache {
    pub fn export_image(&self, path: &str) -> io::Result<Vec<u8>> {
        let address = self.image_address(path)?;
        let mut header = vec![0; 32];
        self.read_address(address, &mut header)?;
        if u32le(&header) != 0xfeedfacf || u32le(&header[24..]) & 0x80000000 == 0 {
            return Err(bad("expected cached 64-bit Mach-O"));
        }
        let count = u32le(&header[16..]) as usize;
        let size = u32le(&header[20..]) as usize;
        if size > 16 << 20 || count > size / 8 {
            return Err(bad("invalid Mach-O load commands"));
        }
        let mut raw = vec![0; size];
        self.read_address(address + 32, &mut raw)?;
        let mut commands = Vec::new();
        let mut cursor = 0;
        for _ in 0..count {
            let prefix = raw
                .get(cursor..cursor + 8)
                .ok_or_else(|| bad("truncated Mach-O command"))?;
            let size = u32le(&prefix[4..]) as usize;
            if size < 8 {
                return Err(bad("invalid Mach-O command length"));
            }
            let command = raw
                .get(cursor..cursor + size)
                .ok_or_else(|| bad("truncated Mach-O command"))?
                .to_vec();
            commands.push(command);
            cursor += size;
        }
        if cursor != raw.len() {
            return Err(bad("Mach-O command count mismatch"));
        }
        let mut segments = Vec::new();
        let mut next = 0usize;
        let mut first_section = None;
        for (index, command) in commands.iter().enumerate() {
            if u32le(command) != 0x19 {
                continue;
            }
            if command.len() < 72 {
                return Err(bad("truncated Mach-O segment"));
            }
            let original = usize::try_from(u64le(&command[48..]))
                .map_err(|_| bad("Mach-O segment too large"))?;
            let size = align(original, 16384)?;
            if (original > 256 << 20 && name(&command[8..24]) != b"__LINKEDIT") || next > 256 << 20
            {
                return Err(bad("Mach-O export exceeds limit"));
            }
            let segment_address = u64le(&command[24..]);
            let sections = u32le(&command[64..]) as usize;
            if sections > (command.len() - 72) / 80 {
                return Err(bad("truncated Mach-O section table"));
            }
            if name(&command[8..24]) == b"__TEXT" {
                for section in command[72..].chunks_exact(80).take(sections) {
                    let relative = u64le(&section[32..])
                        .checked_sub(segment_address)
                        .ok_or_else(|| bad("section precedes segment"))?;
                    if relative != 0 {
                        first_section =
                            Some(first_section.map_or(relative, |v: u64| v.min(relative)));
                    }
                }
            }
            segments.push(Segment {
                command: index,
                address: segment_address,
                memory: u64le(&command[32..]),
                original,
                offset: next,
                size,
            });
            next = next
                .checked_add(size)
                .ok_or_else(|| bad("Mach-O export overflow"))?;
        }
        let link_index = segments
            .iter()
            .position(|s| name(&commands[s.command][8..24]) == b"__LINKEDIT")
            .ok_or_else(|| bad("Mach-O has no linkedit segment"))?;
        let (link_member, _) = self.mapping(segments[link_index].address)?;
        let link_file = &link_member.file;
        let link_offset = segments[link_index].offset;
        let mut link = Vec::new();
        // Upstream reconstructs these data regions in this exact order.
        for kind in [0x80000033, 0x29, 0x26, 0x37, 0x38] {
            for command in &mut commands {
                if u32le(command) != kind {
                    continue;
                }
                if command.len() != 16 {
                    return Err(bad("invalid Mach-O linkedit data command"));
                }
                let offset = u32le(&command[8..]) as u64;
                let size = u32le(&command[12..]) as usize;
                if size > 64 << 20 {
                    return Err(bad("Mach-O linkedit data exceeds limit"));
                }
                let bytes = read(link_file, offset, size)?;
                put32(
                    command,
                    8,
                    u32::try_from(link_offset + link.len())
                        .map_err(|_| bad("Mach-O offset overflow"))?,
                );
                link.extend_from_slice(&bytes);
                link.resize(align(link.len(), 8)?, 0);
            }
        }
        for command in &mut commands {
            if ![0x22, 0x80000022].contains(&u32le(command)) {
                continue;
            }
            if command.len() != 48 {
                return Err(bad("invalid Mach-O dyld info"));
            }
            for field in [8, 16, 24, 32, 40] {
                let size = u32le(&command[field + 4..]) as usize;
                if size == 0 {
                    continue;
                }
                if size > 64 << 20 {
                    return Err(bad("Mach-O dyld info exceeds limit"));
                }
                let bytes = read(link_file, u32le(&command[field..]) as u64, size)?;
                put32(command, field, (link_offset + link.len()) as u32);
                link.extend_from_slice(&bytes);
            }
            link.resize(align(link.len(), 8)?, 0);
        }
        let sym_index = commands
            .iter()
            .position(|c| u32le(c) == 2)
            .ok_or_else(|| bad("Mach-O missing symbols"))?;
        let dynamic_index = commands
            .iter()
            .position(|c| u32le(c) == 0xb)
            .ok_or_else(|| bad("Mach-O missing dynamic symbols"))?;
        if commands[sym_index].len() != 24 || commands[dynamic_index].len() != 80 {
            return Err(bad("invalid Mach-O symbol commands"));
        }
        let sym = &commands[sym_index];
        let symbol_count = u32le(&sym[12..]) as usize;
        if symbol_count > 4 << 20 {
            return Err(bad("Mach-O symbol count exceeds limit"));
        }
        let symbols = read(link_file, u32le(&sym[8..]) as u64, symbol_count * 16)?;
        let strings = u32le(&sym[16..]) as u64;
        let string_size = u32le(&sym[20..]) as u64;
        let mut groups: [Vec<(Vec<u8>, Vec<u8>)>; 3] = Default::default();
        for encoded in symbols.chunks_exact(16) {
            let string_index = u32le(encoded) as u64;
            let mut symbol_name = if string_index >= string_size {
                Vec::new()
            } else {
                let bytes = read(
                    link_file,
                    strings + string_index,
                    (string_size - string_index).min(4096) as usize,
                )?;
                let end = bytes
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or_else(|| bad("unterminated Mach-O symbol name"))?;
                bytes[..end].to_vec()
            };
            if symbol_name.starts_with(b"_") && symbol_name.contains(&b'.') {
                symbol_name.remove(0);
            }
            if symbol_name == b"<redacted>" {
                continue;
            }
            let group = if encoded[4] & 1 == 0 {
                0
            } else if encoded[4] & 0xe == 0 {
                2
            } else {
                1
            };
            groups[group].push((encoded.to_vec(), symbol_name));
        }
        // Reexports and non-regular exports are appended as N_INDR symbols.
        if let Some(command) = commands.iter().find(|c| u32le(c) == 0x80000033) {
            let offset = u32le(&command[8..]) as usize - link_offset;
            let size = u32le(&command[12..]) as usize;
            let trie = link
                .get(offset..offset + size)
                .ok_or_else(|| bad("invalid export trie bounds"))?;
            for export in exports(trie, address)? {
                if export.flags & 3 != 0 || export.flags & 8 != 0 {
                    let mut encoded = vec![0; 16];
                    encoded[4] = 0xb;
                    put64(&mut encoded, 8, export.address);
                    let mut name = export.name;
                    name.push(0);
                    name.extend_from_slice(&export.reexport);
                    groups[1].push((encoded, name));
                }
            }
        }
        let lengths = groups.each_ref().map(|g| g.len() as u32);
        let symbol_offset = link_offset + link.len();
        let mut names = vec![0];
        for group in groups {
            for (mut encoded, name) in group {
                put32(&mut encoded, 0, names.len() as u32);
                link.extend_from_slice(&encoded);
                names.extend_from_slice(&name);
                names.push(0);
            }
        }
        link.resize(align(link.len(), 8)?, 0);
        let indirect_offset = link_offset + link.len();
        let dynamic = &commands[dynamic_index];
        let indirect_count = u32le(&dynamic[60..]) as usize;
        if indirect_count > 4 << 20 {
            return Err(bad("Mach-O indirect symbol count exceeds limit"));
        }
        link.extend_from_slice(&read(
            link_file,
            u32le(&dynamic[56..]) as u64,
            indirect_count * 4,
        )?);
        link.resize(align(link.len(), 8)?, 0);
        let string_offset = link_offset + link.len();
        names.resize(align(names.len(), 8)?, 0);
        link.extend_from_slice(&names);
        let sym = &mut commands[sym_index];
        put32(sym, 8, symbol_offset as u32);
        put32(sym, 12, lengths.iter().sum());
        put32(sym, 16, string_offset as u32);
        put32(sym, 20, names.len() as u32);
        let dynamic = &mut commands[dynamic_index];
        for (offset, value) in [
            (8, 0),
            (12, lengths[0]),
            (16, lengths[0]),
            (20, lengths[1]),
            (24, lengths[0] + lengths[1]),
            (28, lengths[2]),
            (56, indirect_offset as u32),
            (64, 0),
            (68, 0),
            (72, 0),
            (76, 0),
        ] {
            put32(dynamic, offset, value);
        }
        for command in &mut commands {
            if u32le(command) == 0x29 && u32le(&command[12..]) == 0 {
                put32(command, 8, symbol_offset as u32);
            }
        }
        for (index, segment) in segments.iter_mut().enumerate() {
            let command = &mut commands[segment.command];
            put64(command, 40, segment.offset as u64);
            let memory = if index == link_index {
                align(link.len(), 16384)? as u64
            } else {
                segment.size as u64 + segment.memory.saturating_sub(segment.original as u64)
            };
            if index == link_index {
                segment.size = link.len();
            }
            put64(command, 48, segment.size as u64);
            put64(command, 32, memory);
            segment.memory = memory;
            let count = u32le(&command[64..]) as usize;
            for section in command[72..].chunks_exact_mut(80).take(count) {
                if u32le(&section[48..]) != 0 {
                    let relative = u64le(&section[32..])
                        .checked_sub(segment.address)
                        .ok_or_else(|| bad("invalid section address"))?;
                    let offset = (segment.offset as u64)
                        .checked_add(relative)
                        .ok_or_else(|| bad("section offset overflow"))?;
                    put32(
                        section,
                        48,
                        u32::try_from(offset).map_err(|_| bad("section offset overflow"))?,
                    );
                }
            }
        }
        commands.retain(|c| u32le(c) != 0x80000034);
        put32(&mut header, 16, commands.len() as u32);
        put32(
            &mut header,
            20,
            commands.iter().map(Vec::len).sum::<usize>() as u32,
        );
        let flags = u32le(&header[24..]) & 0x7fffffff;
        put32(&mut header, 24, flags);
        let mut output = header;
        for command in &commands {
            output.extend_from_slice(command);
        }
        let load_end = output.len();
        for segment in &segments {
            let command = &raw_segment(&raw, count, segment.command)?;
            let segment_name = name(&command[8..24]);
            if output.len() < segment.offset {
                output.resize(segment.offset, 0);
            }
            if segment_name == b"__LINKEDIT" {
                output.extend_from_slice(&link);
            } else if segment.original != 0 {
                let mut bytes = vec![0; segment.original];
                self.read_address(segment.address, &mut bytes)?;
                if segment_name == b"__TEXT" {
                    let start = first_section
                        .unwrap_or(load_end as u64)
                        .max(load_end as u64) as usize;
                    if start > bytes.len() {
                        return Err(bad("Mach-O headers exceed text segment"));
                    }
                    output.resize(start, 0);
                    output.extend_from_slice(&bytes[start..]);
                } else {
                    output.extend_from_slice(&bytes);
                }
            }
            let end = segment
                .offset
                .checked_add(segment.size)
                .ok_or_else(|| bad("Mach-O output overflow"))?;
            if output.len() < end {
                output.resize(end, 0);
            }
        }
        // Apply shared-cache pointers using original VM addresses.
        for segment in &segments {
            for (pointer, target) in self.rebases(segment.address, segment.memory)? {
                let offset = segment.offset as u64 + pointer - segment.address;
                if offset + 8 <= output.len() as u64 {
                    put64(&mut output, offset as usize, target);
                }
            }
        }
        Ok(output)
    }
}

fn raw_segment(raw: &[u8], count: usize, index: usize) -> io::Result<Vec<u8>> {
    let mut offset = 0;
    for i in 0..count {
        let command = raw
            .get(offset..)
            .filter(|c| c.len() >= 8)
            .ok_or_else(|| bad("truncated Mach-O commands"))?;
        let size = u32le(&command[4..]) as usize;
        if i == index {
            return command
                .get(..size)
                .map(Vec::from)
                .ok_or_else(|| bad("truncated Mach-O segment"));
        }
        offset += size;
    }
    Err(bad("Mach-O segment command missing"))
}

struct Export {
    name: Vec<u8>,
    flags: u64,
    address: u64,
    reexport: Vec<u8>,
}
fn leb(bytes: &[u8], offset: &mut usize) -> io::Result<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes
            .get(*offset)
            .ok_or_else(|| bad("truncated export ULEB"))?;
        *offset += 1;
        if shift == 63 && byte > 1 {
            return Err(bad("export ULEB overflow"));
        }
        value |= ((byte & 127) as u64) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    Err(bad("export ULEB overflow"))
}
fn exports(bytes: &[u8], base: u64) -> io::Result<Vec<Export>> {
    let mut result = Vec::new();
    let mut pending = vec![(0usize, Vec::new(), Vec::new())];
    while let Some((offset, name, mut ancestors)) = pending.pop() {
        if ancestors.len() > 256 || ancestors.contains(&offset) || result.len() > 1_000_000 {
            return Err(bad("cyclic or excessive export trie"));
        }
        ancestors.push(offset);
        let mut cursor = offset;
        let terminal = leb(bytes, &mut cursor)? as usize;
        let end = cursor
            .checked_add(terminal)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| bad("invalid export terminal"))?;
        if terminal != 0 {
            let flags = leb(bytes, &mut cursor)?;
            let mut address = 0;
            let mut reexport = Vec::new();
            if flags & 8 != 0 {
                let _ordinal = leb(bytes, &mut cursor)?;
                let suffix = bytes
                    .get(cursor..end)
                    .ok_or_else(|| bad("invalid reexport"))?;
                let length = suffix
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or_else(|| bad("unterminated reexport"))?;
                reexport.extend_from_slice(&suffix[..length]);
                if reexport.is_empty() {
                    reexport = name.clone();
                }
            } else {
                address = leb(bytes, &mut cursor)?;
                if flags & 3 != 2 {
                    address = address
                        .checked_add(base)
                        .ok_or_else(|| bad("export address overflow"))?;
                }
            }
            result.push(Export {
                name: name.clone(),
                flags,
                address,
                reexport,
            });
        }
        cursor = end;
        let count = *bytes
            .get(cursor)
            .ok_or_else(|| bad("missing export children"))?;
        cursor += 1;
        let mut children = Vec::new();
        for _ in 0..count {
            let suffix = bytes
                .get(cursor..)
                .ok_or_else(|| bad("invalid export edge"))?;
            let length = suffix
                .iter()
                .position(|b| *b == 0)
                .ok_or_else(|| bad("unterminated export edge"))?;
            let mut child_name = name.clone();
            child_name.extend_from_slice(&suffix[..length]);
            if child_name.len() > 16384 {
                return Err(bad("export name exceeds limit"));
            }
            cursor += length + 1;
            let child = usize::try_from(leb(bytes, &mut cursor)?)
                .map_err(|_| bad("export offset overflow"))?;
            children.push((child, child_name, ancestors.clone()));
        }
        pending.extend(children.into_iter().rev());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;
    struct Bytes(Vec<u8>);
    impl super::super::super::apfs::ReadAt for Bytes {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
            let data = self
                .0
                .get(offset as usize..offset as usize + output.len())
                .ok_or_else(|| bad("test range"))?;
            output.copy_from_slice(data);
            Ok(())
        }
    }
    #[test]
    fn exports_segments_and_rebuilds_normalized_symbols() {
        let mut file = vec![0; 0xc000];
        file[..15].copy_from_slice(b"dyld_v1  arm64e");
        put32(&mut file, 312, 0x240);
        put32(&mut file, 316, 1);
        put32(&mut file, 448, 0x300);
        put32(&mut file, 452, 1);
        put64(&mut file, 0x240, 0x180000000);
        put64(&mut file, 0x248, 0xc000);
        put64(&mut file, 0x258, 0x350);
        put64(&mut file, 0x260, 30);
        put64(&mut file, 0x300, 0x180004000);
        put32(&mut file, 0x318, 0x400);
        file[0x400..0x409].copy_from_slice(b"/test\0\0\0\0");
        put32(&mut file, 0x350, 5);
        put32(&mut file, 0x354, 16384);
        put32(&mut file, 0x358, 3);
        put64(&mut file, 0x360, 0x180000000);
        file[0x368..0x36e].fill(255);
        let h = 0x4000;
        put32(&mut file, h, 0xfeedfacf);
        put32(&mut file, h + 4, 0x100000c);
        put32(&mut file, h + 16, 4);
        put32(&mut file, h + 20, 248);
        put32(&mut file, h + 24, 0x80000000);
        let mut p = h + 32;
        for (name, address, offset) in [
            (b"__TEXT".as_slice(), 0x180004000, 0x4000),
            (b"__LINKEDIT".as_slice(), 0x180008000, 0x8000),
        ] {
            put32(&mut file, p, 0x19);
            put32(&mut file, p + 4, 72);
            file[p + 8..p + 8 + name.len()].copy_from_slice(name);
            put64(&mut file, p + 24, address);
            put64(&mut file, p + 32, 0x4000);
            put64(&mut file, p + 40, offset);
            put64(&mut file, p + 48, 0x4000);
            p += 72;
        }
        put32(&mut file, p, 2);
        put32(&mut file, p + 4, 24);
        put32(&mut file, p + 8, 0x8100);
        put32(&mut file, p + 12, 1);
        put32(&mut file, p + 16, 0x8200);
        put32(&mut file, p + 20, 6);
        p += 24;
        put32(&mut file, p, 0xb);
        put32(&mut file, p + 4, 80);
        put32(&mut file, 0x8100, 1);
        file[0x8104] = 0xf;
        file[0x8105] = 1;
        put64(&mut file, 0x8108, 0x180004100);
        file[0x8200..0x8206].copy_from_slice(b"\0_a.b\0");
        let source: File = Rc::new(Bytes(file));
        let cache = Cache::open(|suffix| {
            assert!(suffix.is_empty());
            Ok(source.clone())
        })
        .unwrap();
        let exported = cache.export_image("/test").unwrap();
        assert_eq!(exported.len(), 0x4000 + 24);
        assert_eq!(u32le(&exported[24..]), 0);
        assert_eq!(u64le(&exported[32 + 40..]), 0);
        assert_eq!(u64le(&exported[104 + 40..]), 0x4000);
        assert_eq!(&exported[0x4010..0x4015], b"\0a.b\0");
        assert_eq!(u32le(&exported[0x4000..]), 1);
    }
    #[test]
    fn rejects_cyclic_and_truncated_export_tries() {
        assert!(exports(&[0, 1, b'a', 0, 0], 0).is_err());
        assert!(exports(&[128], 0).is_err());
        assert!(exports(&[1, 8, 0], 0).is_err());
    }
}
