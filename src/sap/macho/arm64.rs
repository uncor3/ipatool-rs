use super::*;

fn invalid() -> ClientError {
    ClientError::Sap("invalid ARM64 Mach-O profile or fixup".into())
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, ClientError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or_else(invalid)?
            .try_into()
            .unwrap(),
    ))
}

/// Same ARM64e instruction transformations as Go machimage.WithoutPointerAuthentication.
fn without_pac(instruction: u32) -> u32 {
    match instruction & 0xffff_fc00 {
        0xd71f0800 | 0xd71f0c00 | 0xd61f0800 | 0xd61f0c00 => {
            return 0xd61f0000 | (instruction & 0x3e0);
        }
        0xd73f0800 | 0xd73f0c00 | 0xd63f0800 | 0xd63f0c00 => {
            return 0xd63f0000 | (instruction & 0x3e0);
        }
        0xdac10000 | 0xdac10400 | 0xdac10800 | 0xdac10c00 | 0xdac11000 | 0xdac11400
        | 0xdac11800 | 0xdac11c00 => return 0xd503201f,
        _ => {}
    }
    match instruction {
        0xd65f0bff | 0xd65f0fff => return 0xd65f03c0,
        0xd503211f | 0xd503215f | 0xd503219f | 0xd50321df | 0xd503233f | 0xd503237f
        | 0xd50323bf | 0xd50323ff | 0xd50320ff => return 0xd503201f,
        _ => {}
    }
    match instruction & 0xffff_ffe0 {
        0xdac123e0 | 0xdac127e0 | 0xdac12be0 | 0xdac12fe0 | 0xdac133e0 | 0xdac137e0
        | 0xdac13be0 | 0xdac13fe0 | 0xdac143e0 | 0xdac147e0 => 0xd503201f,
        _ => instruction,
    }
}

impl Image {
    pub(super) fn load_sparse(
        &self,
        memory: &impl Memory,
        load_base: u64,
    ) -> Result<(), ClientError> {
        let mut ranges = Vec::new();
        for seg in self.loadable() {
            let start = load_base
                .checked_add(seg.address.checked_sub(self.base).ok_or_else(invalid)?)
                .ok_or_else(invalid)?;
            let end = start
                .checked_add(seg.size)
                .ok_or_else(invalid)?
                .checked_add(0xfff)
                .ok_or_else(invalid)?
                & !0xfff;
            ranges.push((start & !0xfff, end));
        }
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (start, end) in ranges {
            if let Some(last) = merged.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
                continue;
            }
            merged.push((start, end));
        }
        let mut total = 0u64;
        for (start, end) in merged {
            total = total
                .checked_add(end - start)
                .filter(|size| *size <= MAX_IMAGE_SPAN)
                .ok_or_else(invalid)?;
            memory.map(start, end - start)?;
        }
        for seg in self.loadable() {
            if seg.file_size == 0 {
                continue;
            }
            memory.write(
                load_base + seg.address - self.base,
                &self.data[seg.file_offset as usize..(seg.file_offset + seg.file_size) as usize],
            )?;
        }
        Ok(())
    }
    pub fn open_arm64(name: &str, input: &[u8]) -> Result<Self, ClientError> {
        let mut data = input;
        if input.get(..4) == Some(&FAT_MAGIC.to_be_bytes()) {
            let count = u32::from_be_bytes(input.get(4..8).ok_or_else(invalid)?.try_into().unwrap())
                as usize;
            let mut selected = None;
            for index in 0..count {
                let offset = 8 + index * 20;
                let entry = input.get(offset..offset + 20).ok_or_else(invalid)?;
                let be = |start| u32::from_be_bytes(entry[start..start + 4].try_into().unwrap());
                if be(0) == 0x0100_000c && be(4) & 0x00ff_ffff == 2 {
                    selected = Some(
                        input
                            .get(
                                be(8) as usize
                                    ..(be(8) as usize)
                                        .checked_add(be(12) as usize)
                                        .ok_or_else(invalid)?,
                            )
                            .ok_or_else(invalid)?,
                    );
                    break;
                }
            }
            data = selected.ok_or_else(invalid)?;
        }
        let mut image = Self {
            name: name.into(),
            data: data.to_vec(),
            segments: Vec::new(),
            symbols: HashMap::new(),
            base: 0,
            rebases: Vec::new(),
            binds: Vec::new(),
            loaded_base: None,
            chained: None,
            arm64: true,
        };
        image.parse()?;
        let mut position = HEADER_64_SIZE;
        for _ in 0..read_u32(&image.data, 16)? {
            let size = read_u32(&image.data, position + 4)? as usize;
            if read_u32(&image.data, position)? == LC_SEGMENT_64 {
                let sections = read_u32(&image.data, position + 64)? as usize;
                for index in 0..sections {
                    let section = position + 72 + index * 80;
                    if section + 80 > position + size {
                        return Err(invalid());
                    }
                    let flags = read_u32(&image.data, section + 64)?;
                    if flags & (0x8000_0000 | 0x400) == 0 {
                        continue;
                    }
                    let start = read_u32(&image.data, section + 48)? as usize;
                    let len = read_u64(&image.data, section + 40)? as usize;
                    let end = start
                        .checked_add(len)
                        .filter(|end| *end <= image.data.len())
                        .ok_or_else(invalid)?;
                    for offset in (start..end.saturating_sub(3)).step_by(4) {
                        let instruction = read_u32(&image.data, offset)?;
                        image.data[offset..offset + 4]
                            .copy_from_slice(&without_pac(instruction).to_le_bytes());
                    }
                }
            }
            position += size;
        }
        Ok(image)
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn prepare_prelinked(
        &mut self,
        external: &[(u64, &str)],
        mut resolve: impl FnMut(&str) -> Result<u64, ClientError>,
    ) -> Result<(), ClientError> {
        if self.loaded_base.is_some() {
            return Err(invalid());
        }
        let mut pointers = HashMap::new();
        for &(address, name) in external {
            pointers.insert(address, resolve(name)?);
        }
        for segment in &self.segments {
            if segment.name == "__TEXT" || segment.name == "__LINKEDIT" || segment.file_size < 8 {
                continue;
            }
            let start = segment.file_offset as usize;
            let end = start + segment.file_size as usize;
            for offset in (start..=end - 8).step_by(8) {
                if let Some(value) = pointers.get(&read_u64(&self.data, offset)?) {
                    self.data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                }
            }
        }
        self.loaded_base = Some(self.base);
        Ok(())
    }

    pub(super) fn relocate_chained(
        &mut self,
        load_base: u64,
        resolve: &mut impl FnMut(&str) -> Result<u64, ClientError>,
    ) -> Result<(), ClientError> {
        let Some(range) = self.chained else {
            return Ok(());
        };
        let header = self.slice(range)?.to_vec();
        if read_u32(&header, 0)? != 0 || read_u32(&header, 24)? != 0 {
            return Err(invalid());
        }
        let starts = read_u32(&header, 4)? as usize;
        let imports_start = read_u32(&header, 8)? as usize;
        let symbols_start = read_u32(&header, 12)? as usize;
        let count = read_u32(&header, 16)? as usize;
        let format = read_u32(&header, 20)?;
        let mut imports = Vec::new();
        for index in 0..count {
            let (name_offset, addend) = match format {
                1 => (
                    (read_u32(&header, imports_start + index * 4)? >> 9) as usize,
                    0i64,
                ),
                2 => {
                    let off = imports_start + index * 8;
                    (
                        (read_u32(&header, off)? >> 9) as usize,
                        read_u32(&header, off + 4)? as i32 as i64,
                    )
                }
                3 => {
                    let off = imports_start + index * 16;
                    (
                        (read_u64(&header, off)? >> 32) as usize,
                        read_u64(&header, off + 8)? as i64,
                    )
                }
                _ => return Err(invalid()),
            };
            let tail = header
                .get(symbols_start.checked_add(name_offset).ok_or_else(invalid)?..)
                .ok_or_else(invalid)?;
            let end = tail
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(invalid)?;
            let name = std::str::from_utf8(&tail[..end]).map_err(|_| invalid())?;
            imports.push((name.to_string(), addend));
        }
        let segment_count = read_u32(&header, starts)? as usize;
        for index in 0..segment_count {
            let info_offset = read_u32(&header, starts + 4 + index * 4)? as usize;
            if info_offset == 0 {
                continue;
            }
            let info = starts.checked_add(info_offset).ok_or_else(invalid)?;
            let page_size = u16_at(&header, info + 4)? as u64;
            let pointer_format = u16_at(&header, info + 6)?;
            let segment_offset = read_u64(&header, info + 8)?;
            let pages = u16_at(&header, info + 20)? as usize;
            for page in 0..pages {
                let start = u16_at(&header, info + 22 + page * 2)?;
                if start == 0xffff {
                    continue;
                }
                if start & 0x8000 != 0 {
                    return Err(ClientError::Sap(
                        "unsupported multi-start chained page".into(),
                    ));
                }
                let page_start = segment_offset
                    .checked_add(page as u64 * page_size)
                    .ok_or_else(invalid)?;
                let mut position = page_start + u64::from(start);
                loop {
                    let address = self.base.checked_add(position).ok_or_else(invalid)?;
                    let segment = self
                        .segments
                        .iter()
                        .find(|seg| address >= seg.address && address - seg.address < seg.file_size)
                        .ok_or_else(invalid)?;
                    let offset = segment.file_offset + address - segment.address;
                    let raw = read_u64(&self.data, offset as usize)?;
                    let (next, stride, target, binding) = match pointer_format {
                        1 | 9 | 12 => {
                            let auth = raw >> 63 != 0;
                            let bind = raw & (1 << 62) != 0;
                            let ordinal_mask = if pointer_format == 12 {
                                0xff_ffff
                            } else {
                                0xffff
                            };
                            let addend = if auth {
                                0
                            } else {
                                (((raw >> 32) & 0x7ffff) as i64) << 45 >> 45
                            };
                            let target = if bind {
                                0
                            } else if auth {
                                raw & 0xffff_ffff
                            } else if pointer_format == 1 {
                                (raw & 0x7ff_ffff_ffff)
                                    .checked_sub(self.base)
                                    .ok_or_else(invalid)?
                            } else {
                                raw & 0x7ff_ffff_ffff
                            };
                            (
                                (raw >> 51) & 0x7ff,
                                8,
                                target,
                                bind.then_some(((raw & ordinal_mask) as usize, addend)),
                            )
                        }
                        2 | 6 => {
                            let bind = raw >> 63 != 0;
                            let unpacked = (raw & 0xf_ffff_ffff) | (((raw >> 36) & 0xff) << 56);
                            let target = if bind {
                                0
                            } else if pointer_format == 2 {
                                unpacked.checked_sub(self.base).ok_or_else(invalid)?
                            } else {
                                unpacked
                            };
                            (
                                (raw >> 51) & 0xfff,
                                4,
                                target,
                                bind.then_some((
                                    (raw & 0xff_ffff) as usize,
                                    ((raw >> 24) & 0xff) as i64,
                                )),
                            )
                        }
                        _ => {
                            return Err(ClientError::Sap(format!(
                                "unsupported chained pointer format {pointer_format}"
                            )));
                        }
                    };
                    let value = if let Some((ordinal, addend)) = binding {
                        let (name, import_addend) = imports.get(ordinal).ok_or_else(invalid)?;
                        resolve(name)?
                            .checked_add_signed(
                                import_addend.checked_add(addend).ok_or_else(invalid)?,
                            )
                            .ok_or_else(invalid)?
                    } else {
                        load_base.checked_add(target).ok_or_else(invalid)?
                    };
                    self.put_pointer(offset, value)?;
                    if next == 0 {
                        break;
                    }
                    position = position.checked_add(next * stride).ok_or_else(invalid)?;
                    if position >= page_start + page_size {
                        return Err(invalid());
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rewrites_authenticated_branches_only() {
        assert_eq!(without_pac(0xd65f0fff), 0xd65f03c0);
        assert_eq!(without_pac(0xd73f0800 | (17 << 5)), 0xd63f0000 | (17 << 5));
        assert_eq!(without_pac(0xd503233f), 0xd503201f);
        assert_eq!(without_pac(0x91000400), 0x91000400);
    }
}
