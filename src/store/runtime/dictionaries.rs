//! Bounded Swift native dictionary storage with strides from the pinned profile.
use super::*;
use unicode_normalization::UnicodeNormalization;
impl State {
    pub(super) fn unique_dictionary(
        &mut self,
        guest: Guest<'_>,
        pointer: u64,
        unique: bool,
        capacity: u64,
        metadata: u64,
    ) -> Result<(), ClientError> {
        let old = read64(guest, pointer)?;
        let old_capacity = read64(guest, old + 24)?;
        if unique && capacity <= old_capacity {
            return self.set(guest, 0);
        }
        let layout = self
            .data
            .metadata
            .swift_dictionaries
            .get(&metadata.to_string())
            .ok_or_else(|| failure("unprepared Swift dictionary metadata"))?;
        let (key_stride, value_stride, storage_type) =
            (layout.key_stride, layout.value_stride, layout.metadata);
        if ![16, 32, 40].contains(&key_stride)
            || ![8, 16, 32].contains(&value_stride)
            || capacity > 768
        {
            return Err(failure("unsupported Swift dictionary capacity or layout"));
        }
        let count = read64(guest, old + 16)?;
        if count != 0 && old_capacity != 768 {
            return Err(failure("Swift dictionary resize requires rehash"));
        }
        let storage = self.alloc(192 + 1024 * (key_stride + value_stride))?;
        let keys = storage + 192;
        let values = keys + 1024 * key_stride;
        for (offset, value) in [
            (0, storage_type),
            (8, 3),
            (16, count),
            (24, 768),
            (32, 10),
            (40, read64(guest, old + 40)?),
            (48, keys),
            (56, values),
        ] {
            guest.mem_write(storage + offset, &value.to_le_bytes())?;
        }
        if count != 0 {
            for (dst, src, size) in [
                (storage + 64, old + 64, 128),
                (keys, read64(guest, old + 48)?, 1024 * key_stride),
                (values, read64(guest, old + 56)?, 1024 * value_stride),
            ] {
                guest.mem_write(dst, &guest.mem_read(src, size as usize)?)?;
            }
        }
        guest.mem_write(pointer, &storage.to_le_bytes())?;
        self.set(guest, u64::from(old_capacity != 768))
    }
    pub(super) fn dictionary_to_swift(
        &mut self,
        guest: Guest<'_>,
        object: u64,
        key_type: u64,
        value_type: u64,
    ) -> Result<u64, ClientError> {
        let empty = self
            .data
            .metadata
            .symbols
            .get("_swiftEmptyDictionarySingleton")
            .copied()
            .ok_or_else(|| failure("missing Swift dictionary singleton"))?;
        if object == 0 {
            return Ok(empty);
        }
        let Value::Dictionary(values) = self
            .objects
            .get(&object)
            .ok_or_else(|| failure("unknown Swift dictionary bridge input"))?
            .value
            .clone()
        else {
            return Err(failure("invalid Swift dictionary bridge input"));
        };
        if values.is_empty() {
            return Ok(empty);
        }
        let string_type = self
            .data
            .metadata
            .symbols
            .get("$sSSN")
            .copied()
            .unwrap_or(0);
        let any_hashable = self
            .data
            .metadata
            .symbols
            .get("$ss11AnyHashableVN")
            .copied()
            .unwrap_or(0);
        let (mut type_ref, mut key_stride, mut value_stride) = (0x1a2e1d5d6u64, 16, 32);
        if value_type == string_type {
            if key_type != value_type {
                return Err(failure("unsupported typed Swift dictionary bridge"));
            }
            type_ref = 0x1a2e1d7c6;
            value_stride = 16;
        }
        if key_type == any_hashable {
            type_ref = 0x1a2e1db1a;
            key_stride = 40;
        }
        let metadata = self
            .data
            .metadata
            .swift_types
            .get(&type_ref.to_string())
            .copied()
            .ok_or_else(|| failure("unprepared String/Any dictionary metadata"))?;
        let slot = self.alloc(8)?;
        guest.mem_write(slot, &empty.to_le_bytes())?;
        self.unique_dictionary(guest, slot, false, values.len() as u64, metadata)?;
        let storage = read64(guest, slot)?;
        let keys = read64(guest, storage + 48)?;
        let items = read64(guest, storage + 56)?;
        let seed = read64(guest, storage + 40)?;
        let mut names: Vec<_> = values.keys().cloned().collect();
        names.sort();
        for key in names {
            let hasher = self.alloc(72)?;
            self.init_hasher(guest, hasher, seed)?;
            let mut bytes = key.nfc().collect::<String>().into_bytes();
            bytes.push(255);
            self.hash_bytes(guest, hasher, &bytes)?;
            let hash = self.hash_compress(guest, hasher, read64(guest, hasher)?, true)?;
            let mut index = hash & 1023;
            while read64(guest, storage + 64 + (index / 64) * 8)? & (1 << (index % 64)) != 0 {
                index = (index + 1) & 1023;
            }
            let bitmap = storage + 64 + (index / 64) * 8;
            guest.mem_write(
                bitmap,
                &(read64(guest, bitmap)? | (1 << (index % 64))).to_le_bytes(),
            )?;
            self.return_swift_string(guest, &key)?;
            guest.mem_write(
                keys + index * key_stride,
                &self.arg(guest, 0)?.to_le_bytes(),
            )?;
            guest.mem_write(
                keys + index * key_stride + 8,
                &self.arg(guest, 1)?.to_le_bytes(),
            )?;
            if key_stride == 40 {
                for (offset, name) in [
                    (24, "anyHashableStringMetadata"),
                    (32, "anyHashableStringWitness"),
                ] {
                    let value = self
                        .data
                        .metadata
                        .bridges
                        .get(name)
                        .copied()
                        .ok_or_else(|| failure("missing AnyHashable String bridge"))?;
                    guest.mem_write(keys + index * key_stride + offset, &value.to_le_bytes())?;
                }
            }
            if value_stride == 16 {
                let value = self.string(values[&key])?;
                self.return_swift_string(guest, &value)?;
                guest.mem_write(items + index * 16, &self.arg(guest, 0)?.to_le_bytes())?;
                guest.mem_write(items + index * 16 + 8, &self.arg(guest, 1)?.to_le_bytes())?;
            } else {
                self.store_swift_any(guest, items + index * 32, values[&key])?;
            }
        }
        guest.mem_write(storage + 16, &(values.len() as u64).to_le_bytes())?;
        Ok(storage)
    }
    fn store_swift_any(
        &mut self,
        guest: Guest<'_>,
        destination: u64,
        object: u64,
    ) -> Result<(), ClientError> {
        let value = self
            .objects
            .get(&object)
            .cloned()
            .ok_or_else(|| failure("unknown Swift Any bridge input"))?;
        let metadata = match value.value {
            Value::String(text) => {
                self.return_swift_string(guest, &text)?;
                guest.mem_write(destination, &self.arg(guest, 0)?.to_le_bytes())?;
                guest.mem_write(destination + 8, &self.arg(guest, 1)?.to_le_bytes())?;
                self.data.metadata.symbols.get("$sSSN").copied()
            }
            Value::Integer(value) => {
                guest.mem_write(destination, &value.to_le_bytes())?;
                self.data.metadata.symbols.get("$sSiN").copied()
            }
            Value::Boolean(value) => {
                guest.mem_write(destination, &u64::from(value).to_le_bytes())?;
                self.data.metadata.symbols.get("$sSbN").copied()
            }
            Value::Real(value) => {
                guest.mem_write(destination, &value.to_bits().to_le_bytes())?;
                self.data.metadata.symbols.get("$sSdN").copied()
            }
            _ => {
                let class = if value.class.contains("Dictionary") {
                    "NSDictionary"
                } else if value.class.contains("Array") {
                    "NSArray"
                } else if value.class.contains("Data") {
                    "NSData"
                } else {
                    &value.class
                };
                guest.mem_write(destination, &object.to_le_bytes())?;
                self.data.metadata.objc_metadata.get(class).copied()
            }
        }
        .ok_or_else(|| failure("unprepared Swift Any metadata"))?;
        guest.mem_write(destination + 24, &metadata.to_le_bytes())
    }
    pub(super) fn dictionary_to_objc(
        &mut self,
        guest: Guest<'_>,
        storage: u64,
        key_type: u64,
        value_type: u64,
    ) -> Result<u64, ClientError> {
        let mut values = HashMap::new();
        let count = read64(guest, storage + 16)?;
        if count != 0 {
            let string_type = self
                .data
                .metadata
                .symbols
                .get("$sSSN")
                .copied()
                .unwrap_or(0);
            if key_type != string_type
                || value_type != string_type
                || count > 768
                || read64(guest, storage + 32)? & 255 > 10
            {
                return Err(failure(
                    "unsupported Swift dictionary Objective-C bridge layout",
                ));
            }
            let keys = read64(guest, storage + 48)?;
            let items = read64(guest, storage + 56)?;
            let buckets = 1u64 << ((read64(guest, storage + 32)? & 255) as u32);
            for index in 0..buckets {
                if read64(guest, storage + 64 + (index / 64) * 8)? & (1 << (index % 64)) == 0 {
                    continue;
                }
                let key = self.swift_string(
                    guest,
                    read64(guest, keys + index * 16)?,
                    read64(guest, keys + index * 16 + 8)?,
                )?;
                let value = self.swift_string(
                    guest,
                    read64(guest, items + index * 16)?,
                    read64(guest, items + index * 16 + 8)?,
                )?;
                values.insert(
                    key,
                    self.new_object(guest, "NSString", Value::String(value))?,
                );
            }
            if values.len() as u64 != count {
                return Err(failure("Swift dictionary count mismatch"));
            }
        }
        self.new_object(guest, "NSDictionary", Value::Dictionary(values))
    }
}
