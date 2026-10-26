use super::*;

impl State {
    pub(super) fn copy_block(
        &mut self,
        guest: Guest<'_>,
        block: u64,
        after: ValueCompletion,
    ) -> Result<(), ClientError> {
        if block == 0 {
            return after(self, guest, 0);
        }
        let flags = read64(guest, block + 8)? as u32;
        if flags & (1 << 28) != 0 {
            return after(self, guest, block);
        }
        let descriptor = read64(guest, block + 24)?;
        let size = read64(guest, descriptor + 8)?;
        if !(32..=1 << 20).contains(&size) {
            return Err(failure("invalid Store block size"));
        }
        let copied = self.alloc(size)?;
        guest.mem_write(copied, &guest.mem_read(block, size as usize)?)?;
        if flags & (1 << 25) != 0 {
            self.callback_then(
                guest,
                read64(guest, descriptor + 16)?,
                &[copied, block],
                Box::new(move |state, guest| after(state, guest, copied)),
            )
        } else {
            after(self, guest, copied)
        }
    }

    pub(super) fn copy_value(
        &mut self,
        guest: Guest<'_>,
        value: u64,
        after: ValueCompletion,
    ) -> Result<(), ClientError> {
        if value == 0 {
            return after(self, guest, 0);
        }
        if let Some(object) = self.objects.get(&value) {
            let entry = self.lookup(&object.class, "copyWithZone:", false);
            if entry != 0 {
                let selector = self.selector(guest, "copyWithZone:")?;
                return self.callback_then(
                    guest,
                    entry,
                    &[value, selector, 0],
                    Box::new(move |state, guest| after(state, guest, guest.reg_read(reg::X0)?)),
                );
            }
            after(self, guest, value)
        } else {
            self.copy_block(guest, value, after)
        }
    }

    pub(super) fn copy_byref(
        &mut self,
        guest: Guest<'_>,
        value: u64,
        after: ValueCompletion,
    ) -> Result<(), ClientError> {
        let forwarded = read64(guest, value + 8)?;
        if forwarded != 0 && forwarded != value {
            return after(self, guest, forwarded);
        }
        let header = read64(guest, value + 16)?;
        let size = header >> 32;
        let flags = header as u32;
        if !(24..=1 << 20).contains(&size) {
            return Err(failure("invalid Store byref capture size"));
        }
        let copied = self.alloc(size)?;
        guest.mem_write(copied, &guest.mem_read(value, size as usize)?)?;
        guest.mem_write(copied + 8, &copied.to_le_bytes())?;
        guest.mem_write(value + 8, &copied.to_le_bytes())?;
        if flags & (1 << 25) != 0 {
            self.callback_then(
                guest,
                read64(guest, value + 24)?,
                &[copied, value],
                Box::new(move |state, guest| after(state, guest, copied)),
            )
        } else {
            after(self, guest, copied)
        }
    }

    pub(super) fn foundation_copy(
        &mut self,
        guest: Guest<'_>,
        receiver: u64,
        mutable: bool,
    ) -> Result<u64, ClientError> {
        let object = self
            .objects
            .get(&receiver)
            .ok_or_else(|| failure("unknown Foundation copy receiver"))?
            .clone();
        let class = match object.class.as_str() {
            "NSDictionary" | "NSMutableDictionary" => {
                if mutable {
                    "NSMutableDictionary"
                } else {
                    "NSDictionary"
                }
            }
            "NSSet" | "NSMutableSet" => {
                if mutable {
                    "NSMutableSet"
                } else {
                    "NSSet"
                }
            }
            "NSArray" | "NSMutableArray" => {
                if mutable {
                    "NSMutableArray"
                } else {
                    "NSArray"
                }
            }
            "NSMutableString" => "NSString",
            _ => return Ok(receiver),
        };
        self.new_object(guest, class, object.value)
    }
}
