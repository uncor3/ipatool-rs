//! Virtual platform services used by Apple's Store code; no host account access.
use super::*;
impl State {
    fn tm_date(&self, guest: Guest<'_>, pointer: u64) -> Result<time::OffsetDateTime, ClientError> {
        let bytes = guest.mem_read(pointer, 36)?;
        let field =
            |i: usize| i32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()) as i64;
        let months = (field(5) + 1900)
            .checked_mul(12)
            .and_then(|v| v.checked_add(field(4)))
            .ok_or_else(|| failure("Store date overflow"))?;
        let year = i32::try_from(months.div_euclid(12))
            .map_err(|_| failure("Store date exceeds supported range"))?;
        let date = time::Date::from_calendar_date(
            year,
            (months.rem_euclid(12) as u8 + 1).try_into().unwrap(),
            1,
        )
        .map_err(|_| failure("Store date exceeds supported range"))?
        .midnight()
        .assume_utc();
        let seconds = (field(3) - 1)
            .checked_mul(86400)
            .and_then(|v| v.checked_add(field(2) * 3600))
            .and_then(|v| v.checked_add(field(1) * 60))
            .and_then(|v| v.checked_add(field(0)))
            .ok_or_else(|| failure("Store date overflow"))?;
        date.checked_add(time::Duration::seconds(seconds))
            .ok_or_else(|| failure("Store date exceeds supported range"))
    }
    fn write_tm(
        &self,
        guest: Guest<'_>,
        out: u64,
        date: time::OffsetDateTime,
    ) -> Result<(), ClientError> {
        for (i, value) in [
            date.second() as i32,
            date.minute() as i32,
            date.hour() as i32,
            date.day() as i32,
            date.month() as i32 - 1,
            date.year() - 1900,
            date.weekday().number_days_from_sunday() as i32,
            date.ordinal() as i32 - 1,
            0,
        ]
        .into_iter()
        .enumerate()
        {
            guest.mem_write(out + i as u64 * 4, &value.to_le_bytes())?;
        }
        Ok(())
    }
    pub(super) fn system_symbol(
        &mut self,
        guest: Guest<'_>,
        name: &str,
    ) -> Result<bool, ClientError> {
        let arg = |i| self.arg(guest, i);
        match name {
            "strptime" => {
                let pointer = arg(0)?;
                let value = self.cstring(guest, pointer)?;
                let format = self.cstring(guest, arg(1)?)?;
                let out = arg(2)?;
                if !["%a, %d %b %Y %H:%M:%S GMT", "%a, %d %b %Y %H:%M:%S %Z"]
                    .contains(&format.as_str())
                {
                    return Err(failure("unsupported Store date format"));
                }
                let description=time::format_description::parse("[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT").map_err(|_|failure("invalid Store date format"))?;
                match time::PrimitiveDateTime::parse(&value, &description) {
                    Ok(date) => {
                        self.write_tm(guest, out, date.assume_utc())?;
                        self.set(guest, pointer + value.len() as u64)?;
                    }
                    Err(_) => self.set(guest, 0)?,
                }
            }
            "timegm" => {
                let date = self.tm_date(guest, arg(0)?)?;
                self.set(guest, date.unix_timestamp() as u64)?;
            }
            "CFUUIDCreate" => {
                let mut bytes = vec![0; 16];
                getrandom::fill(&mut bytes)
                    .map_err(|_| failure("Store UUID entropy unavailable"))?;
                bytes[6] = bytes[6] & 15 | 64;
                bytes[8] = bytes[8] & 63 | 128;
                let value = self.new_object(guest, "HostUUID", Value::Bytes(bytes))?;
                self.set(guest, value)?;
            }
            "CFUUIDGetUUIDBytes" => {
                let bytes = self.bytes(arg(0)?)?;
                if bytes.len() != 16 {
                    return Err(failure("invalid Store UUID"));
                }
                self.set(guest, u64::from_le_bytes(bytes[..8].try_into().unwrap()))?;
                guest.reg_write(
                    reg::X0 + 1,
                    u64::from_le_bytes(bytes[8..].try_into().unwrap()),
                )?;
            }
            "NSSearchPathForDirectoriesInDomains" => {
                if arg(0)? != 5 || arg(1)? != 8 {
                    return Err(failure("unsupported Store virtual directory"));
                }
                let path =
                    self.new_object(guest, "NSString", Value::String("/System/Library".into()))?;
                let paths = self.new_object(guest, "NSArray", Value::Array(vec![path]))?;
                self.set(guest, paths)?;
            }
            "MGCopyAnswerWithError" | "MGCopyAnswer" => {
                let key = self.string(arg(0)?)?;
                let text = match key.as_str() {
                    "BuildVersion" => "26A434",
                    "ProductVersion" => "27.0.1",
                    "DeviceClass" => "Mac",
                    "ProductType" => "Mac14,2",
                    _ => return Err(failure("unsupported Store device property")),
                };
                if name == "MGCopyAnswerWithError" && arg(2)? != 0 {
                    guest.mem_write(arg(2)?, &[0; 4])?;
                }
                let value = self.new_object(guest, "NSString", Value::String(text.into()))?;
                self.set(guest, value)?;
            }
            "CFURLResponseCopyPeerAddress" => self.set(guest, 0)?,
            "res_9_ninit" => self.set(guest, u32::MAX as u64)?,
            "res_9_ndestroy" => (),
            "CC_SHA512" => {
                use sha2::Digest;
                let size = arg(1)? as u32 as usize;
                if size > HEAP_SIZE as usize {
                    return Err(failure("Store digest input exceeds limit"));
                }
                let digest = sha2::Sha512::digest(guest.mem_read(arg(0)?, size)?);
                let out = arg(2)?;
                let out = if out == 0 { self.alloc(64)? } else { out };
                guest.mem_write(out, &digest)?;
                self.set(guest, out)?;
            }
            "localtime" | "localtime_r" | "gmtime_r" => {
                let date =
                    time::OffsetDateTime::from_unix_timestamp(read64(guest, arg(0)?)? as i64)
                        .map_err(|_| failure("invalid Store timestamp"))?;
                let out = if name == "localtime" {
                    self.alloc(56)?
                } else {
                    arg(1)?
                };
                let mut bytes = [0; 56];
                for (i, value) in [
                    date.second() as i32,
                    date.minute() as i32,
                    date.hour() as i32,
                    date.day() as i32,
                    date.month() as i32 - 1,
                    date.year() - 1900,
                    date.weekday().number_days_from_sunday() as i32,
                    date.ordinal() as i32 - 1,
                    0,
                ]
                .into_iter()
                .enumerate()
                {
                    bytes[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
                }
                guest.mem_write(out, &bytes)?;
                self.set(guest, out)?;
            }
            "strftime" => {
                let out = arg(0)?;
                let limit = arg(1)?;
                let format = self.cstring(guest, arg(2)?)?;
                let tm = arg(3)?;
                if format != "%a, %d %b %Y %H:%M:%S GMT" {
                    return Err(failure("unsupported Store date output format"));
                }
                let date = self.tm_date(guest, tm)?;
                let description=time::format_description::parse("[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT").map_err(|_|failure("invalid Store date format"))?;
                let value = date
                    .format(&description)
                    .map_err(|_| failure("invalid Store date output"))?;
                if value.len() as u64 + 1 > limit {
                    self.set(guest, 0)?;
                } else {
                    guest.mem_write(out, value.as_bytes())?;
                    guest.mem_write(out + value.len() as u64, &[0])?;
                    self.set(guest, value.len() as u64)?;
                }
            }
            "CFBooleanGetTypeID" => self.set(guest, 4)?,
            "CFDataGetTypeID" => self.set(guest, 1)?,
            "CFStringGetTypeID" => self.set(guest, 2)?,
            "CFGetTypeID" => {
                let object = self
                    .objects
                    .get(&arg(0)?)
                    .ok_or_else(|| failure("unknown Store CF object"))?;
                self.set(
                    guest,
                    match object.value {
                        Value::Boolean(_) => 4,
                        Value::Bytes(_) => 1,
                        Value::String(_) => 2,
                        _ => 3,
                    },
                )?;
            }
            "CFBooleanGetValue" => {
                let value = matches!(
                    self.objects.get(&arg(0)?).map(|o| &o.value),
                    Some(Value::Boolean(true))
                );
                self.set(guest, u64::from(value))?;
            }
            "IOMasterPort" => {
                guest.mem_write(arg(1)?, &1u32.to_le_bytes())?;
                self.set(guest, 0)?;
            }
            "IOServiceMatching" | "IOBSDNameMatching" => {
                let (key, index) = if name == "IOServiceMatching" {
                    ("IOProviderClass", 0)
                } else {
                    ("IOBSDName", 2)
                };
                let text = self.cstring(guest, arg(index)?)?;
                let value = self.new_object(guest, "NSString", Value::String(text))?;
                let object = self.new_object(
                    guest,
                    "NSDictionary",
                    Value::Dictionary(HashMap::from([(key.into(), value)])),
                )?;
                self.set(guest, object)?;
            }
            "IOServiceGetMatchingService" | "IOObjectRelease" => self.set(guest, 0)?,
            "IOServiceGetMatchingServices" | "IORegistryEntryGetParentEntry" => {
                guest.mem_write(
                    arg(2)?,
                    &if name == "IOServiceGetMatchingServices" {
                        1u32
                    } else {
                        2u32
                    }
                    .to_le_bytes(),
                )?;
                self.set(guest, 0)?;
            }
            "IOIteratorNext" => self.set(guest, 1)?,
            "IORegistryEntryCreateCFProperty" | "IORegistryEntrySearchCFProperty" => {
                if arg(0)? == 0 {
                    self.set(guest, 0)?;
                    return Ok(true);
                }
                let key = self.string(arg(if name == "IORegistryEntrySearchCFProperty" {
                    2
                } else {
                    1
                })?)?;
                let object = match key.as_str() {
                    "IOBuiltin" | "IOPrimaryInterface" => {
                        self.new_object(guest, "NSNumber", Value::Boolean(true))?
                    }
                    "IOMACAddress" => {
                        self.new_object(guest, "NSData", Value::Bytes(self.hardware_id.clone()))?
                    }
                    _ => return Err(failure("unsupported Store IOKit property")),
                };
                self.set(guest, object)?;
            }
            "CFDataGetLength" => self.set(guest, self.bytes(arg(0)?)?.len() as u64)?,
            "CFDataGetBytePtr" => {
                let bytes = self.bytes(arg(0)?)?;
                let out = self.alloc(bytes.len() as u64)?;
                guest.mem_write(out, &bytes)?;
                self.set(guest, out)?;
            }
            "CFDataGetBytes" => {
                let bytes = self.bytes(arg(0)?)?;
                let start = arg(1)? as usize;
                let size = arg(2)? as usize;
                let end = start
                    .checked_add(size)
                    .ok_or_else(|| failure("invalid Store data range"))?;
                guest.mem_write(
                    arg(3)?,
                    bytes
                        .get(start..end)
                        .ok_or_else(|| failure("invalid Store data range"))?,
                )?;
                self.set(guest, 0)?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}
