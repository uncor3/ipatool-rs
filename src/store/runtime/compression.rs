use super::*;
use std::io::Read;
pub(super) struct Inflater {
    bits: i32,
    input: Vec<u8>,
    output: Option<Vec<u8>>,
    position: usize,
}
impl State {
    pub(super) fn compression_symbol(
        &mut self,
        guest: Guest<'_>,
        name: &str,
    ) -> Result<bool, ClientError> {
        match name {
            "inflateInit2_" => {
                if self.arg(guest, 3)? != 112 {
                    return Err(failure("unsupported Store zlib ABI"));
                }
                let address = self.arg(guest, 0)?;
                self.inflaters.insert(
                    address,
                    Inflater {
                        bits: self.arg(guest, 1)? as i32,
                        input: Vec::new(),
                        output: None,
                        position: 0,
                    },
                );
                guest.mem_write(address + 16, &[0; 8])?;
                guest.mem_write(address + 40, &[0; 8])?;
                self.set(guest, 0)?;
            }
            "inflateEnd" => {
                self.inflaters.remove(&self.arg(guest, 0)?);
                self.set(guest, 0)?;
            }
            "inflate" => {
                let address = self.arg(guest, 0)?;
                let state = self
                    .inflaters
                    .get_mut(&address)
                    .ok_or_else(|| failure("uninitialized Store inflater"))?;
                let size = read64(guest, address + 8)? as u32 as usize;
                if size > 32 << 20 || state.input.len() + size > 32 << 20 {
                    return Err(failure("Store inflate input exceeds limit"));
                }
                if size != 0 {
                    let pointer = read64(guest, address)?;
                    state
                        .input
                        .extend_from_slice(&guest.mem_read(pointer, size)?);
                    guest.mem_write(address, &(pointer + size as u64).to_le_bytes())?;
                    guest.mem_write(address + 8, &[0; 4])?;
                    guest.mem_write(
                        address + 16,
                        &(read64(guest, address + 16)? + size as u64).to_le_bytes(),
                    )?;
                }
                if state.output.is_none() {
                    let reader: Box<dyn Read> = match state.bits {
                        31 | 47 => Box::new(flate2::read::GzDecoder::new(state.input.as_slice())),
                        15 => Box::new(flate2::read::ZlibDecoder::new(state.input.as_slice())),
                        -15 => Box::new(flate2::read::DeflateDecoder::new(state.input.as_slice())),
                        _ => return Err(failure("unsupported Store inflate window")),
                    };
                    let mut output = Vec::new();
                    if reader
                        .take((32 << 20) + 1)
                        .read_to_end(&mut output)
                        .is_err()
                    {
                        self.set(guest, (-3i64) as u64)?;
                        return Ok(true);
                    }
                    if output.len() > 32 << 20 {
                        return Err(failure("Store inflated response exceeds limit"));
                    }
                    state.output = Some(output);
                }
                let output = state.output.as_ref().unwrap();
                let size = read64(guest, address + 32)? as u32 as usize;
                let count = size.min(output.len() - state.position);
                let pointer = read64(guest, address + 24)?;
                guest.mem_write(pointer, &output[state.position..state.position + count])?;
                state.position += count;
                guest.mem_write(address + 24, &(pointer + count as u64).to_le_bytes())?;
                guest.mem_write(address + 32, &((size - count) as u32).to_le_bytes())?;
                guest.mem_write(
                    address + 40,
                    &(read64(guest, address + 40)? + count as u64).to_le_bytes(),
                )?;
                let done = state.position == output.len();
                self.set(guest, u64::from(done))?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}
