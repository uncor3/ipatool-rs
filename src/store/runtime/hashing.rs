//! Swift Hasher's SipHash-1-3 primitive; unrelated to SAP or account signatures.
use super::*;
fn round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17) ^ v[2];
    v[2] = v[2].rotate_left(32);
}
impl State {
    pub(super) fn init_hasher(
        &mut self,
        guest: Guest<'_>,
        address: u64,
        seed: u64,
    ) -> Result<(), ClientError> {
        let pointer = self
            .data
            .metadata
            .symbols
            .get("_swift_stdlib_Hashing_parameters")
            .copied()
            .unwrap_or(0);
        let (a, b) = if pointer == 0 {
            (seed, 0)
        } else {
            (read64(guest, pointer)? ^ seed, read64(guest, pointer + 8)?)
        };
        let values = [
            0,
            0x736f6d6570736575 ^ a,
            0x646f72616e646f6d ^ b,
            0x6c7967656e657261 ^ a,
            0x7465646279746573 ^ b,
            0,
            0,
            0,
            0,
        ];
        for (i, value) in values.iter().enumerate() {
            guest.mem_write(address + i as u64 * 8, &value.to_le_bytes())?;
        }
        Ok(())
    }
    pub(super) fn hash_compress(
        &mut self,
        guest: Guest<'_>,
        address: u64,
        word: u64,
        finalize: bool,
    ) -> Result<u64, ClientError> {
        let mut v = [0; 4];
        for (i, value) in v.iter_mut().enumerate() {
            *value = read64(guest, address + 8 + i as u64 * 8)?;
        }
        v[3] ^= word;
        round(&mut v);
        v[0] ^= word;
        if finalize {
            v[2] ^= 255;
            for _ in 0..3 {
                round(&mut v);
            }
        }
        for (i, value) in v.iter().enumerate() {
            guest.mem_write(address + 8 + i as u64 * 8, &value.to_le_bytes())?;
        }
        Ok(v[0] ^ v[1] ^ v[2] ^ v[3])
    }
    pub(super) fn hash_word(
        &mut self,
        guest: Guest<'_>,
        address: u64,
        word: u64,
    ) -> Result<(), ClientError> {
        let mut tail = read64(guest, address)?;
        let count = tail >> 56;
        let shift = (count & 7) * 8;
        let chunk;
        if shift != 0 {
            chunk = (tail & 0xffffffffffffff) | (word << shift);
            tail = ((count + 8) << 56) | (word >> (64 - shift));
        } else {
            chunk = word;
            tail = tail.wrapping_add(8 << 56);
        }
        guest.mem_write(address, &tail.to_le_bytes())?;
        self.hash_compress(guest, address, chunk, false)?;
        Ok(())
    }
    pub(super) fn hash_bytes(
        &mut self,
        guest: Guest<'_>,
        address: u64,
        data: &[u8],
    ) -> Result<(), ClientError> {
        for byte in data {
            let tail = read64(guest, address)?;
            let count = tail >> 56;
            let shift = (count & 7) * 8;
            let word = (tail & 0xffffffffffffff) | ((*byte as u64) << shift);
            if shift == 56 {
                self.hash_compress(guest, address, word, false)?;
                guest.mem_write(address, &((count + 1) << 56).to_le_bytes())?;
            } else {
                guest.mem_write(address, &(((count + 1) << 56) | word).to_le_bytes())?;
            }
        }
        Ok(())
    }
}
