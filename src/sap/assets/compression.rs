//! Bounded decmpfs block codecs used by the pinned APFS volumes.
use std::io::{self, Write};
fn bad() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid APFS compressed block")
}

pub fn decode(encoded: &[u8], method: u32, expected: usize) -> io::Result<Vec<u8>> {
    let first = *encoded.first().ok_or_else(bad)?;
    if expected > 65536 {
        return Err(bad());
    }
    let plain = match method {
        8 if first == 6 => Some(&encoded[1..]),
        12 if first != b'b' => Some(&encoded[1..]),
        14 if first == 255 => Some(&encoded[1..]),
        _ => None,
    };
    if let Some(data) = plain {
        return if data.len() == expected {
            Ok(data.to_vec())
        } else {
            Err(bad())
        };
    }
    if method == 14 {
        return lzbitmap(encoded, expected);
    }
    if method == 8 {
        return lzvn(encoded, expected);
    }
    let input = if method == 12 {
        encoded
    } else {
        return Err(bad());
    };
    let mut output = Limited {
        data: Vec::with_capacity(expected),
        maximum: expected,
    };
    lzfse_rust::LzfseRingDecoder::default()
        .decode(&mut &input[..], &mut output)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("LZFSE/LZVN decoder: {error}"),
            )
        })?;
    if output.data.len() != expected {
        return Err(bad());
    }
    Ok(output.data)
}

// Raw decmpfs LZVN permits padding following its EOS opcode. Framing all bytes
// as a bvxn payload incorrectly treats that padding as compressed instructions.
// Adapted from go-compressions/lzfse (BSD-3-Clause; see third-party notices).
fn lzvn(source: &[u8], expected: usize) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(expected);
    let mut position = 0;
    let mut previous = 0usize;
    while position < source.len() {
        let opcode = source[position];
        position += 1;
        if opcode == 6 {
            return if output.len() == expected {
                Ok(output)
            } else {
                Err(bad())
            };
        }
        if opcode == 14 || opcode == 22 {
            continue;
        }
        let mut byte = || -> io::Result<u8> {
            let value = *source.get(position).ok_or_else(bad)?;
            position += 1;
            Ok(value)
        };
        let (literal, matched, distance) = if opcode >= 0xf0 {
            (
                0,
                if opcode == 0xf0 {
                    byte()? as usize + 16
                } else {
                    (opcode & 15) as usize
                },
                previous,
            )
        } else if opcode >= 0xe0 {
            (
                if opcode == 0xe0 {
                    byte()? as usize + 16
                } else {
                    (opcode & 15) as usize
                },
                0,
                previous,
            )
        } else if (0xa0..0xc0).contains(&opcode) {
            let first = byte()?;
            let second = byte()?;
            (
                (opcode >> 3 & 3) as usize,
                (((opcode & 7) << 2) | (first & 3)) as usize + 3,
                (first >> 2) as usize | ((second as usize) << 6),
            )
        } else {
            let literal = (opcode >> 6) as usize;
            let matched = (opcode >> 3 & 7) as usize + 3;
            let distance = match opcode & 7 {
                0..=5 => ((opcode & 7) as usize) << 8 | byte()? as usize,
                6 => previous,
                _ => {
                    let first = byte()?;
                    let second = byte()?;
                    u16::from_le_bytes([first, second]) as usize
                }
            };
            (literal, matched, distance)
        };
        if literal + matched > expected.saturating_sub(output.len()) {
            return Err(bad());
        }
        let bytes = source.get(position..position + literal).ok_or_else(bad)?;
        output.extend_from_slice(bytes);
        position += literal;
        if matched != 0 {
            if distance == 0 || distance > output.len() {
                return Err(bad());
            }
            for _ in 0..matched {
                output.push(output[output.len() - distance]);
            }
            previous = distance;
        }
    }
    if output.len() == expected {
        Ok(output)
    } else {
        Err(bad())
    }
}

struct Limited {
    data: Vec<u8>,
    maximum: usize,
}
impl Write for Limited {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > self.maximum.saturating_sub(self.data.len()) {
            return Err(bad());
        }
        self.data.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn u24(bytes: &[u8]) -> io::Result<usize> {
    let b = bytes.get(..3).ok_or_else(bad)?;
    Ok(b[0] as usize | (b[1] as usize) << 8 | (b[2] as usize) << 16)
}
fn nibble(chunk: &[u8], position: &mut usize) -> io::Result<u8> {
    let byte = *chunk.get(*position / 2).ok_or_else(bad)?;
    let value = (byte >> ((*position % 2) * 4)) & 15;
    *position += 1;
    Ok(value)
}

// LZBITMAP format described by Corellium/libzbitmap and go-macos-pkg.
fn lzbitmap(mut source: &[u8], expected: usize) -> io::Result<Vec<u8>> {
    if !source.starts_with(b"ZBM\x09") {
        return Err(bad());
    }
    source = &source[4..];
    let mut output = Vec::with_capacity(expected);
    loop {
        let size = u24(source)?;
        let decoded = u24(source.get(3..).ok_or_else(bad)?)?;
        if size < 6 || decoded > 32768 || decoded > expected.saturating_sub(output.len()) {
            return Err(bad());
        }
        let chunk = source.get(..size).ok_or_else(bad)?;
        source = &source[size..];
        if decoded == 0 {
            return if output.len() == expected {
                Ok(output)
            } else {
                Err(bad())
            };
        }
        if size == decoded + 6 {
            output.extend_from_slice(&chunk[6..]);
            continue;
        }
        if size < 17 {
            return Err(bad());
        }
        let mut metadata = [u24(&chunk[6..])?, u24(&chunk[9..])?, u24(&chunk[12..])?];
        if metadata.iter().any(|offset| *offset >= size) {
            return Err(bad());
        }
        let mut descriptors = [(0u8, 0u8); 12];
        for (index, descriptor) in descriptors.iter_mut().enumerate() {
            let mut value = 0u16;
            for bit in 0..10 {
                let position = index * 10 + bit;
                value |= (((chunk[size - 17 + position / 8] >> (position % 8)) & 1) as u16) << bit;
            }
            *descriptor = (value as u8, (value >> 8) as u8);
            if descriptor.1 > 2 {
                return Err(bad());
            }
        }
        let mut literal = 15;
        let mut period = 8;
        let mut nib = metadata[2] * 2;
        let end = output.len() + decoded;
        while output.len() < end {
            let number = nibble(chunk, &mut nib)?;
            if number == 15 {
                return Err(bad());
            }
            let mut repeats = 1usize;
            if end - output.len() > 8 {
                let peek = nibble(chunk, &mut nib)?;
                if peek == 15 {
                    repeats = 4;
                    loop {
                        let extra = nibble(chunk, &mut nib)?;
                        repeats += extra as usize;
                        if repeats > 32768 {
                            return Err(bad());
                        }
                        if extra != 15 {
                            break;
                        }
                    }
                } else {
                    nib -= 1;
                }
            }
            for _ in 0..repeats {
                let (bitmap, bytes) = if number > 2 {
                    descriptors[number as usize - 3]
                } else {
                    let bitmap = *chunk.get(metadata[1]).ok_or_else(bad)?;
                    metadata[1] += 1;
                    (bitmap, number)
                };
                if bytes != 0 {
                    period = 0;
                    for index in 0..bytes {
                        period |=
                            (*chunk.get(metadata[0]).ok_or_else(bad)? as usize) << (index * 8);
                        metadata[0] += 1;
                    }
                }
                if period == 0 {
                    return Err(bad());
                }
                for bit in 0..8 {
                    if output.len() == end {
                        break;
                    }
                    let value = if bitmap & (1 << bit) != 0 {
                        let value = *chunk.get(literal).ok_or_else(bad)?;
                        literal += 1;
                        value
                    } else {
                        *output
                            .get(output.len().checked_sub(period).ok_or_else(bad)?)
                            .ok_or_else(bad)?
                    };
                    output.push(value);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plain_blocks_validate_declared_size() {
        for (method, marker) in [(8, 6), (12, 255), (14, 255)] {
            assert_eq!(decode(&[marker, b'a', b'b'], method, 2).unwrap(), b"ab");
            assert!(decode(&[marker, b'a', b'b'], method, 1).is_err());
        }
    }
    #[test]
    fn bitmap_plain_chunk_and_size_limit() {
        let data = b"ZBM\x09\x08\0\0\x02\0\0ab\x06\0\0\0\0\0";
        assert_eq!(decode(data, 14, 2).unwrap(), b"ab");
        assert!(decode(data, 14, 1).is_err());
    }
    #[test]
    fn raw_lzvn_handles_overlapping_matches_and_eos_padding() {
        let data = [0xe1, b'a', 0, 1, 6, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
        assert_eq!(decode(&data, 8, 4).unwrap(), b"aaaa");
        assert!(decode(&data, 8, 3).is_err());
        assert!(decode(&[0, 1, 6], 8, 3).is_err());
        assert!(decode(&[0xe3, b'a'], 8, 3).is_err());
    }
}
