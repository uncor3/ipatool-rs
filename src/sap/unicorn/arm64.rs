//! Compatibility instructions needed by upstream's macOS 27 ARM64 guest.
//! Adapted from majd/ipatool internal/sap/machine/arm64.go (MIT).

use super::{Guest, arm64_reg as reg};
use crate::error::ClientError;

pub(super) fn emulate_invalid_instruction(guest: Guest<'_>) -> Result<bool, ClientError> {
    let pc = guest.reg_read(reg::PC)?;
    let mut bytes = [0_u8; 4];
    if guest.mem_read_into(pc, &mut bytes).is_err() {
        return Ok(false);
    }
    let instruction = u32::from_le_bytes(bytes);
    if instruction & 0xffe08000 == 0xce000000 {
        // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B (SHA3 extension).
        let first = guest.reg_read128(reg::V0 + ((instruction >> 5) & 31) as i32)?;
        let second = guest.reg_read128(reg::V0 + ((instruction >> 16) & 31) as i32)?;
        let third = guest.reg_read128(reg::V0 + ((instruction >> 10) & 31) as i32)?;
        let mut result = [0_u8; 16];
        for index in 0..16 {
            result[index] = first[index] ^ second[index] ^ third[index];
        }
        guest.reg_write128(reg::V0 + (instruction & 31) as i32, &result)?;
    } else {
        let opcode = instruction & 0xffe0fc00;
        let width = match opcode {
            0x88e0fc00 | 0xb8e08000 => 4,
            0xc8e0fc00 | 0xf8e08000 => 8,
            _ => return Ok(false),
        };
        let source = (instruction >> 16) & 31;
        let base = (instruction >> 5) & 31;
        let destination = instruction & 31;
        let address = guest.reg_read(if base == 31 { reg::SP } else { general(base)? })?;
        let mut memory = [0_u8; 8];
        guest.mem_read_into(address, &mut memory[..width])?;
        let old = u64::from_le_bytes(memory);
        let source_value = read_value(guest, source)?;
        let source_value = if width == 4 {
            source_value & 0xffff_ffff
        } else {
            source_value
        };
        if matches!(opcode, 0x88e0fc00 | 0xc8e0fc00) {
            // CASAL: compare Rs to memory, conditionally write Rt, return old
            // memory in Rs. Register 31 is XZR for values (SP for addresses).
            if old == source_value {
                let new = read_value(guest, destination)?.to_le_bytes();
                guest.mem_write(address, &new[..width])?;
            }
            write_value(guest, source, old)?;
        } else {
            // SWPAL exchanges memory and Rs, returning the old value in Rt.
            guest.mem_write(address, &source_value.to_le_bytes()[..width])?;
            write_value(guest, destination, old)?;
        }
    }
    guest.reg_write(reg::PC, pc + 4)?;
    Ok(true)
}

fn general(index: u32) -> Result<i32, ClientError> {
    reg::general(index).ok_or_else(|| ClientError::Sap(format!("invalid ARM64 register {index}")))
}

fn read_value(guest: Guest<'_>, index: u32) -> Result<u64, ClientError> {
    if index == 31 {
        Ok(0)
    } else {
        guest.reg_read(general(index)?)
    }
}

fn write_value(guest: Guest<'_>, index: u32, value: u64) -> Result<(), ClientError> {
    if index == 31 {
        Ok(())
    } else {
        guest.reg_write(general(index)?, value)
    }
}
