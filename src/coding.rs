//! Binary primitives matching RocksDB's `util/coding.h`, `util/crc32c.h`, and `table/format.cc`.

use crate::{Error, Result};

const CRC32C_MASK_DELTA: u32 = 0xa282_ead8;
const XXH3_LAST_BYTE_PRIME: u32 = 0x6b90_83d9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChecksumType {
    None = 0,
    Crc32c = 1,
    XxHash = 2,
    XxHash64 = 3,
    Xxh3 = 4,
}

impl ChecksumType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::None),
            1 => Ok(Self::Crc32c),
            2 => Ok(Self::XxHash),
            3 => Ok(Self::XxHash64),
            4 => Ok(Self::Xxh3),
            other => Err(Error::Unsupported(format!(
                "unknown checksum type {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompressionType {
    None = 0,
    Snappy = 1,
}

impl CompressionType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::None),
            1 => Ok(Self::Snappy),
            other => Err(Error::Unsupported(format!(
                "unsupported compression type {other}"
            ))),
        }
    }
}

#[inline]
pub fn mask_crc(crc: u32) -> u32 {
    crc.rotate_right(15).wrapping_add(CRC32C_MASK_DELTA)
}

#[inline]
pub fn crc32c_masked(data: &[u8]) -> u32 {
    mask_crc(crc32c::crc32c(data))
}

#[inline]
pub fn checksum_modifier_for_context(base_context_checksum: u32, offset: u64) -> u32 {
    if base_context_checksum == 0 {
        return 0;
    }
    base_context_checksum ^ ((offset as u32).wrapping_add((offset >> 32) as u32))
}

#[inline]
fn modify_checksum_for_last_byte(checksum: u32, last_byte: u8) -> u32 {
    checksum ^ (last_byte as u32).wrapping_mul(XXH3_LAST_BYTE_PRIME)
}

/// Mirrors RocksDB `ComputeBuiltinChecksum(type, data, data_size)`.
pub fn compute_builtin_checksum(kind: ChecksumType, data: &[u8]) -> u32 {
    match kind {
        ChecksumType::None => 0,
        ChecksumType::Crc32c => crc32c_masked(data),
        ChecksumType::XxHash => xxhash_rust::xxh32::xxh32(data, 0),
        ChecksumType::XxHash64 => xxhash_rust::xxh64::xxh64(data, 0) as u32,
        ChecksumType::Xxh3 => {
            if data.is_empty() {
                0
            } else {
                let v = xxhash_rust::xxh3::xxh3_64(&data[..data.len() - 1]) as u32;
                modify_checksum_for_last_byte(v, data[data.len() - 1])
            }
        }
    }
}

/// Mirrors RocksDB `ComputeBuiltinChecksumWithLastByte(type, data, data_size, last_byte)`.
pub fn compute_builtin_checksum_with_last_byte(
    kind: ChecksumType,
    data: &[u8],
    last_byte: u8,
) -> u32 {
    match kind {
        ChecksumType::None => 0,
        ChecksumType::Crc32c => {
            let crc = crc32c::crc32c_append(crc32c::crc32c(data), &[last_byte]);
            mask_crc(crc)
        }
        ChecksumType::XxHash => {
            let mut h = xxhash_rust::xxh32::Xxh32::new(0);
            h.update(data);
            h.update(&[last_byte]);
            h.digest()
        }
        ChecksumType::XxHash64 => {
            let mut h = xxhash_rust::xxh64::Xxh64::new(0);
            h.update(data);
            h.update(&[last_byte]);
            h.digest() as u32
        }
        ChecksumType::Xxh3 => {
            let v = xxhash_rust::xxh3::xxh3_64(data) as u32;
            modify_checksum_for_last_byte(v, last_byte)
        }
    }
}

pub fn get_varint32(input: &mut &[u8]) -> Option<u32> {
    let mut result = 0u32;
    let mut shift = 0u32;
    for (idx, &b) in input.iter().enumerate() {
        if shift > 28 {
            return None;
        }
        result |= u32::from(b & 0x7f) << shift;
        if (b & 0x80) == 0 {
            *input = &input[idx + 1..];
            return Some(result);
        }
        shift += 7;
    }
    None
}

pub fn get_varint64(input: &mut &[u8]) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for (idx, &b) in input.iter().enumerate() {
        if shift > 63 {
            return None;
        }
        result |= u64::from(b & 0x7f) << shift;
        if (b & 0x80) == 0 {
            *input = &input[idx + 1..];
            return Some(result);
        }
        shift += 7;
    }
    None
}

/// Decodes RocksDB's zigzag-encoded signed 64-bit varint (`GetVarsignedint64`).
pub fn get_varsigned64(input: &mut &[u8]) -> Option<i64> {
    let v = get_varint64(input)?;
    let decoded = ((v >> 1) as i64) ^ -((v & 1) as i64);
    Some(decoded)
}

pub fn get_fixed32(input: &mut &[u8]) -> Option<u32> {
    if input.len() < 4 {
        return None;
    }
    let val = u32::from_le_bytes(input[..4].try_into().ok()?);
    *input = &input[4..];
    Some(val)
}

pub fn get_fixed64(input: &mut &[u8]) -> Option<u64> {
    if input.len() < 8 {
        return None;
    }
    let val = u64::from_le_bytes(input[..8].try_into().ok()?);
    *input = &input[8..];
    Some(val)
}

pub fn get_length_prefixed_slice<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = get_varint32(input)? as usize;
    if input.len() < len {
        return None;
    }
    let out = &input[..len];
    *input = &input[len..];
    Some(out)
}

pub fn put_varint32(dst: &mut Vec<u8>, mut v: u32) {
    while v >= 0x80 {
        dst.push((v as u8) | 0x80);
        v >>= 7;
    }
    dst.push(v as u8);
}

pub fn put_varint64(dst: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        dst.push((v as u8) | 0x80);
        v >>= 7;
    }
    dst.push(v as u8);
}

pub fn put_length_prefixed_slice(dst: &mut Vec<u8>, slice: &[u8]) {
    put_varint32(dst, slice.len() as u32);
    dst.extend_from_slice(slice);
}
