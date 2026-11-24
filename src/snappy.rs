//! Pure-Rust Snappy block decompressor for reading legacy Snappy-compressed SSTs.

use crate::coding::get_varint32;
use crate::{Error, Result};

pub fn decompress(mut src: &[u8]) -> Result<Vec<u8>> {
    let uncompressed_len = get_varint32(&mut src)
        .ok_or_else(|| Error::Corruption("snappy: truncated uncompressed length".into()))?
        as usize;
    let mut out = Vec::with_capacity(uncompressed_len.min(16 * 1024 * 1024));

    while !src.is_empty() {
        let tag = src[0];
        src = &src[1..];
        match tag & 0x03 {
            0 => {
                let len = match tag >> 2 {
                    n @ 0..=59 => (n as usize) + 1,
                    60 => {
                        if src.is_empty() {
                            return Err(Error::Corruption("snappy: truncated literal len".into()));
                        }
                        let v = src[0] as usize + 1;
                        src = &src[1..];
                        v
                    }
                    61 => {
                        if src.len() < 2 {
                            return Err(Error::Corruption("snappy: truncated literal len".into()));
                        }
                        let v = u16::from_le_bytes([src[0], src[1]]) as usize + 1;
                        src = &src[2..];
                        v
                    }
                    62 => {
                        if src.len() < 3 {
                            return Err(Error::Corruption("snappy: truncated literal len".into()));
                        }
                        let v = u32::from_le_bytes([src[0], src[1], src[2], 0]) as usize + 1;
                        src = &src[3..];
                        v
                    }
                    63 => {
                        if src.len() < 4 {
                            return Err(Error::Corruption("snappy: truncated literal len".into()));
                        }
                        let v = u32::from_le_bytes([src[0], src[1], src[2], src[3]]) as usize + 1;
                        src = &src[4..];
                        v
                    }
                    _ => unreachable!(),
                };
                if src.len() < len {
                    return Err(Error::Corruption("snappy: truncated literal data".into()));
                }
                out.extend_from_slice(&src[..len]);
                src = &src[len..];
            }
            1 => {
                if src.is_empty() {
                    return Err(Error::Corruption("snappy: truncated copy1".into()));
                }
                let len = (((tag >> 2) & 0x07) as usize) + 4;
                let offset = (((tag & 0xe0) as usize) << 3) | (src[0] as usize);
                src = &src[1..];
                copy_from_output(&mut out, offset, len)?;
            }
            2 => {
                if src.len() < 2 {
                    return Err(Error::Corruption("snappy: truncated copy2".into()));
                }
                let len = ((tag >> 2) as usize) + 1;
                let offset = u16::from_le_bytes([src[0], src[1]]) as usize;
                src = &src[2..];
                copy_from_output(&mut out, offset, len)?;
            }
            3 => {
                if src.len() < 4 {
                    return Err(Error::Corruption("snappy: truncated copy4".into()));
                }
                let len = ((tag >> 2) as usize) + 1;
                let offset = u32::from_le_bytes([src[0], src[1], src[2], src[3]]) as usize;
                src = &src[4..];
                copy_from_output(&mut out, offset, len)?;
            }
            _ => unreachable!(),
        }
        if out.len() > uncompressed_len {
            return Err(Error::Corruption(
                "snappy: output exceeded header length".into(),
            ));
        }
    }

    if out.len() != uncompressed_len {
        return Err(Error::Corruption(format!(
            "snappy: length mismatch (got {}, expected {uncompressed_len})",
            out.len()
        )));
    }
    Ok(out)
}

fn copy_from_output(out: &mut Vec<u8>, offset: usize, len: usize) -> Result<()> {
    if offset == 0 || offset > out.len() {
        return Err(Error::Corruption(format!(
            "snappy: invalid copy offset {offset} at output len {}",
            out.len()
        )));
    }
    let start = out.len() - offset;
    if offset >= len {
        out.extend_from_within(start..start + len);
    } else {
        for i in 0..len {
            let b = out[start + (i % offset)];
            out.push(b);
        }
    }
    Ok(())
}
