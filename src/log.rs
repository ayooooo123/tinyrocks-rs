//! 32 KiB block-framed log reader shared by RocksDB WAL (`*.log`) and `MANIFEST-*`.

use std::io::Write;

use crate::coding::mask_crc;
use crate::{Error, Result};

pub const BLOCK_SIZE: usize = 32_768;
pub const HEADER_SIZE: usize = 7;
pub const RECYCLABLE_HEADER_SIZE: usize = 11;

const RECORD_ZERO: u8 = 0;
const RECORD_FULL: u8 = 1;
const RECORD_FIRST: u8 = 2;
const RECORD_MIDDLE: u8 = 3;
const RECORD_LAST: u8 = 4;
const RECORD_RECYCLABLE_FULL: u8 = 5;
const RECORD_RECYCLABLE_FIRST: u8 = 6;
const RECORD_RECYCLABLE_MIDDLE: u8 = 7;
const RECORD_RECYCLABLE_LAST: u8 = 8;
const RECORD_SET_COMPRESSION: u8 = 9;
const RECORD_UDT_SIZE: u8 = 10;
const RECORD_RECYCLABLE_UDT_SIZE: u8 = 11;
const RECORD_SAFE_IGNORE_MASK: u8 = 0x80;

/// Reads all complete logical records from a RocksDB WAL or MANIFEST file buffer.
///
/// Tolerates a truncated trailing record on crash-recovery WALs/MANIFESTs when
/// `allow_truncated_tail` is true.
pub fn read_records(data: &[u8], allow_truncated_tail: bool) -> Result<Vec<Vec<u8>>> {
    Ok(read_records_with_valid_len(data, allow_truncated_tail)?.0)
}

/// Like [`read_records`], also returning the byte offset immediately after the last
/// complete valid logical record (used to truncate a crash-corrupted MANIFEST tail).
pub fn read_records_with_valid_len(
    data: &[u8],
    allow_truncated_tail: bool,
) -> Result<(Vec<Vec<u8>>, usize)> {
    let mut records = Vec::new();
    let mut offset = 0usize;
    let mut valid_len = 0usize;
    let mut in_fragment = false;
    let mut scratch = Vec::new();

    while offset < data.len() {
        let block_rem = BLOCK_SIZE - (offset % BLOCK_SIZE);
        if block_rem < HEADER_SIZE {
            offset += block_rem;
            continue;
        }
        if offset + HEADER_SIZE > data.len() {
            if allow_truncated_tail {
                break;
            }
            return Err(Error::Corruption("log: truncated record header".into()));
        }

        let stored_crc = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let len = u16::from_le_bytes(data[offset + 4..offset + 6].try_into().unwrap()) as usize;
        let rec_type = data[offset + 6];

        // Preallocated zeroed tail in a recycled/preallocated log block.
        if rec_type == RECORD_ZERO && stored_crc == 0 && len == 0 {
            if in_fragment {
                if allow_truncated_tail {
                    break;
                }
                return Err(Error::Corruption(
                    "log: zero record inside fragmented record".into(),
                ));
            }
            offset += block_rem;
            continue;
        }

        let is_recyclable = matches!(
            rec_type,
            RECORD_RECYCLABLE_FULL
                | RECORD_RECYCLABLE_FIRST
                | RECORD_RECYCLABLE_MIDDLE
                | RECORD_RECYCLABLE_LAST
                | RECORD_RECYCLABLE_UDT_SIZE
                | 131
        );
        let hdr_len = if is_recyclable {
            RECYCLABLE_HEADER_SIZE
        } else {
            HEADER_SIZE
        };

        if hdr_len + len > block_rem || offset + hdr_len + len > data.len() {
            if allow_truncated_tail {
                break;
            }
            return Err(Error::Corruption(format!(
                "log: record length {len} exceeds block/file bounds at offset {offset}"
            )));
        }

        let payload = &data[offset + hdr_len..offset + hdr_len + len];
        // CRC covers [rec_type] + optional [log_number (4B)] + payload.
        let crc_input = &data[offset + 6..offset + hdr_len + len];
        let computed = mask_crc(crc32c::crc32c(crc_input));
        if computed != stored_crc {
            if allow_truncated_tail {
                break;
            }
            return Err(Error::Corruption(format!(
                "log: crc mismatch at offset {offset} (stored {stored_crc:#x}, computed {computed:#x})"
            )));
        }

        offset += hdr_len + len;

        if (rec_type & RECORD_SAFE_IGNORE_MASK) != 0
            || matches!(
                rec_type,
                RECORD_SET_COMPRESSION | RECORD_UDT_SIZE | RECORD_RECYCLABLE_UDT_SIZE
            )
        {
            if !in_fragment {
                valid_len = offset;
            }
            continue;
        }

        match rec_type {
            RECORD_FULL | RECORD_RECYCLABLE_FULL => {
                if in_fragment {
                    return Err(Error::Corruption(
                        "log: unexpected full record inside fragment".into(),
                    ));
                }
                records.push(payload.to_vec());
                valid_len = offset;
            }
            RECORD_FIRST | RECORD_RECYCLABLE_FIRST => {
                if in_fragment {
                    return Err(Error::Corruption(
                        "log: unexpected first record inside fragment".into(),
                    ));
                }
                scratch.clear();
                scratch.extend_from_slice(payload);
                in_fragment = true;
            }
            RECORD_MIDDLE | RECORD_RECYCLABLE_MIDDLE => {
                if !in_fragment {
                    return Err(Error::Corruption(
                        "log: middle record without first".into(),
                    ));
                }
                scratch.extend_from_slice(payload);
            }
            RECORD_LAST | RECORD_RECYCLABLE_LAST => {
                if !in_fragment {
                    return Err(Error::Corruption("log: last record without first".into()));
                }
                scratch.extend_from_slice(payload);
                records.push(std::mem::take(&mut scratch));
                in_fragment = false;
                valid_len = offset;
            }
            other => {
                return Err(Error::Unsupported(format!(
                    "log: unsupported record type {other}"
                )));
            }
        }
    }

    Ok((records, valid_len))
}

/// Appends 32 KiB block-framed RocksDB log records (`FULL` / `FIRST` / `MIDDLE` / `LAST`).
pub struct LogWriter<W: Write> {
    writer: W,
    block_offset: usize,
}

impl<W: Write> LogWriter<W> {
    pub fn new(writer: W, initial_file_len: usize) -> Self {
        Self {
            writer,
            block_offset: initial_file_len % BLOCK_SIZE,
        }
    }

    pub fn add_record(&mut self, mut payload: &[u8]) -> Result<()> {
        let mut begin = true;
        loop {
            let leftover = BLOCK_SIZE - self.block_offset;
            if leftover < HEADER_SIZE {
                if leftover > 0 {
                    let zeros = [0u8; HEADER_SIZE];
                    self.writer.write_all(&zeros[..leftover])?;
                }
                self.block_offset = 0;
            }
            let avail = BLOCK_SIZE - self.block_offset - HEADER_SIZE;
            let fragment_len = payload.len().min(avail);
            let end = fragment_len == payload.len();
            let rec_type = match (begin, end) {
                (true, true) => RECORD_FULL,
                (true, false) => RECORD_FIRST,
                (false, true) => RECORD_LAST,
                (false, false) => RECORD_MIDDLE,
            };
            self.emit_physical(rec_type, &payload[..fragment_len])?;
            payload = &payload[fragment_len..];
            begin = false;
            if payload.is_empty() {
                break;
            }
        }
        Ok(())
    }

    fn emit_physical(&mut self, rec_type: u8, fragment: &[u8]) -> Result<()> {
        let len = fragment.len() as u16;
        let crc = mask_crc(crc32c::crc32c_append(
            crc32c::crc32c(&[rec_type]),
            fragment,
        ));
        let mut hdr = [0u8; HEADER_SIZE];
        hdr[0..4].copy_from_slice(&crc.to_le_bytes());
        hdr[4..6].copy_from_slice(&len.to_le_bytes());
        hdr[6] = rec_type;
        self.writer.write_all(&hdr)?;
        self.writer.write_all(fragment)?;
        self.block_offset += HEADER_SIZE + fragment.len();
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

