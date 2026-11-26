//! Integrated BlobDB (`*.blob` files and `BlobIndex` pointers).

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::coding::{CompressionType, get_varint64, mask_crc, put_varint64};
use crate::snappy;
use crate::{Error, Result};

const BLOB_MAGIC: u32 = 2_395_959; // 0x00248f37
const BLOB_VERSION_1: u32 = 1;
const BLOB_HEADER_SIZE: usize = 30;
const BLOB_RECORD_HEADER_SIZE: usize = 32;
const BLOB_FOOTER_SIZE: usize = 32;

/// Encodes a RocksDB `BlobIndex::Type::kBlob` pointer (stored as a `kTypeBlobIndex` value in SSTs).
pub fn encode_blob_index(
    file_number: u64,
    offset: u64,
    size: u64,
    compression: CompressionType,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.push(1u8); // Type::kBlob
    put_varint64(&mut out, file_number);
    put_varint64(&mut out, offset);
    put_varint64(&mut out, size);
    out.push(compression as u8);
    out
}

pub struct BlobFileStats {
    pub file_number: u64,
    pub total_blob_count: u64,
    pub total_blob_bytes: u64,
}

/// Writes an uncompressed RocksDB integrated BlobDB `*.blob` file.
pub struct BlobFileWriter {
    file_number: u64,
    writer: BufWriter<File>,
    offset: u64,
    blob_count: u64,
    total_blob_bytes: u64,
}

impl BlobFileWriter {
    pub fn create(db_dir: &Path, file_number: u64, cf_id: u32) -> Result<Self> {
        let path = db_dir.join(format!("{file_number:06}.blob"));
        let file = File::create(path)?;
        let mut writer = BufWriter::with_capacity(512 * 1024, file);
        let mut hdr = Vec::with_capacity(BLOB_HEADER_SIZE);
        hdr.extend_from_slice(&BLOB_MAGIC.to_le_bytes());
        hdr.extend_from_slice(&BLOB_VERSION_1.to_le_bytes());
        hdr.extend_from_slice(&cf_id.to_le_bytes());
        hdr.push(0u8); // flags (no TTL)
        hdr.push(CompressionType::None as u8);
        hdr.extend_from_slice(&0u64.to_le_bytes()); // exp start
        hdr.extend_from_slice(&0u64.to_le_bytes()); // exp end
        debug_assert_eq!(hdr.len(), BLOB_HEADER_SIZE);
        writer.write_all(&hdr)?;
        Ok(Self {
            file_number,
            writer,
            offset: BLOB_HEADER_SIZE as u64,
            blob_count: 0,
            total_blob_bytes: 0,
        })
    }

    /// Appends one blob record and returns `(value_offset, value_size)` matching RocksDB `BlobIndex`.
    pub fn add_blob(&mut self, user_key: &[u8], value: &[u8]) -> Result<(u64, u64)> {
        let key_len = user_key.len() as u64;
        let val_len = value.len() as u64;
        let exp = 0u64;

        let mut rec_hdr = [0u8; BLOB_RECORD_HEADER_SIZE];
        rec_hdr[0..8].copy_from_slice(&key_len.to_le_bytes());
        rec_hdr[8..16].copy_from_slice(&val_len.to_le_bytes());
        rec_hdr[16..24].copy_from_slice(&exp.to_le_bytes());
        let hdr_crc = mask_crc(crc32c::crc32c(&rec_hdr[0..24]));
        let blob_crc = mask_crc(crc32c::crc32c_append(crc32c::crc32c(user_key), value));
        rec_hdr[24..28].copy_from_slice(&hdr_crc.to_le_bytes());
        rec_hdr[28..32].copy_from_slice(&blob_crc.to_le_bytes());

        self.writer.write_all(&rec_hdr)?;
        self.writer.write_all(user_key)?;
        self.writer.write_all(value)?;

        let value_offset = self.offset + (BLOB_RECORD_HEADER_SIZE as u64) + key_len;
        let record_bytes = (BLOB_RECORD_HEADER_SIZE as u64) + key_len + val_len;
        self.offset += record_bytes;
        self.blob_count += 1;
        // RocksDB `BlobFileAddition::total_blob_bytes` counts the full record bytes (header+key+value).
        self.total_blob_bytes += record_bytes;
        Ok((value_offset, val_len))
    }

    pub fn current_bytes(&self) -> u64 {
        self.offset
    }

    pub fn file_number(&self) -> u64 {
        self.file_number
    }

    pub fn finish(self) -> Result<BlobFileStats> {
        self.finish_with_sync(true)
    }

    pub fn finish_with_sync(mut self, sync: bool) -> Result<BlobFileStats> {
        let mut footer = Vec::with_capacity(BLOB_FOOTER_SIZE);
        footer.extend_from_slice(&BLOB_MAGIC.to_le_bytes());
        footer.extend_from_slice(&self.blob_count.to_le_bytes());
        footer.extend_from_slice(&0u64.to_le_bytes());
        footer.extend_from_slice(&0u64.to_le_bytes());
        let crc = mask_crc(crc32c::crc32c(&footer));
        footer.extend_from_slice(&crc.to_le_bytes());
        debug_assert_eq!(footer.len(), BLOB_FOOTER_SIZE);
        self.writer.write_all(&footer)?;
        self.writer.flush()?;
        let file = self.writer.into_inner().map_err(|e| e.into_error())?;
        if sync {
            file.sync_data()?;
        }
        Ok(BlobFileStats {
            file_number: self.file_number,
            total_blob_count: self.blob_count,
            total_blob_bytes: self.total_blob_bytes,
        })
    }
}

#[derive(Debug, Clone)]
pub enum BlobIndex {
    InlinedTtl {
        expiration: u64,
        value: Vec<u8>,
    },
    Blob {
        file_number: u64,
        offset: u64,
        size: u64,
        compression: CompressionType,
    },
}

impl BlobIndex {
    pub fn decode(mut input: &[u8]) -> Result<Self> {
        if input.is_empty() {
            return Err(Error::Corruption("empty BlobIndex".into()));
        }
        let kind = input[0];
        input = &input[1..];
        match kind {
            0 => {
                let expiration = get_varint64(&mut input)
                    .ok_or_else(|| Error::Corruption("BlobIndex: bad inlined TTL".into()))?;
                Ok(Self::InlinedTtl {
                    expiration,
                    value: input.to_vec(),
                })
            }
            1 | 2 => {
                if kind == 2 {
                    let _exp = get_varint64(&mut input)
                        .ok_or_else(|| Error::Corruption("BlobIndex: bad blob TTL".into()))?;
                }
                let file_number = get_varint64(&mut input)
                    .ok_or_else(|| Error::Corruption("BlobIndex: bad file_number".into()))?;
                let offset = get_varint64(&mut input)
                    .ok_or_else(|| Error::Corruption("BlobIndex: bad offset".into()))?;
                let size = get_varint64(&mut input)
                    .ok_or_else(|| Error::Corruption("BlobIndex: bad size".into()))?;
                if input.len() != 1 {
                    return Err(Error::Corruption(
                        "BlobIndex: bad trailing compression byte".into(),
                    ));
                }
                let compression = CompressionType::from_u8(input[0])?;
                Ok(Self::Blob {
                    file_number,
                    offset,
                    size,
                    compression,
                })
            }
            other => Err(Error::Corruption(format!(
                "BlobIndex: unknown type {other}"
            ))),
        }
    }
}

/// Reads and CRC32C-verifies a single blob value from `<db_dir>/{file_number:06}.blob`.
pub fn read_blob_value(
    db_dir: &Path,
    user_key: &[u8],
    file_number: u64,
    value_offset: u64,
    value_size: u64,
    compression: CompressionType,
) -> Result<Vec<u8>> {
    let path = db_dir.join(format!("{file_number:06}.blob"));
    let mut file = File::open(&path)?;

    // Validate the 30-byte file header.
    let mut hdr = [0u8; BLOB_HEADER_SIZE];
    file.read_exact(&mut hdr)?;
    let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    let version = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
    if magic != BLOB_MAGIC || version != BLOB_VERSION_1 {
        return Err(Error::Corruption(format!(
            "blob file {file_number:06}.blob: bad header magic/version"
        )));
    }

    let adjustment = (BLOB_RECORD_HEADER_SIZE as u64) + (user_key.len() as u64);
    if value_offset < (BLOB_HEADER_SIZE as u64) + adjustment {
        return Err(Error::Corruption(format!(
            "blob file {file_number:06}.blob: invalid value offset {value_offset}"
        )));
    }
    let rec_start = value_offset - adjustment;
    file.seek(SeekFrom::Start(rec_start))?;

    let mut rec_hdr = [0u8; BLOB_RECORD_HEADER_SIZE];
    file.read_exact(&mut rec_hdr)?;
    let key_len = u64::from_le_bytes(rec_hdr[0..8].try_into().unwrap());
    let val_len = u64::from_le_bytes(rec_hdr[8..16].try_into().unwrap());
    let stored_hdr_crc = u32::from_le_bytes(rec_hdr[24..28].try_into().unwrap());
    let stored_blob_crc = u32::from_le_bytes(rec_hdr[28..32].try_into().unwrap());

    let computed_hdr_crc = mask_crc(crc32c::crc32c(&rec_hdr[0..24]));
    if computed_hdr_crc != stored_hdr_crc {
        return Err(Error::Corruption(format!(
            "blob file {file_number:06}.blob: record header CRC mismatch at {rec_start}"
        )));
    }
    if key_len != user_key.len() as u64 || val_len != value_size {
        return Err(Error::Corruption(format!(
            "blob file {file_number:06}.blob: key/value length mismatch at {rec_start}"
        )));
    }

    let mut key_buf = vec![0u8; key_len as usize];
    file.read_exact(&mut key_buf)?;
    if key_buf != user_key {
        return Err(Error::Corruption(format!(
            "blob file {file_number:06}.blob: key mismatch at {rec_start}"
        )));
    }

    let mut val_buf = vec![0u8; value_size as usize];
    file.read_exact(&mut val_buf)?;

    let blob_crc = mask_crc(crc32c::crc32c_append(crc32c::crc32c(&key_buf), &val_buf));
    if blob_crc != stored_blob_crc {
        return Err(Error::Corruption(format!(
            "blob file {file_number:06}.blob: value CRC mismatch at {rec_start}"
        )));
    }

    match compression {
        CompressionType::None => Ok(val_buf),
        CompressionType::Snappy => snappy::decompress(&val_buf),
    }
}

/// Fast single-pread reader for an already-opened, header-validated `.blob` file.
pub struct BlobFileReader {
    file: File,
    file_number: u64,
}

impl BlobFileReader {
    pub fn open(db_dir: &Path, file_number: u64) -> Result<Self> {
        let path = db_dir.join(format!("{file_number:06}.blob"));
        let mut file = File::open(path)?;
        let mut hdr = [0u8; BLOB_HEADER_SIZE];
        file.read_exact(&mut hdr)?;
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let version = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        if magic != BLOB_MAGIC || version != BLOB_VERSION_1 {
            return Err(Error::Corruption(format!(
                "blob file {file_number:06}.blob: bad header magic/version"
            )));
        }
        Ok(Self { file, file_number })
    }

    pub fn read_value(
        &self,
        user_key: &[u8],
        value_offset: u64,
        value_size: u64,
        compression: CompressionType,
    ) -> Result<Vec<u8>> {
        let adjustment = (BLOB_RECORD_HEADER_SIZE as u64) + (user_key.len() as u64);
        if value_offset < (BLOB_HEADER_SIZE as u64) + adjustment {
            return Err(Error::Corruption(format!(
                "blob file {:06}.blob: invalid value offset {value_offset}",
                self.file_number
            )));
        }
        let rec_start = value_offset - adjustment;
        let total = (adjustment + value_size) as usize;
        let mut buf = vec![0u8; total];
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.file.read_exact_at(&mut buf, rec_start)?;
        }
        #[cfg(not(unix))]
        {
            let mut f = self.file.try_clone()?;
            f.seek(SeekFrom::Start(rec_start))?;
            f.read_exact(&mut buf)?;
        }

        let rec_hdr = &buf[..BLOB_RECORD_HEADER_SIZE];
        let key_len = u64::from_le_bytes(rec_hdr[0..8].try_into().unwrap());
        let val_len = u64::from_le_bytes(rec_hdr[8..16].try_into().unwrap());
        let stored_hdr_crc = u32::from_le_bytes(rec_hdr[24..28].try_into().unwrap());
        let stored_blob_crc = u32::from_le_bytes(rec_hdr[28..32].try_into().unwrap());

        if mask_crc(crc32c::crc32c(&rec_hdr[0..24])) != stored_hdr_crc {
            return Err(Error::Corruption(format!(
                "blob file {:06}.blob: record header CRC mismatch at {rec_start}",
                self.file_number
            )));
        }
        if key_len != user_key.len() as u64 || val_len != value_size {
            return Err(Error::Corruption(format!(
                "blob file {:06}.blob: key/value length mismatch at {rec_start}",
                self.file_number
            )));
        }
        let key_slice = &buf[BLOB_RECORD_HEADER_SIZE..adjustment as usize];
        if key_slice != user_key {
            return Err(Error::Corruption(format!(
                "blob file {:06}.blob: key mismatch at {rec_start}",
                self.file_number
            )));
        }
        let val_slice = &buf[adjustment as usize..];
        let blob_crc = mask_crc(crc32c::crc32c_append(crc32c::crc32c(key_slice), val_slice));
        if blob_crc != stored_blob_crc {
            return Err(Error::Corruption(format!(
                "blob file {:06}.blob: value CRC mismatch at {rec_start}",
                self.file_number
            )));
        }

        match compression {
            CompressionType::None => Ok(val_slice.to_vec()),
            CompressionType::Snappy => snappy::decompress(val_slice),
        }
    }
}
