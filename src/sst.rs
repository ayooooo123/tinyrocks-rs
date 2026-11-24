//! RocksDB `BlockBasedTable` (format v0..v6) reader with `pread` (`read_exact_at`),
//! restart-array binary search, and a small per-table LRU block cache.

use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::os::unix::fs::FileExt;

use crate::bloom::BloomFilter;
use crate::coding::{
    ChecksumType, CompressionType, checksum_modifier_for_context, compute_builtin_checksum,
    compute_builtin_checksum_with_last_byte, get_fixed32, get_fixed64, get_varint32, get_varint64,
    get_varsigned64,
};
use crate::keys::{ParsedInternalKey, ValueType, compare_internal_keys};
use crate::range_del::RangeTombstone;
use crate::snappy;
use crate::{Error, Result};

const BLOCK_BASED_TABLE_MAGIC: u64 = 0x88e2_41b7_85f4_cff7;
const LEGACY_BLOCK_BASED_TABLE_MAGIC: u64 = 0xdb47_7524_8b80_fb57;
const EXTENDED_MAGIC_V6: [u8; 4] = [0x3e, 0x00, 0x7a, 0x00];
const BLOCK_TRAILER_SIZE: usize = 5;
const FOOTER_V0_LEN: usize = 48;
const FOOTER_NEW_LEN: usize = 53;
const MAX_CACHED_BLOCKS_PER_SST: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHandle {
    pub offset: u64,
    pub size: u64,
}

impl BlockHandle {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let offset = get_varint64(input)
            .ok_or_else(|| Error::Corruption("BlockHandle: bad offset".into()))?;
        let size =
            get_varint64(input).ok_or_else(|| Error::Corruption("BlockHandle: bad size".into()))?;
        Ok(Self { offset, size })
    }
}

#[derive(Debug, Clone)]
struct Footer {
    format_version: u32,
    checksum_type: ChecksumType,
    base_context_checksum: u32,
    metaindex_handle: BlockHandle,
    index_handle: Option<BlockHandle>,
}

fn pread_exact(file: &File, offset: u64, buf: &mut [u8]) -> Result<()> {
    #[cfg(unix)]
    {
        file.read_exact_at(buf, offset)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        use std::io::{Read, Seek, SeekFrom};
        let mut clone = file.try_clone()?;
        clone.seek(SeekFrom::Start(offset))?;
        clone.read_exact(buf)?;
        Ok(())
    }
}

impl Footer {
    fn read(file: &File, file_size: u64) -> Result<Self> {
        if file_size < FOOTER_V0_LEN as u64 {
            return Err(Error::Corruption("sst: file shorter than footer".into()));
        }
        let read_len = (file_size as usize).min(FOOTER_NEW_LEN);
        let read_offset = file_size - read_len as u64;
        let mut buf = vec![0u8; read_len];
        pread_exact(file, read_offset, &mut buf)?;

        let magic = u64::from_le_bytes(buf[read_len - 8..read_len].try_into().unwrap());
        if magic == LEGACY_BLOCK_BASED_TABLE_MAGIC {
            let start = read_len - FOOTER_V0_LEN;
            let mut slice = &buf[start..read_len - 8];
            let metaindex_handle = BlockHandle::decode(&mut slice)?;
            let index_handle = BlockHandle::decode(&mut slice)?;
            return Ok(Self {
                format_version: 0,
                checksum_type: ChecksumType::Crc32c,
                base_context_checksum: 0,
                metaindex_handle,
                index_handle: Some(index_handle),
            });
        }
        if magic != BLOCK_BASED_TABLE_MAGIC {
            return Err(Error::Corruption(format!(
                "sst: bad table magic {magic:#x}"
            )));
        }
        if read_len < FOOTER_NEW_LEN {
            return Err(Error::Corruption("sst: truncated v1+ footer".into()));
        }
        let footer_offset = file_size - FOOTER_NEW_LEN as u64;
        let footer_bytes = &buf[read_len - FOOTER_NEW_LEN..];
        let checksum_type = ChecksumType::from_u8(footer_bytes[0])?;
        let format_version = u32::from_le_bytes(footer_bytes[41..45].try_into().unwrap());

        if format_version >= 6 {
            let mut part2 = &footer_bytes[1..41];
            if part2[..4] != EXTENDED_MAGIC_V6 {
                return Err(Error::Corruption("sst: bad v6 extended magic".into()));
            }
            part2 = &part2[4..];
            let stored_checksum = get_fixed32(&mut part2).unwrap();
            let base_context_checksum = get_fixed32(&mut part2).unwrap();
            let metaindex_size = get_fixed32(&mut part2).unwrap() as u64;
            part2 = &part2[16..];
            let reserved = get_fixed64(&mut part2).unwrap();
            if reserved != 0 {
                return Err(Error::Unsupported(
                    "sst: non-zero reserved footer feature bits".into(),
                ));
            }
            if checksum_type != ChecksumType::None {
                let mut copy = [0u8; FOOTER_NEW_LEN];
                copy.copy_from_slice(footer_bytes);
                copy[5..9].fill(0);
                let computed = compute_builtin_checksum(checksum_type, &copy).wrapping_add(
                    checksum_modifier_for_context(base_context_checksum, footer_offset),
                );
                if computed != stored_checksum {
                    return Err(Error::Corruption(format!(
                        "sst: v6 footer checksum mismatch (stored {stored_checksum:#x}, computed {computed:#x})"
                    )));
                }
            }
            let metaindex_end = footer_offset
                .checked_sub(BLOCK_TRAILER_SIZE as u64)
                .ok_or_else(|| Error::Corruption("sst: bad metaindex end".into()))?;
            let metaindex_offset = metaindex_end
                .checked_sub(metaindex_size)
                .ok_or_else(|| Error::Corruption("sst: metaindex size exceeds file".into()))?;
            Ok(Self {
                format_version,
                checksum_type,
                base_context_checksum,
                metaindex_handle: BlockHandle {
                    offset: metaindex_offset,
                    size: metaindex_size,
                },
                index_handle: None,
            })
        } else {
            let mut part2 = &footer_bytes[1..41];
            let metaindex_handle = BlockHandle::decode(&mut part2)?;
            let index_handle = BlockHandle::decode(&mut part2)?;
            Ok(Self {
                format_version,
                checksum_type,
                base_context_checksum: 0,
                metaindex_handle,
                index_handle: Some(index_handle),
            })
        }
    }
}

#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub separator: Vec<u8>,
    pub handle: BlockHandle,
}

#[derive(Debug, Clone)]
pub struct SstEntry {
    pub internal_key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Default)]
struct BlockCache {
    map: HashMap<u64, Arc<[u8]>>,
    order: VecDeque<u64>,
}

impl BlockCache {
    fn get(&self, offset: u64) -> Option<Arc<[u8]>> {
        self.map.get(&offset).cloned()
    }

    fn insert(&mut self, offset: u64, block: Arc<[u8]>) {
        if self.map.contains_key(&offset) {
            return;
        }
        if self.order.len() >= MAX_CACHED_BLOCKS_PER_SST
            && let Some(old) = self.order.pop_front()
        {
            self.map.remove(&old);
        }
        self.order.push_back(offset);
        self.map.insert(offset, block);
    }
}

pub struct SstReader {
    file: File,
    footer: Footer,
    index_key_is_user_key: bool,
    index_entries: Vec<IndexEntry>,
    filter: Option<BloomFilter>,
    block_cache: Mutex<BlockCache>,
    pub range_dels: Vec<RangeTombstone>,
}

impl SstReader {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let file_size = file.metadata()?.len();
        let footer = Footer::read(&file, file_size)?;

        let metaindex_raw = read_block(&file, &footer, footer.metaindex_handle)?;
        let mut meta_blocks: HashMap<Vec<u8>, BlockHandle> = HashMap::new();
        for (k, v) in decode_standard_block(&metaindex_raw)? {
            let mut vs = v.as_slice();
            let handle = BlockHandle::decode(&mut vs)?;
            meta_blocks.insert(k, handle);
        }

        let mut index_key_is_user_key = false;
        let mut index_value_is_delta_encoded = false;
        let mut index_partitions = 0u64;
        if let Some(&props_handle) = meta_blocks
            .get(b"rocksdb.properties".as_slice())
            .or_else(|| meta_blocks.get(b"rocksdb.stats".as_slice()))
        {
            let props_raw = read_block(&file, &footer, props_handle)?;
            for (k, v) in decode_standard_block(&props_raw)? {
                let mut vs = v.as_slice();
                if k == b"rocksdb.index.key.is.user.key" {
                    index_key_is_user_key = get_varint64(&mut vs).unwrap_or(0) != 0;
                } else if k == b"rocksdb.index.value.is.delta.encoded" {
                    index_value_is_delta_encoded = get_varint64(&mut vs).unwrap_or(0) != 0;
                } else if k == b"rocksdb.index.partitions" {
                    index_partitions = get_varint64(&mut vs).unwrap_or(0);
                }
            }
        }

        let index_handle = match footer.index_handle {
            Some(h) => h,
            None => *meta_blocks
                .get(b"rocksdb.index".as_slice())
                .ok_or_else(|| Error::Corruption("sst: v6 table missing rocksdb.index".into()))?,
        };
        let index_raw = read_block(&file, &footer, index_handle)?;
        let top_entries = decode_index_block(&index_raw, index_value_is_delta_encoded)?;
        let index_entries = if index_partitions > 0 {
            let mut flat = Vec::new();
            for part in top_entries {
                let part_raw = read_block(&file, &footer, part.handle)?;
                flat.extend(decode_index_block(&part_raw, index_value_is_delta_encoded)?);
            }
            flat
        } else {
            top_entries
        };

        let mut range_dels = Vec::new();
        if let Some(&rdel_handle) = meta_blocks.get(b"rocksdb.range_del".as_slice()) {
            let rdel_raw = read_block(&file, &footer, rdel_handle)?;
            for (k, v) in decode_standard_block(&rdel_raw)? {
                let parsed = ParsedInternalKey::parse(&k)?;
                if parsed.value_type == ValueType::RangeDeletion {
                    range_dels.push(RangeTombstone {
                        start: parsed.user_key.to_vec(),
                        end: v,
                        seqno: parsed.seqno,
                    });
                }
            }
        }

        let filter = if let Some(&filter_handle) = meta_blocks
            .get(b"fullfilter.rocksdb.BuiltinBloomFilter".as_slice())
            .or_else(|| meta_blocks.get(b"fullfilter.rocksdb.BloomFilter".as_slice()))
        {
            let filter_raw = read_block(&file, &footer, filter_handle)?;
            Some(BloomFilter::from_block(filter_raw))
        } else {
            None
        };

        Ok(Self {
            file,
            footer,
            index_key_is_user_key,
            index_entries,
            filter,
            block_cache: Mutex::new(BlockCache::default()),
            range_dels,
        })
    }

    pub fn has_filter(&self) -> bool {
        self.filter.is_some()
    }

    pub fn filter_may_match(&self, user_key: &[u8]) -> bool {
        self.filter.as_ref().is_none_or(|f| f.may_match(user_key))
    }

    fn get_block(&self, handle: BlockHandle) -> Result<Arc<[u8]>> {
        if let Some(hit) = self.block_cache.lock().unwrap().get(handle.offset) {
            return Ok(hit);
        }
        let raw: Arc<[u8]> = read_block(&self.file, &self.footer, handle)?.into();
        self.block_cache
            .lock()
            .unwrap()
            .insert(handle.offset, Arc::clone(&raw));
        Ok(raw)
    }

    /// Point lookup for `user_key` using Bloom filter screening + restart-array binary search.
    pub fn get(&self, user_key: &[u8]) -> Result<Option<(u64, ValueType, Vec<u8>)>> {
        if let Some(ref filter) = self.filter
            && !filter.may_match(user_key)
        {
            return Ok(None);
        }
        let Some(idx) = self.find_block_index(user_key) else {
            return Ok(None);
        };
        let block = self.get_block(self.index_entries[idx].handle)?;
        search_data_block(&block, user_key)
    }

    /// Reads all entries whose user key falls in `[lower, upper)` (open when `None`).
    pub fn scan_range(&self, lower: Option<&[u8]>, upper: Option<&[u8]>) -> Result<Vec<SstEntry>> {
        if self.index_entries.is_empty() {
            return Ok(Vec::new());
        }
        let start_idx = match lower {
            Some(lo) => self
                .find_block_index(lo)
                .unwrap_or(self.index_entries.len()),
            None => 0,
        };
        let mut out = Vec::new();
        for entry in &self.index_entries[start_idx..] {
            let block = self.get_block(entry.handle)?;
            for (k, v) in decode_standard_block(&block)? {
                let parsed = ParsedInternalKey::parse(&k)?;
                if let Some(lo) = lower
                    && parsed.user_key < lo
                {
                    continue;
                }
                if let Some(hi) = upper
                    && parsed.user_key >= hi
                {
                    return Ok(out);
                }
                out.push(SstEntry {
                    internal_key: k,
                    value: v,
                });
            }
            if let Some(hi) = upper {
                let sep_user = self.separator_user_key(&entry.separator);
                if sep_user >= hi {
                    break;
                }
            }
        }
        Ok(out)
    }

    fn separator_user_key<'a>(&self, sep: &'a [u8]) -> &'a [u8] {
        if self.index_key_is_user_key || sep.len() < 8 {
            sep
        } else {
            &sep[..sep.len() - 8]
        }
    }

    fn find_block_index(&self, user_key: &[u8]) -> Option<usize> {
        let mut target_internal = Vec::new();
        if !self.index_key_is_user_key {
            target_internal.extend_from_slice(user_key);
            let max_trailer = (crate::keys::MAX_SEQUENCE_NUMBER << 8) | 0xffu64;
            target_internal.extend_from_slice(&max_trailer.to_le_bytes());
        }
        let pos = self.index_entries.partition_point(|entry| {
            if self.index_key_is_user_key {
                entry.separator.as_slice() < user_key
            } else {
                compare_internal_keys(&entry.separator, &target_internal) == Ordering::Less
            }
        });
        if pos < self.index_entries.len() {
            Some(pos)
        } else {
            None
        }
    }
}

fn read_block(file: &File, footer: &Footer, handle: BlockHandle) -> Result<Vec<u8>> {
    let total = (handle.size as usize) + BLOCK_TRAILER_SIZE;
    let mut buf = vec![0u8; total];
    pread_exact(file, handle.offset, &mut buf)?;

    let data = &buf[..handle.size as usize];
    let comp_byte = buf[handle.size as usize];
    let stored_checksum =
        u32::from_le_bytes(buf[handle.size as usize + 1..total].try_into().unwrap());

    if footer.checksum_type != ChecksumType::None {
        let mut expected =
            compute_builtin_checksum_with_last_byte(footer.checksum_type, data, comp_byte);
        if footer.format_version >= 6 {
            expected = expected.wrapping_add(checksum_modifier_for_context(
                footer.base_context_checksum,
                handle.offset,
            ));
        }
        if expected != stored_checksum {
            return Err(Error::Corruption(format!(
                "sst: block checksum mismatch at offset {} (stored {stored_checksum:#x}, computed {expected:#x})",
                handle.offset
            )));
        }
    }

    match CompressionType::from_u8(comp_byte)? {
        CompressionType::None => Ok(data.to_vec()),
        CompressionType::Snappy => snappy::decompress(data),
    }
}

/// Splits a block into `(entries_slice, restarts_offset, num_restarts)`.
fn parse_block_layout(block: &[u8]) -> Result<(&[u8], usize, usize)> {
    if block.len() < 4 {
        return Err(Error::Corruption("block shorter than 4-byte footer".into()));
    }
    let packed = u32::from_le_bytes(block[block.len() - 4..].try_into().unwrap());
    let is_hash = (packed & (1u32 << 31)) != 0;
    let num_restarts = (packed & 0x7fff_ffff) as usize;
    let mut end = block.len() - 4;
    if is_hash {
        if end < 2 {
            return Err(Error::Corruption("truncated data block hash index".into()));
        }
        let num_buckets = u16::from_le_bytes(block[end - 2..end].try_into().unwrap()) as usize;
        let hash_bytes = 2 + num_buckets;
        if end < hash_bytes {
            return Err(Error::Corruption(
                "invalid data block hash bucket count".into(),
            ));
        }
        end -= hash_bytes;
    }
    let restart_bytes = num_restarts
        .checked_mul(4)
        .ok_or_else(|| Error::Corruption("restart array overflow".into()))?;
    if end < restart_bytes {
        return Err(Error::Corruption("restart array exceeds block size".into()));
    }
    let restarts_offset = end - restart_bytes;
    Ok((&block[..restarts_offset], restarts_offset, num_restarts))
}

fn block_entries_slice(block: &[u8]) -> Result<&[u8]> {
    Ok(parse_block_layout(block)?.0)
}

/// Binary searches a data block's restart array, then scans only the single restart interval.
fn search_data_block(block: &[u8], user_key: &[u8]) -> Result<Option<(u64, ValueType, Vec<u8>)>> {
    let (entries, restarts_offset, num_restarts) = parse_block_layout(block)?;
    if entries.is_empty() || num_restarts == 0 {
        return Ok(None);
    }

    let restart_at = |i: usize| -> usize {
        let p = restarts_offset + i * 4;
        u32::from_le_bytes(block[p..p + 4].try_into().unwrap()) as usize
    };

    // Binary search for the last restart point whose key has user_key < target.
    let mut left = 0usize;
    let mut right = num_restarts - 1;
    while left < right {
        let mid = (left + right).div_ceil(2);
        let off = restart_at(mid);
        if off >= entries.len() {
            return Err(Error::Corruption("restart offset out of bounds".into()));
        }
        let mut s = &entries[off..];
        let shared = get_varint32(&mut s).ok_or_else(|| Error::Corruption("bad shared".into()))?;
        let non_shared = get_varint32(&mut s)
            .ok_or_else(|| Error::Corruption("bad non_shared".into()))?
            as usize;
        let _val_len =
            get_varint32(&mut s).ok_or_else(|| Error::Corruption("bad val_len".into()))?;
        if shared != 0 || s.len() < non_shared || non_shared < 8 {
            return Err(Error::Corruption("corrupt restart key".into()));
        }
        let mid_user = &s[..non_shared - 8];
        if mid_user < user_key {
            left = mid;
        } else {
            right = mid - 1;
        }
    }

    let mut input = &entries[restart_at(left)..];
    let mut prev_key = Vec::new();
    while !input.is_empty() {
        let shared = get_varint32(&mut input)
            .ok_or_else(|| Error::Corruption("block: bad shared len".into()))?
            as usize;
        let non_shared = get_varint32(&mut input)
            .ok_or_else(|| Error::Corruption("block: bad non_shared len".into()))?
            as usize;
        let value_len = get_varint32(&mut input)
            .ok_or_else(|| Error::Corruption("block: bad value len".into()))?
            as usize;
        if shared > prev_key.len() || input.len() < non_shared + value_len {
            return Err(Error::Corruption("block: truncated entry".into()));
        }
        prev_key.truncate(shared);
        prev_key.extend_from_slice(&input[..non_shared]);
        input = &input[non_shared..];
        let val = &input[..value_len];
        input = &input[value_len..];

        let parsed = ParsedInternalKey::parse(&prev_key)?;
        match parsed.user_key.cmp(user_key) {
            Ordering::Less => continue,
            Ordering::Equal => return Ok(Some((parsed.seqno, parsed.value_type, val.to_vec()))),
            Ordering::Greater => return Ok(None),
        }
    }
    Ok(None)
}

/// Decodes a standard prefix-compressed block (DataBlock, MetaIndex, Properties, RangeDel).
pub fn decode_standard_block(block: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut input = block_entries_slice(block)?;
    let mut entries = Vec::new();
    let mut prev_key = Vec::new();

    while !input.is_empty() {
        let shared = get_varint32(&mut input)
            .ok_or_else(|| Error::Corruption("block: bad shared len".into()))?
            as usize;
        let non_shared = get_varint32(&mut input)
            .ok_or_else(|| Error::Corruption("block: bad non_shared len".into()))?
            as usize;
        let value_len = get_varint32(&mut input)
            .ok_or_else(|| Error::Corruption("block: bad value len".into()))?
            as usize;
        if shared > prev_key.len() || input.len() < non_shared + value_len {
            return Err(Error::Corruption("block: truncated entry".into()));
        }
        let mut key = Vec::with_capacity(shared + non_shared);
        key.extend_from_slice(&prev_key[..shared]);
        key.extend_from_slice(&input[..non_shared]);
        input = &input[non_shared..];
        let val = input[..value_len].to_vec();
        input = &input[value_len..];
        prev_key = key.clone();
        entries.push((key, val));
    }

    Ok(entries)
}

/// Decodes a `BlockBasedTable` index block (standard or format v4+ value-delta-encoded).
fn decode_index_block(block: &[u8], value_delta_encoded: bool) -> Result<Vec<IndexEntry>> {
    if !value_delta_encoded {
        let raw = decode_standard_block(block)?;
        let mut out = Vec::with_capacity(raw.len());
        for (k, v) in raw {
            let mut vs = v.as_slice();
            let handle = BlockHandle::decode(&mut vs)?;
            out.push(IndexEntry {
                separator: k,
                handle,
            });
        }
        return Ok(out);
    }

    let mut input = block_entries_slice(block)?;
    let mut out = Vec::new();
    let mut prev_key = Vec::new();
    let mut prev_handle: Option<BlockHandle> = None;

    while !input.is_empty() {
        let shared = get_varint32(&mut input)
            .ok_or_else(|| Error::Corruption("index: bad shared len".into()))?
            as usize;
        let non_shared = get_varint32(&mut input)
            .ok_or_else(|| Error::Corruption("index: bad non_shared len".into()))?
            as usize;
        if shared > prev_key.len() || input.len() < non_shared {
            return Err(Error::Corruption("index: truncated key".into()));
        }
        let mut key = Vec::with_capacity(shared + non_shared);
        key.extend_from_slice(&prev_key[..shared]);
        key.extend_from_slice(&input[..non_shared]);
        input = &input[non_shared..];

        let handle = if shared == 0 {
            BlockHandle::decode(&mut input)?
        } else {
            let prev = prev_handle.ok_or_else(|| {
                Error::Corruption("index: delta entry without previous handle".into())
            })?;
            let delta = get_varsigned64(&mut input)
                .ok_or_else(|| Error::Corruption("index: bad delta value".into()))?;
            let next_offset = prev.offset + prev.size + (BLOCK_TRAILER_SIZE as u64);
            let next_size = (prev.size as i64)
                .checked_add(delta)
                .ok_or_else(|| Error::Corruption("index: delta size overflow".into()))?;
            if next_size < 0 {
                return Err(Error::Corruption("index: negative block size".into()));
            }
            BlockHandle {
                offset: next_offset,
                size: next_size as u64,
            }
        };

        prev_key = key.clone();
        prev_handle = Some(handle);
        out.push(IndexEntry {
            separator: key,
            handle,
        });
    }

    Ok(out)
}
