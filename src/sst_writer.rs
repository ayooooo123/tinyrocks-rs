//! RocksDB `BlockBasedTable` format version 6 writer (uncompressed, XXH3 + context checksum).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::Result;
use crate::bloom::BloomBuilder;
use crate::coding::{
    ChecksumType, CompressionType, checksum_modifier_for_context, compute_builtin_checksum,
    compute_builtin_checksum_with_last_byte, put_varint32, put_varint64,
};
use crate::keys::{InternalKey, ParsedInternalKey, ValueType};
use crate::range_del::RangeTombstone;
use crate::sst::BlockHandle;

const BLOCK_BASED_TABLE_MAGIC: u64 = 0x88e2_41b7_85f4_cff7;
const EXTENDED_MAGIC_V6: [u8; 4] = [0x3e, 0x00, 0x7a, 0x00];
const BLOCK_TRAILER_SIZE: usize = 5;
const FOOTER_NEW_LEN: usize = 53;
const TARGET_DATA_BLOCK_SIZE: usize = 8192;
const DATA_RESTART_INTERVAL: usize = 16;

/// Standard prefix-compressed RocksDB block builder (`table/block_based/block_builder.cc`).
struct BlockBuilder {
    restart_interval: usize,
    buf: Vec<u8>,
    restarts: Vec<u32>,
    counter: usize,
    last_key: Vec<u8>,
}

impl BlockBuilder {
    fn new(restart_interval: usize) -> Self {
        Self {
            restart_interval: restart_interval.max(1),
            buf: Vec::new(),
            restarts: vec![0],
            counter: 0,
            last_key: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn current_size_estimate(&self) -> usize {
        self.buf.len() + self.restarts.len() * 4 + 4
    }

    fn add(&mut self, key: &[u8], value: &[u8]) {
        let shared = if self.counter < self.restart_interval && !self.last_key.is_empty() {
            let max_shared = self.last_key.len().min(key.len());
            let mut s = 0usize;
            while s < max_shared && self.last_key[s] == key[s] {
                s += 1;
            }
            s
        } else {
            if !self.buf.is_empty() {
                self.restarts.push(self.buf.len() as u32);
            }
            self.counter = 0;
            0
        };
        let non_shared = key.len() - shared;
        put_varint32(&mut self.buf, shared as u32);
        put_varint32(&mut self.buf, non_shared as u32);
        put_varint32(&mut self.buf, value.len() as u32);
        self.buf.extend_from_slice(&key[shared..]);
        self.buf.extend_from_slice(value);
        self.last_key.clear();
        self.last_key.extend_from_slice(key);
        self.counter += 1;
    }

    fn finish(mut self) -> Vec<u8> {
        for r in &self.restarts {
            self.buf.extend_from_slice(&r.to_le_bytes());
        }
        // BinarySearch index type (bit 31 = 0).
        self.buf
            .extend_from_slice(&(self.restarts.len() as u32).to_le_bytes());
        self.buf
    }
}

pub struct BuiltSst {
    pub file_number: u64,
    pub file_size: u64,
    pub smallest: InternalKey,
    pub largest: InternalKey,
    pub smallest_seqno: u64,
    pub largest_seqno: u64,
    pub oldest_blob_file_number: u64,
    pub num_entries: u64,
}

/// Writes a format-v6 `BlockBasedTable` SST from sorted `(InternalKey, value)` entries
/// and optional `RangeTombstone`s, syncing the file to disk before returning.
pub fn write_sst(
    db_dir: &Path,
    file_number: u64,
    cf_id: u32,
    cf_name: &str,
    entries: &[(InternalKey, Vec<u8>)],
    range_dels: &[RangeTombstone],
    oldest_blob_file_number: u64,
) -> Result<BuiltSst> {
    write_sst_with_sync(
        db_dir,
        file_number,
        cf_id,
        cf_name,
        entries,
        range_dels,
        oldest_blob_file_number,
        true,
    )
}

/// Same as [`write_sst`], with caller-controlled `sync_data` (avoids per-flush
/// `F_FULLFSYNC` stalls on macOS when durability is managed at close/suspend).
#[allow(clippy::too_many_arguments)]
pub fn write_sst_with_sync(
    db_dir: &Path,
    file_number: u64,
    cf_id: u32,
    cf_name: &str,
    entries: &[(InternalKey, Vec<u8>)],
    range_dels: &[RangeTombstone],
    oldest_blob_file_number: u64,
    sync: bool,
) -> Result<BuiltSst> {
    assert!(
        !entries.is_empty() || !range_dels.is_empty(),
        "cannot write an empty SST"
    );

    let path = db_dir.join(format!("{file_number:06}.sst"));
    let file = File::create(path)?;
    let mut writer = BufWriter::with_capacity(256 * 1024, file);
    let mut offset = 0u64;

    // Non-zero per-file context checksum seed (`ChecksumModifierForContext(bcc, 0) != 0`).
    let base_context_checksum = ((file_number as u32).wrapping_mul(0x9e37_79b1) ^ 0x85eb_ca6b) | 1;

    let mut data_block = BlockBuilder::new(DATA_RESTART_INTERVAL);
    let mut index_block = BlockBuilder::new(1);
    let mut bloom = BloomBuilder::new();
    let mut num_data_blocks = 0u64;
    let mut num_entries = 0u64;
    let mut num_deletions = 0u64;
    let mut raw_key_size = 0u64;
    let mut raw_value_size = 0u64;
    let mut smallest: Option<InternalKey> = None;
    let mut largest: Option<InternalKey> = None;
    let mut smallest_seqno = u64::MAX;
    let mut largest_seqno = 0u64;
    let mut last_ikey_in_block: Vec<u8> = Vec::new();

    for (ik, val) in entries {
        bloom.add_key(&ik.user_key);
        if !data_block.is_empty()
            && data_block.current_size_estimate() + ik.user_key.len() + 8 + val.len()
                > TARGET_DATA_BLOCK_SIZE
        {
            let block_bytes =
                std::mem::replace(&mut data_block, BlockBuilder::new(DATA_RESTART_INTERVAL))
                    .finish();
            let handle = write_raw_block(
                &mut writer,
                &mut offset,
                &block_bytes,
                base_context_checksum,
            )?;
            let mut enc_handle = Vec::new();
            encode_handle(&mut enc_handle, handle);
            index_block.add(&last_ikey_in_block, &enc_handle);
            num_data_blocks += 1;
        }

        let encoded_key = ik.encode();
        data_block.add(&encoded_key, val);
        last_ikey_in_block = encoded_key;

        if smallest.is_none() {
            smallest = Some(ik.clone());
        }
        largest = Some(ik.clone());
        smallest_seqno = smallest_seqno.min(ik.seqno);
        largest_seqno = largest_seqno.max(ik.seqno);
        num_entries += 1;
        raw_key_size += (ik.user_key.len() + 8) as u64;
        raw_value_size += val.len() as u64;
        if matches!(
            ik.value_type,
            ValueType::Deletion | ValueType::SingleDeletion
        ) {
            num_deletions += 1;
        }
    }

    if !data_block.is_empty() {
        let block_bytes = data_block.finish();
        let handle = write_raw_block(
            &mut writer,
            &mut offset,
            &block_bytes,
            base_context_checksum,
        )?;
        let mut enc_handle = Vec::new();
        encode_handle(&mut enc_handle, handle);
        index_block.add(&last_ikey_in_block, &enc_handle);
        num_data_blocks += 1;
    }

    let data_size = offset;
    let tail_start_offset = offset;

    // Meta-blocks map (sorted by key name for MetaIndexBuilder).
    let mut meta_handles: BTreeMap<Vec<u8>, BlockHandle> = BTreeMap::new();

    // 1. Write range-deletion meta-block if non-empty.
    let mut num_range_deletions = 0u64;
    if !range_dels.is_empty() {
        let mut sorted_rdels: Vec<(InternalKey, Vec<u8>)> = range_dels
            .iter()
            .map(|r| {
                (
                    InternalKey::new(r.start.clone(), r.seqno, ValueType::RangeDeletion),
                    r.end.clone(),
                )
            })
            .collect();
        sorted_rdels.sort_by(|a, b| a.0.cmp(&b.0));

        let mut rdel_block = BlockBuilder::new(1);
        for (ik, end_key) in &sorted_rdels {
            let encoded_key = ik.encode();
            rdel_block.add(&encoded_key, end_key);
            smallest_seqno = smallest_seqno.min(ik.seqno);
            largest_seqno = largest_seqno.max(ik.seqno);
            num_entries += 1;
            num_deletions += 1;
            num_range_deletions += 1;
            raw_key_size += encoded_key.len() as u64;
            raw_value_size += end_key.len() as u64;

            // File boundaries must cover range tombstones too!
            if smallest.as_ref().is_none_or(|s| ik < s) {
                smallest = Some(ik.clone());
            }
            let end_boundary = InternalKey::new(
                end_key.clone(),
                crate::keys::MAX_SEQUENCE_NUMBER,
                ValueType::RangeDeletion,
            );
            if largest.as_ref().is_none_or(|l| &end_boundary > l) {
                largest = Some(end_boundary);
            }
        }
        let rdel_bytes = rdel_block.finish();
        let rdel_handle =
            write_raw_block(&mut writer, &mut offset, &rdel_bytes, base_context_checksum)?;
        meta_handles.insert(b"rocksdb.range_del".to_vec(), rdel_handle);
    }

    // 1b. Write full Bloom filter meta-block (`FastLocalBloom`, 10 bits/key).
    let (filter_size, num_filter_entries) = if !bloom.is_empty() {
        let filter_bytes = bloom.finish();
        let filter_handle = write_raw_block(
            &mut writer,
            &mut offset,
            &filter_bytes,
            base_context_checksum,
        )?;
        meta_handles.insert(
            b"fullfilter.rocksdb.BuiltinBloomFilter".to_vec(),
            filter_handle,
        );
        (filter_bytes.len() as u64, bloom.num_entries())
    } else {
        (0, 0)
    };

    // 2. Write index block (`rocksdb.index` in metaindex for format v6).
    let index_bytes = index_block.finish();
    let index_handle = write_raw_block(
        &mut writer,
        &mut offset,
        &index_bytes,
        base_context_checksum,
    )?;
    let index_size = index_handle.size + BLOCK_TRAILER_SIZE as u64;
    meta_handles.insert(b"rocksdb.index".to_vec(), index_handle);

    // 3. Write properties block (`rocksdb.properties`).
    let props_bytes = build_properties_block(
        file_number,
        cf_id,
        cf_name,
        data_size,
        index_size,
        filter_size,
        num_filter_entries,
        num_data_blocks,
        num_entries,
        num_deletions,
        num_range_deletions,
        raw_key_size,
        raw_value_size,
        tail_start_offset,
        largest_seqno,
    );
    let props_handle = write_raw_block(
        &mut writer,
        &mut offset,
        &props_bytes,
        base_context_checksum,
    )?;
    meta_handles.insert(b"rocksdb.properties".to_vec(), props_handle);

    // 4. Write metaindex block immediately before the format-v6 footer.
    let mut metaindex_block = BlockBuilder::new(1);
    for (k, h) in &meta_handles {
        let mut v = Vec::new();
        encode_handle(&mut v, *h);
        metaindex_block.add(k, &v);
    }
    let metaindex_bytes = metaindex_block.finish();
    let metaindex_handle = write_raw_block(
        &mut writer,
        &mut offset,
        &metaindex_bytes,
        base_context_checksum,
    )?;

    // 5. Write 53-byte format-v6 Footer.
    let footer_offset = offset;
    let footer = build_v6_footer(
        footer_offset,
        metaindex_handle.size as u32,
        base_context_checksum,
    );
    writer.write_all(&footer)?;
    offset += FOOTER_NEW_LEN as u64;

    writer.flush()?;
    let file = writer.into_inner().map_err(|e| e.into_error())?;
    if sync {
        file.sync_data()?;
    }

    // Verify boundaries parsed cleanly.
    let smallest = smallest.unwrap();
    let largest = largest.unwrap();
    let _ = ParsedInternalKey::parse(&smallest.encode())?;

    Ok(BuiltSst {
        file_number,
        file_size: offset,
        smallest,
        largest,
        smallest_seqno: if smallest_seqno == u64::MAX {
            0
        } else {
            smallest_seqno
        },
        largest_seqno,
        oldest_blob_file_number,
        num_entries,
    })
}

fn encode_handle(dst: &mut Vec<u8>, handle: BlockHandle) {
    put_varint64(dst, handle.offset);
    put_varint64(dst, handle.size);
}

fn write_raw_block<W: Write>(
    writer: &mut W,
    offset: &mut u64,
    data: &[u8],
    base_context_checksum: u32,
) -> Result<BlockHandle> {
    let block_offset = *offset;
    let comp = CompressionType::None as u8;
    let checksum =
        compute_builtin_checksum_with_last_byte(ChecksumType::Xxh3, data, comp).wrapping_add(
            checksum_modifier_for_context(base_context_checksum, block_offset),
        );
    writer.write_all(data)?;
    writer.write_all(&[comp])?;
    writer.write_all(&checksum.to_le_bytes())?;
    *offset += (data.len() + BLOCK_TRAILER_SIZE) as u64;
    Ok(BlockHandle {
        offset: block_offset,
        size: data.len() as u64,
    })
}

fn build_v6_footer(
    footer_offset: u64,
    metaindex_size: u32,
    base_context_checksum: u32,
) -> [u8; FOOTER_NEW_LEN] {
    let mut buf = [0u8; FOOTER_NEW_LEN];
    buf[0] = ChecksumType::Xxh3 as u8;
    buf[1..5].copy_from_slice(&EXTENDED_MAGIC_V6);
    // [5..9] = footer checksum (zeroed while computing)
    buf[9..13].copy_from_slice(&base_context_checksum.to_le_bytes());
    buf[13..17].copy_from_slice(&metaindex_size.to_le_bytes());
    // [17..41] = 24 zero reserved bytes
    buf[41..45].copy_from_slice(&6u32.to_le_bytes()); // format_version = 6
    buf[45..53].copy_from_slice(&BLOCK_BASED_TABLE_MAGIC.to_le_bytes());

    let checksum = compute_builtin_checksum(ChecksumType::Xxh3, &buf).wrapping_add(
        checksum_modifier_for_context(base_context_checksum, footer_offset),
    );
    buf[5..9].copy_from_slice(&checksum.to_le_bytes());
    buf
}

#[allow(clippy::too_many_arguments)]
fn build_properties_block(
    orig_file_number: u64,
    cf_id: u32,
    cf_name: &str,
    data_size: u64,
    index_size: u64,
    filter_size: u64,
    num_filter_entries: u64,
    num_data_blocks: u64,
    num_entries: u64,
    num_deletions: u64,
    num_range_deletions: u64,
    raw_key_size: u64,
    raw_value_size: u64,
    tail_start_offset: u64,
    largest_seqno: u64,
) -> Vec<u8> {
    let mut props: BTreeMap<&'static [u8], Vec<u8>> = BTreeMap::new();
    let mut put_u64 = |k: &'static [u8], v: u64| {
        let mut buf = Vec::new();
        put_varint64(&mut buf, v);
        props.insert(k, buf);
    };

    put_u64(b"rocksdb.column.family.id", cf_id as u64);
    put_u64(b"rocksdb.creation.time", 0);
    put_u64(b"rocksdb.data.size", data_size);
    put_u64(b"rocksdb.deleted.keys", num_deletions);
    put_u64(b"rocksdb.filter.size", filter_size);
    put_u64(b"rocksdb.fixed.key.length", 0);
    put_u64(b"rocksdb.format.version", 6);
    put_u64(b"rocksdb.index.key.is.user.key", 0);
    put_u64(b"rocksdb.index.size", index_size);
    put_u64(b"rocksdb.index.value.is.delta.encoded", 0);
    put_u64(b"rocksdb.key.largest.seqno", largest_seqno);
    put_u64(b"rocksdb.merge.operands", 0);
    put_u64(b"rocksdb.newest.key.time", 0);
    put_u64(b"rocksdb.num.data.blocks", num_data_blocks);
    put_u64(b"rocksdb.num.entries", num_entries);
    put_u64(b"rocksdb.num.filter_entries", num_filter_entries);
    put_u64(b"rocksdb.num.range-deletions", num_range_deletions);
    put_u64(b"rocksdb.oldest.key.time", 0);
    put_u64(b"rocksdb.original.file.number", orig_file_number);
    put_u64(b"rocksdb.raw.key.size", raw_key_size);
    put_u64(b"rocksdb.raw.value.size", raw_value_size);
    put_u64(b"rocksdb.tail.start.offset", tail_start_offset);

    props.insert(b"rocksdb.column.family.name", cf_name.as_bytes().to_vec());
    props.insert(
        b"rocksdb.comparator",
        b"leveldb.BytewiseComparator".to_vec(),
    );
    props.insert(b"rocksdb.compression", b"NoCompression".to_vec());
    if filter_size > 0 {
        props.insert(
            b"rocksdb.filter.policy",
            b"rocksdb.BuiltinBloomFilter".to_vec(),
        );
    }
    props.insert(b"rocksdb.merge.operator", b"nullptr".to_vec());
    props.insert(b"rocksdb.prefix.extractor.name", b"nullptr".to_vec());
    props.insert(b"rocksdb.property.collectors", b"[]".to_vec());

    let mut bb = BlockBuilder::new(i32::MAX as usize);
    for (k, v) in props {
        bb.add(k, &v);
    }
    bb.finish()
}
