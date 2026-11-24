//! RocksDB `MANIFEST-*` `VersionEdit` encoder and atomic `CURRENT` / manifest appender.

use std::fs::{File, OpenOptions};
use std::path::Path;

use crate::coding::{put_length_prefixed_slice, put_varint32, put_varint64};
use crate::log::LogWriter;
use crate::manifest::SstFileMeta;
use crate::Result;

const TAG_COMPARATOR: u32 = 1;
const TAG_LOG_NUMBER: u32 = 2;
const TAG_NEXT_FILE_NUMBER: u32 = 3;
const TAG_LAST_SEQUENCE: u32 = 4;
const TAG_DELETED_FILE: u32 = 6;
const TAG_MIN_LOG_NUMBER_TO_KEEP: u32 = 10;
const TAG_NEW_FILE4: u32 = 103;
const TAG_COLUMN_FAMILY: u32 = 200;
const TAG_COLUMN_FAMILY_ADD: u32 = 201;
const TAG_MAX_COLUMN_FAMILY: u32 = 203;
const TAG_BLOB_FILE_ADDITION: u32 = 400;
const TAG_BLOB_FILE_GARBAGE: u32 = 401;
const TAG_PERSIST_UDT: u32 = (1 << 13) + 9;

const CUSTOM_TERMINATE: u32 = 1;
const CUSTOM_OLDEST_BLOB_FILE_NUMBER: u32 = 4;
const CUSTOM_OLDEST_ANCESTER_TIME: u32 = 5;
const CUSTOM_FILE_CREATION_TIME: u32 = 6;
const CUSTOM_EPOCH_NUMBER: u32 = 13;

#[derive(Default)]
pub struct VersionEditBuilder {
    pub comparator: Option<String>,
    pub persist_udt: Option<bool>,
    pub column_family: u32,
    pub column_family_add: Option<String>,
    pub max_column_family: Option<u32>,
    pub log_number: Option<u64>,
    pub min_log_number_to_keep: Option<u64>,
    pub next_file_number: Option<u64>,
    pub last_sequence: Option<u64>,
    pub deleted_files: Vec<(u32, u64)>,
    pub new_files: Vec<SstFileMeta>,
    pub blob_additions: Vec<(u64, u64, u64)>, // (file_num, count, bytes)
    pub blob_garbages: Vec<(u64, u64, u64)>,  // (file_num, garbage_count, garbage_bytes)
}

impl VersionEditBuilder {
    pub fn encode(&self) -> Vec<u8> {
        let mut dst = Vec::new();
        if let Some(cmp) = &self.comparator {
            put_varint32(&mut dst, TAG_COMPARATOR);
            put_length_prefixed_slice(&mut dst, cmp.as_bytes());
        }
        if let Some(v) = self.log_number {
            put_varint32(&mut dst, TAG_LOG_NUMBER);
            put_varint64(&mut dst, v);
        }
        if let Some(v) = self.next_file_number {
            put_varint32(&mut dst, TAG_NEXT_FILE_NUMBER);
            put_varint64(&mut dst, v);
        }
        if let Some(v) = self.max_column_family {
            put_varint32(&mut dst, TAG_MAX_COLUMN_FAMILY);
            put_varint32(&mut dst, v);
        }
        if let Some(v) = self.min_log_number_to_keep {
            put_varint32(&mut dst, TAG_MIN_LOG_NUMBER_TO_KEEP);
            put_varint64(&mut dst, v);
        }
        if let Some(v) = self.last_sequence {
            put_varint32(&mut dst, TAG_LAST_SEQUENCE);
            put_varint64(&mut dst, v);
        }
        for &(level, num) in &self.deleted_files {
            put_varint32(&mut dst, TAG_DELETED_FILE);
            put_varint32(&mut dst, level);
            put_varint64(&mut dst, num);
        }
        for f in &self.new_files {
            put_varint32(&mut dst, TAG_NEW_FILE4);
            put_varint32(&mut dst, f.level);
            put_varint64(&mut dst, f.number);
            put_varint64(&mut dst, f.file_size);
            put_length_prefixed_slice(&mut dst, &f.smallest.encode());
            put_length_prefixed_slice(&mut dst, &f.largest.encode());
            put_varint64(&mut dst, f.smallest_seqno);
            put_varint64(&mut dst, f.largest_seqno);

            put_custom_varint(&mut dst, CUSTOM_OLDEST_ANCESTER_TIME, 0);
            put_custom_varint(&mut dst, CUSTOM_FILE_CREATION_TIME, 0);
            put_custom_varint(&mut dst, CUSTOM_EPOCH_NUMBER, f.epoch_number.max(1));
            if f.oldest_blob_file_number != 0 {
                put_custom_varint(&mut dst, CUSTOM_OLDEST_BLOB_FILE_NUMBER, f.oldest_blob_file_number);
            }
            put_varint32(&mut dst, CUSTOM_TERMINATE);
        }
        for &(num, count, bytes) in &self.blob_additions {
            put_varint32(&mut dst, TAG_BLOB_FILE_ADDITION);
            put_varint64(&mut dst, num);
            put_varint64(&mut dst, count);
            put_varint64(&mut dst, bytes);
            put_length_prefixed_slice(&mut dst, b"");
            put_length_prefixed_slice(&mut dst, b"");
            put_varint32(&mut dst, 0); // kEndMarker
        }
        for &(num, count, bytes) in &self.blob_garbages {
            put_varint32(&mut dst, TAG_BLOB_FILE_GARBAGE);
            put_varint64(&mut dst, num);
            put_varint64(&mut dst, count);
            put_varint64(&mut dst, bytes);
            put_varint32(&mut dst, 0); // kEndMarker
        }
        if self.column_family != 0 {
            put_varint32(&mut dst, TAG_COLUMN_FAMILY);
            put_varint32(&mut dst, self.column_family);
        }
        if let Some(name) = &self.column_family_add {
            put_varint32(&mut dst, TAG_COLUMN_FAMILY_ADD);
            put_length_prefixed_slice(&mut dst, name.as_bytes());
        }
        if let Some(persist) = self.persist_udt {
            put_varint32(&mut dst, TAG_PERSIST_UDT);
            put_length_prefixed_slice(&mut dst, &[u8::from(persist)]);
        }
        dst
    }
}

fn put_custom_varint(dst: &mut Vec<u8>, tag: u32, val: u64) {
    put_varint32(dst, tag);
    let mut tmp = Vec::new();
    put_varint64(&mut tmp, val);
    put_length_prefixed_slice(dst, &tmp);
}

/// Best-effort directory fsync so newly created/renamed SST, blob, and CURRENT entries
/// survive sudden power loss.
pub fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// Appends one or more `VersionEditBuilder` records to the active `MANIFEST-*` and syncs it.
pub fn append_edits(db_dir: &Path, manifest_name: &str, edits: &[VersionEditBuilder]) -> Result<()> {
    let path = db_dir.join(manifest_name);
    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    let initial_len = file.metadata()?.len() as usize;
    let mut lw = LogWriter::new(file, initial_len);
    for edit in edits {
        lw.add_record(&edit.encode())?;
    }
    lw.flush()?;
    let file = lw.into_inner();
    file.sync_data()?;
    sync_dir(db_dir);
    Ok(())
}

/// Initializes a brand-new RocksDB directory with `default` (CF 0) and `cf_names`.
pub fn create_new_manifest(db_dir: &Path, cf_names: &[&str]) -> Result<String> {
    let manifest_name = "MANIFEST-000001".to_string();
    let mut edits = Vec::new();

    // Edit 0: default column family (id 0).
    let max_cf = cf_names.len() as u32;
    edits.push(VersionEditBuilder {
        comparator: Some("leveldb.BytewiseComparator".to_string()),
        persist_udt: Some(true),
        column_family: 0,
        log_number: Some(0),
        next_file_number: Some(2),
        last_sequence: Some(0),
        max_column_family: Some(max_cf),
        ..Default::default()
    });

    for (idx, &name) in cf_names.iter().enumerate() {
        let cf_id = (idx as u32) + 1;
        edits.push(VersionEditBuilder {
            comparator: Some("leveldb.BytewiseComparator".to_string()),
            persist_udt: Some(true),
            column_family: cf_id,
            column_family_add: Some(name.to_string()),
            max_column_family: Some(max_cf),
            log_number: Some(0),
            ..Default::default()
        });
    }

    append_edits(db_dir, &manifest_name, &edits)?;

    // Atomically write CURRENT -> "MANIFEST-000001\n".
    let tmp = db_dir.join("CURRENT.tmp");
    std::fs::write(&tmp, format!("{manifest_name}\n"))?;
    File::open(&tmp)?.sync_data()?;
    std::fs::rename(&tmp, db_dir.join("CURRENT"))?;

    // Write minimal IDENTITY file if absent.
    let id_path = db_dir.join("IDENTITY");
    if !id_path.exists() {
        std::fs::write(&id_path, "00000000-0000-4000-8000-000000000001\n")?;
        File::open(&id_path)?.sync_data()?;
    }
    sync_dir(db_dir);

    Ok(manifest_name)
}
