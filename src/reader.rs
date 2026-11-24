//! Unified RocksDB 10.x-compatible database engine: read, write, WAL, flush, BlobDB, and compaction.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::blob::{self, BlobFileReader, BlobFileWriter, BlobIndex};
use crate::coding::CompressionType;
use crate::keys::{InternalKey, ParsedInternalKey, ValueType};
use crate::log::LogWriter;
use crate::manifest::{BlobFileMeta, SstFileMeta, VersionState};
use crate::manifest_writer::{self, VersionEditBuilder};
use crate::range_del::{RangeTombstone, max_covering_seqno};
use crate::sst::SstReader;
use crate::sst_writer;
use crate::wal::{self, BatchOp, MemTable, MemValue};
use crate::{Error, Result};

const MIN_BLOB_SIZE: usize = 4096;
const DEFAULT_WRITE_BUFFER_BYTES: usize = 12 * 1024 * 1024;
const DEFAULT_BLOB_FILE_SIZE: u64 = 256 * 1024 * 1024;
const BLOB_RECORD_HEADER_SIZE: u64 = 32;
const L0_COMPACTION_TRIGGER: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanDirection {
    Forward,
    Reverse,
}

#[derive(Debug, Default, Clone)]
pub struct WriteBatch {
    ops: Vec<BatchOp>,
}

impl WriteBatch {
    pub fn put_cf(&mut self, cf_id: u32, key: &[u8], value: &[u8]) {
        self.ops.push(BatchOp::Put {
            cf_id,
            key: key.to_vec(),
            value: value.to_vec(),
        });
    }

    pub fn delete_cf(&mut self, cf_id: u32, key: &[u8]) {
        self.ops.push(BatchOp::Delete {
            cf_id,
            key: key.to_vec(),
        });
    }

    pub fn delete_range_cf(&mut self, cf_id: u32, start: &[u8], end: &[u8]) {
        self.ops.push(BatchOp::DeleteRange {
            cf_id,
            start: start.to_vec(),
            end: end.to_vec(),
        });
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

struct OpenedSst {
    meta: SstFileMeta,
    reader: SstReader,
}

struct ColumnFamilyEngine {
    id: u32,
    log_number: u64,
    memtable: MemTable,
    memtable_bytes: usize,
    levels: Vec<Vec<OpenedSst>>,
    blob_files: BTreeMap<u64, BlobFileMeta>,
    all_range_dels: Vec<RangeTombstone>,
    next_epoch: u64,
}

impl ColumnFamilyEngine {
    fn rebuild_range_dels(&mut self) {
        self.all_range_dels.clear();
        self.all_range_dels.extend(self.memtable.range_dels.iter().cloned());
        for lvl in &self.levels {
            for sst in lvl {
                self.all_range_dels.extend(sst.reader.range_dels.iter().cloned());
            }
        }
    }

    fn live_blob_file_size(&self) -> u64 {
        const BLOB_HEADER_PLUS_FOOTER: u64 = 30 + 32;
        self.blob_files
            .values()
            .filter(|b| b.garbage_blob_count < b.total_blob_count)
            .map(|b| b.total_blob_bytes + BLOB_HEADER_PLUS_FOOTER)
            .sum()
    }

    fn live_blob_file_garbage_size(&self) -> u64 {
        self.blob_files
            .values()
            .filter(|b| b.garbage_blob_count < b.total_blob_count)
            .map(|b| b.garbage_blob_bytes)
            .sum()
    }
}

pub struct Db {
    dir: PathBuf,
    memory: bool,
    read_only: bool,
    _lock_file: Option<File>,
    manifest_name: String,
    next_file_number: u64,
    last_sequence: u64,
    active_wal_number: u64,
    wal_writer: Option<LogWriter<File>>,
    cfs: BTreeMap<String, ColumnFamilyEngine>,
    cf_id_to_name: HashMap<u32, String>,
    blob_readers: Mutex<HashMap<u64, Arc<BlobFileReader>>>,
    write_buffer_bytes: usize,
    blob_file_size: u64,
}

impl Db {
    /// Opens an existing RocksDB directory read-only, replaying any live WAL files.
    pub fn open_read_only(dir: &Path) -> Result<Self> {
        Self::open_internal(dir, &[], true)
    }

    /// Opens or creates a RocksDB-10.x-compatible directory for read/write with the listed
    /// non-default column families (e.g. `&["corestore"]`).
    pub fn open_rw(dir: &Path, cf_names: &[&str]) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        Self::open_internal(dir, cf_names, false)
    }

    /// Creates a process-local in-memory database; touches no files on disk.
    pub fn open_memory(cf_names: &[&str]) -> Result<Self> {
        let mut cfs = BTreeMap::new();
        let mut cf_id_to_name = HashMap::new();
        let mut insert_cf = |id: u32, name: &str| {
            cf_id_to_name.insert(id, name.to_string());
            cfs.insert(
                name.to_string(),
                ColumnFamilyEngine {
                    id,
                    log_number: 0,
                    memtable: MemTable::default(),
                    memtable_bytes: 0,
                    levels: (0..7).map(|_| Vec::new()).collect(),
                    blob_files: BTreeMap::new(),
                    all_range_dels: Vec::new(),
                    next_epoch: 1,
                },
            );
        };
        insert_cf(0, "default");
        for (idx, &name) in cf_names.iter().enumerate() {
            insert_cf((idx as u32) + 1, name);
        }
        Ok(Self {
            dir: PathBuf::new(),
            memory: true,
            read_only: false,
            _lock_file: None,
            manifest_name: String::new(),
            next_file_number: 1,
            last_sequence: 0,
            active_wal_number: 0,
            wal_writer: None,
            cfs,
            cf_id_to_name,
            blob_readers: Mutex::new(HashMap::new()),
            write_buffer_bytes: DEFAULT_WRITE_BUFFER_BYTES,
            blob_file_size: DEFAULT_BLOB_FILE_SIZE,
        })
    }

    pub fn set_blob_file_size(&mut self, bytes: u64) {
        self.blob_file_size = bytes.max(64 * 1024);
    }

    pub fn set_write_buffer_size(&mut self, bytes: usize) {
        self.write_buffer_bytes = bytes.max(64 * 1024);
    }

    fn open_internal(dir: &Path, requested_cfs: &[&str], read_only: bool) -> Result<Self> {
        let lock_file = if read_only {
            None
        } else {
            let lf = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(dir.join("LOCK"))?;
            lf.try_lock().map_err(|_| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "LOCK is already held by another process",
                ))
            })?;
            Some(lf)
        };

        let current_path = dir.join("CURRENT");
        if !current_path.exists() {
            if read_only {
                return Err(Error::NotFound("CURRENT missing in read-only open".into()));
            }
            manifest_writer::create_new_manifest(dir, requested_cfs)?;
        }

        let manifest_name = std::fs::read_to_string(&current_path)?.trim().to_string();
        let mut version = VersionState::load(dir)?;

        // Repair a crash-truncated MANIFEST tail before appending any new VersionEdits.
        if !read_only && version.manifest_valid_len < version.manifest_file_len {
            let mf = OpenOptions::new().write(true).open(dir.join(&manifest_name))?;
            mf.set_len(version.manifest_valid_len as u64)?;
            mf.sync_data()?;
            manifest_writer::sync_dir(dir);
        }

        // Create any missing requested column families in MANIFEST.
        if !read_only {
            let mut missing = Vec::new();
            for &name in requested_cfs {
                if !version.cf_by_name.contains_key(name) {
                    version.max_column_family += 1;
                    let cf_id = version.max_column_family;
                    missing.push(VersionEditBuilder {
                        comparator: Some("leveldb.BytewiseComparator".to_string()),
                        persist_udt: Some(true),
                        column_family: cf_id,
                        column_family_add: Some(name.to_string()),
                        max_column_family: Some(version.max_column_family),
                        log_number: Some(0),
                        ..Default::default()
                    });
                }
            }
            if !missing.is_empty() {
                manifest_writer::append_edits(dir, &manifest_name, &missing)?;
                version = VersionState::load(dir)?;
            }
        }

        // Collect existing WAL files sorted by file number.
        let mut wal_files: Vec<(u64, PathBuf)> = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(s) = name.to_str() else { continue };
            if let Some(stem) = s.strip_suffix(".log")
                && let Ok(num) = stem.parse::<u64>()
            {
                wal_files.push((num, entry.path()));
            }
        }
        wal_files.sort_by_key(|(num, _)| *num);

        let mut last_sequence = version.last_sequence;
        let mut next_file_number = version.next_file_number;
        let mut cfs = BTreeMap::new();
        let mut cf_id_to_name = HashMap::new();

        for cf_state in version.column_families.values() {
            let mut memtable = MemTable::default();
            let mut memtable_bytes = 0usize;
            for (wal_num, wal_path) in &wal_files {
                if *wal_num >= cf_state.log_number {
                    let bytes = std::fs::read(wal_path)?;
                    wal::replay_wal_file(&bytes, cf_state.id, &mut memtable, &mut last_sequence)?;
                }
                if *wal_num >= next_file_number {
                    next_file_number = *wal_num + 1;
                }
            }
            for (k, v) in &memtable.entries {
                memtable_bytes += k.user_key.len() + 8;
                if let MemValue::Value(b) = v {
                    memtable_bytes += b.len();
                }
            }

            let mut max_epoch = 0u64;
            let mut opened_levels = Vec::with_capacity(cf_state.levels.len());
            for lvl in &cf_state.levels {
                let mut opened = Vec::with_capacity(lvl.len());
                for meta in lvl {
                    max_epoch = max_epoch.max(meta.epoch_number);
                    if meta.number >= next_file_number {
                        next_file_number = meta.number + 1;
                    }
                    let sst_path = dir.join(format!("{:06}.sst", meta.number));
                    let reader = SstReader::open(&sst_path)?;
                    opened.push(OpenedSst {
                        meta: meta.clone(),
                        reader,
                    });
                }
                opened_levels.push(opened);
            }
            for &bnum in cf_state.blob_files.keys() {
                if bnum >= next_file_number {
                    next_file_number = bnum + 1;
                }
            }

            let mut engine = ColumnFamilyEngine {
                id: cf_state.id,
                log_number: cf_state.log_number,
                memtable,
                memtable_bytes,
                levels: opened_levels,
                blob_files: cf_state.blob_files.clone(),
                all_range_dels: Vec::new(),
                next_epoch: max_epoch + 1,
            };
            engine.rebuild_range_dels();
            cf_id_to_name.insert(cf_state.id, cf_state.name.clone());
            cfs.insert(cf_state.name.clone(), engine);
        }

        // Open a fresh WAL file for new writes when read-write, and clean up orphaned files
        // left behind by an earlier crash before MANIFEST commit.
        let (active_wal_number, wal_writer) = if read_only {
            (0, None)
        } else {
            let wal_num = next_file_number;
            next_file_number += 1;
            let wal_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(dir.join(format!("{wal_num:06}.log")))?;
            cleanup_orphan_files(dir, &cfs, wal_num);
            (wal_num, Some(LogWriter::new(wal_file, 0)))
        };

        Ok(Self {
            dir: dir.to_path_buf(),
            memory: false,
            read_only,
            _lock_file: lock_file,
            manifest_name,
            next_file_number,
            last_sequence,
            active_wal_number,
            wal_writer,
            cfs,
            cf_id_to_name,
            blob_readers: Mutex::new(HashMap::new()),
            write_buffer_bytes: DEFAULT_WRITE_BUFFER_BYTES,
            blob_file_size: DEFAULT_BLOB_FILE_SIZE,
        })
    }

    pub fn cf_id(&self, cf_name: &str) -> Result<u32> {
        Ok(self.cf(cf_name)?.id)
    }

    /// Number of L0 SST files currently in `cf_name` (useful for diagnostics/tests).
    pub fn l0_file_count(&self, cf_name: &str) -> Result<usize> {
        Ok(self.cf(cf_name)?.levels.first().map_or(0, Vec::len))
    }

    pub fn live_blob_file_size(&self, cf_name: &str) -> Result<u64> {
        let cf = self.cf(cf_name)?;
        if self.memory {
            // In memory mode, sum live >= MIN_BLOB_SIZE values currently held in RAM.
            let mut latest: BTreeMap<&[u8], (u64, &MemValue)> = BTreeMap::new();
            for (ik, mv) in &cf.memtable.entries {
                latest
                    .entry(ik.user_key.as_slice())
                    .and_modify(|e| {
                        if ik.seqno > e.0 {
                            *e = (ik.seqno, mv);
                        }
                    })
                    .or_insert((ik.seqno, mv));
            }
            let total: u64 = latest
                .into_iter()
                .filter_map(|(k, (seq, mv))| {
                    if max_covering_seqno(&cf.all_range_dels, k).is_some_and(|t| t >= seq) {
                        return None;
                    }
                    match mv {
                        MemValue::Value(v) if v.len() >= MIN_BLOB_SIZE => {
                            Some(BLOB_RECORD_HEADER_SIZE + (k.len() + v.len()) as u64)
                        }
                        _ => None,
                    }
                })
                .sum();
            return Ok(total);
        }
        Ok(cf.live_blob_file_size())
    }

    pub fn live_blob_file_garbage_size(&self, cf_name: &str) -> Result<u64> {
        Ok(self.cf(cf_name)?.live_blob_file_garbage_size())
    }

    pub fn write_batch(&mut self, batch: &WriteBatch, disable_wal: bool) -> Result<()> {
        if self.read_only {
            return Err(Error::Unsupported("database is read-only".into()));
        }
        if batch.is_empty() {
            return Ok(());
        }

        let first_seq = self.last_sequence + 1;
        if !disable_wal {
            let encoded = wal::encode_write_batch(first_seq, &batch.ops);
            if let Some(w) = self.wal_writer.as_mut() {
                w.add_record(&encoded)?;
                w.flush()?;
            }
        }

        let mut seq = first_seq;
        let mut cfs_to_flush: Vec<String> = Vec::new();
        for op in &batch.ops {
            let cf_id = match op {
                BatchOp::Put { cf_id, .. }
                | BatchOp::Delete { cf_id, .. }
                | BatchOp::DeleteRange { cf_id, .. } => *cf_id,
            };
            let cf_name = self
                .cf_id_to_name
                .get(&cf_id)
                .ok_or_else(|| Error::NotFound(format!("unknown cf id {cf_id}")))?
                .clone();
            let cf = self.cfs.get_mut(&cf_name).unwrap();
            match op {
                BatchOp::Put { key, value, .. } => {
                    cf.memtable_bytes += key.len() + 8 + value.len();
                    cf.memtable.entries.insert(
                        InternalKey::new(key.clone(), seq, ValueType::Value),
                        MemValue::Value(value.clone()),
                    );
                }
                BatchOp::Delete { key, .. } => {
                    cf.memtable_bytes += key.len() + 8;
                    cf.memtable.entries.insert(
                        InternalKey::new(key.clone(), seq, ValueType::Deletion),
                        MemValue::Deletion,
                    );
                }
                BatchOp::DeleteRange { start, end, .. } => {
                    cf.memtable_bytes += start.len() + end.len() + 8;
                    let rdel = RangeTombstone {
                        start: start.clone(),
                        end: end.clone(),
                        seqno: seq,
                    };
                    cf.memtable.range_dels.push(rdel.clone());
                    cf.all_range_dels.push(rdel);
                }
            }
            if cf.memtable_bytes >= self.write_buffer_bytes && !cfs_to_flush.contains(&cf_name) {
                cfs_to_flush.push(cf_name);
            }
            seq += 1;
        }
        self.last_sequence = seq - 1;

        if !self.memory {
            for cf_name in cfs_to_flush {
                self.flush_cf(&cf_name)?;
            }
        }
        Ok(())
    }

    pub fn flush_wal(&mut self, sync: bool) -> Result<()> {
        if self.read_only || self.memory {
            return Ok(());
        }
        if let Some(w) = self.wal_writer.take() {
            let mut w = w;
            w.flush()?;
            let file = w.into_inner();
            if sync {
                file.sync_data()?;
            }
            let len = file.metadata()?.len() as usize;
            self.wal_writer = Some(LogWriter::new(file, len));
        }
        Ok(())
    }

    /// Flushes the column family's memtable into a format-v6 L0 SST + integrated `.blob` file,
    /// commits to `MANIFEST`, and rotates the WAL.
    pub fn flush_cf(&mut self, cf_name: &str) -> Result<()> {
        if self.read_only {
            return Err(Error::Unsupported("database is read-only".into()));
        }
        if self.memory {
            return Ok(());
        }
        let (cf_id, mem_entries, mem_rdels, epoch) = {
            let cf = self.cf(cf_name)?;
            if cf.memtable.entries.is_empty() && cf.memtable.range_dels.is_empty() {
                return Ok(());
            }
            let entries: Vec<(InternalKey, MemValue)> = cf
                .memtable
                .entries
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            (cf.id, entries, cf.memtable.range_dels.clone(), cf.next_epoch)
        };

        // Write values >= MIN_BLOB_SIZE into rolling .blob files (capped at self.blob_file_size)
        // and emit kTypeBlobIndex in the SST.
        let mut blob_writer: Option<BlobFileWriter> = None;
        let mut finished_blobs = Vec::new();
        let mut sst_entries: Vec<(InternalKey, Vec<u8>)> = Vec::with_capacity(mem_entries.len());

        for (ik, mv) in mem_entries {
            match mv {
                MemValue::Deletion => {
                    sst_entries.push((ik, Vec::new()));
                }
                MemValue::Value(val) => {
                    if val.len() >= MIN_BLOB_SIZE {
                        if let Some(bw) = blob_writer.as_ref()
                            && bw.current_bytes() >= self.blob_file_size
                        {
                            finished_blobs.push(blob_writer.take().unwrap().finish()?);
                        }
                        if blob_writer.is_none() {
                            let blob_file_num = self.next_file_number;
                            self.next_file_number += 1;
                            blob_writer = Some(BlobFileWriter::create(
                                &self.dir,
                                blob_file_num,
                                cf_id,
                            )?);
                        }
                        let bw = blob_writer.as_mut().unwrap();
                        let bnum = bw.file_number();
                        let (val_off, val_sz) = bw.add_blob(&ik.user_key, &val)?;
                        let idx_val =
                            blob::encode_blob_index(bnum, val_off, val_sz, CompressionType::None);
                        sst_entries.push((
                            InternalKey::new(ik.user_key, ik.seqno, ValueType::BlobIndex),
                            idx_val,
                        ));
                    } else {
                        sst_entries.push((ik, val));
                    }
                }
            }
        }

        if let Some(bw) = blob_writer {
            finished_blobs.push(bw.finish()?);
        }
        let oldest_blob = finished_blobs
            .iter()
            .map(|s| s.file_number)
            .min()
            .unwrap_or(0);

        let sst_num = self.next_file_number;
        self.next_file_number += 1;
        let built = sst_writer::write_sst(
            &self.dir,
            sst_num,
            cf_id,
            cf_name,
            &sst_entries,
            &mem_rdels,
            oldest_blob,
        )?;

        // Rotate WAL so RocksDB knows all flushed ops are <= new_wal_num.
        let old_wal = self.active_wal_number;
        let new_wal_num = self.next_file_number;
        self.next_file_number += 1;
        let new_wal_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(self.dir.join(format!("{new_wal_num:06}.log")))?;
        self.wal_writer = Some(LogWriter::new(new_wal_file, 0));
        self.active_wal_number = new_wal_num;

        let sst_meta = SstFileMeta {
            number: built.file_number,
            level: 0,
            file_size: built.file_size,
            smallest: built.smallest,
            largest: built.largest,
            smallest_seqno: built.smallest_seqno,
            largest_seqno: built.largest_seqno,
            oldest_blob_file_number: built.oldest_blob_file_number,
            epoch_number: epoch,
        };

        let mut edit = VersionEditBuilder {
            column_family: cf_id,
            log_number: Some(new_wal_num),
            next_file_number: Some(self.next_file_number),
            last_sequence: Some(self.last_sequence),
            new_files: vec![sst_meta.clone()],
            ..Default::default()
        };
        for bs in &finished_blobs {
            edit.blob_additions
                .push((bs.file_number, bs.total_blob_count, bs.total_blob_bytes));
        }
        manifest_writer::append_edits(&self.dir, &self.manifest_name, &[edit])?;

        // Update in-memory state.
        let reader = SstReader::open(&self.dir.join(format!("{sst_num:06}.sst")))?;
        let cf = self.cfs.get_mut(cf_name).unwrap();
        cf.memtable.entries.clear();
        cf.memtable.range_dels.clear();
        cf.memtable_bytes = 0;
        cf.log_number = new_wal_num;
        cf.next_epoch += 1;
        if cf.levels.is_empty() {
            cf.levels.push(Vec::new());
        }
        cf.levels[0].insert(
            0,
            OpenedSst {
                meta: sst_meta,
                reader,
            },
        );
        for bs in finished_blobs {
            cf.blob_files.insert(
                bs.file_number,
                BlobFileMeta {
                    number: bs.file_number,
                    total_blob_count: bs.total_blob_count,
                    total_blob_bytes: bs.total_blob_bytes,
                    garbage_blob_count: 0,
                    garbage_blob_bytes: 0,
                },
            );
        }
        cf.rebuild_range_dels();

        // Remove obsolete WAL if no CF still depends on it.
        let min_cf_log = self.cfs.values().map(|c| c.log_number).min().unwrap_or(0);
        if old_wal > 0 && old_wal < min_cf_log {
            let _ = std::fs::remove_file(self.dir.join(format!("{old_wal:06}.log")));
        }

        // Incremental L0 -> L1 merge when L0 fanout reaches the trigger (without relocating blobs).
        if self.cfs.get(cf_name).is_some_and(|c| {
            c.levels
                .first()
                .is_some_and(|l0| l0.len() >= L0_COMPACTION_TRIGGER)
        }) {
            self.compact_l0_to_l1(cf_name)?;
        }

        Ok(())
    }

    /// Merges all L0 SSTs with overlapping L1 SSTs into a clean L1 SST without copying live
    /// `.blob` files, keeping point-lookup fanout bounded on large databases.
    fn compact_l0_to_l1(&mut self, cf_name: &str) -> Result<()> {
        let (
            cf_id,
            epoch,
            is_bottommost,
            selected_l1_nums,
            deleted_ssts,
            final_entries,
            final_rdels,
            dead_blobs,
            oldest_blob_in_new_sst,
        ) = {
            let cf = self.cf(cf_name)?;
            let l0 = match cf.levels.first() {
                Some(l) if !l.is_empty() => l,
                _ => return Ok(()),
            };

            // Determine the combined key span of all L0 SSTs + L0 range tombstones.
            let mut min_key: Option<&[u8]> = None;
            let mut max_key: Option<&[u8]> = None;
            for sst in l0 {
                let lo = sst.meta.smallest.user_key.as_slice();
                let hi = sst.meta.largest.user_key.as_slice();
                if min_key.is_none_or(|cur| lo < cur) {
                    min_key = Some(lo);
                }
                if max_key.is_none_or(|cur| hi > cur) {
                    max_key = Some(hi);
                }
                for rd in &sst.reader.range_dels {
                    if min_key.is_none_or(|cur| rd.start.as_slice() < cur) {
                        min_key = Some(rd.start.as_slice());
                    }
                    if max_key.is_none_or(|cur| rd.end.as_slice() > cur) {
                        max_key = Some(rd.end.as_slice());
                    }
                }
            }
            let (Some(span_lo), Some(span_hi)) = (min_key, max_key) else {
                return Ok(());
            };

            // Select L1 SSTs overlapping [span_lo, span_hi].
            let mut selected_l1_nums: HashSet<u64> = HashSet::new();
            if let Some(l1) = cf.levels.get(1) {
                for sst in l1 {
                    let s_lo = sst.meta.smallest.user_key.as_slice();
                    let s_hi = sst.meta.largest.user_key.as_slice();
                    if s_hi >= span_lo && s_lo <= span_hi {
                        selected_l1_nums.insert(sst.meta.number);
                    }
                }
            }

            let is_bottommost = cf.levels.iter().skip(2).all(Vec::is_empty);

            let mut deleted_ssts: Vec<(u32, u64)> = Vec::new();
            let mut by_user_key: BTreeMap<Vec<u8>, Vec<(u64, ValueType, Vec<u8>)>> =
                BTreeMap::new();
            let mut merged_rdels: Vec<RangeTombstone> = Vec::new();

            for sst in l0 {
                deleted_ssts.push((0, sst.meta.number));
                merged_rdels.extend(sst.reader.range_dels.iter().cloned());
                for entry in sst.reader.scan_range(None, None)? {
                    let parsed = ParsedInternalKey::parse(&entry.internal_key)?;
                    by_user_key
                        .entry(parsed.user_key.to_vec())
                        .or_default()
                        .push((parsed.seqno, parsed.value_type, entry.value));
                }
            }
            if let Some(l1) = cf.levels.get(1) {
                for sst in l1 {
                    if !selected_l1_nums.contains(&sst.meta.number) {
                        continue;
                    }
                    deleted_ssts.push((1, sst.meta.number));
                    merged_rdels.extend(sst.reader.range_dels.iter().cloned());
                    for entry in sst.reader.scan_range(None, None)? {
                        let parsed = ParsedInternalKey::parse(&entry.internal_key)?;
                        by_user_key
                            .entry(parsed.user_key.to_vec())
                            .or_default()
                            .push((parsed.seqno, parsed.value_type, entry.value));
                    }
                }
            }

            let mut final_entries: Vec<(InternalKey, Vec<u8>)> = Vec::new();
            let mut dead_blobs: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
            let mut oldest_blob = u64::MAX;

            for (ukey, mut versions) in by_user_key {
                versions.sort_by(|a, b| b.0.cmp(&a.0));
                let tomb_seq = max_covering_seqno(&merged_rdels, &ukey);
                let mut kept_newest = false;

                for (seq, vtype, raw) in versions {
                    let covered = tomb_seq.is_some_and(|t| t >= seq);
                    if !kept_newest && !covered {
                        kept_newest = true;
                        match vtype {
                            ValueType::Value => {
                                final_entries.push((InternalKey::new(ukey.clone(), seq, vtype), raw));
                            }
                            ValueType::BlobIndex => {
                                if let Ok(BlobIndex::Blob { file_number, .. }) =
                                    BlobIndex::decode(&raw)
                                {
                                    oldest_blob = oldest_blob.min(file_number);
                                }
                                final_entries.push((InternalKey::new(ukey.clone(), seq, vtype), raw));
                            }
                            ValueType::Deletion | ValueType::SingleDeletion => {
                                if !is_bottommost {
                                    final_entries
                                        .push((InternalKey::new(ukey.clone(), seq, vtype), raw));
                                }
                            }
                            _ => {}
                        }
                    } else if vtype == ValueType::BlobIndex
                        && let Ok(BlobIndex::Blob {
                            file_number,
                            size,
                            ..
                        }) = BlobIndex::decode(&raw)
                    {
                        let rec_bytes = BLOB_RECORD_HEADER_SIZE + ukey.len() as u64 + size;
                        let e = dead_blobs.entry(file_number).or_insert((0, 0));
                        e.0 += 1;
                        e.1 += rec_bytes;
                    }
                }
            }

            let final_rdels = if is_bottommost {
                Vec::new()
            } else {
                merged_rdels
            };
            let oldest_blob_in_new_sst = if oldest_blob == u64::MAX {
                0
            } else {
                oldest_blob
            };

            (
                cf.id,
                cf.next_epoch,
                is_bottommost,
                selected_l1_nums,
                deleted_ssts,
                final_entries,
                final_rdels,
                dead_blobs,
                oldest_blob_in_new_sst,
            )
        };
        let _ = is_bottommost;

        let mut new_sst_meta = None;
        if !final_entries.is_empty() || !final_rdels.is_empty() {
            let sst_num = self.next_file_number;
            self.next_file_number += 1;
            let built = sst_writer::write_sst(
                &self.dir,
                sst_num,
                cf_id,
                cf_name,
                &final_entries,
                &final_rdels,
                oldest_blob_in_new_sst,
            )?;
            new_sst_meta = Some(SstFileMeta {
                number: built.file_number,
                level: 1,
                file_size: built.file_size,
                smallest: built.smallest,
                largest: built.largest,
                smallest_seqno: built.smallest_seqno,
                largest_seqno: built.largest_seqno,
                oldest_blob_file_number: built.oldest_blob_file_number,
                epoch_number: epoch,
            });
        }

        let mut edit = VersionEditBuilder {
            column_family: cf_id,
            next_file_number: Some(self.next_file_number),
            last_sequence: Some(self.last_sequence),
            deleted_files: deleted_ssts.clone(),
            new_files: new_sst_meta.iter().cloned().collect(),
            ..Default::default()
        };
        for (&bnum, &(gc, gb)) in &dead_blobs {
            edit.blob_garbages.push((bnum, gc, gb));
        }
        manifest_writer::append_edits(&self.dir, &self.manifest_name, &[edit])?;

        let new_opened = match new_sst_meta {
            Some(meta) => {
                let reader = SstReader::open(&self.dir.join(format!("{:06}.sst", meta.number)))?;
                Some(OpenedSst { meta, reader })
            }
            None => None,
        };

        let dead_blob_files: Vec<u64> = {
            let cf = self.cfs.get_mut(cf_name).unwrap();
            cf.levels[0].clear();
            if cf.levels.len() < 2 {
                cf.levels.resize_with(2, Vec::new);
            }
            cf.levels[1].retain(|s| !selected_l1_nums.contains(&s.meta.number));
            if let Some(opened) = new_opened {
                cf.levels[1].push(opened);
                cf.levels[1].sort_by(|a, b| a.meta.smallest.user_key.cmp(&b.meta.smallest.user_key));
            }
            cf.next_epoch += 1;

            for (&bnum, &(gc, gb)) in &dead_blobs {
                if let Some(meta) = cf.blob_files.get_mut(&bnum) {
                    meta.garbage_blob_count = meta.garbage_blob_count.saturating_add(gc);
                    meta.garbage_blob_bytes = meta.garbage_blob_bytes.saturating_add(gb);
                }
            }

            let min_live_blob = cf
                .levels
                .iter()
                .flatten()
                .filter(|s| s.meta.oldest_blob_file_number != 0)
                .map(|s| s.meta.oldest_blob_file_number)
                .min();
            let unreferenced: Vec<u64> = cf
                .blob_files
                .iter()
                .filter(|(bnum, m)| {
                    let all_garb = m.garbage_blob_count >= m.total_blob_count
                        && m.total_blob_count > 0;
                    let older_than_live = min_live_blob.is_none_or(|min_b| **bnum < min_b);
                    all_garb && older_than_live
                })
                .map(|(bnum, _)| *bnum)
                .collect();
            for bnum in &unreferenced {
                cf.blob_files.remove(bnum);
            }
            cf.rebuild_range_dels();
            unreferenced
        };

        for (_, sst_num) in deleted_ssts {
            let _ = std::fs::remove_file(self.dir.join(format!("{sst_num:06}.sst")));
        }
        for bnum in &dead_blob_files {
            self.blob_readers.lock().unwrap().remove(bnum);
            let _ = std::fs::remove_file(self.dir.join(format!("{bnum:06}.blob")));
        }

        Ok(())
    }

    /// Full compaction of `cf_name` into a clean bottommost SST, dropping tombstones and
    /// accounting BlobDB garbage. When `relocate_blobs` is true (or garbage >= 25% of live
    /// blob bytes), rewrites surviving blobs into a fresh `.blob` file and unlinks obsolete files.
    pub fn compact_cf(&mut self, cf_name: &str, relocate_blobs: bool) -> Result<()> {
        if self.read_only {
            return Err(Error::Unsupported("database is read-only".into()));
        }
        if self.memory {
            let cf = self.cfs.get_mut(cf_name).ok_or_else(|| {
                Error::NotFound(format!("column family {cf_name:?} not found"))
            })?;
            let mut latest: BTreeMap<Vec<u8>, (u64, MemValue)> = BTreeMap::new();
            for (ik, mv) in std::mem::take(&mut cf.memtable.entries) {
                match latest.get_mut(&ik.user_key) {
                    Some(e) if e.0 >= ik.seqno => {}
                    Some(e) => *e = (ik.seqno, mv),
                    None => {
                        latest.insert(ik.user_key, (ik.seqno, mv));
                    }
                }
            }
            let rdels = std::mem::take(&mut cf.memtable.range_dels);
            let mut new_bytes = 0usize;
            for (ukey, (seq, mv)) in latest {
                if max_covering_seqno(&rdels, &ukey).is_some_and(|t| t >= seq) {
                    continue;
                }
                if let MemValue::Value(v) = mv {
                    new_bytes += ukey.len() + 8 + v.len();
                    cf.memtable.entries.insert(
                        InternalKey::new(ukey, seq, ValueType::Value),
                        MemValue::Value(v),
                    );
                }
            }
            cf.memtable_bytes = new_bytes;
            cf.rebuild_range_dels();
            return Ok(());
        }
        self.flush_cf(cf_name)?;

        // Match RocksDB's BottommostLevelCompaction::Skip: when `relocate_blobs` is false,
        // if no L0 files need merging, there is at most one non-empty level with no range
        // tombstones, and blob garbage is below the 25% threshold, skip rewriting bottommost SSTs.
        if !relocate_blobs {
            let cf = self.cf(cf_name)?;
            let l0_empty = cf.levels.first().is_none_or(|l| l.is_empty());
            let non_empty_levels = cf.levels.iter().filter(|l| !l.is_empty()).count();
            let live_blob = cf.live_blob_file_size();
            let garb_blob = cf.live_blob_file_garbage_size();
            let needs_blob_gc = garb_blob > 0 && garb_blob >= live_blob.div_ceil(4);
            if l0_empty && non_empty_levels <= 1 && cf.all_range_dels.is_empty() && !needs_blob_gc {
                return Ok(());
            }
        }

        let (cf_id, deleted_ssts, live_entries, dead_blobs, epoch) = {
            let cf = self.cf(cf_name)?;
            let mut deleted_ssts: Vec<(u32, u64)> = Vec::new();
            // Keep ALL versions so we can accurately account for shadowed BlobIndex records.
            let mut by_user_key: BTreeMap<Vec<u8>, Vec<(u64, ValueType, Vec<u8>)>> =
                BTreeMap::new();

            for (lvl_idx, lvl) in cf.levels.iter().enumerate() {
                for sst in lvl {
                    deleted_ssts.push((lvl_idx as u32, sst.meta.number));
                    for entry in sst.reader.scan_range(None, None)? {
                        let parsed = ParsedInternalKey::parse(&entry.internal_key)?;
                        by_user_key
                            .entry(parsed.user_key.to_vec())
                            .or_default()
                            .push((parsed.seqno, parsed.value_type, entry.value));
                    }
                }
            }
            if deleted_ssts.is_empty() {
                return Ok(());
            }

            let mut live_entries: Vec<(InternalKey, Vec<u8>)> = Vec::new();
            let mut dead_blobs: BTreeMap<u64, (u64, u64)> = BTreeMap::new();

            for (ukey, mut versions) in by_user_key {
                versions.sort_by(|a, b| b.0.cmp(&a.0)); // newest first
                let tomb_seq = max_covering_seqno(&cf.all_range_dels, &ukey);
                let mut kept_newest = false;

                for (seq, vtype, raw) in versions {
                    let covered = tomb_seq.is_some_and(|t| t >= seq);
                    if !kept_newest && !covered {
                        kept_newest = true;
                        match vtype {
                            ValueType::Value | ValueType::BlobIndex => {
                                live_entries.push((InternalKey::new(ukey.clone(), seq, vtype), raw));
                            }
                            ValueType::Deletion | ValueType::SingleDeletion => {}
                            _ => {}
                        }
                    } else if vtype == ValueType::BlobIndex
                        && let Ok(BlobIndex::Blob {
                            file_number,
                            size,
                            ..
                        }) = BlobIndex::decode(&raw)
                    {
                        let rec_bytes = BLOB_RECORD_HEADER_SIZE + ukey.len() as u64 + size;
                        let e = dead_blobs.entry(file_number).or_insert((0, 0));
                        e.0 += 1;
                        e.1 += rec_bytes;
                    }
                }
            }
            (cf.id, deleted_ssts, live_entries, dead_blobs, cf.next_epoch)
        };

        // Decide whether to relocate live blobs.
        let mut do_relocate = relocate_blobs;
        if !do_relocate {
            let cf = self.cf(cf_name)?;
            let projected_live: u64 = cf
                .blob_files
                .values()
                .map(|b| {
                    let add_g = dead_blobs.get(&b.number).map_or(0, |x| x.0);
                    if b.garbage_blob_count + add_g < b.total_blob_count {
                        b.total_blob_bytes
                    } else {
                        0
                    }
                })
                .sum();
            let projected_garb: u64 = cf
                .blob_files
                .values()
                .map(|b| {
                    let (ag_c, ag_b) = dead_blobs.get(&b.number).copied().unwrap_or((0, 0));
                    if b.garbage_blob_count + ag_c < b.total_blob_count {
                        b.garbage_blob_bytes + ag_b
                    } else {
                        0
                    }
                })
                .sum();
            if projected_live > 0 && projected_garb.saturating_mul(4) >= projected_live {
                do_relocate = true;
            }
        }

        let mut final_entries = Vec::with_capacity(live_entries.len());
        let mut new_blob_writer: Option<BlobFileWriter> = None;
        let mut finished_new_blobs = Vec::new();
        let mut all_garbage = dead_blobs;
        let mut oldest_blob = u64::MAX;

        for (ik, raw) in live_entries {
            if ik.value_type == ValueType::BlobIndex {
                if let BlobIndex::Blob {
                    file_number,
                    offset,
                    size,
                    compression,
                } = BlobIndex::decode(&raw)?
                {
                    if do_relocate {
                        let val = blob::read_blob_value(
                            &self.dir,
                            &ik.user_key,
                            file_number,
                            offset,
                            size,
                            compression,
                        )?;
                        if let Some(bw) = new_blob_writer.as_ref()
                            && bw.current_bytes() >= self.blob_file_size
                        {
                            finished_new_blobs.push(new_blob_writer.take().unwrap().finish()?);
                        }
                        if new_blob_writer.is_none() {
                            let new_blob_num = self.next_file_number;
                            self.next_file_number += 1;
                            new_blob_writer = Some(BlobFileWriter::create(
                                &self.dir,
                                new_blob_num,
                                cf_id,
                            )?);
                        }
                        let bw = new_blob_writer.as_mut().unwrap();
                        let bnum = bw.file_number();
                        let (new_off, new_sz) = bw.add_blob(&ik.user_key, &val)?;
                        let new_idx =
                            blob::encode_blob_index(bnum, new_off, new_sz, CompressionType::None);
                        oldest_blob = oldest_blob.min(bnum);
                        final_entries.push((ik.clone(), new_idx));

                        // Mark old blob record as garbage.
                        let rec_bytes = BLOB_RECORD_HEADER_SIZE + ik.user_key.len() as u64 + size;
                        let e = all_garbage.entry(file_number).or_insert((0, 0));
                        e.0 += 1;
                        e.1 += rec_bytes;
                    } else {
                        oldest_blob = oldest_blob.min(file_number);
                        final_entries.push((ik, raw));
                    }
                } else {
                    final_entries.push((ik, raw));
                }
            } else {
                final_entries.push((ik, raw));
            }
        }

        if let Some(bw) = new_blob_writer {
            finished_new_blobs.push(bw.finish()?);
        }
        let oldest_blob_file_number = if oldest_blob == u64::MAX {
            0
        } else {
            oldest_blob
        };

        let mut new_sst_meta = None;
        if !final_entries.is_empty() {
            let sst_num = self.next_file_number;
            self.next_file_number += 1;
            let built = sst_writer::write_sst(
                &self.dir,
                sst_num,
                cf_id,
                cf_name,
                &final_entries,
                &[],
                oldest_blob_file_number,
            )?;
            new_sst_meta = Some(SstFileMeta {
                number: built.file_number,
                level: 1,
                file_size: built.file_size,
                smallest: built.smallest,
                largest: built.largest,
                smallest_seqno: built.smallest_seqno,
                largest_seqno: built.largest_seqno,
                oldest_blob_file_number: built.oldest_blob_file_number,
                epoch_number: epoch,
            });
        }

        let mut edit = VersionEditBuilder {
            column_family: cf_id,
            next_file_number: Some(self.next_file_number),
            last_sequence: Some(self.last_sequence),
            deleted_files: deleted_ssts.clone(),
            new_files: new_sst_meta.iter().cloned().collect(),
            ..Default::default()
        };
        for bs in &finished_new_blobs {
            edit.blob_additions
                .push((bs.file_number, bs.total_blob_count, bs.total_blob_bytes));
        }
        for (&bnum, &(gc, gb)) in &all_garbage {
            edit.blob_garbages.push((bnum, gc, gb));
        }
        manifest_writer::append_edits(&self.dir, &self.manifest_name, &[edit])?;

        // Update in-memory state and unlink obsolete SSTs & fully-dead .blob files.
        let new_opened = match new_sst_meta {
            Some(meta) => {
                let reader = SstReader::open(&self.dir.join(format!("{:06}.sst", meta.number)))?;
                Some(OpenedSst { meta, reader })
            }
            None => None,
        };

        let dead_blob_files: Vec<u64> = {
            let cf = self.cfs.get_mut(cf_name).unwrap();
            for lvl in &mut cf.levels {
                lvl.clear();
            }
            if cf.levels.len() < 2 {
                cf.levels.resize_with(2, Vec::new);
            }
            if let Some(opened) = new_opened {
                cf.levels[1].push(opened);
            }
            cf.next_epoch += 1;
            for bs in finished_new_blobs {
                cf.blob_files.insert(
                    bs.file_number,
                    BlobFileMeta {
                        number: bs.file_number,
                        total_blob_count: bs.total_blob_count,
                        total_blob_bytes: bs.total_blob_bytes,
                        garbage_blob_count: 0,
                        garbage_blob_bytes: 0,
                    },
                );
            }
            for (&bnum, &(gc, gb)) in &all_garbage {
                if let Some(meta) = cf.blob_files.get_mut(&bnum) {
                    meta.garbage_blob_count = meta.garbage_blob_count.saturating_add(gc);
                    meta.garbage_blob_bytes = meta.garbage_blob_bytes.saturating_add(gb);
                }
            }
            let unreferenced: Vec<u64> = cf
                .blob_files
                .iter()
                .filter(|(bnum, m)| {
                    let all_garb = m.garbage_blob_count >= m.total_blob_count
                        && m.total_blob_count > 0;
                    let older_than_live =
                        oldest_blob_file_number == 0 || **bnum < oldest_blob_file_number;
                    all_garb && older_than_live
                })
                .map(|(bnum, _)| *bnum)
                .collect();
            for bnum in &unreferenced {
                cf.blob_files.remove(bnum);
            }
            cf.rebuild_range_dels();
            unreferenced
        };

        for (_, sst_num) in deleted_ssts {
            let _ = std::fs::remove_file(self.dir.join(format!("{sst_num:06}.sst")));
        }
        for bnum in &dead_blob_files {
            self.blob_readers.lock().unwrap().remove(bnum);
            let _ = std::fs::remove_file(self.dir.join(format!("{bnum:06}.blob")));
        }

        Ok(())
    }

    pub fn get_cf(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf = self.cf(cf_name)?;
        let tomb_seq = max_covering_seqno(&cf.all_range_dels, key);

        let mut best: Option<(u64, ValueType, Vec<u8>)> = None;

        // 1. Memtable.
        let search = InternalKey::new(
            key.to_vec(),
            crate::keys::MAX_SEQUENCE_NUMBER,
            ValueType::Unknown,
        );
        if let Some((ik, mv)) = cf.memtable.entries.range(search..).next()
            && ik.user_key.as_slice() == key
        {
            best = Some(match mv {
                MemValue::Value(v) => (ik.seqno, ValueType::Value, v.clone()),
                MemValue::Deletion => (ik.seqno, ValueType::Deletion, Vec::new()),
            });
        }

        // 2. L0 (overlapping).
        if let Some(l0) = cf.levels.first() {
            for sst in l0 {
                if key < sst.meta.smallest.user_key.as_slice()
                    || key > sst.meta.largest.user_key.as_slice()
                {
                    continue;
                }
                if let Some(hit) = sst.reader.get(key)?
                    && best.as_ref().is_none_or(|b| hit.0 > b.0)
                {
                    best = Some(hit);
                }
            }
        }

        // 3. L1..L6 (non-overlapping).
        for lvl in cf.levels.iter().skip(1) {
            let pos = lvl.partition_point(|s| s.meta.largest.user_key.as_slice() < key);
            if let Some(sst) = lvl.get(pos)
                && key >= sst.meta.smallest.user_key.as_slice()
                && let Some(hit) = sst.reader.get(key)?
                && best.as_ref().is_none_or(|b| hit.0 > b.0)
            {
                best = Some(hit);
            }
        }

        let Some((seq, vtype, raw)) = best else {
            return Ok(None);
        };
        if tomb_seq.is_some_and(|t| t >= seq) {
            return Ok(None);
        }
        self.resolve_value(key, vtype, raw)
    }

    pub fn multi_get_cf(&self, cf_name: &str, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>> {
        let mut out = Vec::with_capacity(keys.len());
        for &k in keys {
            out.push(self.get_cf(cf_name, k)?);
        }
        Ok(out)
    }

    pub fn scan_cf(
        &self,
        cf_name: &str,
        lower: Option<&[u8]>,
        upper: Option<&[u8]>,
        direction: ScanDirection,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let cf = self.cf(cf_name)?;
        let mut merged: BTreeMap<Vec<u8>, (u64, ValueType, Vec<u8>)> = BTreeMap::new();

        for (ik, mv) in &cf.memtable.entries {
            if !in_bounds(&ik.user_key, lower, upper) {
                continue;
            }
            let (vt, val) = match mv {
                MemValue::Value(v) => (ValueType::Value, v.clone()),
                MemValue::Deletion => (ValueType::Deletion, Vec::new()),
            };
            insert_if_newer(&mut merged, ik.user_key.clone(), ik.seqno, vt, val);
        }

        for lvl in &cf.levels {
            for sst in lvl {
                if let Some(lo) = lower
                    && sst.meta.largest.user_key.as_slice() < lo
                {
                    continue;
                }
                if let Some(hi) = upper
                    && sst.meta.smallest.user_key.as_slice() >= hi
                {
                    continue;
                }
                for entry in sst.reader.scan_range(lower, upper)? {
                    let parsed = ParsedInternalKey::parse(&entry.internal_key)?;
                    insert_if_newer(
                        &mut merged,
                        parsed.user_key.to_vec(),
                        parsed.seqno,
                        parsed.value_type,
                        entry.value,
                    );
                }
            }
        }

        let mut out = Vec::new();
        for (k, (seq, vtype, raw)) in merged {
            if max_covering_seqno(&cf.all_range_dels, &k).is_some_and(|t| t >= seq) {
                continue;
            }
            if let Some(resolved) = self.resolve_value(&k, vtype, raw)? {
                out.push((k, resolved));
            }
        }
        if direction == ScanDirection::Reverse {
            out.reverse();
        }
        Ok(out)
    }

    fn resolve_value(
        &self,
        user_key: &[u8],
        vtype: ValueType,
        raw: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        match vtype {
            ValueType::Value => Ok(Some(raw)),
            ValueType::Deletion | ValueType::SingleDeletion => Ok(None),
            ValueType::BlobIndex => match BlobIndex::decode(&raw)? {
                BlobIndex::InlinedTtl { value, .. } => Ok(Some(value)),
                BlobIndex::Blob {
                    file_number,
                    offset,
                    size,
                    compression,
                } => {
                    let reader = {
                        let mut cache = self.blob_readers.lock().unwrap();
                        if let Some(r) = cache.get(&file_number) {
                            Arc::clone(r)
                        } else {
                            if cache.len() >= 32 {
                                cache.clear();
                            }
                            let r = Arc::new(BlobFileReader::open(&self.dir, file_number)?);
                            cache.insert(file_number, Arc::clone(&r));
                            r
                        }
                    };
                    Ok(Some(reader.read_value(
                        user_key,
                        offset,
                        size,
                        compression,
                    )?))
                }
            },
            other => Err(Error::Unsupported(format!(
                "unsupported value type {other:?}"
            ))),
        }
    }

    fn cf(&self, name: &str) -> Result<&ColumnFamilyEngine> {
        self.cfs
            .get(name)
            .ok_or_else(|| Error::NotFound(format!("column family {name:?} not found")))
    }
}

fn cleanup_orphan_files(
    dir: &Path,
    cfs: &BTreeMap<String, ColumnFamilyEngine>,
    active_wal_number: u64,
) {
    let mut live_ssts: HashSet<u64> = HashSet::new();
    let mut live_blobs: HashSet<u64> = HashSet::new();
    let mut min_cf_log = u64::MAX;

    for cf in cfs.values() {
        min_cf_log = min_cf_log.min(cf.log_number);
        for lvl in &cf.levels {
            for sst in lvl {
                live_ssts.insert(sst.meta.number);
            }
        }
        for &bnum in cf.blob_files.keys() {
            live_blobs.insert(bnum);
        }
    }
    if min_cf_log == u64::MAX {
        min_cf_log = 0;
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(s) = name.to_str() else { continue };
        if s == "CURRENT.tmp" {
            let _ = std::fs::remove_file(entry.path());
        } else if let Some(stem) = s.strip_suffix(".sst")
            && let Ok(num) = stem.parse::<u64>()
            && !live_ssts.contains(&num)
        {
            let _ = std::fs::remove_file(entry.path());
        } else if let Some(stem) = s.strip_suffix(".blob")
            && let Ok(num) = stem.parse::<u64>()
            && !live_blobs.contains(&num)
        {
            let _ = std::fs::remove_file(entry.path());
        } else if let Some(stem) = s.strip_suffix(".log")
            && let Ok(num) = stem.parse::<u64>()
            && num < min_cf_log
            && num != active_wal_number
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn in_bounds(key: &[u8], lower: Option<&[u8]>, upper: Option<&[u8]>) -> bool {
    if let Some(lo) = lower
        && key < lo
    {
        return false;
    }
    if let Some(hi) = upper
        && key >= hi
    {
        return false;
    }
    true
}

fn insert_if_newer(
    map: &mut BTreeMap<Vec<u8>, (u64, ValueType, Vec<u8>)>,
    key: Vec<u8>,
    seqno: u64,
    vtype: ValueType,
    val: Vec<u8>,
) {
    match map.get_mut(&key) {
        Some(existing) if existing.0 >= seqno => {}
        Some(existing) => *existing = (seqno, vtype, val),
        None => {
            map.insert(key, (seqno, vtype, val));
        }
    }
}
