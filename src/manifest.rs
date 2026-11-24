//! RocksDB `CURRENT` and `MANIFEST-*` (`VersionEdit`) decoder and live version state.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::coding::{get_fixed64, get_length_prefixed_slice, get_varint32, get_varint64};
use crate::keys::InternalKey;
use crate::log;
use crate::{Error, Result};

// VersionEdit tags (`db/version_edit.h`).
const TAG_COMPARATOR: u32 = 1;
const TAG_LOG_NUMBER: u32 = 2;
const TAG_NEXT_FILE_NUMBER: u32 = 3;
const TAG_LAST_SEQUENCE: u32 = 4;
const TAG_COMPACT_CURSOR: u32 = 5;
const TAG_DELETED_FILE: u32 = 6;
const TAG_NEW_FILE: u32 = 7;
const TAG_PREV_LOG_NUMBER: u32 = 9;
const TAG_MIN_LOG_NUMBER_TO_KEEP: u32 = 10;
const TAG_NEW_FILE2: u32 = 100;
const TAG_NEW_FILE3: u32 = 102;
const TAG_NEW_FILE4: u32 = 103;
const TAG_COLUMN_FAMILY: u32 = 200;
const TAG_COLUMN_FAMILY_ADD: u32 = 201;
const TAG_COLUMN_FAMILY_DROP: u32 = 202;
const TAG_MAX_COLUMN_FAMILY: u32 = 203;
const TAG_IN_ATOMIC_GROUP: u32 = 300;
const TAG_BLOB_FILE_ADDITION: u32 = 400;
const TAG_BLOB_FILE_GARBAGE: u32 = 401;
const TAG_SAFE_IGNORE_MASK: u32 = 1 << 13;
const TAG_DB_ID: u32 = TAG_SAFE_IGNORE_MASK + 1;
const TAG_BLOB_FILE_ADDITION_DEPRECATED: u32 = TAG_SAFE_IGNORE_MASK + 2;
const TAG_BLOB_FILE_GARBAGE_DEPRECATED: u32 = TAG_SAFE_IGNORE_MASK + 3;
const TAG_WAL_ADDITION: u32 = TAG_SAFE_IGNORE_MASK + 4;
const TAG_WAL_DELETION: u32 = TAG_SAFE_IGNORE_MASK + 5;
const TAG_FULL_HISTORY_TS_LOW: u32 = TAG_SAFE_IGNORE_MASK + 6;
const TAG_WAL_ADDITION2: u32 = TAG_SAFE_IGNORE_MASK + 7;
const TAG_WAL_DELETION2: u32 = TAG_SAFE_IGNORE_MASK + 8;
const TAG_PERSIST_UDT: u32 = TAG_SAFE_IGNORE_MASK + 9;

// NewFile4 custom tags.
const CUSTOM_TERMINATE: u32 = 1;
const CUSTOM_MIN_LOG_NUMBER_TO_KEEP_HACK: u32 = 3;
const CUSTOM_OLDEST_BLOB_FILE_NUMBER: u32 = 4;
const CUSTOM_EPOCH_NUMBER: u32 = 13;
const CUSTOM_NON_SAFE_IGNORE_MASK: u32 = 1 << 6;
const CUSTOM_PATH_ID: u32 = CUSTOM_NON_SAFE_IGNORE_MASK + 1;

#[derive(Debug, Clone)]
pub struct SstFileMeta {
    pub number: u64,
    pub level: u32,
    pub file_size: u64,
    pub smallest: InternalKey,
    pub largest: InternalKey,
    pub smallest_seqno: u64,
    pub largest_seqno: u64,
    pub oldest_blob_file_number: u64,
    pub epoch_number: u64,
}

#[derive(Debug, Clone, Default)]
pub struct BlobFileMeta {
    pub number: u64,
    pub total_blob_count: u64,
    pub total_blob_bytes: u64,
    pub garbage_blob_count: u64,
    pub garbage_blob_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct ColumnFamilyState {
    pub id: u32,
    pub name: String,
    pub log_number: u64,
    pub levels: Vec<Vec<SstFileMeta>>,
    pub blob_files: BTreeMap<u64, BlobFileMeta>,
}

impl ColumnFamilyState {
    fn new(id: u32, name: String) -> Self {
        Self {
            id,
            name,
            log_number: 0,
            levels: vec![Vec::new(); 7],
            blob_files: BTreeMap::new(),
        }
    }

    pub fn live_blob_file_size(&self) -> u64 {
        const BLOB_HEADER_PLUS_FOOTER: u64 = 30 + 32;
        self.blob_files
            .values()
            .filter(|b| b.garbage_blob_count < b.total_blob_count)
            .map(|b| b.total_blob_bytes + BLOB_HEADER_PLUS_FOOTER)
            .sum()
    }

    pub fn live_blob_file_garbage_size(&self) -> u64 {
        self.blob_files
            .values()
            .filter(|b| b.garbage_blob_count < b.total_blob_count)
            .map(|b| b.garbage_blob_bytes)
            .sum()
    }
}

#[derive(Debug, Clone)]
pub struct VersionState {
    pub column_families: HashMap<u32, ColumnFamilyState>,
    pub cf_by_name: HashMap<String, u32>,
    pub next_file_number: u64,
    pub last_sequence: u64,
    pub min_log_number_to_keep: u64,
    pub max_column_family: u32,
    pub manifest_valid_len: usize,
    pub manifest_file_len: usize,
}

impl VersionState {
    pub fn load(db_dir: &Path) -> Result<Self> {
        let current = std::fs::read_to_string(db_dir.join("CURRENT"))?;
        let manifest_name = current.trim();
        if manifest_name.is_empty() {
            return Err(Error::Corruption("CURRENT file is empty".into()));
        }
        let manifest_bytes = std::fs::read(db_dir.join(manifest_name))?;
        let manifest_file_len = manifest_bytes.len();
        let (records, manifest_valid_len) =
            log::read_records_with_valid_len(&manifest_bytes, true)?;

        let mut state = Self {
            column_families: HashMap::new(),
            cf_by_name: HashMap::new(),
            next_file_number: 1,
            last_sequence: 0,
            min_log_number_to_keep: 0,
            max_column_family: 0,
            manifest_valid_len,
            manifest_file_len,
        };
        // Column family 0 ("default") always exists initially.
        state
            .column_families
            .insert(0, ColumnFamilyState::new(0, "default".to_string()));
        state.cf_by_name.insert("default".to_string(), 0);

        for rec in &records {
            let edit = decode_version_edit(rec)?;
            state.apply(edit)?;
        }

        // Sort L0 newest-first (largest epoch_number / file number first) and L1+ by smallest user key.
        for cf in state.column_families.values_mut() {
            if let Some(l0) = cf.levels.first_mut() {
                l0.sort_by(|a, b| {
                    b.epoch_number
                        .cmp(&a.epoch_number)
                        .then_with(|| b.largest_seqno.cmp(&a.largest_seqno))
                        .then_with(|| b.number.cmp(&a.number))
                });
            }
            for lvl in cf.levels.iter_mut().skip(1) {
                lvl.sort_by(|a, b| a.smallest.user_key.cmp(&b.smallest.user_key));
            }
            // Drop blob files that are no longer referenced by any SST and are 100% garbage.
            let min_live_blob = cf
                .levels
                .iter()
                .flatten()
                .filter(|f| f.oldest_blob_file_number != 0)
                .map(|f| f.oldest_blob_file_number)
                .min();
            cf.blob_files.retain(|&num, meta| {
                let all_garbage =
                    meta.garbage_blob_count >= meta.total_blob_count && meta.total_blob_count > 0;
                if !all_garbage {
                    return true;
                }
                match min_live_blob {
                    Some(min_ref) => num >= min_ref,
                    None => false,
                }
            });
        }

        Ok(state)
    }

    fn apply(&mut self, edit: VersionEdit) -> Result<()> {
        if let Some(v) = edit.next_file_number {
            self.next_file_number = v;
        }
        if let Some(v) = edit.last_sequence {
            self.last_sequence = v;
        }
        if let Some(v) = edit.min_log_number_to_keep {
            self.min_log_number_to_keep = v;
        }
        if let Some(v) = edit.max_column_family {
            self.max_column_family = v;
        }

        let cf_id = edit.column_family;
        if let Some(name) = edit.column_family_add {
            self.column_families
                .insert(cf_id, ColumnFamilyState::new(cf_id, name.clone()));
            self.cf_by_name.insert(name, cf_id);
        }
        if edit.column_family_drop {
            if let Some(removed) = self.column_families.remove(&cf_id) {
                self.cf_by_name.remove(&removed.name);
            }
            return Ok(());
        }

        let Some(cf) = self.column_families.get_mut(&cf_id) else {
            // Edits targeting an already-dropped CF can appear before the drop completes.
            return Ok(());
        };

        if let Some(log_num) = edit.log_number {
            cf.log_number = log_num;
        }
        for (level, number) in edit.deleted_files {
            if let Some(lvl) = cf.levels.get_mut(level as usize) {
                lvl.retain(|f| f.number != number);
            }
        }
        for file in edit.new_files {
            let lvl_idx = file.level as usize;
            if lvl_idx >= cf.levels.len() {
                cf.levels.resize_with(lvl_idx + 1, Vec::new);
            }
            cf.levels[lvl_idx].push(file);
        }
        for add in edit.blob_additions {
            cf.blob_files.insert(
                add.number,
                BlobFileMeta {
                    number: add.number,
                    total_blob_count: add.total_blob_count,
                    total_blob_bytes: add.total_blob_bytes,
                    garbage_blob_count: 0,
                    garbage_blob_bytes: 0,
                },
            );
        }
        for garb in edit.blob_garbages {
            if let Some(meta) = cf.blob_files.get_mut(&garb.number) {
                meta.garbage_blob_count = meta
                    .garbage_blob_count
                    .saturating_add(garb.garbage_blob_count);
                meta.garbage_blob_bytes = meta
                    .garbage_blob_bytes
                    .saturating_add(garb.garbage_blob_bytes);
            }
        }

        Ok(())
    }
}

#[derive(Default)]
struct VersionEdit {
    column_family: u32,
    column_family_add: Option<String>,
    column_family_drop: bool,
    log_number: Option<u64>,
    next_file_number: Option<u64>,
    last_sequence: Option<u64>,
    min_log_number_to_keep: Option<u64>,
    max_column_family: Option<u32>,
    deleted_files: Vec<(u32, u64)>,
    new_files: Vec<SstFileMeta>,
    blob_additions: Vec<BlobAdditionEdit>,
    blob_garbages: Vec<BlobGarbageEdit>,
}

struct BlobAdditionEdit {
    number: u64,
    total_blob_count: u64,
    total_blob_bytes: u64,
}

struct BlobGarbageEdit {
    number: u64,
    garbage_blob_count: u64,
    garbage_blob_bytes: u64,
}

fn decode_version_edit(mut input: &[u8]) -> Result<VersionEdit> {
    let mut edit = VersionEdit::default();

    while !input.is_empty() {
        let tag = get_varint32(&mut input)
            .ok_or_else(|| Error::Corruption("manifest: truncated tag".into()))?;
        match tag {
            TAG_COMPARATOR => {
                let cmp = get_length_prefixed_slice(&mut input)
                    .ok_or_else(|| Error::Corruption("manifest: bad comparator".into()))?;
                if cmp != b"leveldb.BytewiseComparator" {
                    return Err(Error::Unsupported(format!(
                        "unsupported comparator {:?}",
                        String::from_utf8_lossy(cmp)
                    )));
                }
            }
            TAG_LOG_NUMBER => {
                edit.log_number = Some(
                    get_varint64(&mut input)
                        .ok_or_else(|| Error::Corruption("manifest: bad log_number".into()))?,
                );
            }
            TAG_PREV_LOG_NUMBER => {
                let _ = get_varint64(&mut input)
                    .ok_or_else(|| Error::Corruption("manifest: bad prev_log_number".into()))?;
            }
            TAG_NEXT_FILE_NUMBER => {
                edit.next_file_number =
                    Some(get_varint64(&mut input).ok_or_else(|| {
                        Error::Corruption("manifest: bad next_file_number".into())
                    })?);
            }
            TAG_LAST_SEQUENCE => {
                edit.last_sequence = Some(
                    get_varint64(&mut input)
                        .ok_or_else(|| Error::Corruption("manifest: bad last_sequence".into()))?,
                );
            }
            TAG_MIN_LOG_NUMBER_TO_KEEP => {
                edit.min_log_number_to_keep = Some(get_varint64(&mut input).ok_or_else(|| {
                    Error::Corruption("manifest: bad min_log_number_to_keep".into())
                })?);
            }
            TAG_MAX_COLUMN_FAMILY => {
                edit.max_column_family =
                    Some(get_varint32(&mut input).ok_or_else(|| {
                        Error::Corruption("manifest: bad max_column_family".into())
                    })?);
            }
            TAG_COMPACT_CURSOR => {
                let _level = get_varint32(&mut input).ok_or_else(|| {
                    Error::Corruption("manifest: bad compact_cursor level".into())
                })?;
                let _key = get_length_prefixed_slice(&mut input)
                    .ok_or_else(|| Error::Corruption("manifest: bad compact_cursor key".into()))?;
            }
            TAG_DELETED_FILE => {
                let level = get_varint32(&mut input)
                    .ok_or_else(|| Error::Corruption("manifest: bad deleted_file level".into()))?;
                let num = get_varint64(&mut input)
                    .ok_or_else(|| Error::Corruption("manifest: bad deleted_file num".into()))?;
                edit.deleted_files.push((level, num));
            }
            TAG_NEW_FILE | TAG_NEW_FILE2 | TAG_NEW_FILE3 => {
                let level = get_varint32(&mut input)
                    .ok_or_else(|| Error::Corruption("manifest: bad new_file level".into()))?;
                let number = get_varint64(&mut input)
                    .ok_or_else(|| Error::Corruption("manifest: bad new_file number".into()))?;
                if tag == TAG_NEW_FILE3 {
                    let _path_id = get_varint32(&mut input)
                        .ok_or_else(|| Error::Corruption("manifest: bad path_id".into()))?;
                }
                let file_size = get_varint64(&mut input)
                    .ok_or_else(|| Error::Corruption("manifest: bad new_file size".into()))?;
                let smallest_raw = get_length_prefixed_slice(&mut input)
                    .ok_or_else(|| Error::Corruption("manifest: bad smallest key".into()))?;
                let largest_raw = get_length_prefixed_slice(&mut input)
                    .ok_or_else(|| Error::Corruption("manifest: bad largest key".into()))?;
                let (smallest_seqno, largest_seqno) = if tag == TAG_NEW_FILE {
                    (0, 0)
                } else {
                    let s = get_varint64(&mut input)
                        .ok_or_else(|| Error::Corruption("manifest: bad smallest_seqno".into()))?;
                    let l = get_varint64(&mut input)
                        .ok_or_else(|| Error::Corruption("manifest: bad largest_seqno".into()))?;
                    (s, l)
                };
                edit.new_files.push(SstFileMeta {
                    number,
                    level,
                    file_size,
                    smallest: InternalKey::from_encoded(smallest_raw)?,
                    largest: InternalKey::from_encoded(largest_raw)?,
                    smallest_seqno,
                    largest_seqno,
                    oldest_blob_file_number: 0,
                    epoch_number: 0,
                });
            }
            TAG_NEW_FILE4 => {
                let file = decode_new_file4(&mut input, &mut edit.min_log_number_to_keep)?;
                edit.new_files.push(file);
            }
            TAG_COLUMN_FAMILY => {
                edit.column_family = get_varint32(&mut input)
                    .ok_or_else(|| Error::Corruption("manifest: bad column_family".into()))?;
            }
            TAG_COLUMN_FAMILY_ADD => {
                let name = get_length_prefixed_slice(&mut input)
                    .ok_or_else(|| Error::Corruption("manifest: bad cf_add".into()))?;
                edit.column_family_add = Some(String::from_utf8_lossy(name).into_owned());
            }
            TAG_COLUMN_FAMILY_DROP => {
                edit.column_family_drop = true;
            }
            TAG_IN_ATOMIC_GROUP => {
                let _remaining = get_varint32(&mut input)
                    .ok_or_else(|| Error::Corruption("manifest: bad atomic_group".into()))?;
            }
            TAG_BLOB_FILE_ADDITION | TAG_BLOB_FILE_ADDITION_DEPRECATED => {
                edit.blob_additions.push(decode_blob_addition(&mut input)?);
            }
            TAG_BLOB_FILE_GARBAGE | TAG_BLOB_FILE_GARBAGE_DEPRECATED => {
                edit.blob_garbages.push(decode_blob_garbage(&mut input)?);
            }
            TAG_DB_ID
            | TAG_WAL_ADDITION2
            | TAG_WAL_DELETION2
            | TAG_FULL_HISTORY_TS_LOW
            | TAG_PERSIST_UDT => {
                let _ = get_length_prefixed_slice(&mut input)
                    .ok_or_else(|| Error::Corruption(format!("manifest: bad tag {tag}")))?;
            }
            TAG_WAL_ADDITION | TAG_WAL_DELETION => {
                return Err(Error::Unsupported(format!(
                    "manifest: legacy non-length-prefixed WAL tag {tag}"
                )));
            }
            other => {
                if (other & TAG_SAFE_IGNORE_MASK) != 0 {
                    let _ = get_length_prefixed_slice(&mut input).ok_or_else(|| {
                        Error::Corruption(format!("manifest: bad safe-ignore tag {other}"))
                    })?;
                } else {
                    return Err(Error::Unsupported(format!(
                        "manifest: unknown non-ignorable tag {other}"
                    )));
                }
            }
        }
    }

    Ok(edit)
}

fn decode_new_file4(
    input: &mut &[u8],
    min_log_number_to_keep: &mut Option<u64>,
) -> Result<SstFileMeta> {
    let level = get_varint32(input)
        .ok_or_else(|| Error::Corruption("manifest: bad new_file4 level".into()))?;
    let number = get_varint64(input)
        .ok_or_else(|| Error::Corruption("manifest: bad new_file4 number".into()))?;
    let file_size = get_varint64(input)
        .ok_or_else(|| Error::Corruption("manifest: bad new_file4 size".into()))?;
    let smallest_raw = get_length_prefixed_slice(input)
        .ok_or_else(|| Error::Corruption("manifest: bad new_file4 smallest".into()))?;
    let largest_raw = get_length_prefixed_slice(input)
        .ok_or_else(|| Error::Corruption("manifest: bad new_file4 largest".into()))?;
    let smallest_seqno = get_varint64(input)
        .ok_or_else(|| Error::Corruption("manifest: bad new_file4 smallest_seqno".into()))?;
    let largest_seqno = get_varint64(input)
        .ok_or_else(|| Error::Corruption("manifest: bad new_file4 largest_seqno".into()))?;

    let mut oldest_blob_file_number = 0u64;
    let mut epoch_number = 0u64;

    loop {
        let custom_tag = get_varint32(input)
            .ok_or_else(|| Error::Corruption("manifest: bad new_file4 custom tag".into()))?;
        if custom_tag == CUSTOM_TERMINATE {
            break;
        }
        let mut field = get_length_prefixed_slice(input)
            .ok_or_else(|| Error::Corruption("manifest: bad new_file4 custom field".into()))?;
        match custom_tag {
            CUSTOM_MIN_LOG_NUMBER_TO_KEEP_HACK => {
                let v = get_fixed64(&mut field)
                    .ok_or_else(|| Error::Corruption("manifest: bad min_log_keep hack".into()))?;
                *min_log_number_to_keep = Some(v);
            }
            CUSTOM_OLDEST_BLOB_FILE_NUMBER => {
                oldest_blob_file_number = get_varint64(&mut field).ok_or_else(|| {
                    Error::Corruption("manifest: bad oldest_blob_file_number".into())
                })?;
            }
            CUSTOM_EPOCH_NUMBER => {
                epoch_number = get_varint64(&mut field)
                    .ok_or_else(|| Error::Corruption("manifest: bad epoch_number".into()))?;
            }
            CUSTOM_PATH_ID => {
                if field.len() != 1 || field[0] != 0 {
                    return Err(Error::Unsupported("non-zero db_paths path_id".into()));
                }
            }
            other => {
                if (other & CUSTOM_NON_SAFE_IGNORE_MASK) != 0 {
                    return Err(Error::Unsupported(format!(
                        "manifest: unsupported non-ignorable custom tag {other}"
                    )));
                }
            }
        }
    }

    Ok(SstFileMeta {
        number,
        level,
        file_size,
        smallest: InternalKey::from_encoded(smallest_raw)?,
        largest: InternalKey::from_encoded(largest_raw)?,
        smallest_seqno,
        largest_seqno,
        oldest_blob_file_number,
        epoch_number,
    })
}

fn decode_blob_addition(input: &mut &[u8]) -> Result<BlobAdditionEdit> {
    let number = get_varint64(input)
        .ok_or_else(|| Error::Corruption("blob_addition: bad file number".into()))?;
    let total_blob_count =
        get_varint64(input).ok_or_else(|| Error::Corruption("blob_addition: bad count".into()))?;
    let total_blob_bytes =
        get_varint64(input).ok_or_else(|| Error::Corruption("blob_addition: bad bytes".into()))?;
    let _checksum_method = get_length_prefixed_slice(input)
        .ok_or_else(|| Error::Corruption("blob_addition: bad checksum_method".into()))?;
    let _checksum_value = get_length_prefixed_slice(input)
        .ok_or_else(|| Error::Corruption("blob_addition: bad checksum_value".into()))?;
    skip_blob_custom_fields(input, "blob_addition")?;
    Ok(BlobAdditionEdit {
        number,
        total_blob_count,
        total_blob_bytes,
    })
}

fn decode_blob_garbage(input: &mut &[u8]) -> Result<BlobGarbageEdit> {
    let number = get_varint64(input)
        .ok_or_else(|| Error::Corruption("blob_garbage: bad file number".into()))?;
    let garbage_blob_count =
        get_varint64(input).ok_or_else(|| Error::Corruption("blob_garbage: bad count".into()))?;
    let garbage_blob_bytes =
        get_varint64(input).ok_or_else(|| Error::Corruption("blob_garbage: bad bytes".into()))?;
    skip_blob_custom_fields(input, "blob_garbage")?;
    Ok(BlobGarbageEdit {
        number,
        garbage_blob_count,
        garbage_blob_bytes,
    })
}

fn skip_blob_custom_fields(input: &mut &[u8], label: &str) -> Result<()> {
    loop {
        let tag = get_varint32(input)
            .ok_or_else(|| Error::Corruption(format!("{label}: bad custom tag")))?;
        if tag == 0 {
            break;
        }
        if (tag & (1 << 6)) != 0 {
            return Err(Error::Unsupported(format!(
                "{label}: incompatible custom field {tag}"
            )));
        }
        let _ = get_length_prefixed_slice(input)
            .ok_or_else(|| Error::Corruption(format!("{label}: bad custom field value")))?;
    }
    Ok(())
}
