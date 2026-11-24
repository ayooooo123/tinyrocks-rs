//! RocksDB WAL (`WriteBatch`) decoder for replaying unflushed writes on open.

use std::collections::BTreeMap;

use crate::coding::{
    get_length_prefixed_slice, get_varint32, put_length_prefixed_slice, put_varint32,
};
use crate::keys::{InternalKey, ValueType};
use crate::log;
use crate::range_del::RangeTombstone;
use crate::{Error, Result};

const WRITE_BATCH_HEADER_SIZE: usize = 12;

#[derive(Debug, Clone)]
pub enum BatchOp {
    Put { cf_id: u32, key: Vec<u8>, value: Vec<u8> },
    Delete { cf_id: u32, key: Vec<u8> },
    DeleteRange { cf_id: u32, start: Vec<u8>, end: Vec<u8> },
}

/// Encodes a RocksDB `WriteBatch` payload starting at `first_seqno`.
pub fn encode_write_batch(first_seqno: u64, ops: &[BatchOp]) -> Vec<u8> {
    let mut out = Vec::with_capacity(WRITE_BATCH_HEADER_SIZE + ops.len() * 32);
    out.extend_from_slice(&first_seqno.to_le_bytes());
    out.extend_from_slice(&(ops.len() as u32).to_le_bytes());
    for op in ops {
        match op {
            BatchOp::Put { cf_id, key, value } => {
                if *cf_id == 0 {
                    out.push(ValueType::Value as u8);
                } else {
                    out.push(ValueType::ColumnFamilyValue as u8);
                    put_varint32(&mut out, *cf_id);
                }
                put_length_prefixed_slice(&mut out, key);
                put_length_prefixed_slice(&mut out, value);
            }
            BatchOp::Delete { cf_id, key } => {
                if *cf_id == 0 {
                    out.push(ValueType::Deletion as u8);
                } else {
                    out.push(ValueType::ColumnFamilyDeletion as u8);
                    put_varint32(&mut out, *cf_id);
                }
                put_length_prefixed_slice(&mut out, key);
            }
            BatchOp::DeleteRange { cf_id, start, end } => {
                if *cf_id == 0 {
                    out.push(ValueType::RangeDeletion as u8);
                } else {
                    out.push(ValueType::ColumnFamilyRangeDeletion as u8);
                    put_varint32(&mut out, *cf_id);
                }
                put_length_prefixed_slice(&mut out, start);
                put_length_prefixed_slice(&mut out, end);
            }
        }
    }
    out
}

#[derive(Debug, Clone)]
pub enum MemValue {
    Value(Vec<u8>),
    Deletion,
}

#[derive(Debug, Default)]
pub struct MemTable {
    pub entries: BTreeMap<InternalKey, MemValue>,
    pub range_dels: Vec<RangeTombstone>,
}

/// Replays one WAL file into `memtable`, keeping only ops targeting `target_cf`.
pub fn replay_wal_file(
    data: &[u8],
    target_cf: u32,
    memtable: &mut MemTable,
    max_seqno: &mut u64,
) -> Result<()> {
    let records = log::read_records(data, true)?;
    for rec in records {
        if rec.len() < WRITE_BATCH_HEADER_SIZE {
            return Err(Error::Corruption("wal: WriteBatch shorter than 12 bytes".into()));
        }
        let mut seqno = u64::from_le_bytes(rec[0..8].try_into().unwrap());
        let count = u32::from_le_bytes(rec[8..12].try_into().unwrap());
        let mut input = &rec[WRITE_BATCH_HEADER_SIZE..];

        for _ in 0..count {
            if input.is_empty() {
                return Err(Error::Corruption("wal: truncated WriteBatch record".into()));
            }
            let tag = ValueType::from_u8(input[0]);
            input = &input[1..];
            let mut cf_id = 0u32;

            match tag {
                ValueType::ColumnFamilyValue => {
                    cf_id = get_varint32(&mut input)
                        .ok_or_else(|| Error::Corruption("wal: bad cf id".into()))?;
                    let key = get_length_prefixed_slice(&mut input)
                        .ok_or_else(|| Error::Corruption("wal: bad put key".into()))?;
                    let val = get_length_prefixed_slice(&mut input)
                        .ok_or_else(|| Error::Corruption("wal: bad put val".into()))?;
                    if cf_id == target_cf {
                        memtable.entries.insert(
                            InternalKey::new(key.to_vec(), seqno, ValueType::Value),
                            MemValue::Value(val.to_vec()),
                        );
                    }
                }
                ValueType::Value => {
                    let key = get_length_prefixed_slice(&mut input)
                        .ok_or_else(|| Error::Corruption("wal: bad put key".into()))?;
                    let val = get_length_prefixed_slice(&mut input)
                        .ok_or_else(|| Error::Corruption("wal: bad put val".into()))?;
                    if cf_id == target_cf {
                        memtable.entries.insert(
                            InternalKey::new(key.to_vec(), seqno, ValueType::Value),
                            MemValue::Value(val.to_vec()),
                        );
                    }
                }
                ValueType::ColumnFamilyDeletion | ValueType::ColumnFamilySingleDeletion => {
                    cf_id = get_varint32(&mut input)
                        .ok_or_else(|| Error::Corruption("wal: bad del cf id".into()))?;
                    let key = get_length_prefixed_slice(&mut input)
                        .ok_or_else(|| Error::Corruption("wal: bad del key".into()))?;
                    if cf_id == target_cf {
                        memtable.entries.insert(
                            InternalKey::new(key.to_vec(), seqno, ValueType::Deletion),
                            MemValue::Deletion,
                        );
                    }
                }
                ValueType::Deletion | ValueType::SingleDeletion => {
                    let key = get_length_prefixed_slice(&mut input)
                        .ok_or_else(|| Error::Corruption("wal: bad del key".into()))?;
                    if cf_id == target_cf {
                        memtable.entries.insert(
                            InternalKey::new(key.to_vec(), seqno, ValueType::Deletion),
                            MemValue::Deletion,
                        );
                    }
                }
                ValueType::ColumnFamilyRangeDeletion => {
                    cf_id = get_varint32(&mut input)
                        .ok_or_else(|| Error::Corruption("wal: bad range_del cf id".into()))?;
                    let start = get_length_prefixed_slice(&mut input)
                        .ok_or_else(|| Error::Corruption("wal: bad range_del start".into()))?;
                    let end = get_length_prefixed_slice(&mut input)
                        .ok_or_else(|| Error::Corruption("wal: bad range_del end".into()))?;
                    if cf_id == target_cf {
                        memtable.range_dels.push(RangeTombstone {
                            start: start.to_vec(),
                            end: end.to_vec(),
                            seqno,
                        });
                    }
                }
                ValueType::RangeDeletion => {
                    let start = get_length_prefixed_slice(&mut input)
                        .ok_or_else(|| Error::Corruption("wal: bad range_del start".into()))?;
                    let end = get_length_prefixed_slice(&mut input)
                        .ok_or_else(|| Error::Corruption("wal: bad range_del end".into()))?;
                    if cf_id == target_cf {
                        memtable.range_dels.push(RangeTombstone {
                            start: start.to_vec(),
                            end: end.to_vec(),
                            seqno,
                        });
                    }
                }
                ValueType::LogData => {
                    let _ = get_length_prefixed_slice(&mut input)
                        .ok_or_else(|| Error::Corruption("wal: bad log_data".into()))?;
                    // LogData does not consume a sequence number.
                    continue;
                }
                other => {
                    return Err(Error::Unsupported(format!(
                        "wal: unsupported WriteBatch record type {other:?}"
                    )));
                }
            }

            if seqno > *max_seqno {
                *max_seqno = seqno;
            }
            seqno += 1;
        }
    }
    Ok(())
}
