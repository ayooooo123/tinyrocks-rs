//! RocksDB internal keys (`user_key || packed_seq_and_type`) and ordering.

use std::cmp::Ordering;

use crate::{Error, Result};

pub const MAX_SEQUENCE_NUMBER: u64 = (1u64 << 56) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ValueType {
    Deletion = 0x0,
    Value = 0x1,
    Merge = 0x2,
    LogData = 0x3,
    ColumnFamilyDeletion = 0x4,
    ColumnFamilyValue = 0x5,
    ColumnFamilyMerge = 0x6,
    SingleDeletion = 0x7,
    ColumnFamilySingleDeletion = 0x8,
    ColumnFamilyRangeDeletion = 0x0e,
    RangeDeletion = 0x0f,
    ColumnFamilyBlobIndex = 0x10,
    BlobIndex = 0x11,
    Unknown = 0xff,
}

impl ValueType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x0 => Self::Deletion,
            0x1 => Self::Value,
            0x2 => Self::Merge,
            0x3 => Self::LogData,
            0x4 => Self::ColumnFamilyDeletion,
            0x5 => Self::ColumnFamilyValue,
            0x6 => Self::ColumnFamilyMerge,
            0x7 => Self::SingleDeletion,
            0x8 => Self::ColumnFamilySingleDeletion,
            0x0e => Self::ColumnFamilyRangeDeletion,
            0x0f => Self::RangeDeletion,
            0x10 => Self::ColumnFamilyBlobIndex,
            0x11 => Self::BlobIndex,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedInternalKey<'a> {
    pub user_key: &'a [u8],
    pub seqno: u64,
    pub value_type: ValueType,
}

impl<'a> ParsedInternalKey<'a> {
    pub fn parse(internal_key: &'a [u8]) -> Result<Self> {
        if internal_key.len() < 8 {
            return Err(Error::Corruption(format!(
                "internal key too short ({} bytes)",
                internal_key.len()
            )));
        }
        let split = internal_key.len() - 8;
        let trailer = u64::from_le_bytes(internal_key[split..].try_into().unwrap());
        let value_type = ValueType::from_u8((trailer & 0xff) as u8);
        let seqno = trailer >> 8;
        Ok(Self {
            user_key: &internal_key[..split],
            seqno,
            value_type,
        })
    }
}

/// Owned internal key ordered by RocksDB's default bytewise `InternalKeyComparator`:
/// `user_key` ascending, then `(seqno << 8 | value_type)` descending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalKey {
    pub user_key: Vec<u8>,
    pub seqno: u64,
    pub value_type: ValueType,
}

impl InternalKey {
    pub fn new(user_key: Vec<u8>, seqno: u64, value_type: ValueType) -> Self {
        Self {
            user_key,
            seqno,
            value_type,
        }
    }

    pub fn from_encoded(bytes: &[u8]) -> Result<Self> {
        let p = ParsedInternalKey::parse(bytes)?;
        Ok(Self {
            user_key: p.user_key.to_vec(),
            seqno: p.seqno,
            value_type: p.value_type,
        })
    }

    pub fn trailer(&self) -> u64 {
        (self.seqno << 8) | (self.value_type as u64)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.user_key.len() + 8);
        out.extend_from_slice(&self.user_key);
        out.extend_from_slice(&self.trailer().to_le_bytes());
        out
    }
}

impl Ord for InternalKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.user_key
            .cmp(&other.user_key)
            .then_with(|| other.trailer().cmp(&self.trailer()))
    }
}

impl PartialOrd for InternalKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Compares two raw encoded internal keys under bytewise `InternalKeyComparator`.
pub fn compare_internal_keys(a: &[u8], b: &[u8]) -> Ordering {
    if a.len() < 8 || b.len() < 8 {
        return a.cmp(b);
    }
    let a_split = a.len() - 8;
    let b_split = b.len() - 8;
    match a[..a_split].cmp(&b[..b_split]) {
        Ordering::Equal => {
            let ta = u64::from_le_bytes(a[a_split..].try_into().unwrap());
            let tb = u64::from_le_bytes(b[b_split..].try_into().unwrap());
            tb.cmp(&ta)
        }
        ord => ord,
    }
}
