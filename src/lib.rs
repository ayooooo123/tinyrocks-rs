//! Minimal pure-Rust storage engine compatible with RocksDB 10.x's on-disk format.
//!
//! Targets the exact subset used by `hypercore-storage-rs` (column family `corestore`,
//! `BlockBasedTable` format v0..v6, XXH3/CRC32C checksums, Snappy read fallback,
//! integrated BlobDB `.blob` files, range tombstones, WAL, and MANIFEST).

pub mod blob;
pub mod bloom;
pub mod coding;
pub mod keys;
pub mod log;
pub mod manifest;
pub mod manifest_writer;
pub mod range_del;
pub mod reader;
pub mod snappy;
pub mod sst;
pub mod sst_writer;
pub mod wal;

use std::fmt;

pub use reader::{Db, ScanDirection, WriteBatch};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Corruption(String),
    Unsupported(String),
    NotFound(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Corruption(m) => write!(f, "corruption: {m}"),
            Self::Unsupported(m) => write!(f, "unsupported: {m}"),
            Self::NotFound(m) => write!(f, "not found: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
