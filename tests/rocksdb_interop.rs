//! Oracle tests: write real RocksDB 10.4.2 databases with `hypercore-storage-rs`'s exact
//! options, then open and verify every read, scan, tombstone, WAL record, and BlobDB value
//! with `tinyrocks`.

use rocksdb::{
    BlockBasedOptions, ChecksumType, DB, DBCompressionType, IteratorMode, Options, ReadOptions,
    WriteBatch,
};
use tinyrocks::{Db, ScanDirection};

const CF: &str = "corestore";

fn open_rocks(path: &std::path::Path, compression: DBCompressionType) -> DB {
    let mut table = BlockBasedOptions::default();
    table.set_block_size(8192);
    table.set_format_version(6);
    table.set_cache_index_and_filter_blocks(true);
    table.set_bloom_filter(10.0, true);
    table.set_checksum_type(ChecksumType::XXH3);

    let mut cf_opts = Options::default();
    cf_opts.set_block_based_table_factory(&table);
    cf_opts.set_num_levels(7);
    cf_opts.set_compression_type(compression);
    cf_opts.set_enable_blob_files(true);
    cf_opts.set_min_blob_size(4096);
    cf_opts.set_blob_file_size(256 * 1024 * 1024);
    cf_opts.set_enable_blob_gc(true);
    cf_opts.set_blob_compression_type(compression);

    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);

    DB::open_cf_with_opts(&db_opts, path, [(CF, cf_opts)]).unwrap()
}

#[test]
fn reads_format_v6_ssts_blobs_wal_deletes_and_range_deletes() {
    let dir = tempfile::tempdir().unwrap();
    let big_block_a = vec![0xab; 512 * 1024];
    let big_block_b = vec![0xcd; 64 * 1024];

    {
        let db = open_rocks(dir.path(), DBCompressionType::None);
        let cf = db.cf_handle(CF).unwrap();

        // Batch 1 -> flushed to SST + .blob
        let mut batch = WriteBatch::default();
        for i in 0u32..400 {
            let k = format!("meta/{i:04}");
            let v = format!("val-{i:04}");
            batch.put_cf(cf, k.as_bytes(), v.as_bytes());
        }
        batch.put_cf(cf, b"blob/video0", &big_block_a);
        batch.put_cf(cf, b"blob/video1", &big_block_b);
        db.write(batch).unwrap();
        db.flush_cf(cf).unwrap();

        // Batch 2 -> range delete + point delete + overwrite + re-insert inside deleted range, flushed to L0
        let mut batch2 = WriteBatch::default();
        batch2.delete_range_cf(cf, b"meta/0100", b"meta/0250");
        batch2.delete_cf(cf, b"meta/0010");
        batch2.put_cf(cf, b"meta/0005", b"updated-5");
        batch2.put_cf(cf, b"meta/0150", b"resurrected-150");
        db.write(batch2).unwrap();
        db.flush_cf(cf).unwrap();

        // Compact into deeper levels, then add one more unflushed WAL-only batch!
        db.compact_range_cf(cf, None::<&[u8]>, None::<&[u8]>);

        let mut wal_batch = WriteBatch::default();
        wal_batch.put_cf(cf, b"meta/0200", b"wal-resurrected-200");
        wal_batch.delete_cf(cf, b"meta/0001");
        wal_batch.delete_range_cf(cf, b"meta/0300", b"meta/0320");
        wal_batch.put_cf(cf, b"wal/fresh", b"only-in-wal");
        db.write(wal_batch).unwrap();
        db.flush_wal(true).unwrap();
        // Close cleanly (RocksDB flushes on drop or leaves WAL; either way verify against RocksDB's own view).
    }

    // Collect ground truth from real RocksDB.
    let (expected_all, expected_sub_rev, rocks_blob_live, rocks_blob_garb) = {
        let db = open_rocks(dir.path(), DBCompressionType::None);
        let cf = db.cf_handle(CF).unwrap();
        let all: Vec<(Vec<u8>, Vec<u8>)> = db
            .iterator_cf(cf, IteratorMode::Start)
            .map(|r| {
                let (k, v) = r.unwrap();
                (k.to_vec(), v.to_vec())
            })
            .collect();

        let mut ro = ReadOptions::default();
        ro.set_iterate_lower_bound(b"meta/0090".to_vec());
        ro.set_iterate_upper_bound(b"meta/0210".to_vec());
        let sub_rev: Vec<(Vec<u8>, Vec<u8>)> = db
            .iterator_cf_opt(cf, ro, IteratorMode::End)
            .map(|r| {
                let (k, v) = r.unwrap();
                (k.to_vec(), v.to_vec())
            })
            .collect();

        let live = db
            .property_int_value_cf(cf, "rocksdb.live-blob-file-size")
            .unwrap()
            .unwrap_or(0);
        let garb = db
            .property_int_value_cf(cf, "rocksdb.live-blob-file-garbage-size")
            .unwrap()
            .unwrap_or(0);
        (all, sub_rev, live, garb)
    };

    // Open with pure-Rust tinyrocks and compare EVERYTHING bit-for-bit!
    let tiny = Db::open_read_only(dir.path()).unwrap();

    // Point lookups: live, updated, deleted, range-deleted, resurrected, WAL, and 512 KiB blob.
    assert_eq!(
        tiny.get_cf(CF, b"meta/0000").unwrap().as_deref(),
        Some(b"val-0000".as_slice())
    );
    assert_eq!(tiny.get_cf(CF, b"meta/0001").unwrap(), None);
    assert_eq!(
        tiny.get_cf(CF, b"meta/0005").unwrap().as_deref(),
        Some(b"updated-5".as_slice())
    );
    assert_eq!(tiny.get_cf(CF, b"meta/0010").unwrap(), None);
    assert_eq!(tiny.get_cf(CF, b"meta/0120").unwrap(), None);
    assert_eq!(
        tiny.get_cf(CF, b"meta/0150").unwrap().as_deref(),
        Some(b"resurrected-150".as_slice())
    );
    assert_eq!(
        tiny.get_cf(CF, b"meta/0200").unwrap().as_deref(),
        Some(b"wal-resurrected-200".as_slice())
    );
    assert_eq!(tiny.get_cf(CF, b"meta/0310").unwrap(), None);
    assert_eq!(
        tiny.get_cf(CF, b"wal/fresh").unwrap().as_deref(),
        Some(b"only-in-wal".as_slice())
    );
    assert_eq!(
        tiny.get_cf(CF, b"blob/video0").unwrap().unwrap(),
        big_block_a
    );
    assert_eq!(
        tiny.get_cf(CF, b"blob/video1").unwrap().unwrap(),
        big_block_b
    );

    // Full forward scan matches real RocksDB byte-for-byte.
    let got_all = tiny
        .scan_cf(CF, None, None, ScanDirection::Forward)
        .unwrap();
    assert_eq!(got_all, expected_all);

    // Bounded reverse scan matches real RocksDB byte-for-byte.
    let got_sub_rev = tiny
        .scan_cf(
            CF,
            Some(b"meta/0090"),
            Some(b"meta/0210"),
            ScanDirection::Reverse,
        )
        .unwrap();
    assert_eq!(got_sub_rev, expected_sub_rev);

    // Blob stats match RocksDB's reported live blob file size & garbage size.
    assert_eq!(tiny.live_blob_file_size(CF).unwrap(), rocks_blob_live);
    assert_eq!(
        tiny.live_blob_file_garbage_size(CF).unwrap(),
        rocks_blob_garb
    );
}

#[test]
fn reads_snappy_compressed_ssts_and_blobs() {
    let dir = tempfile::tempdir().unwrap();
    let repeated_blob = b"peartube-snappy-compressible-video-chunk-".repeat(2000);

    {
        let db = open_rocks(dir.path(), DBCompressionType::Snappy);
        let cf = db.cf_handle(CF).unwrap();
        for i in 0u32..500 {
            let k = format!("k/{i:05}");
            let v = format!("repeated-payload-for-snappy-compression-{i:05}-xxxxxxxxxxxx");
            db.put_cf(cf, k.as_bytes(), v.as_bytes()).unwrap();
        }
        db.put_cf(cf, b"blob/snappy", &repeated_blob).unwrap();
        db.flush_cf(cf).unwrap();
    }

    let tiny = Db::open_read_only(dir.path()).unwrap();
    assert_eq!(
        tiny.get_cf(CF, b"k/00250").unwrap().as_deref(),
        Some(b"repeated-payload-for-snappy-compression-00250-xxxxxxxxxxxx".as_slice())
    );
    assert_eq!(
        tiny.get_cf(CF, b"blob/snappy").unwrap().unwrap(),
        repeated_blob
    );
}

#[test]
fn tinyrocks_writes_and_real_rocksdb_reads_roundtrips_and_compacts_blobs() {
    let dir = tempfile::tempdir().unwrap();
    let blob_a = vec![0x11u8; 512 * 1024];
    let blob_b = vec![0x22u8; 512 * 1024];

    // Turn 1: tinyrocks creates a brand-new DB, writes small keys + two 512 KiB blobs +
    // point/range deletes, flushes SST + .blob, and leaves one unflushed WAL batch.
    {
        let mut db = Db::open_rw(dir.path(), &[CF]).unwrap();
        let cf = db.cf_id(CF).unwrap();

        let mut b1 = tinyrocks::WriteBatch::default();
        for i in 0u32..300 {
            b1.put_cf(
                cf,
                format!("row/{i:04}").as_bytes(),
                format!("v-{i:04}").as_bytes(),
            );
        }
        b1.put_cf(cf, b"vid/a", &blob_a);
        b1.put_cf(cf, b"vid/b", &blob_b);
        db.write_batch(&b1, false).unwrap();
        db.flush_cf(CF).unwrap();

        let mut b2 = tinyrocks::WriteBatch::default();
        b2.delete_cf(cf, b"row/0007");
        b2.delete_range_cf(cf, b"row/0100", b"row/0150");
        b2.put_cf(cf, b"row/0125", b"reborn-125");
        db.write_batch(&b2, false).unwrap();
        db.flush_cf(CF).unwrap();

        let mut wal_only = tinyrocks::WriteBatch::default();
        wal_only.put_cf(cf, b"wal/from-tiny", b"survived-into-rocksdb");
        db.write_batch(&wal_only, false).unwrap();
        db.flush_wal(true).unwrap();
    }

    // Turn 2: Real RocksDB 10.4.2 opens tinyrocks's directory, verifies EVERY key & blob,
    // then deletes vid/a, adds new keys, flushes, and closes.
    {
        let db = open_rocks(dir.path(), DBCompressionType::None);
        let cf = db.cf_handle(CF).unwrap();

        assert_eq!(
            db.get_cf(cf, b"row/0000").unwrap().as_deref(),
            Some(b"v-0000".as_slice())
        );
        assert_eq!(db.get_cf(cf, b"row/0007").unwrap(), None);
        assert_eq!(db.get_cf(cf, b"row/0110").unwrap(), None);
        assert_eq!(
            db.get_cf(cf, b"row/0125").unwrap().as_deref(),
            Some(b"reborn-125".as_slice())
        );
        assert_eq!(
            db.get_cf(cf, b"wal/from-tiny").unwrap().as_deref(),
            Some(b"survived-into-rocksdb".as_slice())
        );
        assert_eq!(db.get_cf(cf, b"vid/a").unwrap().unwrap(), blob_a);
        assert_eq!(db.get_cf(cf, b"vid/b").unwrap().unwrap(), blob_b);

        // RocksDB writes back into the same directory!
        db.delete_cf(cf, b"vid/a").unwrap();
        db.put_cf(cf, b"from-rocks/hello", b"world").unwrap();
        db.flush_cf(cf).unwrap();
    }

    // Turn 3: tinyrocks reopens, runs full compaction with blob relocation (reclaiming vid/a's 512 KiB).
    {
        let mut db = Db::open_rw(dir.path(), &[CF]).unwrap();
        assert_eq!(db.get_cf(CF, b"vid/a").unwrap(), None);
        assert_eq!(db.get_cf(CF, b"vid/b").unwrap().unwrap(), blob_b);
        assert_eq!(
            db.get_cf(CF, b"from-rocks/hello").unwrap().as_deref(),
            Some(b"world".as_slice())
        );

        db.compact_cf(CF, true).unwrap();
        assert_eq!(db.get_cf(CF, b"vid/a").unwrap(), None);
        assert_eq!(db.get_cf(CF, b"vid/b").unwrap().unwrap(), blob_b);
    }

    // Verify on-disk .blob bytes actually shrank below 600 KiB (vid/a's 512 KiB reclaimed!).
    let blob_disk_bytes: u64 = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "blob"))
        .map(|e| e.metadata().unwrap().len())
        .sum();
    assert!(
        blob_disk_bytes >= 512 * 1024 && blob_disk_bytes < 600 * 1024,
        "expected ~512 KiB of surviving blob bytes, got {blob_disk_bytes}"
    );

    // Turn 4: Real RocksDB 10.4.2 opens the compacted DB one more time and verifies everything!
    {
        let db = open_rocks(dir.path(), DBCompressionType::None);
        let cf = db.cf_handle(CF).unwrap();
        assert_eq!(db.get_cf(cf, b"vid/a").unwrap(), None);
        assert_eq!(db.get_cf(cf, b"vid/b").unwrap().unwrap(), blob_b);
        assert_eq!(
            db.get_cf(cf, b"from-rocks/hello").unwrap().as_deref(),
            Some(b"world".as_slice())
        );
        assert_eq!(
            db.get_cf(cf, b"row/0125").unwrap().as_deref(),
            Some(b"reborn-125".as_slice())
        );
        assert_eq!(db.get_cf(cf, b"row/0110").unwrap(), None);
    }
}

#[test]
fn differential_fuzz_against_real_rocksdb() {
    let dir_rocks = tempfile::tempdir().unwrap();
    let dir_tiny = tempfile::tempdir().unwrap();

    let mut rocks = Some(open_rocks(dir_rocks.path(), DBCompressionType::None));
    let mut tiny = Some(Db::open_rw(dir_tiny.path(), &[CF]).unwrap());

    // Deterministic xorshift64 PRNG so failures reproduce identically.
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next_u64 = || -> u64 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    let key_space = 250u32;
    for step in 0..2000u32 {
        let op = next_u64() % 100;
        let rdb = rocks.as_ref().unwrap();
        let rcf = rdb.cf_handle(CF).unwrap();
        let tdb = tiny.as_mut().unwrap();
        let tcf = tdb.cf_id(CF).unwrap();

        if op < 52 {
            // Put (20% large >= 4 KiB blobs, 80% small rows)
            let k_idx = (next_u64() % key_space as u64) as u32;
            let key = format!("k/{k_idx:04}");
            let val = if op < 10 {
                let len = 4096 + (next_u64() % 12_000) as usize;
                vec![(step & 0xff) as u8; len]
            } else {
                format!("v-{step}-{k_idx}").into_bytes()
            };
            rdb.put_cf(rcf, key.as_bytes(), &val).unwrap();
            let mut b = tinyrocks::WriteBatch::default();
            b.put_cf(tcf, key.as_bytes(), &val);
            tdb.write_batch(&b, false).unwrap();
        } else if op < 68 {
            // Point delete
            let k_idx = (next_u64() % key_space as u64) as u32;
            let key = format!("k/{k_idx:04}");
            rdb.delete_cf(rcf, key.as_bytes()).unwrap();
            let mut b = tinyrocks::WriteBatch::default();
            b.delete_cf(tcf, key.as_bytes());
            tdb.write_batch(&b, false).unwrap();
        } else if op < 80 {
            // Range delete
            let a = (next_u64() % key_space as u64) as u32;
            let b_raw = (next_u64() % key_space as u64) as u32;
            let (lo, hi) = if a <= b_raw {
                (a, b_raw + 1)
            } else {
                (b_raw, a + 1)
            };
            let ks = format!("k/{lo:04}");
            let ke = format!("k/{hi:04}");
            let mut rb = WriteBatch::default();
            rb.delete_range_cf(rcf, ks.as_bytes(), ke.as_bytes());
            rdb.write(rb).unwrap();
            let mut tb = tinyrocks::WriteBatch::default();
            tb.delete_range_cf(tcf, ks.as_bytes(), ke.as_bytes());
            tdb.write_batch(&tb, false).unwrap();
        } else if op < 92 {
            // Frequent flushes to exercise auto L0 -> L1 compaction + Bloom filters
            rdb.flush_cf(rcf).unwrap();
            tdb.flush_cf(CF).unwrap();
        } else if op < 96 {
            // Compact (alternating relocate_blobs)
            rdb.compact_range_cf(rcf, None::<&[u8]>, None::<&[u8]>);
            tdb.compact_cf(CF, step % 2 == 0).unwrap();
        } else {
            // Close & reopen both engines
            drop(rocks.take());
            drop(tiny.take());
            rocks = Some(open_rocks(dir_rocks.path(), DBCompressionType::None));
            tiny = Some(Db::open_rw(dir_tiny.path(), &[CF]).unwrap());
        }

        // Every 100 steps, assert bit-for-bit equality across the entire key space (hits & misses).
        if step % 100 == 99 {
            let rdb = rocks.as_ref().unwrap();
            let rcf = rdb.cf_handle(CF).unwrap();
            let tdb = tiny.as_ref().unwrap();
            let r_all: Vec<(Vec<u8>, Vec<u8>)> = rdb
                .iterator_cf(rcf, IteratorMode::Start)
                .map(|r| {
                    let (k, v) = r.unwrap();
                    (k.to_vec(), v.to_vec())
                })
                .collect();
            let t_all = tdb.scan_cf(CF, None, None, ScanDirection::Forward).unwrap();
            assert_eq!(t_all, r_all, "full scan diverged at step {step}");
            for i in 0..key_space {
                let k = format!("k/{i:04}");
                assert_eq!(
                    tdb.get_cf(CF, k.as_bytes()).unwrap(),
                    rdb.get_cf(rcf, k.as_bytes()).unwrap(),
                    "point get diverged for {k} at step {step}"
                );
            }
        }
    }

    // Finally, close tinyrocks and prove REAL RocksDB 10.4.2 opens tinyrocks's directory
    // and reads the EXACT same state as the reference RocksDB!
    drop(tiny.take());
    let r_ref = rocks.as_ref().unwrap();
    let r_ref_all: Vec<(Vec<u8>, Vec<u8>)> = r_ref
        .iterator_cf(r_ref.cf_handle(CF).unwrap(), IteratorMode::Start)
        .map(|r| {
            let (k, v) = r.unwrap();
            (k.to_vec(), v.to_vec())
        })
        .collect();

    let r_opened_tiny = open_rocks(dir_tiny.path(), DBCompressionType::None);
    let r_tiny_all: Vec<(Vec<u8>, Vec<u8>)> = r_opened_tiny
        .iterator_cf(r_opened_tiny.cf_handle(CF).unwrap(), IteratorMode::Start)
        .map(|r| {
            let (k, v) = r.unwrap();
            (k.to_vec(), v.to_vec())
        })
        .collect();
    assert_eq!(r_tiny_all, r_ref_all);
}

#[test]
fn bloom_filter_interop_bidirectional() {
    // 1. RocksDB 10.4.2 writes FastLocalBloom (10 bpk) across short, mid, and long (>240B) keys;
    //    tinyrocks probes it directly with 0 false negatives and ~1% false positives.
    let dir_r = tempfile::tempdir().unwrap();
    let keys: Vec<Vec<u8>> = (0..1000u32)
        .map(|i| match i % 5 {
            0 => vec![(i & 0xff) as u8, ((i >> 8) & 0xff) as u8], // len 2
            1 => format!("k{i:04}").into_bytes(),                 // len 5
            2 => format!("medium-key-{i:06}").into_bytes(),       // len 17
            3 => format!("midsize-key-{i:06}-{}", "x".repeat(140)).into_bytes(), // len 159
            _ => format!("long-key-{i:06}-{}", "y".repeat(320)).into_bytes(), // len 336
        })
        .collect();
    {
        let db = open_rocks(dir_r.path(), DBCompressionType::None);
        let cf = db.cf_handle(CF).unwrap();
        let mut b = WriteBatch::default();
        for (i, k) in keys.iter().enumerate() {
            b.put_cf(cf, k, format!("val-{i}").as_bytes());
        }
        db.write(b).unwrap();
        db.flush_cf(cf).unwrap();
    }

    let sst_path = std::fs::read_dir(dir_r.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "sst"))
        .expect("RocksDB should have flushed an SST");
    let reader = tinyrocks::sst::SstReader::open(&sst_path).unwrap();
    assert!(
        reader.has_filter(),
        "RocksDB SST should carry BuiltinBloomFilter"
    );

    // 0 false negatives across every length tier (2B, 5B, 17B, 159B, 336B).
    for k in &keys {
        assert!(
            reader.filter_may_match(k),
            "false negative on RocksDB bloom filter for key len {}",
            k.len()
        );
    }
    // Check false positive rate on 2,000 absent keys (expected ~1%, require < 4%).
    let mut fps = 0usize;
    for i in 0..2000u32 {
        let miss = format!("absent-probe-key-{i:06}");
        if reader.filter_may_match(miss.as_bytes()) {
            fps += 1;
        }
    }
    assert!(
        fps < 80,
        "RocksDB bloom filter FP rate too high ({fps}/2000) — XXPH3 hash mismatch!"
    );

    // 2. tinyrocks writes FastLocalBloom; real RocksDB 10.4.2 opens and probes it cleanly.
    let dir_t = tempfile::tempdir().unwrap();
    {
        let mut db = Db::open_rw(dir_t.path(), &[CF]).unwrap();
        let cf = db.cf_id(CF).unwrap();
        let mut b = tinyrocks::WriteBatch::default();
        for (i, k) in keys.iter().enumerate() {
            b.put_cf(cf, k, format!("val-{i}").as_bytes());
        }
        db.write_batch(&b, false).unwrap();
        db.flush_cf(CF).unwrap();
    }
    {
        let db = open_rocks(dir_t.path(), DBCompressionType::None);
        let cf = db.cf_handle(CF).unwrap();
        for (i, k) in keys.iter().enumerate() {
            assert_eq!(
                db.get_cf(cf, k).unwrap().as_deref(),
                Some(format!("val-{i}").as_bytes()),
                "RocksDB failed to read key len {} through tinyrocks Bloom filter",
                k.len()
            );
        }
        for i in 0..500u32 {
            assert_eq!(
                db.get_cf(cf, format!("absent-probe-key-{i:06}").as_bytes())
                    .unwrap(),
                None
            );
        }
    }
}

#[test]
fn crash_recovery_truncated_wal_manifest_and_orphan_cleanup() {
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();
    {
        let mut db = Db::open_rw(dir.path(), &[CF]).unwrap();
        let cf = db.cf_id(CF).unwrap();
        let mut b1 = tinyrocks::WriteBatch::default();
        b1.put_cf(cf, b"committed/sst", b"in-sst");
        b1.put_cf(cf, b"committed/blob", &vec![0x77u8; 8192]);
        db.write_batch(&b1, false).unwrap();
        db.flush_cf(CF).unwrap();

        let mut b2 = tinyrocks::WriteBatch::default();
        b2.put_cf(cf, b"committed/wal", b"in-wal");
        db.write_batch(&b2, false).unwrap();
        db.flush_wal(true).unwrap();
    }

    // Simulate power loss: append partial corrupt bytes to active WAL + MANIFEST, and leave
    // uncommitted orphan SST, blob, and CURRENT.tmp files in the directory.
    let mut wal_paths: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "log"))
        .collect();
    wal_paths.sort();
    let active_wal = wal_paths.last().unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(active_wal)
        .unwrap()
        .write_all(&[0xde, 0xad, 0xbe, 0xef, 0x20, 0x00, 0x01, 0x99, 0x88])
        .unwrap();

    let manifest_name = std::fs::read_to_string(dir.path().join("CURRENT"))
        .unwrap()
        .trim()
        .to_string();
    std::fs::OpenOptions::new()
        .append(true)
        .open(dir.path().join(&manifest_name))
        .unwrap()
        .write_all(&[0x12, 0x34, 0x56, 0x78, 0x10, 0x00, 0x01, 0xff])
        .unwrap();

    let orphan_sst = dir.path().join("999901.sst");
    let orphan_blob = dir.path().join("999902.blob");
    let orphan_tmp = dir.path().join("CURRENT.tmp");
    std::fs::write(&orphan_sst, b"uncommitted-sst").unwrap();
    std::fs::write(&orphan_blob, b"uncommitted-blob").unwrap();
    std::fs::write(&orphan_tmp, b"MANIFEST-999999\n").unwrap();

    // Reopen with tinyrocks: recovers committed SST + WAL, repairs MANIFEST tail, unlinks orphans.
    {
        let mut db = Db::open_rw(dir.path(), &[CF]).unwrap();
        assert_eq!(
            db.get_cf(CF, b"committed/sst").unwrap().as_deref(),
            Some(b"in-sst".as_slice())
        );
        assert_eq!(
            db.get_cf(CF, b"committed/blob").unwrap().unwrap(),
            vec![0x77u8; 8192]
        );
        assert_eq!(
            db.get_cf(CF, b"committed/wal").unwrap().as_deref(),
            Some(b"in-wal".as_slice())
        );
        assert!(
            !orphan_sst.exists(),
            "orphan SST should be removed on open_rw"
        );
        assert!(
            !orphan_blob.exists(),
            "orphan blob should be removed on open_rw"
        );
        assert!(
            !orphan_tmp.exists(),
            "CURRENT.tmp should be removed on open_rw"
        );

        // Write & flush one more batch to verify repaired MANIFEST accepts subsequent edits.
        let cf = db.cf_id(CF).unwrap();
        let mut b3 = tinyrocks::WriteBatch::default();
        b3.put_cf(cf, b"post/recovery", b"alive");
        db.write_batch(&b3, false).unwrap();
        db.flush_cf(CF).unwrap();
    }

    // Real RocksDB 10.4.2 opens the recovered directory cleanly and sees every key!
    {
        let db = open_rocks(dir.path(), DBCompressionType::None);
        let cf = db.cf_handle(CF).unwrap();
        assert_eq!(
            db.get_cf(cf, b"committed/sst").unwrap().as_deref(),
            Some(b"in-sst".as_slice())
        );
        assert_eq!(
            db.get_cf(cf, b"committed/wal").unwrap().as_deref(),
            Some(b"in-wal".as_slice())
        );
        assert_eq!(
            db.get_cf(cf, b"post/recovery").unwrap().as_deref(),
            Some(b"alive".as_slice())
        );
    }
}

#[test]
fn auto_l0_compaction_triggers_and_stays_compatible() {
    let dir = tempfile::tempdir().unwrap();
    let blob_payload = vec![0x42u8; 16 * 1024];

    {
        let mut db = Db::open_rw(dir.path(), &[CF]).unwrap();
        let cf = db.cf_id(CF).unwrap();
        for batch_idx in 0..12u32 {
            let mut b = tinyrocks::WriteBatch::default();
            for j in 0..20u32 {
                let k = format!("auto/{batch_idx:02}/{j:02}");
                b.put_cf(cf, k.as_bytes(), format!("v-{batch_idx}-{j}").as_bytes());
            }
            b.put_cf(cf, format!("blob/{batch_idx:02}").as_bytes(), &blob_payload);
            if batch_idx == 5 {
                b.delete_range_cf(cf, b"auto/02/00", b"auto/03/00");
            }
            db.write_batch(&b, false).unwrap();
            db.flush_cf(CF).unwrap();
        }
        assert!(
            db.l0_file_count(CF).unwrap() < 8,
            "auto L0->L1 compaction should keep L0 bounded below 8"
        );
    }

    // Real RocksDB 10.4.2 opens the auto-compacted DB and reads every surviving key & blob.
    let db = open_rocks(dir.path(), DBCompressionType::None);
    let cf = db.cf_handle(CF).unwrap();
    assert_eq!(db.get_cf(cf, b"auto/02/05").unwrap(), None);
    assert_eq!(
        db.get_cf(cf, b"auto/11/19").unwrap().as_deref(),
        Some(b"v-11-19".as_slice())
    );
    for batch_idx in 0..12u32 {
        assert_eq!(
            db.get_cf(cf, format!("blob/{batch_idx:02}").as_bytes())
                .unwrap()
                .unwrap(),
            blob_payload
        );
    }
}

#[test]
fn bench_peartube_workload_tinyrocks_vs_rocksdb() {
    use std::time::Instant;

    let n_blobs = 256u32; // 128 MiB of 512 KiB video blocks
    let n_meta = 5000u32;
    let n_misses = 5000u32;
    let payload = vec![0x5au8; 512 * 1024];

    // 1. Real RocksDB
    let dir_r = tempfile::tempdir().unwrap();
    let t0 = Instant::now();
    {
        let db = open_rocks(dir_r.path(), DBCompressionType::None);
        let cf = db.cf_handle(CF).unwrap();
        // Flush across 5 SSTs so Bloom filters are exercised across multiple tables.
        for chunk in 0..5u32 {
            let mut b = WriteBatch::default();
            for i in (chunk * 1000)..((chunk + 1) * 1000) {
                b.put_cf(cf, format!("tree/{i:06}").as_bytes(), &[0x33u8; 40]);
            }
            db.write(b).unwrap();
            db.flush_cf(cf).unwrap();
        }
        for i in 0..n_blobs {
            db.put_cf(cf, format!("blk/{i:06}").as_bytes(), &payload)
                .unwrap();
        }
        db.flush_cf(cf).unwrap();
    }
    let rocks_write_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let t1 = Instant::now();
    {
        let db = open_rocks(dir_r.path(), DBCompressionType::None);
        let cf = db.cf_handle(CF).unwrap();
        for i in 0..n_meta {
            let v = db
                .get_cf(cf, format!("tree/{i:06}").as_bytes())
                .unwrap()
                .unwrap();
            assert_eq!(v.len(), 40);
        }
        for i in 0..n_misses {
            assert!(
                db.get_cf(cf, format!("miss/{i:06}").as_bytes())
                    .unwrap()
                    .is_none()
            );
        }
        for i in 0..n_blobs {
            let v = db
                .get_cf(cf, format!("blk/{i:06}").as_bytes())
                .unwrap()
                .unwrap();
            assert_eq!(v.len(), payload.len());
        }
    }
    let rocks_read_ms = t1.elapsed().as_secs_f64() * 1000.0;

    // 2. tinyrocks
    let dir_t = tempfile::tempdir().unwrap();
    let t2 = Instant::now();
    {
        let mut db = Db::open_rw(dir_t.path(), &[CF]).unwrap();
        let cf = db.cf_id(CF).unwrap();
        for chunk in 0..5u32 {
            let mut b = tinyrocks::WriteBatch::default();
            for i in (chunk * 1000)..((chunk + 1) * 1000) {
                b.put_cf(cf, format!("tree/{i:06}").as_bytes(), &[0x33u8; 40]);
            }
            db.write_batch(&b, false).unwrap();
            db.flush_cf(CF).unwrap();
        }
        for i in 0..n_blobs {
            let mut bb = tinyrocks::WriteBatch::default();
            bb.put_cf(cf, format!("blk/{i:06}").as_bytes(), &payload);
            db.write_batch(&bb, false).unwrap();
        }
        db.flush_cf(CF).unwrap();
    }
    let tiny_write_ms = t2.elapsed().as_secs_f64() * 1000.0;

    let t3 = Instant::now();
    {
        let db = Db::open_read_only(dir_t.path()).unwrap();
        for i in 0..n_meta {
            let v = db
                .get_cf(CF, format!("tree/{i:06}").as_bytes())
                .unwrap()
                .unwrap();
            assert_eq!(v.len(), 40);
        }
        for i in 0..n_misses {
            assert!(
                db.get_cf(CF, format!("miss/{i:06}").as_bytes())
                    .unwrap()
                    .is_none()
            );
        }
        for i in 0..n_blobs {
            let v = db
                .get_cf(CF, format!("blk/{i:06}").as_bytes())
                .unwrap()
                .unwrap();
            assert_eq!(v.len(), payload.len());
        }
    }
    let tiny_read_ms = t3.elapsed().as_secs_f64() * 1000.0;

    eprintln!(
        "BENCH (128 MiB video + 5k hits + 5k misses across 6 SSTs): RocksDB write={rocks_write_ms:.1}ms read={rocks_read_ms:.1}ms | tinyrocks write={tiny_write_ms:.1}ms read={tiny_read_ms:.1}ms"
    );
}
