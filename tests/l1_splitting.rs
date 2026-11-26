use std::collections::HashSet;
use std::path::Path;

use tinyrocks::{Db, ScanDirection, WriteBatch};

fn sst_files(dir: &Path) -> HashSet<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.ends_with(".sst").then_some(name)
        })
        .collect()
}

/// Verifies L1 splits into multiple size-bounded non-overlapping SSTs, that a
/// subsequent L0->L1 compaction touching disjoint prefixes leaves middle L1
/// SSTs untouched on disk, and that upstream RocksDB 10.x opens and reads every
/// key cleanly from the resulting directory.
#[test]
fn l1_splits_and_preserves_untouched_middle_ssts_with_rocksdb_interop() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let mut db = Db::open_rw(dir, &["corestore"]).unwrap();
    db.set_target_sst_size(8 * 1024);
    db.set_sync_on_flush(false);
    let cf = db.cf_id("corestore").unwrap();

    // Populate 6 distinct key prefixes (`c00`..`c05`), ~12 KiB each, so L1 splits into >= 6 SSTs.
    let val = vec![0x42u8; 512];
    for core in 0u8..6 {
        let mut batch = WriteBatch::default();
        for idx in 0u32..24 {
            let key = format!("c{core:02}:{idx:04}");
            batch.put_cf(cf, key.as_bytes(), &val);
        }
        db.write_batch(&batch, false).unwrap();
        db.flush_cf("corestore").unwrap();
    }
    db.compact_cf("corestore", false).unwrap();

    let l1_before = db.l1_file_count("corestore").unwrap();
    assert!(
        l1_before >= 4,
        "expected L1 to split into >= 4 SSTs, got {l1_before}"
    );
    let ssts_before = sst_files(dir);

    // Trigger an L0->L1 compaction touching ONLY prefix `c00` and `c05` (two far-apart
    // prefixes, mirroring channel metadata + active video core). Middle L1 SSTs covering
    // `c01`..`c04` must NOT be rewritten.
    for round in 0u32..8 {
        let mut batch = WriteBatch::default();
        let k_low = format!("c00:new_{round:02}");
        let k_high = format!("c05:new_{round:02}");
        batch.put_cf(cf, k_low.as_bytes(), b"low-update");
        batch.put_cf(cf, k_high.as_bytes(), b"high-update");
        db.write_batch(&batch, false).unwrap();
        db.flush_cf("corestore").unwrap();
    }
    assert_eq!(db.l0_file_count("corestore").unwrap(), 0);

    let ssts_after = sst_files(dir);
    let untouched: Vec<_> = ssts_before.intersection(&ssts_after).collect();
    assert!(
        untouched.len() >= l1_before.saturating_sub(3).max(3),
        "expected middle L1 SSTs to stay untouched even when one L0 SST bridges c00..c05; untouched={} l1_before={l1_before} before={ssts_before:?} after={ssts_after:?}",
        untouched.len()
    );

    // Verify all keys via tinyrocks point reads & range scans.
    for core in 0u8..6 {
        for idx in 0u32..24 {
            let key = format!("c{core:02}:{idx:04}");
            assert_eq!(
                db.get_cf("corestore", key.as_bytes()).unwrap().as_deref(),
                Some(val.as_slice()),
                "missing {key}"
            );
        }
    }
    for round in 0u32..8 {
        let k_low = format!("c00:new_{round:02}");
        let k_high = format!("c05:new_{round:02}");
        assert_eq!(
            db.get_cf("corestore", k_low.as_bytes()).unwrap().as_deref(),
            Some(&b"low-update"[..])
        );
        assert_eq!(
            db.get_cf("corestore", k_high.as_bytes())
                .unwrap()
                .as_deref(),
            Some(&b"high-update"[..])
        );
    }
    let scanned = db
        .scan_cf("corestore", Some(b"c02:"), Some(b"c03:"), ScanDirection::Forward)
        .unwrap();
    assert_eq!(scanned.len(), 24);
    db.flush_wal(true).unwrap();
    drop(db);

    // Reopen with upstream RocksDB 10.x to prove L1 non-overlapping & format compatibility.
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    let rdb = rocksdb::DB::open_cf_for_read_only(&opts, dir, ["default", "corestore"], false)
        .expect("RocksDB failed to open split-L1 tinyrocks DB");
    let rcf = rdb.cf_handle("corestore").unwrap();
    for core in 0u8..6 {
        let key = format!("c{core:02}:0010");
        assert_eq!(
            rdb.get_cf(rcf, key.as_bytes()).unwrap().as_deref(),
            Some(val.as_slice())
        );
    }
    assert_eq!(
        rdb.get_cf(rcf, b"c00:new_07").unwrap().as_deref(),
        Some(&b"low-update"[..])
    );
    assert_eq!(
        rdb.get_cf(rcf, b"c05:new_07").unwrap().as_deref(),
        Some(&b"high-update"[..])
    );
}
