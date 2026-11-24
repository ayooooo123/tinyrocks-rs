//! Pure-Rust RocksDB `BuiltinBloomFilter` (`FastLocalBloom` format v5+ and `LegacyBloom`
//! reader) using RocksDB's exact vendored preview `XXPH3_64bits` (`util/xxph3.h`).

const K_METADATA_LEN: usize = 5;
const FAST_LOCAL_MARKER: u8 = 0xff;
const FAST_LOCAL_SUB_IMPL: u8 = 0x00;
const MILLIBITS_PER_KEY: usize = 10_000; // 10 bits/key -> ~1% FP rate, 6 probes
const NUM_PROBES_10_BPK: u8 = 6;

const PRIME32_1: u32 = 0x9E37_79B1;
const PRIME32_2: u32 = 0x85EB_CA77;
const PRIME32_3: u32 = 0xC2B2_AE3D;

const PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
const PRIME64_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const PRIME64_3: u64 = 0x1656_67B1_9E37_79F9;
const PRIME64_4: u64 = 0x85EB_CA77_C2B2_AE63;
const PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;

const K_SECRET: [u8; 192] = [
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
];

#[inline]
fn read_le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
fn read_le64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

#[inline]
fn mul128_fold64(lhs: u64, rhs: u64) -> u64 {
    let prod = (lhs as u128).wrapping_mul(rhs as u128);
    (prod as u64) ^ ((prod >> 64) as u64)
}

#[inline]
fn avalanche(mut h64: u64) -> u64 {
    h64 ^= h64 >> 37;
    h64 = h64.wrapping_mul(PRIME64_3);
    h64 ^= h64 >> 32;
    h64
}

#[inline]
fn mix16b(input: &[u8], secret: &[u8]) -> u64 {
    let lo = read_le64(input) ^ read_le64(secret);
    let hi = read_le64(&input[8..]) ^ read_le64(&secret[8..]);
    mul128_fold64(lo, hi)
}

fn accumulate_512(acc: &mut [u64; 8], input: &[u8], secret: &[u8]) {
    for i in 0..8 {
        let data_val = read_le64(&input[8 * i..]);
        let data_key = data_val ^ read_le64(&secret[8 * i..]);
        acc[i] = acc[i].wrapping_add(data_val);
        let lo = data_key & 0xffff_ffff;
        let hi = data_key >> 32;
        acc[i] = acc[i].wrapping_add(lo.wrapping_mul(hi));
    }
}

fn scramble_acc(acc: &mut [u64; 8], secret: &[u8]) {
    for i in 0..8 {
        let key64 = read_le64(&secret[8 * i..]);
        let mut a = acc[i];
        a ^= a >> 47;
        a ^= key64;
        a = a.wrapping_mul(PRIME32_1 as u64);
        acc[i] = a;
    }
}

/// RocksDB's exact `Hash64(data, len)` (`ROCKSDB_XXPH3_64bits`, preview v0.7.2).
pub fn xxph3_64bits(input: &[u8]) -> u64 {
    let len = input.len();
    if len == 0 {
        return mul128_fold64(read_le64(&K_SECRET[..8]), PRIME64_2);
    }
    if len <= 3 {
        let c1 = input[0] as u32;
        let c2 = input[len >> 1] as u32;
        let c3 = input[len - 1] as u32;
        let combined = c1 | (c2 << 8) | (c3 << 16) | ((len as u32) << 24);
        let keyed = (combined as u64) ^ (read_le32(&K_SECRET[..4]) as u64);
        return avalanche(keyed.wrapping_mul(PRIME64_1));
    }
    if len <= 8 {
        let lo = read_le32(&input[..4]) as u64;
        let hi = read_le32(&input[len - 4..]) as u64;
        let input_64 = lo | (hi << 32);
        let keyed = input_64 ^ read_le64(&K_SECRET[..8]);
        let mix64 = (len as u64).wrapping_add((keyed ^ (keyed >> 51)).wrapping_mul(PRIME32_1 as u64));
        return avalanche((mix64 ^ (mix64 >> 47)).wrapping_mul(PRIME64_2));
    }
    if len <= 16 {
        let lo = read_le64(&input[..8]) ^ read_le64(&K_SECRET[..8]);
        let hi = read_le64(&input[len - 8..]) ^ read_le64(&K_SECRET[8..16]);
        let acc = (len as u64)
            .wrapping_add(lo.wrapping_add(hi))
            .wrapping_add(mul128_fold64(lo, hi));
        return avalanche(acc);
    }
    if len <= 128 {
        let mut acc = (len as u64).wrapping_mul(PRIME64_1);
        if len > 32 {
            if len > 64 {
                if len > 96 {
                    acc = acc.wrapping_add(mix16b(&input[48..], &K_SECRET[96..]));
                    acc = acc.wrapping_add(mix16b(&input[len - 64..], &K_SECRET[112..]));
                }
                acc = acc.wrapping_add(mix16b(&input[32..], &K_SECRET[64..]));
                acc = acc.wrapping_add(mix16b(&input[len - 48..], &K_SECRET[80..]));
            }
            acc = acc.wrapping_add(mix16b(&input[16..], &K_SECRET[32..]));
            acc = acc.wrapping_add(mix16b(&input[len - 32..], &K_SECRET[48..]));
        }
        acc = acc.wrapping_add(mix16b(&input[0..], &K_SECRET[0..]));
        acc = acc.wrapping_add(mix16b(&input[len - 16..], &K_SECRET[16..]));
        return avalanche(acc);
    }
    if len <= 240 {
        let mut acc = (len as u64).wrapping_mul(PRIME64_1);
        let nb_rounds = len / 16;
        for i in 0..8 {
            acc = acc.wrapping_add(mix16b(&input[16 * i..], &K_SECRET[16 * i..]));
        }
        acc = avalanche(acc);
        for i in 8..nb_rounds {
            acc = acc.wrapping_add(mix16b(&input[16 * i..], &K_SECRET[16 * (i - 8) + 3..]));
        }
        acc = acc.wrapping_add(mix16b(&input[len - 16..], &K_SECRET[136 - 17..]));
        return avalanche(acc);
    }

    // Long keys (> 240 bytes)
    let mut acc: [u64; 8] = [
        PRIME32_3 as u64,
        PRIME64_1,
        PRIME64_2,
        PRIME64_3,
        PRIME64_4,
        PRIME32_2 as u64,
        PRIME64_5,
        PRIME32_1 as u64,
    ];
    let nb_rounds = (K_SECRET.len() - 64) / 8; // 16
    let block_len = 64 * nb_rounds; // 1024
    let nb_blocks = len / block_len;

    for b in 0..nb_blocks {
        let base = b * block_len;
        for s in 0..nb_rounds {
            accumulate_512(&mut acc, &input[base + s * 64..], &K_SECRET[s * 8..]);
        }
        scramble_acc(&mut acc, &K_SECRET[K_SECRET.len() - 64..]);
    }
    let rem_start = nb_blocks * block_len;
    let nb_stripes = (len - rem_start) / 64;
    for s in 0..nb_stripes {
        accumulate_512(&mut acc, &input[rem_start + s * 64..], &K_SECRET[s * 8..]);
    }
    if (len & 63) != 0 {
        accumulate_512(
            &mut acc,
            &input[len - 64..],
            &K_SECRET[K_SECRET.len() - 64 - 7..],
        );
    }

    let mut result = (len as u64).wrapping_mul(PRIME64_1);
    for pair in 0..4 {
        let sec = &K_SECRET[11 + pair * 16..];
        result = result.wrapping_add(mul128_fold64(
            acc[pair * 2] ^ read_le64(sec),
            acc[pair * 2 + 1] ^ read_le64(&sec[8..]),
        ));
    }
    avalanche(result)
}

/// RocksDB's legacy `BloomHash` (`MurmurHash1` with seed `0xbc9f1d34`).
fn legacy_bloom_hash(data: &[u8]) -> u32 {
    const M: u32 = 0xc6a4_a793;
    let mut h = 0xbc9f_1d34u32 ^ ((data.len() as u32).wrapping_mul(M));
    let mut i = 0;
    while i + 4 <= data.len() {
        let w = read_le32(&data[i..]);
        h = h.wrapping_add(w).wrapping_mul(M);
        h ^= h >> 16;
        i += 4;
    }
    let rem = data.len() - i;
    if rem >= 3 {
        h = h.wrapping_add(((data[i + 2] as i8 as i32) as u32) << 16);
    }
    if rem >= 2 {
        h = h.wrapping_add(((data[i + 1] as i8 as i32) as u32) << 8);
    }
    if rem >= 1 {
        h = h.wrapping_add((data[i] as i8 as i32) as u32);
        h = h.wrapping_mul(M);
        h ^= h >> 24;
    }
    h
}

#[inline]
fn fast_range32(hash: u32, range: u32) -> u32 {
    (((range as u64).wrapping_mul(hash as u64)) >> 32) as u32
}

/// Builds a RocksDB format-v5+ `FastLocalBloom` full filter block (`10 bits/key`).
pub struct BloomBuilder {
    hashes: Vec<u64>,
    last_key: Vec<u8>,
}

impl Default for BloomBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BloomBuilder {
    pub fn new() -> Self {
        Self {
            hashes: Vec::new(),
            last_key: Vec::new(),
        }
    }

    pub fn add_key(&mut self, user_key: &[u8]) {
        if !self.hashes.is_empty() && self.last_key.as_slice() == user_key {
            return;
        }
        self.hashes.push(xxph3_64bits(user_key));
        self.last_key.clear();
        self.last_key.extend_from_slice(user_key);
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    pub fn num_entries(&self) -> u64 {
        self.hashes.len() as u64
    }

    /// Serializes the full filter block including RocksDB's 5-byte `FastLocalBloom` trailer.
    pub fn finish(&self) -> Vec<u8> {
        let num_entries = self.hashes.len();
        if num_entries == 0 {
            return vec![FAST_LOCAL_MARKER, FAST_LOCAL_SUB_IMPL, 0, 0, 0];
        }
        let raw_len = (num_entries.saturating_mul(MILLIBITS_PER_KEY) + 7999) / 8000;
        let bit_bytes = ((raw_len + 63) & !63).clamp(64, 0xffff_ffc0);
        let mut out = vec![0u8; bit_bytes + K_METADATA_LEN];
        let num_lines = (bit_bytes >> 6) as u32;

        for &h in &self.hashes {
            let h1 = h as u32;
            let h2 = (h >> 32) as u32;
            let line_off = (fast_range32(h1, num_lines) as usize) << 6;
            let line = &mut out[line_off..line_off + 64];
            let mut probe = h2;
            for _ in 0..NUM_PROBES_10_BPK {
                let bitpos = (probe >> 23) as usize;
                line[bitpos >> 3] |= 1u8 << (bitpos & 7);
                probe = probe.wrapping_mul(0x9e37_79b9);
            }
        }

        out[bit_bytes] = FAST_LOCAL_MARKER;
        out[bit_bytes + 1] = FAST_LOCAL_SUB_IMPL;
        out[bit_bytes + 2] = NUM_PROBES_10_BPK;
        out[bit_bytes + 3] = 0;
        out[bit_bytes + 4] = 0;
        out
    }
}

/// Reader for RocksDB `BuiltinBloomFilter` blocks (`FastLocalBloom` + `LegacyBloom`).
pub enum BloomFilter {
    AlwaysTrue,
    AlwaysFalse,
    FastLocal {
        data: Vec<u8>,
        num_lines: u32,
        num_probes: u8,
    },
    Legacy {
        data: Vec<u8>,
        num_lines: u32,
        num_probes: u8,
    },
}

impl BloomFilter {
    pub fn from_block(data: Vec<u8>) -> Self {
        if data.len() < K_METADATA_LEN {
            return Self::AlwaysTrue;
        }
        let bit_bytes = data.len() - K_METADATA_LEN;
        let meta = &data[bit_bytes..];

        if meta[0] == FAST_LOCAL_MARKER {
            if meta[1] != FAST_LOCAL_SUB_IMPL {
                // Ribbon or newer filter sub-implementation: fall back conservatively.
                return Self::AlwaysTrue;
            }
            let num_probes = meta[2];
            if num_probes == 0 {
                return Self::AlwaysFalse;
            }
            if num_probes <= 30 && bit_bytes >= 64 && (bit_bytes & 63) == 0 {
                return Self::FastLocal {
                    data,
                    num_lines: (bit_bytes >> 6) as u32,
                    num_probes,
                };
            }
            return Self::AlwaysTrue;
        }

        if (1..=30).contains(&meta[0]) {
            let num_probes = meta[0];
            let num_lines = read_le32(&meta[1..5]);
            if (num_lines as usize).saturating_mul(64) == bit_bytes && num_lines > 0 {
                return Self::Legacy {
                    data,
                    num_lines,
                    num_probes,
                };
            }
        }

        Self::AlwaysTrue
    }

    pub fn may_match(&self, user_key: &[u8]) -> bool {
        match self {
            Self::AlwaysTrue => true,
            Self::AlwaysFalse => false,
            Self::FastLocal {
                data,
                num_lines,
                num_probes,
            } => {
                let h = xxph3_64bits(user_key);
                let h1 = h as u32;
                let h2 = (h >> 32) as u32;
                let line_off = (fast_range32(h1, *num_lines) as usize) << 6;
                let line = &data[line_off..line_off + 64];
                let mut probe = h2;
                for _ in 0..*num_probes {
                    let bitpos = (probe >> 23) as usize;
                    if (line[bitpos >> 3] & (1u8 << (bitpos & 7))) == 0 {
                        return false;
                    }
                    probe = probe.wrapping_mul(0x9e37_79b9);
                }
                true
            }
            Self::Legacy {
                data,
                num_lines,
                num_probes,
            } => {
                let mut h = legacy_bloom_hash(user_key);
                let delta = h.rotate_right(17);
                let line_off = ((h % *num_lines) as usize) << 6;
                let line = &data[line_off..line_off + 64];
                for _ in 0..*num_probes {
                    let bitpos = (h & 511) as usize;
                    if (line[bitpos >> 3] & (1u8 << (bitpos & 7))) == 0 {
                        return false;
                    }
                    h = h.wrapping_add(delta);
                }
                true
            }
        }
    }
}
