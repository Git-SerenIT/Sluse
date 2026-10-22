// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Hyper-V's key-value pool, as `hv_kvp_daemon` keeps it in the box: the
//! host-to-guest items in pool 0, as fixed-size records of a 512-byte key and
//! a 2,048-byte value, NUL-padded, UTF-8 (S-8 step 2). The same layout
//! `packaging/box/kiosk/sluse-bootstrap` reads.

pub const POOL: &str = "/var/lib/hyperv/.kvp_pool_0";

const KEY: usize = 512;
const VALUE: usize = 2048;

/// The value under `key`, if the pool has one.
pub fn find(pool: &[u8], key: &str) -> Option<String> {
    let field = |b: &[u8]| String::from_utf8_lossy(b.split(|&c| c == 0).next().unwrap_or(b)).into_owned();
    pool.as_chunks::<{ KEY + VALUE }>()
        .0
        .iter()
        .find(|rec| field(&rec[..KEY]) == key)
        .map(|rec| field(&rec[KEY..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(k: &str, v: &str) -> Vec<u8> {
        let mut r = vec![0u8; KEY + VALUE];
        r[..k.len()].copy_from_slice(k.as_bytes());
        r[KEY..KEY + v.len()].copy_from_slice(v.as_bytes());
        r
    }

    #[test]
    fn a_value_is_found_by_its_key_among_others() {
        let mut pool = record("other", "x");
        pool.extend(record("sluse-bootstrap", "{\"a\":1}"));
        assert_eq!(find(&pool, "sluse-bootstrap").as_deref(), Some("{\"a\":1}"));
        assert_eq!(find(&pool, "missing"), None);
        assert_eq!(find(&pool, "sluse-boot"), None, "a prefix is not the key");
        assert_eq!(find(&pool[..100], "other"), None, "a torn record is no record");
    }
}
