// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! A fixed VHD is a raw disk with a 512-byte footer (Microsoft's "Virtual Hard
//! Disk Image Format Specification"). That footer is all Sluse writes; Hyper-V's
//! own `Convert-VHD` turns the result into the dynamic VHDX a Generation 2 VM
//! boots from (D-027 design point 2). No VHDX writer, because Windows has one.

/// The footer for a raw disk of `size` bytes, `size` a multiple of 512.
pub fn footer(size: u64, uuid: [u8; 16], seconds_since_2000: u32) -> [u8; 512] {
    let mut f = [0u8; 512];
    f[0..8].copy_from_slice(b"conectix");
    f[8..12].copy_from_slice(&2u32.to_be_bytes()); // features: reserved bit, always set
    f[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes()); // format version 1.0
    f[16..24].copy_from_slice(&u64::MAX.to_be_bytes()); // data offset: none, a fixed disk
    f[24..28].copy_from_slice(&seconds_since_2000.to_be_bytes());
    f[28..32].copy_from_slice(b"slus"); // creator application
    f[32..36].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    f[36..40].copy_from_slice(b"Wi2k"); // creator host OS
    f[40..48].copy_from_slice(&size.to_be_bytes()); // original size
    f[48..56].copy_from_slice(&size.to_be_bytes()); // current size
    let (c, h, s) = geometry(size);
    f[56..58].copy_from_slice(&c.to_be_bytes());
    f[58] = h;
    f[59] = s;
    f[60..64].copy_from_slice(&2u32.to_be_bytes()); // disk type: fixed
    f[68..84].copy_from_slice(&uuid);
    let sum: u32 = f.iter().map(|&b| b as u32).fold(0, u32::wrapping_add);
    f[64..68].copy_from_slice(&(!sum).to_be_bytes());
    f
}

/// Cylinders, heads and sectors per track, by the specification's own
/// algorithm (appendix, "CHS Calculation").
fn geometry(size: u64) -> (u16, u8, u8) {
    let mut total = (size / 512).min(65535 * 16 * 255);
    let (spt, heads, cth);
    if total >= 65535 * 16 * 63 {
        total = total.min(65535 * 16 * 255);
        spt = 255;
        heads = 16;
        cth = total / spt;
    } else {
        let mut s = 17;
        let mut c = total / s;
        let mut h = c.div_ceil(1024).max(4);
        if c >= h * 1024 || h > 16 {
            s = 31;
            h = 16;
            c = total / s;
        }
        if c >= h * 1024 {
            s = 63;
            h = 16;
            c = total / s;
        }
        spt = s;
        heads = h;
        cth = c;
    }
    ((cth / heads) as u16, heads as u8, spt as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_footer_checksums_and_describes_a_fixed_disk() {
        let f = footer(3 * 1024 * 1024 * 1024, [7; 16], 1);
        assert_eq!(&f[0..8], b"conectix");
        assert_eq!(u32::from_be_bytes(f[60..64].try_into().unwrap()), 2);
        let stored = u32::from_be_bytes(f[64..68].try_into().unwrap());
        let mut g = f;
        g[64..68].fill(0);
        let sum: u32 = g.iter().map(|&b| b as u32).fold(0, u32::wrapping_add);
        assert_eq!(stored, !sum);
    }

    #[test]
    fn geometry_follows_the_specification() {
        // 3.5 GiB: the large-disk branch.
        assert_eq!(geometry(3_758_096_384), (7281, 16, 63));
        // A small disk takes the 17-sector branch.
        assert_eq!(geometry(10 * 1024 * 1024), (301, 4, 17));
        // Beyond 127 GiB the geometry is capped, the size is not.
        assert_eq!(geometry(200 * 1024 * 1024 * 1024), (65535, 16, 255));
    }

    /// Hyper-V's own reading of the file: the proof that matters, on a
    /// Windows machine with the Hyper-V module (CI's runner has it).
    #[cfg(windows)]
    #[test]
    fn hyper_v_reads_it_as_a_fixed_vhd_and_converts_it() {
        let dir = tempfile::tempdir().unwrap();
        let vhd = dir.path().join("t.vhd");
        let size = 4 * 1024 * 1024u64;
        let mut bytes = vec![0x5au8; size as usize];
        bytes.extend_from_slice(&footer(size, [3; 16], 0));
        std::fs::write(&vhd, bytes).unwrap();
        let vhdx = dir.path().join("t.vhdx");
        let script = format!(
            "$ErrorActionPreference='Stop'; $v = Get-VHD -Path '{}'; \
             Convert-VHD -Path '{}' -DestinationPath '{}' -VHDType Dynamic; \
             $x = Get-VHD -Path '{}'; \"$($v.VhdFormat) $($v.VhdType) $($v.Size) $($x.VhdFormat) $($x.Size)\"",
            vhd.display(), vhd.display(), vhdx.display(), vhdx.display()
        );
        let out = std::process::Command::new("powershell.exe").args(["-NoProfile", "-Command", &script]).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("is not recognized") {
            // CI sets SLUSE_REQUIRE_HYPERV: its runner has the module, and a
            // skipped proof is not a proof.
            assert!(std::env::var_os("SLUSE_REQUIRE_HYPERV").is_none(), "SLUSE_REQUIRE_HYPERV is set and there is no Hyper-V module");
            eprintln!("no Hyper-V module here: the VHD test did not run");
            return;
        }
        assert!(out.status.success(), "{err}");
        assert_eq!(text, format!("VHD Fixed {size} VHDX {size}"));
    }
}
