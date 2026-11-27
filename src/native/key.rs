//! Server public-key substitution in `libg.so` (Hay Day 1.43.150 build 1598).
//!
//! The 32-byte X25519 key is embedded three times (client Login encryption,
//! first-response decryption, nonce-hash input) as 16 obfuscated 16-bit limbs:
//! `encoded[i] = rotr16(limb[i], ROTATIONS[i]) ^ limb[i-1]`. The encoded limbs
//! are compile-time constants, so every ABI carries the same 16 values, only
//! in different instructions:
//!
//! - x86: 32-bit immediate operands (`xor r32, imm32` and friends);
//! - arm64-v8a: `MOVZ Wd, #imm16`.
//!
//! Sites are located by pattern: each limb's candidates are collected, then
//! grouped into address clusters, and exactly three clusters must each hold
//! every limb exactly once. Any ambiguity aborts before writing. The SHA-256
//! allow-list keeps patching to the build this was verified against.

use std::ops::Range;

use anyhow::{bail, ensure, Result};
use sha2::{Digest, Sha256};

use super::{arm64, Abi};

const ROTATIONS: [u32; 16] = [0, 1, 2, 3, 4, 2, 6, 2, 2, 2, 0, 2, 5, 3, 2, 1];
/// Encoded limbs of Supercell's original server key.
const ORIGINAL: [u16; 16] = [
    0xb0b5, 0x971f, 0x3073, 0x505b, 0x09a3, 0xd02b, 0x27ce, 0x8829, 0x8b70, 0x751e, 0x2685, 0xf6d7,
    0x236e, 0x9cba, 0xef95, 0xd03e,
];
/// Maximum gap between consecutive sites of one key copy.
const CLUSTER_GAP: usize = 0x4000;

impl Abi {
    /// (SHA-256 of the original library, executable segment file range).
    pub(super) fn build(self) -> (&'static str, Range<usize>) {
        match self {
            Self::X86 => (
                "00146c7fbad5a9ba97ee401a29a4d87d045bcebae7ab0f9123ff11e2a80ccd8a",
                0..0xb0d1e8,
            ),
            Self::Arm64 => (
                "cf8d193c080fc21bb1dbfc97d7bbef8f161a1ce6608c06e4ef616d4e00c6175b",
                0..0xa1ac5c,
            ),
        }
    }

    /// Offsets in `text` whose instruction carries `value`.
    fn candidates(self, text: &[u8], value: u16) -> Vec<usize> {
        match self {
            Self::X86 => {
                // Only `xor r32, imm32`: `35 id` (eax) or `81 /6 id` with a
                // register operand (ModRM 0xf0..=0xf7). Plain value matches
                // elsewhere in .text are data or unrelated immediates.
                let pattern = (value as u32).to_le_bytes();
                text.windows(4)
                    .enumerate()
                    .filter(|(i, w)| {
                        *w == pattern
                            && *i >= 2
                            && (text[i - 1] == 0x35
                                || (text[i - 2] == 0x81 && (0xf0..=0xf7).contains(&text[i - 1])))
                    })
                    .map(|(i, _)| i)
                    .collect()
            }
            Self::Arm64 => text
                .as_chunks::<4>()
                .0
                .iter()
                .enumerate()
                .filter(|(_, w)| {
                    let insn = u32::from_le_bytes(**w);
                    is_movz_w(insn) && (insn >> 5) & 0xffff == value as u32
                })
                .map(|(i, _)| i * 4)
                .collect(),
        }
    }

    fn write(self, data: &mut [u8], offset: usize, value: u16) {
        match self {
            Self::X86 => data[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes()),
            Self::Arm64 => {
                let insn = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
                let patched = (insn & !(0xffff << 5)) | ((value as u32) << 5);
                data[offset..offset + 4].copy_from_slice(&patched.to_le_bytes());
            }
        }
    }
}

/// `MOVZ Wd, #imm16` with no shift (sf=0, opc=10, hw=00).
fn is_movz_w(insn: u32) -> bool {
    insn & 0xffe0_0000 == 0x5280_0000
}

pub fn parse_key(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        bail!("server public key must be 64 hexadecimal characters");
    }
    let mut key = [0; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    // The native field decoder does not mask bit 255 as standard X25519 does.
    if key[31] & 0x80 != 0 {
        bail!("X25519 public key must have its high bit clear");
    }
    Ok(key)
}

fn encode(key: &[u8; 32]) -> [u16; 16] {
    let mut previous = 0u16;
    std::array::from_fn(|i| {
        let limb = u16::from_le_bytes([key[2 * i], key[2 * i + 1]]);
        let encoded = limb.rotate_right(ROTATIONS[i]) ^ previous;
        previous = limb;
        encoded
    })
}

/// The three key copies: `sites[copy][limb]` file offsets.
pub fn find_sites(abi: Abi, data: &[u8]) -> Result<[[usize; 16]; 3]> {
    let (_, text) = abi.build();
    ensure!(
        data.len() >= text.end,
        "library shorter than its text segment"
    );
    let text = &data[text];
    let mut all: Vec<(usize, usize)> = Vec::new();
    for (limb, value) in ORIGINAL.into_iter().enumerate() {
        all.extend(abi.candidates(text, value).into_iter().map(|o| (o, limb)));
    }
    all.sort_unstable();
    let mut clusters: Vec<Vec<(usize, usize)>> = Vec::new();
    for hit in all {
        match clusters.last_mut() {
            Some(c) if hit.0 - c.last().unwrap().0 <= CLUSTER_GAP => c.push(hit),
            _ => clusters.push(vec![hit]),
        }
    }
    let mut copies = Vec::new();
    for cluster in clusters {
        let mut sites = [None; 16];
        for &(offset, limb) in &cluster {
            sites[limb] = Some(match sites[limb] {
                None => offset,
                Some(_) => bail!("ambiguous key limb {limb} near {offset:#x}"),
            });
        }
        if sites.iter().all(Option::is_some) {
            ensure!(
                cluster.len() == 16,
                "extra key-like constants near {:#x}",
                cluster[0].0
            );
            copies.push(sites.map(Option::unwrap));
        }
    }
    ensure!(
        copies.len() == 3,
        "expected 3 embedded key copies, found {}",
        copies.len()
    );
    Ok([copies[0], copies[1], copies[2]])
}

/// C3 decodes slot 2 of the peer public key as
/// `rol16(0xffff - (previous ^ C), 2)` rather than `rol16(previous ^ encoded, 2)`
/// (its `MOVZ` there is a decoy that a following `orr` cancels).  The plain
/// limb patch leaves `C` at the complement of the *original* limb, so C3 would
/// decode a different peer key than C1/C2.  Solving the expression for the
/// wanted limb shows the constant must be `!encoded[2]`.
const C3_DECODE_CONSTANT: usize = 0x69_3adc;
const C3_DECODE_PRISTINE: u32 = 0x5299_f18a; // mov w10, #0xcf8c

pub fn patch(abi: Abi, data: &mut Vec<u8>, key: &[u8; 32]) -> Result<()> {
    let (sha, _) = abi.build();
    let digest: String = Sha256::digest(&*data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if digest != sha {
        bail!("unsupported {abi:?} libg.so SHA-256 {digest}; only the original 1.43.150 build 1598 is supported");
    }
    let sites = find_sites(abi, data)?;
    let encoded = encode(key);
    // The arm64 client hashes the three patched regions at login; make the
    // checker read pristine copies instead.  This must see the original bytes,
    // so it runs before any write below.
    if abi == Abi::Arm64 {
        arm64::harden(data)?;
        ensure!(
            u32::from_le_bytes(
                data[C3_DECODE_CONSTANT..C3_DECODE_CONSTANT + 4]
                    .try_into()
                    .unwrap()
            ) == C3_DECODE_PRISTINE,
            "unexpected C3 decode constant at {C3_DECODE_CONSTANT:#x}"
        );
    }
    for copy in sites {
        for (limb, offset) in copy.into_iter().enumerate() {
            abi.write(data, offset, encoded[limb]);
        }
    }
    if abi == Abi::Arm64 {
        abi.write(data, C3_DECODE_CONSTANT, !encoded[2]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGINAL_KEY: &str = "b5b0544f9dfc356666f934a5a0be24da51453cc1b9e7b845ccdab2339f704341";

    #[test]
    fn key_encoding_recovers_original_immediates() {
        assert_eq!(encode(&parse_key(ORIGINAL_KEY).unwrap()), ORIGINAL);
    }

    #[test]
    fn rejects_unsupported_binary_without_writing() {
        for abi in [Abi::X86, Abi::Arm64] {
            let mut data = vec![0x42; 64];
            let before = data.clone();
            assert!(patch(abi, &mut data, &[1; 32]).is_err());
            assert_eq!(data, before);
        }
        assert!(parse_key("bad").is_err());
        assert!(parse_key(&"ff".repeat(32)).is_err());
        assert_eq!(Abi::from_entry("lib/armeabi-v7a/libg.so"), None);
    }

    /// Synthetic arm64 text: three copies of 16 MOVZ instructions plus noise.
    #[test]
    fn arm64_pattern_finds_and_rewrites_three_copies() {
        let mut text = vec![0u8; 0x30000];
        let mut put = |offset: usize, insn: u32| {
            text[offset..offset + 4].copy_from_slice(&insn.to_le_bytes())
        };
        for (copy, base) in [0x1000usize, 0x10000, 0x20000].into_iter().enumerate() {
            for (limb, value) in ORIGINAL.into_iter().enumerate() {
                put(
                    base + limb * 0x40,
                    0x5280_0000 | (value as u32) << 5 | ((copy as u32 + limb as u32) % 31),
                );
            }
        }
        // A MOVK carrying a limb value is not a candidate.
        put(0x8000, 0x7280_0000 | (ORIGINAL[0] as u32) << 5);
        let mut data = text.clone();
        let abi = Abi::Arm64;
        let sites = {
            // find_sites uses the real build's text range; exercise the core.
            let mut all = Vec::new();
            for (limb, v) in ORIGINAL.into_iter().enumerate() {
                all.extend(abi.candidates(&text, v).into_iter().map(|o| (o, limb)));
            }
            all
        };
        assert_eq!(sites.len(), 48);
        let key = [0x11; 32];
        let encoded = encode(&key);
        for &(offset, limb) in &sites {
            abi.write(&mut data, offset, encoded[limb]);
            let insn = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            assert!(is_movz_w(insn));
            assert_eq!((insn >> 5) & 0xffff, encoded[limb] as u32);
            // Destination register preserved.
            let before = u32::from_le_bytes(text[offset..offset + 4].try_into().unwrap());
            assert_eq!(insn & 0x1f, before & 0x1f);
        }
    }

    /// Against the real libraries when present (set HD_X86_LIBG / HD_ARM64_LIBG).
    #[test]
    fn real_libraries_match_known_sites() {
        let x86 = std::env::var_os("HD_X86_LIBG");
        if let Some(data) = x86.and_then(|p| std::fs::read(p).ok()) {
            let sites = find_sites(Abi::X86, &data).unwrap();
            // Hand-verified operand table from the original x86 patch.
            let recv = [
                0x24c0e8, 0x24c531, 0x24df7b, 0x24efb0, 0x24bbfe, 0x24ec69, 0x24f60d, 0x24e83a,
                0x24b6ec, 0x24f42c, 0x24bf19, 0x24e462, 0x24dd12, 0x24eb3f, 0x24bd70, 0x24ebd9,
            ];
            let hash = [
                0x383c7f, 0x384004, 0x382106, 0x3852a3, 0x3861c8, 0x381cd6, 0x382dc8, 0x383443,
                0x3865e8, 0x383ba8, 0x384b41, 0x38573a, 0x384cef, 0x386aac, 0x38379c, 0x386e87,
            ];
            let send = [
                0x4d983f, 0x4d8946, 0x4dac4f, 0x4dd9db, 0x4dd0a0, 0x4dd56e, 0x4d8ef4, 0x4dd3bf,
                0x4dc1c7, 0x4dcb82, 0x4dc872, 0x4d94c9, 0x4db4a5, 0x4db176, 0x4db418, 0x4deb64,
            ];
            assert_eq!(sites, [recv, hash, send]);
        }
        if let Ok(path) = std::env::var("HD_ARM64_LIBG") {
            let mut data = std::fs::read(path).unwrap();
            let sites = find_sites(Abi::Arm64, &data).unwrap();
            assert_eq!(sites.iter().flatten().count(), 48);
            patch(Abi::Arm64, &mut data, &[0x22; 32]).unwrap();
            assert!(
                find_sites(Abi::Arm64, &data).is_err(),
                "original limbs must be gone"
            );
        }
    }
}
