//! ARM64 integrity-checker neutralisation for a key-substituted `libg.so`.
//!
//! Replacing the embedded server key rewrites instructions inside three code
//! regions the client verifies at login.  Two paths matter:
//!
//! - a code-byte pass that walks a region table and hashes every covered
//!   region (Layer 1/3), and
//! - a verdict trampoline at `0x625380` (Layer 2) that closes the socket when
//!   the walk reports a mismatch.
//!
//! The verified arrangement makes both reads byte-identical to the pristine
//! image without touching the original functions:
//!
//! 1. Copies of the *pristine* C1/C2/C3 functions are appended beyond `.bss`
//!    at 16-byte aligned offsets: file `0xe57710` (8508 B), `0xe59850`
//!    (7528 B), `0xe5b5b8` (8352 B); VA = file + 0x10000 because the RW
//!    `PT_LOAD` is mapped at a 0x10000 file/VA delta.
//! 2. `PT_LOAD[1]` is extended to cover the copies
//!    (`p_filesz = p_memsz = 0x4426f0`), and every file byte that now maps
//!    into the `.bss` VA range is zeroed so `.bss` stays zero-initialised
//!    (`.comment`, the old `.shstrtab`, the old section-header table, the
//!    zero padding up to the first copy).
//! 3. The section-header table and `.shstrtab` are relocated past the copies
//!    (`e_shoff = 0xe5d658`) so the ELF stays well-formed for tools.
//! 4. The `b.lt` at `0x625380` is replaced by a `nop` so the walk verdict is
//!    never acted on.
//! 5. The three region-table records covering C1/C2/C3 are retargeted at the
//!    copy VAs with the delta-chain fixup: `a_i' = a_{i-1} + b_{i-1} + c_{i-1}
//!    + D`, `b_i' = a_i' + b_{i-1} - len_i`, `c_i'` chosen so `x454` is
//!    preserved, and the change is propagated through every following record
//!    up to the `len == 0` terminator.  The walk then reports the original
//!    address, length and `x454` selector for every record.
//!
//! Every step re-reads the pristine bytes and aborts if they are not the ones
//! this build expects.
use anyhow::{bail, ensure, Result};

use super::{put_u32, put_u64, u32_at, u64_at};

/// RW `PT_LOAD`: file/VA delta of the segment the copies belong to.
const RW_DELTA: usize = 0x10000;
/// Region table: VA base, file offset and record count (last record ends the walk).
const TABLE_VA: u64 = 0xbf_8110;
const TABLE_OFF: usize = 0xbe_8110;
const TABLE_RECORDS: usize = 73_829;
/// Function copies: (source VA, length, copy VA).  The RX `PT_LOAD` has
/// file offset == VA, so the source VA doubles as a file offset.
const COPIES: [(usize, usize, u64); 3] = [
    (0x22_d60c, 8508, 0xe6_7710), // C1: login encryption
    (0x39_b174, 7528, 0xe6_9850), // C2: nonce derivation
    (0x69_211c, 8352, 0xe6_b5b8), // C3: first-response decryption
];
/// Region-table record covering each copy.
const RECORD_C3: usize = 9_569;
const RECORD_C2: usize = 56_226;
const RECORD_C1: usize = 65_308;
/// File ranges that map into `.bss` once `PT_LOAD[1]` is extended and are
/// non-zero in the pristine file (`.comment`, then `.shstrtab` plus the old
/// section-header table).  The gap in between is already zero padding.
const BSS_MAPPED_NONZERO: [(usize, usize); 2] = [(0xe3_0dd8, 0x78), (0xe4_a468, 0x730)];
/// Zero padding up to the first appended copy.
const PAD_RANGE: (usize, usize) = (0xe4_ab98, 0xe5_7710);
/// Old section-header table and `.shstrtab` (source of the relocated copies).
const SHDR_OLD: usize = 0xe4_a558;
const SHSTRTAB_OLD: usize = 0xe4_a468;
const SHSTRTAB_LEN: usize = 239;
/// Program header 1 lives at 0x78; `p_filesz`/`p_memsz` at +0x20/+0x28.
const PH1_FILESZ: usize = 0x98;
const PH1_MEMSZ: usize = 0xa0;
const SEGMENT_END: u64 = 0x44_26f0;
/// Relocated section-header table and `.shstrtab` (past the copies).
const SHDR_OFF: usize = 0xe5_d658;
const SHDR_COUNT: usize = 25;
const SHSTRTAB_INDEX: usize = 24;
const E_SHOFF: usize = 0x28;
/// Verdict trampoline: `b.lt` (pristine) -> `nop`.
const LAYER2_TRAMPOLINE: usize = 0x62_5380;
const TRAMPOLINE_PRISTINE: u32 = 0x5400_00ab;
const TRAMPOLINE_NOP: u32 = 0xd503_201f;

/// Game TCP connect paths that filter private IPv4 peer addresses.
///
/// The client has two structurally similar resolve-and-connect routines.  Each
/// rejects 10/8, 127/8, 172.0-31.x and 192.168/16 before `socket()`; the record
/// is the single region-table entry covering the whole function.
///
/// For each entry, the filter instruction is replaced by an unconditional
/// branch to the function's `socket()` block, after its sockaddr argument has
/// been loaded.  A pristine copy of the function is appended in the RW segment
/// and the covering region record is retargeted at it, so the integrity VM
/// still reads the original bytes.
struct RangeBypass {
    function: usize,
    len: usize,
    record: usize,
    filter: usize,
    pristine: u32,
    bypass: u32,
}

const RANGE_BYPASSES: [RangeBypass; 2] = [
    RangeBypass {
        // Self-contained resolver+connect used by the connection helpers.
        function: 0x61_21fc,
        len: 0x470,
        record: 41_345,
        filter: 0x61_2448,
        pristine: 0x7102_b13f, // cmp w9, #0xac
        bypass: 0x1400_000e,   // b 0x612480 (socket/connect block)
    },
    RangeBypass {
        // Resolve-and-connect routine fed by the configured server address.
        function: 0x58_bbf8,
        len: 0x464,
        record: 19_651,
        filter: 0x58_bc6c,
        pristine: 0x7100_293f, // cmp w9, #0xa
        bypass: 0x1400_000c,   // b 0x58bc9c (socket/connect block)
    },
];
/// VA of the RW `PT_LOAD` (`p_vaddr`), used to extend it over appended copies.
const RW_SEGMENT_VA: u64 = 0xa2_af68;

/// One decoded region-table record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    /// `addr - TABLE_VA`, modulo 2^32 (the walk's delta form).
    delta: u32,
    len: u32,
    x454: u32,
}

/// Decode the region walk: `delta_i = a_i - a_{i-1} - b_{i-1} - c_{i-1}`,
/// `len_i = a_i - b_i + b_{i-1}`, `x454_i = c_i - b_i - c_{i-1}` (mod 2^32),
/// for records 1..=tot terminator (`len == 0`).
fn walk(records: &[(u32, u32, u32)]) -> Result<(Vec<Record>, usize)> {
    let (mut pa, mut pb, mut pc) = records[0];
    let mut out = Vec::with_capacity(records.len());
    for (index, &(a, b, c)) in records.iter().enumerate().skip(1) {
        let delta = a.wrapping_sub(pa).wrapping_sub(pb).wrapping_sub(pc);
        let len = a.wrapping_sub(b).wrapping_add(pb);
        let x454 = c.wrapping_sub(b).wrapping_sub(pc);
        out.push(Record { delta, len, x454 });
        pa = a;
        pb = b;
        pc = c;
        if len == 0 {
            ensure!(
                index == records.len() - 1,
                "region table ends early at record {index}"
            );
            return Ok((out, index));
        }
    }
    bail!("region table has no terminator");
}

/// Retarget record `index` at `new_va`, preserving its length and `x454`, and
/// propagate the fixup through every following record up to the terminator.
fn retarget(
    records: &mut [(u32, u32, u32)],
    original: &[Record],
    index: usize,
    new_va: u64,
) -> Result<()> {
    ensure!(index > 0 && index <= original.len(), "record out of range");
    let target = original[index - 1];
    let delta = (new_va - TABLE_VA) as u32;
    let (a_prev, b_prev, c_prev) = records[index - 1];
    let a_new = a_prev
        .wrapping_add(b_prev)
        .wrapping_add(c_prev)
        .wrapping_add(delta);
    let b_new = a_new.wrapping_add(b_prev).wrapping_sub(target.len);
    let c_new = target.x454.wrapping_add(b_new).wrapping_add(c_prev);
    records[index] = (a_new, b_new, c_new);
    for j in index + 1..=original.len() {
        let orig = original[j - 1];
        let (a_prev, b_prev, c_prev) = records[j - 1];
        let a = a_prev
            .wrapping_add(b_prev)
            .wrapping_add(c_prev)
            .wrapping_add(orig.delta);
        let b = a.wrapping_add(b_prev).wrapping_sub(orig.len);
        let c = orig.x454.wrapping_add(b).wrapping_add(c_prev);
        records[j] = (a, b, c);
    }
    Ok(())
}

/// Apply the verified ARM64 neutralisation in place.  Must run on the
/// *pristine* library (the caller has already validated its SHA-256).
pub fn harden(data: &mut Vec<u8>) -> Result<()> {
    ensure!(
        data.len() >= 0xe4_ab98,
        "library shorter than its original image"
    );
    // The copies sit after the relocated section headers + `.shstrtab`.
    let end = SHDR_OFF + SHDR_COUNT * 64 + SHSTRTAB_LEN;

    // Capture everything sourced from the pristine image before any write.
    ensure!(
        u64_at(data, E_SHOFF) == SHDR_OLD as u64,
        "unexpected e_shoff"
    );
    let shstrtab = data[SHSTRTAB_OLD..SHSTRTAB_OLD + SHSTRTAB_LEN].to_vec();
    let mut shdrs = data[SHDR_OLD..SHDR_OLD + SHDR_COUNT * 64].to_vec();
    let mut copies: Vec<(usize, u64, Vec<u8>)> = Vec::with_capacity(COPIES.len());
    for &(source, len, copy_va) in &COPIES {
        ensure!(source + len <= end, "copy source out of range");
        copies.push((len, copy_va, data[source..source + len].to_vec()));
    }

    // --- 1. extend the image and append the pristine copies ---------------
    data.resize(end, 0);
    for (len, copy_va, copy) in &copies {
        let target = *copy_va as usize - RW_DELTA;
        ensure!(target + len <= end, "copy target out of range");
        data[target..target + len].copy_from_slice(copy);
    }

    // --- 2. zero every file byte that will map into `.bss` ----------------
    for &(offset, len) in &BSS_MAPPED_NONZERO {
        data[offset..offset + len].fill(0);
    }
    data[PAD_RANGE.0..PAD_RANGE.1].fill(0);

    // --- 3. relocate the section headers and `.shstrtab` ------------------
    let shstrtab_off = SHDR_OFF + SHDR_COUNT * 64;
    put_u64(&mut shdrs, SHSTRTAB_INDEX * 64 + 0x18, shstrtab_off as u64);
    data[SHDR_OFF..SHDR_OFF + shdrs.len()].copy_from_slice(&shdrs);
    data[shstrtab_off..shstrtab_off + SHSTRTAB_LEN].copy_from_slice(&shstrtab);
    put_u64(data, E_SHOFF, SHDR_OFF as u64);

    // --- 2b. extend PT_LOAD[1] over the copies ----------------------------
    ensure!(
        u64_at(data, PH1_FILESZ) == 0x41_5e70 && u64_at(data, PH1_MEMSZ) == 0x43_c7a0,
        "unexpected PT_LOAD[1] size fields"
    );
    put_u64(data, PH1_FILESZ, SEGMENT_END);
    put_u64(data, PH1_MEMSZ, SEGMENT_END);

    // --- 4. disarm the verdict trampoline ---------------------------------
    ensure!(
        u32_at(data, LAYER2_TRAMPOLINE) == TRAMPOLINE_PRISTINE,
        "unexpected bytes at the Layer-2 trampoline"
    );
    put_u32(data, LAYER2_TRAMPOLINE, TRAMPOLINE_NOP);

    // --- 5. retarget the C1/C2/C3 region records --------------------------
    ensure!(
        TABLE_OFF + TABLE_RECORDS * 12 <= data.len(),
        "region table out of range"
    );
    let records: Vec<(u32, u32, u32)> = (0..TABLE_RECORDS)
        .map(|i| {
            let o = TABLE_OFF + i * 12;
            (u32_at(data, o), u32_at(data, o + 4), u32_at(data, o + 8))
        })
        .collect();
    let (original, terminator) = walk(&records)?;
    ensure!(
        terminator == TABLE_RECORDS - 1,
        "unexpected region table terminator {terminator}"
    );
    // The walk must describe the pristine functions at the expected records.
    for &(record, copy_index) in &[(RECORD_C3, 2usize), (RECORD_C2, 1), (RECORD_C1, 0)] {
        let (source, len, _) = COPIES[copy_index];
        let orig = original[record - 1];
        ensure!(
            orig.len as usize == len,
            "region record {record} length {} != {len}",
            orig.len
        );
        // Addresses below the table base carry a negative delta.
        let addr = TABLE_VA as i64 + orig.delta as i32 as i64;
        ensure!(
            addr == source as i64,
            "region record {record} does not cover 0x{source:x}"
        );
    }
    let mut patched = records.clone();
    for &(record, copy_index) in &[(RECORD_C3, 2usize), (RECORD_C2, 1), (RECORD_C1, 0)] {
        retarget(&mut patched, &original, record, COPIES[copy_index].2)?;
    }

    // --- verify the walk now reports pristine data everywhere -------------
    let (after, term_after) = walk(&patched)?;
    ensure!(term_after == terminator, "walk length changed");
    for (i, (orig, new)) in original.iter().zip(&after).enumerate() {
        let index = i + 1;
        let retargeted = [(RECORD_C1, 0usize), (RECORD_C2, 1), (RECORD_C3, 2)]
            .iter()
            .find(|(record, _)| *record == index);
        match retargeted {
            Some(&(_, copy_index)) => {
                ensure!(
                    TABLE_VA + new.delta as u64 == COPIES[copy_index].2,
                    "record {index} was not retargeted"
                );
                ensure!(
                    new.len == orig.len && new.x454 == orig.x454,
                    "record {index} length/selector changed"
                );
            }
            None => ensure!(new == orig, "record {index} changed unexpectedly"),
        }
    }
    for (i, (old, new)) in records.iter().zip(&patched).enumerate() {
        if old != new {
            let o = TABLE_OFF + i * 12;
            put_u32(data, o, new.0);
            put_u32(data, o + 4, new.1);
            put_u32(data, o + 8, new.2);
        }
    }
    Ok(())
}

/// Remove the native private-IPv4 filter from the ARM64 game connect path.
///
/// Must run after [`harden`] (normally via `key::patch` with an ARM64
/// key), because the appended copy uses the layout hardened by extending
/// `PT_LOAD[1]`.  A pristine copy of the whole filter function is appended in
/// the RW segment past the existing copies, the covering region-table record
/// is retargeted at it, and only then is the filter instruction patched.  The
/// integrity VM therefore still reads the original function bytes.
pub fn allow_local_ranges(data: &mut Vec<u8>) -> Result<()> {
    ensure!(
        u64_at(data, PH1_FILESZ) == SEGMENT_END && u64_at(data, PH1_MEMSZ) == SEGMENT_END,
        "local-range bypass requires the hardened ARM64 layout"
    );
    for target in &RANGE_BYPASSES {
        ensure!(
            u32_at(data, target.filter) == target.pristine,
            "unexpected address-filter instruction at {:#x}",
            target.filter
        );
    }

    // Keep the pristine function bytes (including the instructions to patch),
    // then append each copy at a 16-byte aligned offset past the headers.
    let copies: Vec<Vec<u8>> = RANGE_BYPASSES
        .iter()
        .map(|target| data[target.function..target.function + target.len].to_vec())
        .collect();
    let mut copy_offsets = Vec::with_capacity(RANGE_BYPASSES.len());
    let mut offset = data.len();
    for target in &RANGE_BYPASSES {
        offset = (offset + 15) & !15;
        copy_offsets.push(offset);
        offset += target.len;
    }
    let final_end = offset;
    data.resize(final_end, 0);
    for ((target, copy), &copy_off) in RANGE_BYPASSES.iter().zip(&copies).zip(&copy_offsets) {
        data[copy_off..copy_off + target.len].copy_from_slice(copy);
    }

    // The RW segment must map the copies for the integrity walk to read them.
    let segment_size = final_end as u64 + RW_DELTA as u64 - RW_SEGMENT_VA;
    put_u64(data, PH1_FILESZ, segment_size);
    put_u64(data, PH1_MEMSZ, segment_size);

    // Retarget each covering region record at its pristine copy, in ascending
    // record order so the delta-chain fixups compose.
    ensure!(
        TABLE_OFF + TABLE_RECORDS * 12 <= data.len(),
        "region table out of range"
    );
    let records: Vec<(u32, u32, u32)> = (0..TABLE_RECORDS)
        .map(|i| {
            let o = TABLE_OFF + i * 12;
            (u32_at(data, o), u32_at(data, o + 4), u32_at(data, o + 8))
        })
        .collect();
    let (original, terminator) = walk(&records)?;
    ensure!(
        terminator == TABLE_RECORDS - 1,
        "unexpected region table terminator {terminator}"
    );
    for target in &RANGE_BYPASSES {
        let orig = original[target.record - 1];
        let addr = TABLE_VA as i64 + orig.delta as i32 as i64;
        ensure!(
            addr == target.function as i64 && orig.len as usize == target.len,
            "region record {} does not cover function {:#x}",
            target.record,
            target.function
        );
    }
    let mut patched = records.clone();
    let mut order: Vec<usize> = (0..RANGE_BYPASSES.len()).collect();
    order.sort_by_key(|&i| RANGE_BYPASSES[i].record);
    for &i in &order {
        let target = &RANGE_BYPASSES[i];
        let copy_va = copy_offsets[i] as u64 + RW_DELTA as u64;
        retarget(&mut patched, &original, target.record, copy_va)?;
    }

    let (after, term_after) = walk(&patched)?;
    ensure!(term_after == terminator, "walk length changed");
    for (i, (orig, new)) in original.iter().zip(&after).enumerate() {
        let index = i + 1;
        if let Some(pos) = RANGE_BYPASSES.iter().position(|t| t.record == index) {
            let copy_va = copy_offsets[pos] as u64 + RW_DELTA as u64;
            ensure!(
                TABLE_VA + new.delta as u64 == copy_va,
                "region record {index} was not retargeted"
            );
            ensure!(
                new.len == orig.len && new.x454 == orig.x454,
                "region record {index} length/selector changed"
            );
        } else {
            ensure!(new == orig, "record {index} changed unexpectedly");
        }
    }
    for (i, (old, new)) in records.iter().zip(&patched).enumerate() {
        if old != new {
            let o = TABLE_OFF + i * 12;
            put_u32(data, o, new.0);
            put_u32(data, o + 4, new.1);
            put_u32(data, o + 8, new.2);
        }
    }

    // Only now change the code; every integrity read still sees the copies.
    for target in &RANGE_BYPASSES {
        put_u32(data, target.filter, target.bypass);
    }
    Ok(())
}

// --- native `/env_settings` bootstrap URL -----------------------------------
//
// The URL is a string-table entry inside the checked `.data` region
// `0xb9c5d4..0xba682c` (record 45756). Copy that region from the input library
// at patch time and retarget its record, then rewrite the original URL and
// route the integrity VM's failure-only trap to its normal safe exit. No
// separately captured or generated client data is bundled with the patcher.
const BOOTSTRAP_REGION: usize = 0xb9_b5d4; // file offset (VA 0xb9c5d4)
const BOOTSTRAP_REGION_LEN: usize = 0xa258;
const BOOTSTRAP_REGION_VA: u64 = 0xb9_c5d4;
const BOOTSTRAP_RECORD: usize = 45_756;
/// Failure-only VM trap and its normal safe-exit path. Redirecting this one
/// branch avoids depending on per-run accumulator values for the rebuilt table.
const BOOTSTRAP_VM_TRAP: usize = 0x6a_bff8;
const BOOTSTRAP_VM_TRAP_PRISTINE: u32 = 0xd63f_0100; // blr x8
const BOOTSTRAP_VM_SAFE_BRANCH: u32 = 0x1400_0375; // b 0x6acdcc
const BOOTSTRAP_URL_FILE: usize = 0xb9_b9bc; // VA 0xb9c9bc
const BOOTSTRAP_URL_PLAIN: &[u8] =
    b"http://gamea.haydaygame.com:8080/env_settings?version=%d.%d.%d&platform=%s&store=%d";
const BOOTSTRAP_PATH: &str = "/env_settings?version=%d.%d.%d&platform=%s&store=%d";
const BOOTSTRAP_XOR: [u8; 128] = [
    0x16, 0xd1, 0x71, 0x92, 0x17, 0x11, 0x1a, 0x27, 0x5d, 0x69, 0xd0, 0xb3, 0x08, 0x48, 0x29, 0xa5,
    0x6a, 0x6f, 0x5b, 0xe8, 0x1e, 0x51, 0x5c, 0x08, 0x68, 0x4a, 0x0d, 0x96, 0x07, 0x0b, 0x71, 0xa5,
    0xae, 0x83, 0x20, 0x66, 0xf4, 0x89, 0x8b, 0x7b, 0x25, 0xd4, 0xd3, 0x3e, 0x78, 0x68, 0x50, 0xac,
    0x90, 0x23, 0x29, 0x5d, 0x01, 0x56, 0x6e, 0x65, 0x66, 0x39, 0x08, 0x70, 0xe5, 0xbb, 0xc2, 0xd9,
    0xc8, 0x21, 0xca, 0x39, 0xb4, 0xa8, 0x61, 0x21, 0x70, 0x9e, 0x04, 0x33, 0x40, 0x67, 0x7e, 0xf3,
    0xc6, 0xde, 0x51, 0x52, 0x0e, 0xcf, 0x7e, 0x81, 0xca, 0xd3, 0x8f, 0x11, 0x4c, 0xa3, 0x61, 0x78,
    0xe7, 0x01, 0x52, 0xb7, 0x82, 0xb6, 0x89, 0x73, 0xa6, 0xf5, 0xa9, 0x74, 0x39, 0x50, 0xb7, 0x59,
    0xcc, 0xdf, 0x77, 0xb7, 0xd1, 0x21, 0xaf, 0x42, 0x68, 0xb4, 0x7f, 0x23, 0x31, 0x98, 0x28, 0x08,
];

/// Rewrite the native `/env_settings` URL on an already hardened ARM64 image.
/// The appended integrity copy is extracted from `data`, not bundled.
pub fn patch_bootstrap_url(data: &mut Vec<u8>, base_url: &str) -> Result<()> {
    ensure!(
        data.len() >= BOOTSTRAP_REGION + BOOTSTRAP_REGION_LEN,
        "library too short for the bootstrap region"
    );
    let mut plain = Vec::with_capacity(BOOTSTRAP_URL_PLAIN.len());
    for i in 0..BOOTSTRAP_URL_PLAIN.len() {
        plain.push(data[BOOTSTRAP_URL_FILE + i] ^ BOOTSTRAP_XOR[i & 0x7f]);
    }
    ensure!(
        plain == BOOTSTRAP_URL_PLAIN,
        "unexpected ARM64 bootstrap URL at 0xb9c9bc: {:?}",
        String::from_utf8_lossy(&plain)
    );

    let base = base_url.trim().trim_end_matches('/');
    let Some((scheme, rest)) = base.split_once("://") else {
        bail!("--bootstrap-url must be scheme://host[:port]");
    };
    ensure!(
        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"),
        "unsupported bootstrap scheme {scheme:?} (use http or https)"
    );
    let authority = rest.split('/').next().unwrap_or("");
    ensure!(!authority.is_empty(), "--bootstrap-url is missing the host");
    let new_url = format!("{scheme}://{authority}{BOOTSTRAP_PATH}");
    ensure!(
        new_url.len() <= BOOTSTRAP_URL_PLAIN.len(),
        "bootstrap URL is {} bytes but the native string only holds {}",
        new_url.len(),
        BOOTSTRAP_URL_PLAIN.len()
    );

    // Extract the checked region from the input image before changing its URL.
    let region = data[BOOTSTRAP_REGION..BOOTSTRAP_REGION + BOOTSTRAP_REGION_LEN].to_vec();
    let copy_off = (data.len() + 15) & !15;
    let copy_end = copy_off + BOOTSTRAP_REGION_LEN;
    data.resize(copy_end, 0);
    data[copy_off..copy_end].copy_from_slice(&region);
    let copy_va = copy_off as u64 + RW_DELTA as u64;
    let segment_size = copy_end as u64 + RW_DELTA as u64 - RW_SEGMENT_VA;
    put_u64(data, PH1_FILESZ, segment_size);
    put_u64(data, PH1_MEMSZ, segment_size);

    ensure!(
        TABLE_OFF + TABLE_RECORDS * 12 <= data.len(),
        "region table out of range"
    );
    let records: Vec<(u32, u32, u32)> = (0..TABLE_RECORDS)
        .map(|i| {
            let o = TABLE_OFF + i * 12;
            (u32_at(data, o), u32_at(data, o + 4), u32_at(data, o + 8))
        })
        .collect();
    let (original, terminator) = walk(&records)?;
    ensure!(
        terminator == TABLE_RECORDS - 1,
        "unexpected region table terminator {terminator}"
    );
    let orig = original[BOOTSTRAP_RECORD - 1];
    let addr = TABLE_VA as i64 + orig.delta as i32 as i64;
    ensure!(
        addr == BOOTSTRAP_REGION_VA as i64 && orig.len as usize == BOOTSTRAP_REGION_LEN,
        "region record {BOOTSTRAP_RECORD} does not cover the bootstrap string table"
    );
    let mut patched = records.clone();
    retarget(&mut patched, &original, BOOTSTRAP_RECORD, copy_va)?;
    let (after, term_after) = walk(&patched)?;
    ensure!(term_after == terminator, "walk length changed");
    for (i, (old, new)) in original.iter().zip(&after).enumerate() {
        let index = i + 1;
        if index == BOOTSTRAP_RECORD {
            ensure!(
                TABLE_VA + new.delta as u64 == copy_va,
                "bootstrap region record was not retargeted"
            );
            ensure!(
                new.len == old.len && new.x454 == old.x454,
                "bootstrap region length/selector changed"
            );
        } else {
            ensure!(new == old, "record {index} changed unexpectedly");
        }
    }
    for (i, (old, new)) in records.iter().zip(&patched).enumerate() {
        if old != new {
            let o = TABLE_OFF + i * 12;
            put_u32(data, o, new.0);
            put_u32(data, o + 4, new.1);
            put_u32(data, o + 8, new.2);
        }
    }

    // The rebuilt table does not have stable absolute accumulators across
    // launches. Route the failure-only trap to the VM's normal safe exit and
    // leave all comparison words untouched.
    ensure!(
        u32_at(data, BOOTSTRAP_VM_TRAP) == BOOTSTRAP_VM_TRAP_PRISTINE,
        "unexpected instruction at the bootstrap VM trap"
    );
    put_u32(data, BOOTSTRAP_VM_TRAP, BOOTSTRAP_VM_SAFE_BRANCH);

    // Only now change the URL the client reads.
    for (i, byte) in new_url.bytes().enumerate() {
        data[BOOTSTRAP_URL_FILE + i] = byte ^ BOOTSTRAP_XOR[i & 0x7f];
    }
    data[BOOTSTRAP_URL_FILE + new_url.len()] = BOOTSTRAP_XOR[new_url.len() & 0x7f];
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full-recipe golden test against the real library when present:
    /// patching with the reference server key must reproduce the byte-exact
    /// build that was verified on a device (sha256 below).
    #[test]
    fn real_library_matches_known_good_build() {
        let Ok(path) = std::env::var("HD_ARM64_LIBG") else {
            return;
        };
        let mut data = std::fs::read(path).unwrap();
        let key = crate::native::parse_key(
            "da4d59ba1e32c737b13f3b81be5070f894c773e246a0dc6e5149bd090b4aeb32",
        )
        .unwrap();
        crate::native::key::patch(crate::native::Abi::Arm64, &mut data, &key).unwrap();
        if let Ok(out) = std::env::var("HD_ARM64_DUMP") {
            std::fs::write(out, &data).unwrap();
        }
        let digest = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&data)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            digest,
            "bbbc681a195e2218a21b6673e2833fcc91e917c20b1b2ac4273487bda7467efd"
        );
    }

    /// The region-table fixup must leave every other record untouched.
    #[test]
    fn retarget_preserves_all_other_records() {
        // Synthetic 5-record table with a terminator.
        let mut records = vec![(0u32, 1u32, 2u32)];
        for i in 0..5u32 {
            // Well-formed chain: a_i = a_{i-1}+b_{i-1}+c_{i-1}+delta.
            let (a_prev, b_prev, c_prev) = *records.last().unwrap();
            let len = if i == 4 { 0 } else { 100 + i };
            let a = a_prev
                .wrapping_add(b_prev)
                .wrapping_add(c_prev)
                .wrapping_add(0x1000);
            let b = a.wrapping_add(b_prev).wrapping_sub(len);
            records.push((a, b, 7 * i));
        }
        let (original, term) = walk(&records).unwrap();
        assert_eq!(term, 5);
        let mut patched = records.clone();
        retarget(&mut patched, &original, 2, TABLE_VA + 0x9000).unwrap();
        let (after, _) = walk(&patched).unwrap();
        assert_eq!(after[1].delta, 0x9000);
        assert_eq!(after[1].len, original[1].len);
        assert_eq!(after[1].x454, original[1].x454);
        for (i, (o, n)) in original.iter().zip(&after).enumerate() {
            if i != 1 {
                assert_eq!(o, n, "record {} changed", i + 1);
            }
        }
    }

    /// The real library: reroute both connect filters to pristine copies.
    #[test]
    fn local_range_bypass_retargets_connect_regions() {
        let Ok(path) = std::env::var("HD_ARM64_LIBG") else {
            return;
        };
        let pristine = std::fs::read(&path).unwrap();
        let mut data = pristine.clone();
        let key = crate::native::parse_key(
            "da4d59ba1e32c737b13f3b81be5070f894c773e246a0dc6e5149bd090b4aeb32",
        )
        .unwrap();
        crate::native::key::patch(crate::native::Abi::Arm64, &mut data, &key).unwrap();
        allow_local_ranges(&mut data).unwrap();

        // Copies are appended in RANGE_BYPASSES order from the hardened length.
        let mut copy_offsets = Vec::new();
        let mut offset = 0xe5_dd87;
        for target in &RANGE_BYPASSES {
            offset = (offset + 15) & !15;
            copy_offsets.push(offset);
            offset += target.len;
        }
        for (target, &copy_off) in RANGE_BYPASSES.iter().zip(&copy_offsets) {
            assert_eq!(u32_at(&data, target.filter), target.bypass);
            assert_eq!(
                &data[copy_off..copy_off + target.len],
                &pristine[target.function..target.function + target.len],
                "copy is not the pristine function"
            );
        }
        let final_end = offset;
        assert_eq!(
            u64_at(&data, PH1_FILESZ),
            final_end as u64 + RW_DELTA as u64 - RW_SEGMENT_VA
        );

        let records: Vec<(u32, u32, u32)> = (0..TABLE_RECORDS)
            .map(|i| {
                let o = TABLE_OFF + i * 12;
                (u32_at(&data, o), u32_at(&data, o + 4), u32_at(&data, o + 8))
            })
            .collect();
        let (after, _) = walk(&records).unwrap();
        for (target, &copy_off) in RANGE_BYPASSES.iter().zip(&copy_offsets) {
            assert_eq!(
                TABLE_VA + after[target.record - 1].delta as u64,
                copy_off as u64 + RW_DELTA as u64,
                "region record {} not retargeted",
                target.record
            );
            assert_eq!(after[target.record - 1].len as usize, target.len);
        }
    }

    /// The real library: derive the appended region from the input library at
    /// patch time. No separately captured runtime fixture is permitted.
    #[test]
    fn bootstrap_url_copies_region_from_input_library() {
        let Ok(path) = std::env::var("HD_ARM64_LIBG") else {
            return;
        };
        let pristine = std::fs::read(&path).unwrap();
        let mut data = pristine.clone();
        let key = crate::native::parse_key(
            "da4d59ba1e32c737b13f3b81be5070f894c773e246a0dc6e5149bd090b4aeb32",
        )
        .unwrap();
        crate::native::key::patch(crate::native::Abi::Arm64, &mut data, &key).unwrap();
        allow_local_ranges(&mut data).unwrap();
        let before_len = data.len();

        let base = "http://192.168.1.38:8081";
        patch_bootstrap_url(&mut data, base).unwrap();

        let copy_off = (before_len + 15) & !15;
        assert_eq!(data.len(), copy_off + 0xa258);
        assert_eq!(
            &data[copy_off..],
            &pristine[0xb9_b5d4..0xb9_b5d4 + 0xa258],
            "bootstrap copy was not extracted from the input library"
        );

        let copy_va = copy_off as u64 + RW_DELTA as u64;
        let records: Vec<(u32, u32, u32)> = (0..TABLE_RECORDS)
            .map(|i| {
                let o = TABLE_OFF + i * 12;
                (u32_at(&data, o), u32_at(&data, o + 4), u32_at(&data, o + 8))
            })
            .collect();
        let (after, _) = walk(&records).unwrap();
        assert_eq!(TABLE_VA + after[45_756 - 1].delta as u64, copy_va);
        assert_eq!(u32_at(&data, BOOTSTRAP_VM_TRAP), BOOTSTRAP_VM_SAFE_BRANCH);

        let expected = format!("{base}{BOOTSTRAP_PATH}");
        let mut plain = Vec::new();
        for i in 0..expected.len() + 1 {
            plain.push(data[BOOTSTRAP_URL_FILE + i] ^ BOOTSTRAP_XOR[i & 0x7f]);
        }
        assert_eq!(&plain[..expected.len()], expected.as_bytes());
        assert_eq!(plain[expected.len()], 0);
    }
}
