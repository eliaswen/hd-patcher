//! x86 local-range handling and native HTTP bootstrap rewrite.
//!
//! ## Local ranges
//!
//! Both game connect routines reject private IPv4 results before `connect()`.
//! Their code is integrity-checked, but the `getaddrinfo@plt` entry at
//! `0x74e70` is not. The bypass therefore leaves both routines untouched and
//! redirects that PLT entry to a 163-byte wrapper in the extended RX segment.
//!
//! The wrapper calls the original `getaddrinfo` through its GOT slot, then
//! expands each filtered AF_INET result's `sockaddr_in` in place into an
//! IPv4-mapped `sockaddr_in6`. Bionic backs `ai_addr` with an inline
//! `sockaddr_storage`, so no allocation or free is needed. The native
//! AF_INET6 fast path skips the range checks and the kernel routes the mapped
//! address over IPv4. Only 10/8, 127/8, 172.0-31.x and 192.168/16 are changed;
//! public IPv4 and native IPv6 results pass through unchanged.
//!
//! ## Bootstrap URL
//!
//! The native `/env_settings` URL lives in the XOR-obfuscated `.data` string
//! table:
//!
//! ```text
//! VA 0xcd209f (file 0xcd109f):
//! http://gamea.haydaygame.com:8080/env_settings?version=%d.%d.%d&platform=%s&store=%d
//! plain[i] = cipher[i] ^ table[i & 0x7f]; table at file 0xbc5e31
//! ```
//!
//! Re-encrypting that string in place crashes the client (the `.data` string
//! table is integrity-checked: verified live with the identical replacement at
//! the same length). Instead, both `lea` references to the string are
//! redirected to a **plaintext** copy appended to the extended RX segment:
//!
//! ```text
//! 53dac7  lea edx,[ebx+0x74b2b]   ; alternate URL (stage/fallback)
//! 53dacd  lea ecx,[ebx+0x182557]  ; production URL (0xcd209f)
//! ```
//!
//! The `.data` ciphertext and the XOR table stay pristine; only the two
//! displacements, the RX `p_filesz`/`p_memsz`, and the appended URL change.

use anyhow::{bail, ensure, Result};

use super::{put_u32, u32_at};

const GETADDRINFO_PLT: usize = 0x74_e70;
const GETADDRINFO_PLT_BYTES: [u8; 6] = [0xff, 0xa3, 0xe4, 0x01, 0x00, 0x00];
const FAMILY_CHECK: usize = 0x3b_4c03;
const FILTER_A: usize = 0x3b_4c11;
const FILTER_B: usize = 0x47_8582;

/// Position-independent getaddrinfo wrapper, linked at `WRAPPER_OFF`.
/// `ebx` is the client's usual PIC base (`0xb4fb48`), so +0x1e4 selects the
/// original getaddrinfo GOT entry.
const WRAPPER_OFF: usize = 0xb0_d400;
const WRAPPER: [u8; 163] = [
    0x55, 0x89, 0xe5, 0x53, 0x56, 0x57, 0x83, 0xec, 0x0c, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x5b, 0x81,
    0xc3, 0x3a, 0x27, 0x04, 0x00, 0xff, 0x75, 0x14, 0xff, 0x75, 0x10, 0xff, 0x75, 0x0c, 0xff, 0x75,
    0x08, 0xff, 0x93, 0xe4, 0x01, 0x00, 0x00, 0x83, 0xc4, 0x10, 0x85, 0xc0, 0x75, 0x6d, 0x8b, 0x75,
    0x14, 0x8b, 0x36, 0x85, 0xf6, 0x74, 0x62, 0x83, 0x7e, 0x04, 0x02, 0x75, 0x57, 0x8b, 0x4e, 0x18,
    0x8b, 0x51, 0x04, 0x80, 0xfa, 0x0a, 0x74, 0x16, 0x80, 0xfa, 0x7f, 0x74, 0x11, 0x66, 0x81, 0xfa,
    0xc0, 0xa8, 0x74, 0x0a, 0x80, 0xfa, 0xac, 0x75, 0x3b, 0xf6, 0xc6, 0xe0, 0x75, 0x36, 0x89, 0xcf,
    0x66, 0x8b, 0x4f, 0x02, 0x89, 0x55, 0xf0, 0x0f, 0x57, 0xc0, 0x0f, 0x11, 0x07, 0x0f, 0x11, 0x47,
    0x0c, 0x66, 0xc7, 0x07, 0x0a, 0x00, 0x66, 0x89, 0x4f, 0x02, 0x8b, 0x55, 0xf0, 0x89, 0x57, 0x14,
    0x66, 0xc7, 0x47, 0x12, 0xff, 0xff, 0xc7, 0x46, 0x04, 0x0a, 0x00, 0x00, 0x00, 0xc7, 0x46, 0x10,
    0x1c, 0x00, 0x00, 0x00, 0x8b, 0x76, 0x1c, 0xeb, 0x9a, 0x31, 0xc0, 0x83, 0xc4, 0x0c, 0x5f, 0x5e,
    0x5b, 0x5d, 0xc3,
];

const LEA_ALT: usize = 0x53_dac7;
const LEA_DEFAULT: usize = 0x53_dacd;
const LEA_ALT_BYTES: [u8; 6] = [0x8d, 0x93, 0x2b, 0x4b, 0x07, 0x00];
const LEA_DEFAULT_BYTES: [u8; 6] = [0x8d, 0x8b, 0x57, 0x25, 0x18, 0x00];
const PIC_BASE: u32 = 0xb4_fb48;

const BOOTSTRAP_STR: usize = 0xb0_d1f0; // first bytes of the inter-segment RX gap
const BOOTSTRAP_PATH: &str = "/env_settings?version=%d.%d.%d&platform=%s&store=%d";
const RX_FILESZ: usize = 0x64;
const RX_MEMSZ: usize = 0x68;
const RX_OLD_END: u32 = 0xb0_d1e8;
const RX_RW_START: usize = 0xb0_e0d0; // RW segment file start, gap must not reach it

pub fn allow_local_ranges(data: &mut [u8]) -> Result<()> {
    ensure!(
        data[GETADDRINFO_PLT..GETADDRINFO_PLT + 6] == GETADDRINFO_PLT_BYTES,
        "unexpected x86 getaddrinfo PLT entry at 0x74e70"
    );
    ensure!(
        data[FAMILY_CHECK..FAMILY_CHECK + 5] == [0x83, 0xf8, 0x02, 0x75, 0x48],
        "unexpected x86 connect family check at 0x3b4c03"
    );
    ensure!(
        data[FILTER_A..FILTER_A + 3] == [0x83, 0xfa, 0x0a],
        "unexpected x86 private-IPv4 filter at 0x3b4c11"
    );
    ensure!(
        data[FILTER_B..FILTER_B + 6] == [0x81, 0xfa, 0xac, 0x00, 0x00, 0x00],
        "unexpected x86 private-IPv4 filter at 0x478582"
    );
    ensure!(
        u32_at(data, RX_FILESZ) == RX_OLD_END && u32_at(data, RX_MEMSZ) == RX_OLD_END,
        "local-range bypass requires the pristine x86 RX segment sizes"
    );
    let wrapper_end = WRAPPER_OFF + WRAPPER.len();
    ensure!(wrapper_end <= RX_RW_START, "x86 wrapper exceeds the RX gap");
    ensure!(
        data[WRAPPER_OFF..wrapper_end].iter().all(|&b| b == 0),
        "x86 wrapper space is not zero-filled"
    );

    data[WRAPPER_OFF..wrapper_end].copy_from_slice(&WRAPPER);
    data[GETADDRINFO_PLT] = 0xe9;
    let displacement = (WRAPPER_OFF as i64 - (GETADDRINFO_PLT + 5) as i64) as i32;
    put_u32(data, GETADDRINFO_PLT + 1, displacement as u32);
    data[GETADDRINFO_PLT + 5] = 0x90;
    put_u32(data, RX_FILESZ, wrapper_end as u32);
    put_u32(data, RX_MEMSZ, wrapper_end as u32);
    Ok(())
}

pub fn patch_bootstrap_url(data: &mut [u8], base_url: &str) -> Result<()> {
    ensure!(
        data[LEA_ALT..LEA_ALT + 6] == LEA_ALT_BYTES,
        "unexpected alternate bootstrap lea at 0x53dac7"
    );
    ensure!(
        data[LEA_DEFAULT..LEA_DEFAULT + 6] == LEA_DEFAULT_BYTES,
        "unexpected default bootstrap lea at 0x53dacd"
    );
    let rx_end = u32_at(data, RX_FILESZ);
    ensure!(
        rx_end == u32_at(data, RX_MEMSZ)
            && rx_end >= RX_OLD_END
            && (rx_end as usize) <= RX_RW_START,
        "unexpected x86 RX segment sizes"
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

    let url = format!("{scheme}://{authority}{BOOTSTRAP_PATH}");
    let end = BOOTSTRAP_STR + url.len() + 1;
    ensure!(
        end <= RX_RW_START,
        "bootstrap URL is {} bytes and does not fit the RX gap",
        url.len()
    );
    ensure!(
        data[BOOTSTRAP_STR..end].iter().all(|&b| b == 0),
        "x86 RX gap is not zero-filled"
    );

    data[BOOTSTRAP_STR..BOOTSTRAP_STR + url.len()].copy_from_slice(url.as_bytes());
    data[BOOTSTRAP_STR + url.len()] = 0;

    let disp = (BOOTSTRAP_STR as i64 - PIC_BASE as i64) as i32 as u32;
    put_u32(data, LEA_ALT + 2, disp);
    put_u32(data, LEA_DEFAULT + 2, disp);
    let new_end = end.max(rx_end as usize);
    put_u32(data, RX_FILESZ, new_end as u32);
    put_u32(data, RX_MEMSZ, new_end as u32);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original() -> Option<Vec<u8>> {
        std::fs::read(std::env::var_os("HD_X86_LIBG")?).ok()
    }

    #[test]
    fn local_range_bypass_wraps_getaddrinfo_without_touching_connect_code() {
        let Some(mut data) = original() else { return };
        let pristine = data.clone();
        allow_local_ranges(&mut data).unwrap();

        // The integrity-checked connect routines stay byte-identical.
        assert_eq!(&data[0x3b4bb0..0x3b50f8], &pristine[0x3b4bb0..0x3b50f8]);
        assert_eq!(&data[0x478250..0x47880e], &pristine[0x478250..0x47880e]);
        assert_eq!(&data[WRAPPER_OFF..WRAPPER_OFF + WRAPPER.len()], &WRAPPER);
        assert_eq!(data[GETADDRINFO_PLT], 0xe9);
        assert_eq!(data[GETADDRINFO_PLT + 5], 0x90);
        let displacement = u32_at(&data, GETADDRINFO_PLT + 1) as i32 as i64;
        assert_eq!(
            (GETADDRINFO_PLT as i64 + 5 + displacement) as usize,
            WRAPPER_OFF
        );
        assert_eq!(
            u32_at(&data, RX_FILESZ),
            (WRAPPER_OFF + WRAPPER.len()) as u32
        );

        // The two RX-gap edits compose in normal patch_library order.
        patch_bootstrap_url(&mut data, "http://192.168.240.1:18082").unwrap();
        assert_eq!(&data[WRAPPER_OFF..WRAPPER_OFF + WRAPPER.len()], &WRAPPER);
        assert_eq!(
            u32_at(&data, RX_FILESZ),
            (WRAPPER_OFF + WRAPPER.len()) as u32
        );
        assert_eq!(u32_at(&data, RX_MEMSZ), u32_at(&data, RX_FILESZ));
    }

    #[test]
    fn redirects_bootstrap_url_to_rx_gap() {
        let Some(mut data) = original() else { return };
        let pristine_data_url = data[0xcd_109f..0xcd_109f + 83].to_vec();
        let base = "http://192.168.240.1:18080";
        patch_bootstrap_url(&mut data, base).unwrap();

        // The integrity-checked .data ciphertext must stay untouched.
        assert_eq!(&data[0xcd_109f..0xcd_109f + 83], &pristine_data_url[..]);

        let expected = format!("{base}{BOOTSTRAP_PATH}");
        assert_eq!(
            &data[BOOTSTRAP_STR..BOOTSTRAP_STR + expected.len()],
            expected.as_bytes()
        );
        assert_eq!(data[BOOTSTRAP_STR + expected.len()], 0);

        for lea in [LEA_ALT, LEA_DEFAULT] {
            let disp = u32_at(&data, lea + 2) as i32 as i64;
            assert_eq!(
                (PIC_BASE as i64 + disp) as u32,
                BOOTSTRAP_STR as u32,
                "lea at {lea:#x} does not target the new string"
            );
        }
        assert_eq!(
            u32_at(&data, RX_FILESZ),
            (BOOTSTRAP_STR + expected.len() + 1) as u32
        );
    }

    #[test]
    fn rejects_bootstrap_url_that_does_not_fit() {
        let Some(mut data) = original() else { return };
        let long = format!("http://{}{}", "a".repeat(5000), ":18080");
        assert!(patch_bootstrap_url(&mut data, &long).is_err());
    }
}
