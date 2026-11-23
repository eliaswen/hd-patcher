//! x86 local-range handling and native HTTP bootstrap rewrite.
//!
//! ## Local ranges
//!
//! The x86 build integrity-checks the game connect path: editing the filter in
//! `0x3b4bb0`, retargeting its vtable slot, or even redirecting the slot to a
//! byte-identical relocated clone crashes the client in the GL thread (proven
//! live on Waydroid). The filter itself is AF_INET-only:
//!
//! ```text
//! 3b4c00  mov eax,[esi+4]     ; ai_family
//! 3b4c03  cmp eax,2
//! 3b4c06  jne 3b4c50          ; non-IPv4 -> socket()/connect() directly
//! ...
//! 3b4c11  cmp edx,0xa         ; 10.0.0.0/8   -> skip
//! 3b4c1a  cmp edx,0x7f        ; 127.0.0.0/8  -> skip
//! 3b4c26  cmp edx,0xac        ; 172.16/12    -> skip
//! 3b4c37  cmp ecx,0xc0a8      ; 192.168/16   -> skip
//! ```
//!
//! Therefore the supported bypass is data-only: advertise the server as an
//! IPv4-mapped IPv6 address (`::ffff:a.b.c.d`). `getaddrinfo` returns family 10,
//! the `jne` skips every IPv4 range check, and the kernel routes the v4-mapped
//! connect over IPv4. Verified on Waydroid: TCP established and the farm loaded.
//!
//! `allow_local_ranges` deliberately does not modify the library; it validates
//! that the expected filter and IPv6 fast path are present.
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

const FAMILY_CHECK: usize = 0x3b_4c03;
const FILTER: usize = 0x3b_4c11;

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

pub fn allow_local_ranges(data: &[u8]) -> Result<()> {
    ensure!(
        data[FAMILY_CHECK..FAMILY_CHECK + 5] == [0x83, 0xf8, 0x02, 0x75, 0x48],
        "unexpected x86 connect family check at 0x3b4c03"
    );
    ensure!(
        data[FILTER..FILTER + 3] == [0x83, 0xfa, 0x0a],
        "unexpected x86 private-IPv4 filter at 0x3b4c11"
    );
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
    ensure!(
        u32_at(data, RX_FILESZ) == RX_OLD_END && u32_at(data, RX_MEMSZ) == RX_OLD_END,
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
    put_u32(data, RX_FILESZ, end as u32);
    put_u32(data, RX_MEMSZ, end as u32);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original() -> Option<Vec<u8>> {
        std::fs::read(std::env::var_os("HD_X86_LIBG")?).ok()
    }

    #[test]
    fn verifies_filter_and_ipv6_fast_path() {
        let Some(data) = original() else { return };
        allow_local_ranges(&data).unwrap();
        assert_eq!(&data[FILTER..FILTER + 3], &[0x83, 0xfa, 0x0a]);
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
