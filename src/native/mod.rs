//! Patching of the native game library (`libg.so`, Hay Day 1.43.150 build 1598).
//!
//! - [`key`]: replaces the embedded server public key (all ABIs).
//! - [`arm64`]: the extra work arm64-v8a needs (integrity-check handling,
//!   local-range filter bypass, bootstrap URL rewrite).
//! - [`x86`]: x86 local-range resolver wrapper and bootstrap URL rewrite.
//!
//! [`patch_library`] is the single entry point used by the APK repackager.

mod arm64;
mod key;
mod x86;

use anyhow::Result;

pub use key::parse_key;

/// CPU architecture of a bundled `libg.so`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abi {
    X86,
    Arm64,
}

impl Abi {
    /// ABI of an APK entry such as `lib/arm64-v8a/libg.so`.
    pub fn from_entry(name: &str) -> Option<Self> {
        match name {
            "lib/x86/libg.so" => Some(Self::X86),
            "lib/arm64-v8a/libg.so" => Some(Self::Arm64),
            _ => None,
        }
    }

    /// SHA-256 (hex) of the one `libg.so` build this ABI's edits are verified
    /// against; any other library is rejected before anything is written.
    pub fn verified_sha256(self) -> &'static str {
        self.build().0
    }
}

/// True for any `lib/<abi>/libg.so` entry, supported ABI or not.
pub fn is_libg(name: &str) -> bool {
    name.starts_with("lib/") && name.ends_with("/libg.so")
}

/// Native edits to apply to every supported `libg.so`.
#[derive(Debug, Clone)]
pub struct Options {
    /// Replacement server public key (X25519, 32 bytes).
    pub key: [u8; 32],
    pub allow_local_ranges: bool,
    /// Replacement base (`scheme://host[:port]`) for the native bootstrap URL.
    pub bootstrap_url: Option<String>,
}

/// Patch one library in place and return a human-readable note per edit.
pub fn patch_library(
    abi: Abi,
    name: &str,
    data: &mut Vec<u8>,
    options: &Options,
) -> Result<Vec<String>> {
    let mut notes = Vec::new();

    key::patch(abi, data, &options.key)?;
    let extra = match abi {
        Abi::Arm64 => " + C3 decode constant + integrity neutralisation",
        Abi::X86 => "",
    };
    notes.push(format!(
        "{name}: replaced server public key in send, receive and nonce derivation ({abi:?}){extra}"
    ));

    if options.allow_local_ranges {
        match abi {
            Abi::Arm64 => {
                arm64::allow_local_ranges(data)?;
                notes.push(format!(
                    "{name}: bypassed both native private-IPv4 connect filters (0x612448/0x58bc6c)"
                ));
            }
            Abi::X86 => {
                x86::allow_local_ranges(data)?;
                notes.push(format!(
                    "{name}: wrapped getaddrinfo (0x74e70) to map filtered private-IPv4 \
                     results to IPv6; both integrity-checked connect routines remain pristine"
                ));
            }
        }
    }

    if let Some(base) = &options.bootstrap_url {
        match abi {
            Abi::X86 => {
                x86::patch_bootstrap_url(data, base)?;
                notes.push(format!(
                    "{name}: rewrote the native /env_settings bootstrap URL to {base}"
                ));
            }
            Abi::Arm64 => {
                arm64::patch_bootstrap_url(data, base)?;
                notes.push(format!(
                    "{name}: rewrote the native /env_settings bootstrap URL to {base} \
                     (input-derived region copy + checker safe exit; no bundled runtime data)"
                ));
            }
        }
    }
    Ok(notes)
}

// Little-endian helpers shared by the ABI modules.

fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn put_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn u64_at(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn put_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
