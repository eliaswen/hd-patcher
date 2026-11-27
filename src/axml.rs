//! Just enough of Android's binary XML to read `<uses-sdk android:minSdkVersion>`
//! from a compiled `AndroidManifest.xml`, which decides the v1 digest.

use anyhow::{Context, Result, bail, ensure};

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
/// `android:minSdkVersion`.
const MIN_SDK_VERSION_ATTR: u32 = 0x0101_020c;
const TYPE_STRING: u8 = 0x03;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const UTF8_FLAG: u32 = 1 << 8;

fn u16_at(data: &[u8], at: usize) -> Result<u16> {
    let bytes = data.get(at..at + 2).context("truncated binary XML")?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    let bytes = data.get(at..at + 4).context("truncated binary XML")?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

/// `minSdkVersion` of a compiled manifest, or 1 (Android's default) when the
/// manifest declares none. Like `apksigner`, only a `<uses-sdk>` directly
/// inside the root `<manifest>` counts.
pub fn min_sdk_version(manifest: &[u8]) -> Result<u32> {
    ensure!(
        u16_at(manifest, 0)? == RES_XML_TYPE,
        "not a binary XML document"
    );
    let header = u16_at(manifest, 2)? as usize;
    let mut strings: Vec<String> = Vec::new();
    let mut resource_ids: Vec<u32> = Vec::new();

    let mut depth = 0usize;
    let mut root_is_manifest = false;
    let mut at = header;
    while at + 8 <= manifest.len() {
        let kind = u16_at(manifest, at)?;
        let header_size = u16_at(manifest, at + 2)? as usize;
        let size = u32_at(manifest, at + 4)? as usize;
        ensure!(
            size >= 8 && at + size <= manifest.len(),
            "bad binary XML chunk size"
        );
        let chunk = &manifest[at..at + size];
        match kind {
            RES_STRING_POOL_TYPE => strings = string_pool(chunk)?,
            RES_XML_RESOURCE_MAP_TYPE => {
                resource_ids = chunk[header_size..]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|b| u32::from_le_bytes(*b))
                    .collect();
            }
            RES_XML_START_ELEMENT_TYPE => {
                depth += 1;
                let name = strings.get(u32_at(chunk, 20)? as usize).map(String::as_str);
                if depth == 1 {
                    root_is_manifest = name == Some("manifest");
                } else if depth == 2 && root_is_manifest && name == Some("uses-sdk") {
                    return uses_sdk(chunk, header_size, &strings, &resource_ids);
                }
            }
            RES_XML_END_ELEMENT_TYPE => depth = depth.saturating_sub(1),
            _ => {}
        }
        at += size;
    }
    Ok(1)
}

fn uses_sdk(chunk: &[u8], header_size: usize, strings: &[String], ids: &[u32]) -> Result<u32> {
    let ext = header_size;
    let start = u16_at(chunk, ext + 8)? as usize;
    let attr_size = u16_at(chunk, ext + 10)? as usize;
    let count = u16_at(chunk, ext + 12)? as usize;
    ensure!(attr_size >= 20, "bad binary XML attribute size");
    for index in 0..count {
        let attr = ext + start + index * attr_size;
        let name = u32_at(chunk, attr + 4)? as usize;
        let is_min_sdk = ids.get(name) == Some(&MIN_SDK_VERSION_ATTR)
            || strings.get(name).map(String::as_str) == Some("minSdkVersion");
        if !is_min_sdk {
            continue;
        }
        let raw = u32_at(chunk, attr + 8)?;
        let data_type = chunk[attr + 15];
        let data = u32_at(chunk, attr + 16)?;
        return match data_type {
            TYPE_INT_DEC | TYPE_INT_HEX => Ok(data),
            TYPE_STRING => {
                let text = strings
                    .get(raw as usize)
                    .context("bad minSdkVersion string")?;
                // A codename (preview SDK) sorts above every released level.
                Ok(text.parse().unwrap_or(10_000))
            }
            other => bail!("unsupported minSdkVersion value type {other:#x}"),
        };
    }
    Ok(1)
}

fn string_pool(chunk: &[u8]) -> Result<Vec<String>> {
    let count = u32_at(chunk, 8)? as usize;
    let flags = u32_at(chunk, 16)?;
    let strings_start = u32_at(chunk, 20)? as usize;
    let header_size = u16_at(chunk, 2)? as usize;
    let utf8 = flags & UTF8_FLAG != 0;
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let offset = strings_start + u32_at(chunk, header_size + index * 4)? as usize;
        out.push(if utf8 {
            utf8_string(chunk, offset)?
        } else {
            utf16_string(chunk, offset)?
        });
    }
    Ok(out)
}

fn utf8_string(chunk: &[u8], at: usize) -> Result<String> {
    // A character count, then a byte count, each one byte or two when the
    // first byte has its high bit set; then the bytes.
    let (_chars, at) = read_utf8_len(chunk, at)?;
    let (len, start) = read_utf8_len(chunk, at)?;
    let bytes = chunk
        .get(start..start + len)
        .context("truncated string pool")?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn read_utf8_len(chunk: &[u8], at: usize) -> Result<(usize, usize)> {
    let first = *chunk.get(at).context("truncated string pool")? as usize;
    if first & 0x80 != 0 {
        let second = *chunk.get(at + 1).context("truncated string pool")? as usize;
        Ok((((first & 0x7f) << 8) | second, at + 2))
    } else {
        Ok((first, at + 1))
    }
}

fn utf16_string(chunk: &[u8], at: usize) -> Result<String> {
    let first = u16_at(chunk, at)? as usize;
    let (len, start) = if first & 0x8000 != 0 {
        (
            ((first & 0x7fff) << 16) | u16_at(chunk, at + 2)? as usize,
            at + 4,
        )
    } else {
        (first, at + 2)
    };
    let units: Vec<u16> = (0..len)
        .map(|i| u16_at(chunk, start + i * 2))
        .collect::<Result<_>>()?;
    Ok(String::from_utf16_lossy(&units))
}
