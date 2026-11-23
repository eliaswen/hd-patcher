//! APK repackaging: strips the old signature, rewrites the bootstrap settings
//! CSV and hands each native library to [`crate::native`].

use std::io::{Read, Write};
use std::path::Path;

use anyhow::{bail, Result};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::native::{self, Abi};

/// What to change in the APK.
pub struct Options {
    /// Server host written to the settings CSV.
    pub host: String,
    pub port: u16,
    /// Native `libg.so` edits; `None` means only the CSV is edited.
    pub native: Option<native::Options>,
}

pub struct Report {
    pub total: usize,
    pub edits: Vec<String>,
}

/// Copy every zip entry from `src` to `dst`, applying redirection edits and
/// dropping the old signature files (`META-INF/*.SF|.RSA|.DSA|.EC`,
/// `MANIFEST.MF`) so the output can be freshly signed.
pub fn repackage(src: &Path, dst: &Path, options: &Options) -> Result<Report> {
    let file = std::fs::File::open(src)?;
    let mut zip = ZipArchive::new(file)?;

    let out = std::fs::File::create(dst)?;
    let mut writer = ZipWriter::new(out);

    let mut edits = Vec::new();
    let mut total = 0usize;
    let mut patched_native = false;

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name()?.into_owned();

        // Drop prior signature material.
        if is_signature_file(&name) {
            continue;
        }

        let mut data = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut data)?;

        // Apply content edits.
        if name == "assets/settings_template.csv" {
            match rewrite_settings_csv(&data, &options.host, options.port) {
                Some(new) => {
                    edits.push(format!(
                        "assets/settings_template.csv ServerURL->{} Port->{}",
                        options.host, options.port
                    ));
                    data = new;
                }
                None => {
                    eprintln!(
                        "WARN: could not locate ServerURL/Port columns in settings_template.csv"
                    );
                }
            }
        }

        if let Some(native_options) = &options.native {
            if let Some(abi) = Abi::from_entry(&name) {
                edits.extend(native::patch_library(
                    abi,
                    &name,
                    &mut data,
                    native_options,
                )?);
                patched_native = true;
            } else if native::is_libg(&name) {
                bail!("native server key patch is not implemented for {name}");
            }
        }

        // Native libraries must be Stored for zipalign/Android's direct-load
        // path. Preserve the original storage method for every other entry.
        let method = if name.starts_with("lib/") && name.ends_with(".so") {
            CompressionMethod::Stored
        } else {
            match entry.compression() {
                CompressionMethod::Stored => CompressionMethod::Stored,
                _ => CompressionMethod::Deflated,
            }
        };
        let opts = SimpleFileOptions::default()
            .compression_method(method)
            .unix_permissions(entry.unix_mode().unwrap_or(0o644))
            .large_file(data.len() >= u32::MAX as usize);

        writer.start_file(&name, opts)?;
        writer.write_all(&data)?;
        total += 1;
    }

    if options.native.is_some() && !patched_native {
        bail!("APK has no supported (x86 or arm64-v8a) libg.so to patch");
    }
    writer.finish()?;
    Ok(Report { total, edits })
}

fn is_signature_file(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper == "META-INF/MANIFEST.MF"
        || (upper.starts_with("META-INF/")
            && (upper.ends_with(".SF")
                || upper.ends_with(".RSA")
                || upper.ends_with(".DSA")
                || upper.ends_with(".EC")))
}

/// Rewrite the `ServerURL` and `Port` columns of the single data row in
/// `settings_template.csv`. Returns `None` if the expected header isn't found.
///
/// The file is tiny CSV with quoted fields:
///   row0: header names, row1: type names, row2: values.
fn rewrite_settings_csv(data: &[u8], host: &str, port: u16) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines: Vec<String> = text.split('\n').map(|s| s.to_string()).collect();
    if lines.len() < 3 {
        return None;
    }

    let header = parse_csv_row(&lines[0]);
    let server_idx = header.iter().position(|c| c == "ServerURL")?;
    let port_idx = header.iter().position(|c| c == "Port")?;
    // Also force OfflineMode off if present (dev template ships it true).
    let offline_idx = header.iter().position(|c| c == "OfflineMode");

    let mut values = parse_csv_row(&lines[2]);
    if values.len() <= server_idx.max(port_idx) {
        return None;
    }
    values[server_idx] = host.to_string();
    values[port_idx] = port.to_string();
    if let Some(oi) = offline_idx {
        if oi < values.len() {
            values[oi] = "false".to_string();
        }
    }

    // Re-emit: quote strings, leave the numeric Port and boolean OfflineMode bare
    // to match the original formatting.
    let rebuilt: Vec<String> = values
        .iter()
        .enumerate()
        .map(|(idx, v)| {
            if idx == port_idx || Some(idx) == offline_idx {
                v.clone()
            } else {
                format!("\"{v}\"")
            }
        })
        .collect();
    lines[2] = rebuilt.join(",");

    Some(lines.join("\n").into_bytes())
}

/// Minimal CSV field splitter for one row: handles double-quoted fields and
/// commas inside quotes. Adequate for this fixed, simple settings file.
fn parse_csv_row(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.trim_end_matches('\r').chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                fields.push(cur.clone());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Native libraries must remain uncompressed so zipalign can page-align
    /// them for Android's direct native-library loading path.
    #[test]
    fn arm64_native_libraries_are_stored() {
        // Needs an arm64 Hay Day APK supplied by the tester.
        let Some(source) = std::env::var_os("HD_ARM64_APK").map(PathBuf::from) else {
            return;
        };
        if !source.exists() {
            return;
        }
        let output = std::env::temp_dir().join(format!(
            "hd-patcher-arm64-storage-{}.apk",
            std::process::id()
        ));
        let options = Options {
            host: "192.168.1.38".into(),
            port: 19339,
            native: None,
        };
        repackage(&source, &output, &options).unwrap();
        let file = std::fs::File::open(&output).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        let method = archive
            .by_name("lib/arm64-v8a/libg.so")
            .unwrap()
            .compression();
        drop(archive);
        std::fs::remove_file(output).unwrap();
        assert_eq!(method, CompressionMethod::Stored);
    }
}
