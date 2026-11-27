//! APK repackaging: strips the old signature, rewrites the bootstrap settings
//! CSV, hands each native library to [`crate::native`], aligns uncompressed
//! entries, and writes a fresh v1 signature for the result.

use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::native::{self, Abi};
use crate::progress::{self, Progress};
use crate::signing::{SigningKey, v1};
use crate::{Options, axml};

/// Data alignment of uncompressed entries, as `zipalign 4`.
const STORED_ALIGNMENT: u16 = 4;
/// Data alignment of uncompressed native libraries, so Android can map them
/// straight from the APK on 4 KiB- and 16 KiB-page devices (`zipalign -P 16`).
const LIBRARY_ALIGNMENT: u16 = 16 * 1024;

pub struct Repackaged {
    pub edits: Vec<String>,
    pub min_sdk: u32,
    pub entries: usize,
}

/// Copy every zip entry from `src` to `dst`, applying redirection edits and
/// replacing the v1 signature files with ones made by `key`.
pub fn repackage(
    src: &Path,
    dst: &Path,
    options: &Options,
    key: &SigningKey,
    progress: &mut dyn Progress,
) -> Result<Repackaged> {
    let started = Instant::now();
    let file = std::fs::File::open(src).with_context(|| format!("opening {}", src.display()))?;
    let mut zip = ZipArchive::new(std::io::BufReader::new(file))
        .with_context(|| format!("{} is not a valid APK (zip) file", src.display()))?;

    let min_sdk = {
        let mut manifest = Vec::new();
        zip.by_name("AndroidManifest.xml")
            .context("the APK has no AndroidManifest.xml")?
            .read_to_end(&mut manifest)?;
        axml::min_sdk_version(&manifest)
            .context("reading minSdkVersion from AndroidManifest.xml")?
    };
    let algorithm = v1::DigestAlgorithm::for_min_sdk(min_sdk);
    progress.info(&format!(
        "minSdkVersion {min_sdk}: v1 digests use {algorithm:?}"
    ));

    let out = std::fs::File::create(dst).with_context(|| format!("creating {}", dst.display()))?;
    let mut writer = ZipWriter::new(std::io::BufWriter::new(out));

    let mut edits = Vec::new();
    let mut digests = Vec::new();
    let mut total = 0usize;
    let mut patched_native = false;
    let count = zip.len();

    for i in 0..count {
        let mut entry = zip.by_index(i)?;
        let name = entry.name()?.into_owned();
        progress.entry(i, count, &name);

        if v1::is_signature_file(&name) {
            continue;
        }

        let mut data = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut data)
            .with_context(|| format!("reading {name}"))?;

        if name == "assets/settings_template.csv" {
            match rewrite_settings_csv(&data, &options.host, options.port) {
                Some(new) => {
                    let note = format!(
                        "assets/settings_template.csv ServerURL->{} Port->{}",
                        options.host, options.port
                    );
                    progress.info(&format!("edit: {note}"));
                    edits.push(note);
                    data = new;
                }
                None => progress
                    .info("WARN: could not locate ServerURL/Port columns in settings_template.csv"),
            }
        }

        if let Some(native_options) = &options.native {
            if let Some(abi) = Abi::from_entry(&name) {
                progress.entry(i, count, &format!("patching {name}"));
                let notes = native::patch_library(abi, &name, &mut data, native_options)?;
                for note in &notes {
                    progress.info(&format!("edit: {note}"));
                }
                edits.extend(notes);
                patched_native = true;
            } else if native::is_libg(&name) {
                bail!("native server key patch is not implemented for {name}");
            }
        }

        // Native libraries must be Stored (and page-aligned) for Android's
        // direct-load path. Every other entry keeps its storage method.
        let is_library = name.starts_with("lib/") && name.ends_with(".so");
        let method = if is_library || entry.compression() == CompressionMethod::Stored {
            CompressionMethod::Stored
        } else {
            CompressionMethod::Deflated
        };
        let mut opts = SimpleFileOptions::default()
            .compression_method(method)
            .unix_permissions(entry.unix_mode().unwrap_or(0o644))
            .large_file(data.len() >= u32::MAX as usize);
        if method == CompressionMethod::Stored {
            opts = opts.with_alignment(if is_library {
                LIBRARY_ALIGNMENT
            } else {
                STORED_ALIGNMENT
            });
        }

        if entry.is_dir() {
            writer.add_directory(name.trim_end_matches('/'), opts)?;
        } else {
            writer.start_file(&name, opts)?;
            writer.write_all(&data)?;
        }
        if v1::is_signed_entry(&name) {
            digests.push((name, algorithm.digest(&data)));
        }
        total += 1;
    }
    progress.entry(count, count, "signing (v1)");

    if options.native.is_some() && !patched_native {
        bail!("APK has no supported (x86 or arm64-v8a) libg.so to patch");
    }

    for (name, contents) in v1::signature_files(&digests, algorithm, key, true)? {
        writer.start_file(
            name,
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
        )?;
        writer.write_all(&contents)?;
    }

    let out_file = writer
        .finish()?
        .into_inner()
        .map_err(|e| e.into_error())
        .with_context(|| format!("writing {}", dst.display()))?;
    let size = out_file.metadata().map(|m| m.len()).unwrap_or(0);
    drop(out_file);
    progress.done(
        &format!(
            "repackaged {total} entries ({}), v1-signed",
            progress::fmt_bytes(size)
        ),
        started.elapsed(),
    );
    Ok(Repackaged {
        edits,
        min_sdk,
        entries: total,
    })
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
        let key = crate::signing::tests::key();
        repackage(
            &source,
            &output,
            &options,
            key,
            &mut crate::progress::Silent,
        )
        .unwrap();
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
