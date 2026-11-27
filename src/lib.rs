//! Repackage and sign a Hay Day APK so it connects to a custom server.
//!
//! The library behind the `hd-patcher` CLI, also used by apps that patch on
//! the device itself. Everything is pure Rust: no JDK or Android SDK tools are
//! run, so it works the same on Linux, macOS, Windows and Android.
//!
//! - [`patch`]: the whole job, from an input APK to a signed output APK.
//! - [`inspect`]: what an APK contains and whether it is the supported build.
//! - [`signing`]: signing keys and PKCS#12 keystores.
//! - [`progress`]: progress callbacks ([`progress::Console`] for terminals).

mod apk;
mod axml;
mod native;
pub mod progress;
pub mod signing;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

pub use native::{Abi, Options as NativeOptions, parse_key};
use progress::Progress;
use signing::SigningKey;

/// Hay Day version the native edits are verified against.
pub const SUPPORTED_VERSION: &str = "1.43.150 (build 1598)";

/// What to change in the APK.
#[derive(Debug, Clone)]
pub struct Options {
    /// Server host written to the settings CSV.
    pub host: String,
    /// Server port written to the settings CSV (ignored by the arm64 client).
    pub port: u16,
    /// Native `libg.so` edits; `None` means only the CSV is edited.
    pub native: Option<NativeOptions>,
}

/// The outcome of [`patch`].
#[derive(Debug, Clone)]
pub struct Report {
    /// One human-readable line per applied edit.
    pub edits: Vec<String>,
    /// The APK's `minSdkVersion`, which chose the v1 digest.
    pub min_sdk: u32,
    /// Archive entries written, signature files excluded.
    pub entries: usize,
    /// SHA-256 of the signing certificate.
    pub certificate_sha256: String,
}

/// Patch `input` into a new, v1+v2-signed APK at `output`.
///
/// Nothing is left behind on failure: the intermediate file and any partial
/// output are removed. Fails without writing an APK when no redirection edit
/// could be applied.
pub fn patch(
    input: &Path,
    output: &Path,
    options: &Options,
    key: &SigningKey,
    progress: &mut dyn Progress,
) -> Result<Report> {
    if !input.is_file() {
        bail!("input APK does not exist: {}", input.display());
    }
    if same_file(input, output) {
        bail!("the output must not overwrite the input APK");
    }
    let partial = sibling(output, "partial");
    let result = patch_via(input, &partial, output, options, key, progress);
    let _ = std::fs::remove_file(&partial);
    if result.is_err() {
        let _ = std::fs::remove_file(output);
    }
    result
}

fn patch_via(
    input: &Path,
    partial: &Path,
    output: &Path,
    options: &Options,
    key: &SigningKey,
    progress: &mut dyn Progress,
) -> Result<Report> {
    progress.step(1, 2, "Repackaging APK");
    let repackaged =
        apk::repackage(input, partial, options, key, progress).context("repackaging APK")?;
    if repackaged.edits.is_empty() {
        bail!(
            "no redirection edit was applied — refusing to produce an APK that still points at the original servers"
        );
    }

    progress.step(2, 2, "Signing (APK Signature Scheme v2)");
    let started = Instant::now();
    signing::v2::sign(partial, output, key).context("adding the v2 signature")?;
    progress.done(
        &format!(
            "signed v1+v2, certificate SHA-256 {}",
            key.certificate_sha256()
        ),
        started.elapsed(),
    );
    Ok(Report {
        edits: repackaged.edits,
        min_sdk: repackaged.min_sdk,
        entries: repackaged.entries,
        certificate_sha256: key.certificate_sha256(),
    })
}

/// One `lib/<abi>/libg.so` found by [`inspect`].
#[derive(Debug, Clone)]
pub struct Library {
    /// Zip entry, e.g. `lib/arm64-v8a/libg.so`.
    pub entry: String,
    /// The ABI, when it is one this tool can patch.
    pub abi: Option<Abi>,
    /// SHA-256 of the library, hex.
    pub sha256: String,
    /// Whether this is exactly the build the native edits are verified for.
    pub supported: bool,
}

/// What [`inspect`] found in an APK.
#[derive(Debug, Clone)]
pub struct Inspection {
    pub min_sdk: u32,
    pub libraries: Vec<Library>,
}

impl Inspection {
    /// True when the APK has at least one supported library and no
    /// unsupported `libg.so` that [`patch`] would refuse.
    pub fn is_patchable(&self) -> bool {
        !self.libraries.is_empty() && self.libraries.iter().all(|l| l.supported)
    }
}

/// Read an APK's manifest and native game libraries without changing
/// anything, e.g. to vet a file a user picked before patching it. Split APKs
/// (`.apks`, `.xapk`) are not handled here; pass the split that carries
/// `lib/<abi>/libg.so`.
pub fn inspect(apk: &Path) -> Result<Inspection> {
    let file = std::fs::File::open(apk).with_context(|| format!("opening {}", apk.display()))?;
    let mut zip = zip::ZipArchive::new(std::io::BufReader::new(file))
        .with_context(|| format!("{} is not a valid APK (zip) file", apk.display()))?;
    let min_sdk = match zip.by_name("AndroidManifest.xml") {
        Ok(mut entry) => {
            let mut manifest = Vec::new();
            entry.read_to_end(&mut manifest)?;
            axml::min_sdk_version(&manifest)?
        }
        Err(_) => bail!("{} has no AndroidManifest.xml", apk.display()),
    };
    let mut names = Vec::new();
    for index in 0..zip.len() {
        let name = zip.by_index_raw(index)?.name()?.into_owned();
        if native::is_libg(&name) {
            names.push(name);
        }
    }
    let mut libraries = Vec::new();
    for entry in names {
        let mut hasher = Sha256::new();
        std::io::copy(&mut zip.by_name(&entry)?, &mut HashWriter(&mut hasher))?;
        let sha256 = signing::hex(&hasher.finalize());
        let abi = Abi::from_entry(&entry);
        let supported = abi.is_some_and(|abi| abi.verified_sha256() == sha256);
        libraries.push(Library {
            entry,
            abi,
            sha256,
            supported,
        });
    }
    libraries.sort_by(|a, b| a.entry.cmp(&b.entry));
    Ok(Inspection { min_sdk, libraries })
}

struct HashWriter<'a>(&'a mut Sha256);

impl std::io::Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `dir/name.<suffix>` next to `path`.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
