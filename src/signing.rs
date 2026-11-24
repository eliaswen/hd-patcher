//! Keystore handling and APK alignment/signing.
//!
//! Prefers the Android SDK `zipalign` + `apksigner` (v1+v2+v3, best
//! compatibility on modern Android) and falls back to `jarsigner` (v1 only,
//! fine for targetSdk < 30).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::progress;

/// Signing identity; created with `keytool` on first use if the file is absent.
pub struct Keystore {
    pub path: PathBuf,
    pub password: String,
    pub alias: String,
}

/// Align (when `zipalign` is available) and sign `unsigned` into `out`.
pub fn sign(unsigned: &Path, out: &Path, ks: &Keystore) -> Result<()> {
    ensure_keystore(&ks.path, &ks.password, &ks.alias).context("ensuring keystore")?;

    match find_build_tool("apksigner") {
        Some(apksigner) => {
            // zipalign must run before apksigner (apksigner preserves alignment).
            let aligned = out.with_extension("aligned.apk");
            if let Some(zipalign) = find_build_tool("zipalign") {
                progress::info("aligning with zipalign…");
                run(
                    Command::new(&zipalign)
                        .args(["-p", "-f", "4"])
                        .arg(unsigned)
                        .arg(&aligned),
                    "zipalign",
                )?;
            } else {
                progress::info("zipalign not found — skipping alignment");
                std::fs::copy(unsigned, &aligned)?;
            }
            progress::info("signing with apksigner (v1+v2+v3)…");
            sign_apksigner(&apksigner, &aligned, out, &ks.path, &ks.password, &ks.alias)
                .context("signing APK (apksigner)")?;
            let _ = std::fs::remove_file(&aligned);
            progress::info("signed with apksigner (v1+v2+v3)");
        }
        None => {
            progress::info("apksigner not found — signing with jarsigner (v1 only)…");
            std::fs::copy(unsigned, out)
                .with_context(|| format!("copying {} -> {}", unsigned.display(), out.display()))?;
            sign_v1(out, &ks.path, &ks.password, &ks.alias).context("signing APK (jarsigner)")?;
            progress::info("signed with jarsigner (v1 only)");
        }
    }
    Ok(())
}

fn ensure_keystore(keystore: &Path, storepass: &str, alias: &str) -> Result<()> {
    if keystore.exists() {
        return Ok(());
    }
    progress::info(&format!("generating debug keystore at {}", keystore.display()));
    let status = Command::new("keytool")
        .args(["-genkeypair", "-keystore"])
        .arg(keystore)
        .args([
            "-storepass",
            storepass,
            "-keypass",
            storepass,
            "-alias",
            alias,
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "10000",
            "-dname",
            "CN=Hay Day Debug, OU=Dev, O=HayDayCustomServer, C=US",
        ])
        .status()
        .context("spawning keytool")?;
    if !status.success() {
        bail!("keytool failed");
    }
    Ok(())
}

/// Locate an Android build-tool (`apksigner`, `zipalign`) in `PATH` or in the
/// Android SDK (`$ANDROID_SDK_ROOT`, `$ANDROID_HOME`, `~/Android/Sdk`), choosing
/// the highest build-tools version.
fn find_build_tool(name: &str) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let p = dir.join(name);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    let mut roots: Vec<PathBuf> = Vec::new();
    for var in ["ANDROID_SDK_ROOT", "ANDROID_HOME"] {
        if let Ok(r) = std::env::var(var) {
            roots.push(PathBuf::from(r));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        roots.push(PathBuf::from(home).join("Android/Sdk"));
    }
    for root in roots {
        let bt = root.join("build-tools");
        if let Ok(rd) = std::fs::read_dir(&bt) {
            let mut versions: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
            // Highest version directory first (lexicographic is close enough for
            // the `NN.N.N` scheme used by build-tools).
            versions.sort();
            versions.reverse();
            for v in versions {
                let p = v.join(name);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    None
}

fn run(cmd: &mut Command, what: &str) -> Result<()> {
    let status = cmd.status().with_context(|| format!("spawning {what}"))?;
    if !status.success() {
        bail!("{what} failed");
    }
    Ok(())
}

fn sign_apksigner(
    apksigner: &Path,
    input: &Path,
    out: &Path,
    keystore: &Path,
    storepass: &str,
    alias: &str,
) -> Result<()> {
    run(
        Command::new(apksigner)
            .arg("sign")
            .arg("--ks")
            .arg(keystore)
            .args(["--ks-pass", &format!("pass:{storepass}")])
            .args(["--ks-key-alias", alias])
            .args([
                "--v1-signing-enabled",
                "true",
                "--v2-signing-enabled",
                "true",
                "--v3-signing-enabled",
                "true",
            ])
            .arg("--out")
            .arg(out)
            .arg(input),
        "apksigner",
    )
}

fn sign_v1(apk: &Path, keystore: &Path, storepass: &str, alias: &str) -> Result<()> {
    let status = Command::new("jarsigner")
        .args([
            "-sigalg",
            "SHA256withRSA",
            "-digestalg",
            "SHA-256",
            "-keystore",
        ])
        .arg(keystore)
        .args(["-storepass", storepass])
        .arg(apk)
        .arg(alias)
        .status()
        .context("spawning jarsigner")?;
    if !status.success() {
        bail!("jarsigner failed");
    }
    Ok(())
}
