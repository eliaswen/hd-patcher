//! End-to-end: patch an APK through the public API and check the result with
//! the Android SDK's `apksigner` when one is installed (GitHub's hosted
//! runners have it). The synthetic APK needs no game files; the real-APK test
//! runs when `HD_ARM64_APK` / `HD_X86_APK` point at Hay Day build 1598.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use hd_patcher::progress::Silent;
use hd_patcher::signing::SigningKey;
use zip::write::SimpleFileOptions;

fn key() -> &'static SigningKey {
    static KEY: OnceLock<SigningKey> = OnceLock::new();
    KEY.get_or_init(|| SigningKey::generate().unwrap())
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hd-patcher-it-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A compiled `AndroidManifest.xml`:
/// `<manifest><uses-sdk android:minSdkVersion=N/></manifest>`.
fn binary_manifest(min_sdk: u32) -> Vec<u8> {
    fn u16le(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }
    fn u32le(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }
    // Index 0 is the attribute, so the resource map can name it.
    let strings = ["minSdkVersion", "uses-sdk", "manifest"];
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for s in strings {
        offsets.push(data.len() as u32);
        data.extend_from_slice(&[s.len() as u8, s.len() as u8]);
        data.extend_from_slice(s.as_bytes());
        data.push(0);
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let header = 28u32;
    let starts = header + 4 * strings.len() as u32;
    let mut pool = Vec::new();
    pool.extend(u16le(1));
    pool.extend(u16le(header as u16));
    pool.extend(u32le(starts + data.len() as u32));
    pool.extend(u32le(strings.len() as u32));
    pool.extend(u32le(0));
    pool.extend(u32le(1 << 8)); // UTF-8
    pool.extend(u32le(starts));
    pool.extend(u32le(0));
    for offset in offsets {
        pool.extend(u32le(offset));
    }
    pool.extend(data);

    let mut map = Vec::new();
    map.extend(u16le(0x0180));
    map.extend(u16le(8));
    map.extend(u32le(12));
    map.extend(u32le(0x0101_020c));

    let start = |name: u32, attributes: &[u8], count: u16| {
        let mut e = Vec::new();
        e.extend(u16le(0x0102));
        e.extend(u16le(16));
        e.extend(u32le(16 + 20 + attributes.len() as u32));
        e.extend(u32le(1)); // line
        e.extend(u32le(u32::MAX)); // comment
        e.extend(u32le(u32::MAX)); // namespace
        e.extend(u32le(name));
        e.extend(u16le(20)); // attributeStart
        e.extend(u16le(20)); // attributeSize
        e.extend(u16le(count));
        e.extend([0; 6]);
        e.extend_from_slice(attributes);
        e
    };
    let end = |name: u32| {
        let mut e = Vec::new();
        e.extend(u16le(0x0103));
        e.extend(u16le(16));
        e.extend(u32le(24));
        e.extend(u32le(1));
        e.extend(u32le(u32::MAX));
        e.extend(u32le(u32::MAX));
        e.extend(u32le(name));
        e
    };
    let mut attribute = Vec::new();
    attribute.extend(u32le(u32::MAX)); // namespace
    attribute.extend(u32le(0)); // name: minSdkVersion
    attribute.extend(u32le(u32::MAX)); // raw value
    attribute.extend(u16le(8));
    attribute.push(0);
    attribute.push(0x10); // TYPE_INT_DEC
    attribute.extend(u32le(min_sdk));

    let body = [
        pool,
        map,
        start(2, &[], 0),
        start(1, &attribute, 1),
        end(1),
        end(2),
    ]
    .concat();
    let mut out = Vec::new();
    out.extend(u16le(3));
    out.extend(u16le(8));
    out.extend(u32le(8 + body.len() as u32));
    out.extend(body);
    out
}

fn synthetic_apk(path: &Path, min_sdk: u32) {
    let mut zip = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
    let deflated = SimpleFileOptions::default();
    let stored = deflated.compression_method(zip::CompressionMethod::Stored);
    zip.start_file("AndroidManifest.xml", deflated).unwrap();
    zip.write_all(&binary_manifest(min_sdk)).unwrap();
    zip.add_directory("assets", deflated).unwrap();
    zip.start_file("assets/settings_template.csv", deflated)
        .unwrap();
    zip.write_all(b"\"ServerURL\",\"Port\",\"OfflineMode\"\n\"string\",\"int\",\"boolean\"\n\"game.haydaygame.com\",9339,true\n").unwrap();
    zip.start_file("resources.arsc", stored).unwrap();
    zip.write_all(&[7u8; 1000]).unwrap();
    zip.start_file("lib/x86/libother.so", stored).unwrap();
    zip.write_all(&[1u8; 5000]).unwrap();
    // A stale signature that must be replaced.
    zip.start_file("META-INF/OLD.RSA", deflated).unwrap();
    zip.write_all(b"stale").unwrap();
    // A long name to exercise manifest line wrapping.
    zip.start_file(format!("assets/{}.txt", "long-name-".repeat(12)), deflated)
        .unwrap();
    zip.write_all(b"hello").unwrap();
    zip.finish().unwrap();
}

/// The newest `apksigner` of the Android SDK, if one is installed.
fn apksigner() -> Option<PathBuf> {
    let name = if cfg!(windows) {
        "apksigner.bat"
    } else {
        "apksigner"
    };
    let mut roots: Vec<PathBuf> = ["ANDROID_HOME", "ANDROID_SDK_ROOT"]
        .iter()
        .filter_map(|v| std::env::var_os(v).map(PathBuf::from))
        .collect();
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        roots.push(PathBuf::from(home).join("Android").join("Sdk"));
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        roots.push(PathBuf::from(local).join("Android").join("Sdk"));
    }
    let version = |p: &Path| -> Vec<u32> {
        p.file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.split(['.', '-']).filter_map(|x| x.parse().ok()).collect())
            .unwrap_or_default()
    };
    roots
        .into_iter()
        .filter_map(|root| std::fs::read_dir(root.join("build-tools")).ok())
        .flat_map(|dir| dir.filter_map(|e| e.ok().map(|e| e.path())))
        .filter(|dir| dir.join(name).is_file())
        .max_by_key(|dir| version(dir))
        .map(|dir| dir.join(name))
}

/// Run `apksigner verify`; returns false when no `apksigner` is installed.
fn verify(apk: &Path) -> bool {
    let Some(tool) = apksigner() else {
        eprintln!("apksigner not found; skipping its verification");
        return false;
    };
    let out = Command::new(&tool)
        .args(["verify", "-v", "--print-certs"])
        .arg(apk)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "apksigner rejected {}:\n{text}\n{}",
        apk.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("Verified using v1 scheme (JAR signing): true"),
        "{text}"
    );
    assert!(
        text.contains("Verified using v2 scheme (APK Signature Scheme v2): true"),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "certificate SHA-256 digest: {}",
            key().certificate_sha256()
        )),
        "{text}"
    );
    true
}

fn read_entry(apk: &Path, name: &str) -> Vec<u8> {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(apk).unwrap()).unwrap();
    let mut data = Vec::new();
    zip.by_name(name).unwrap().read_to_end(&mut data).unwrap();
    data
}

fn data_offset(apk: &Path, name: &str) -> u64 {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(apk).unwrap()).unwrap();
    zip.by_name(name).unwrap().data_start().unwrap()
}

#[test]
fn synthetic_apk_is_signed_for_old_and_new_android() {
    let dir = scratch("synthetic");
    for (min_sdk, digest) in [(16, "SHA1-Digest"), (21, "SHA-256-Digest")] {
        let input = dir.join(format!("in-{min_sdk}.apk"));
        let output = dir.join(format!("out-{min_sdk}.apk"));
        synthetic_apk(&input, min_sdk);
        let options = hd_patcher::Options {
            host: "127.0.0.1".into(),
            port: 9339,
            native: None,
        };
        let report = hd_patcher::patch(&input, &output, &options, key(), &mut Silent).unwrap();
        assert_eq!(report.min_sdk, min_sdk);
        assert_eq!(report.edits.len(), 1);

        let csv = String::from_utf8(read_entry(&output, "assets/settings_template.csv")).unwrap();
        assert!(csv.ends_with("\"127.0.0.1\",9339,false\n"), "{csv}");
        let manifest = String::from_utf8(read_entry(&output, "META-INF/MANIFEST.MF")).unwrap();
        assert!(manifest.contains(digest), "{manifest}");
        assert!(!manifest.contains("OLD.RSA"));
        assert!(
            zip::ZipArchive::new(std::fs::File::open(&output).unwrap())
                .unwrap()
                .by_name("META-INF/OLD.RSA")
                .is_err()
        );
        assert_eq!(data_offset(&output, "lib/x86/libother.so") % 16384, 0);
        assert_eq!(data_offset(&output, "resources.arsc") % 4, 0);
        assert!(!dir.join(format!("out-{min_sdk}.apk.partial")).exists());
        verify(&output);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn failure_leaves_no_output() {
    let dir = scratch("failure");
    let input = dir.join("in.apk");
    let output = dir.join("out.apk");
    synthetic_apk(&input, 21);
    // No libg.so to patch: the native edits must fail the whole run.
    let options = hd_patcher::Options {
        host: "127.0.0.1".into(),
        port: 9339,
        native: Some(hd_patcher::NativeOptions {
            key: [0x11; 32],
            allow_local_ranges: false,
            bootstrap_url: None,
        }),
    };
    assert!(hd_patcher::patch(&input, &output, &options, key(), &mut Silent).is_err());
    assert!(!output.exists());
    assert!(!dir.join("out.apk.partial").exists());
    assert!(hd_patcher::patch(&input, &input, &options, key(), &mut Silent).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn real_apks_patch_and_verify() {
    for (var, abi) in [
        ("HD_ARM64_APK", hd_patcher::Abi::Arm64),
        ("HD_X86_APK", hd_patcher::Abi::X86),
    ] {
        let Some(input) = std::env::var_os(var).map(PathBuf::from) else {
            eprintln!("{var} not set; skipping");
            continue;
        };
        let inspection = hd_patcher::inspect(&input).unwrap();
        assert!(inspection.is_patchable(), "{inspection:?}");
        assert!(inspection.libraries.iter().any(|l| l.abi == Some(abi)));
        assert_eq!(inspection.min_sdk, 16);

        let dir = scratch(var);
        let output = dir.join("patched.apk");
        let options = hd_patcher::Options {
            host: "127.0.0.1".into(),
            port: 9339,
            native: Some(hd_patcher::NativeOptions {
                key: [0x11; 32],
                allow_local_ranges: true,
                bootstrap_url: Some("http://127.0.0.1:8080".into()),
            }),
        };
        let report = hd_patcher::patch(&input, &output, &options, key(), &mut Silent).unwrap();
        assert_eq!(report.edits.len(), 4, "{:?}", report.edits);
        verify(&output);
        // The patched library is no longer the verified original.
        assert!(!hd_patcher::inspect(&output).unwrap().is_patchable());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
