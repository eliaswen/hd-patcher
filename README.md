# hd-patcher

A command-line tool that repackages an Android APK of the mobile game *Hay Day*
so that the client connects to a server of your choice instead of the original
one, and signs the result with your own key.

It is a research and preservation tool for people running their own
compatible server. It is **not affiliated with, endorsed by or sponsored by
Supercell**. "Hay Day" and "Supercell" are trademarks of their owners and are
used here only to describe what the tool is compatible with.

The tool is intended for use with [hd-server](https://github.com/eliaswen/hd-server), but it can work with any compatible server.

## What it does not contain

- No game code, assets, libraries or APKs. You must supply an APK you
  obtained lawfully yourself.
- No patched APKs, key material or download links.

## Notice

This project does not comply with Supercell's Terms of Service, which prohibit
reverse engineering or modifying the client. It is intended only for
interoperability, educational and research purposes. You are responsible for
complying with your local laws and regulations. See the
[legal notice](LEGAL.md) for more information.

## Supported build

Hay Day **1.43.150, build 1598**, ABIs `x86` and `arm64-v8a`.

The native edits are applied only if the SHA-256 of `lib/<abi>/libg.so` matches
the verified build, and the tool aborts before writing if any expected code
pattern is ambiguous or missing. Other versions are rejected, not guessed at.

## What it changes

1. **Repackages** every zip entry and removes the existing signature files
   (`META-INF/MANIFEST.MF`, `*.SF`, `*.RSA`, `*.DSA`, `*.EC`).
2. **Settings CSV:** in `assets/settings_template.csv` sets `ServerURL` and
   `Port` to `--host` / `--port` and forces `OfflineMode` to `false`.
3. **Server public key** (`--server-public-key`): replaces the embedded 32-byte
   X25519 server public key in `libg.so`. The key appears three times
   (login encryption, first-response decryption, nonce derivation) as obfuscated
   16-bit immediates; all three copies are located by pattern and replaced.
4. **ARM64 only, together with the key swap:** the arm64 library verifies its
   own code regions at login, so the patcher also
   - fixes up a secondary decode constant derived from the key, and
   - makes that self-check read pristine copies of the three modified
     functions, and disables its failure branch.

   This is a modification that defeats the client's own integrity check. See
   the legal note below before distributing or using it.
5. **`--allow-local-ranges`:** allows private-IPv4 servers on both ABIs. On
   x86, an unchecked `getaddrinfo` PLT entry is redirected to a wrapper that
   expands filtered IPv4 results into IPv4-mapped IPv6 results in Bionic's
   inline `sockaddr_storage`; both integrity-checked connect routines stay
   byte-identical. On ARM64, both connect filters are bypassed while their
   integrity checks read pristine copies.
6. **`--bootstrap-url`:** rewrites the native `/env_settings` bootstrap URL to
   your base URL (`scheme://host[:port]`). The new `host:port` must not be longer
   than the original.
7. **Aligns and signs**, built in, with no JDK or Android SDK needed:
   uncompressed entries are aligned to 4 bytes and native libraries to 16 KiB
   (as `zipalign -P 16`), then the APK gets a v1 (JAR) signature and an APK
   Signature Scheme v2 signature. Like `apksigner`, the v1 digests are SHA-1
   when the APK's `minSdkVersion` is below 18 (it is 16 for build 1598) and
   SHA-256 otherwise. The key comes from a PKCS#12 keystore; a new one with a
   2048-bit RSA key is created on first use if it does not exist.

The tool refuses to produce an output if it applied no redirection edit.

## Install

Each [release](https://github.com/eliaswen/hd-patcher/releases) has archives for
Linux, macOS, Windows and Android (arm64 and x86_64, for Termux or `adb shell`). On Linux you can install from the signed apt or dnf
repository instead; [eliaswen.github.io/hd-patcher](https://eliaswen.github.io/hd-patcher/)
has the setup commands.

## Build

```sh
cargo build --release
```

Requires a recent stable Rust toolchain, and nothing else: signing is done
in Rust. For Android, build with [cargo-ndk](https://github.com/bbqsrc/cargo-ndk):

```sh
cargo ndk -t arm64-v8a -P 24 build --release
```

## Library

The crate is also a library, so an app can patch on the device itself:

```rust
use hd_patcher::{Options, NativeOptions, signing::SigningKey, progress::Silent};

let inspection = hd_patcher::inspect("hayday.apk".as_ref())?;
assert!(inspection.is_patchable()); // the verified 1.43.150 build 1598

let (key, _created) = SigningKey::load_or_create("signing.p12".as_ref(), "android", "haydaydebug")?;
let options = Options {
    host: "127.0.0.1".into(),
    port: 9339,
    native: Some(NativeOptions {
        key: hd_patcher::parse_key(server_public_key_hex)?,
        allow_local_ranges: true,
        bootstrap_url: Some("http://127.0.0.1:8080".into()),
    }),
};
hd_patcher::patch("hayday.apk".as_ref(), "patched.apk".as_ref(), &options, &key, &mut Silent)?;
```

Implement `hd_patcher::progress::Progress` to show progress in your own UI.

## Usage

```sh
hd-patcher \
  --apk original.apk \
  -o patched.apk \
  --host 192.168.1.10 --port 9339 \
  --server-public-key <64 hex chars> \
  --allow-local-ranges \
  --bootstrap-url http://192.168.1.10:8080
```

| Option | Meaning |
| --- | --- |
| `--apk` | Input APK (yours). |
| `-o, --out` | Output patched, signed APK. |
| `--host`, `--port` | Server written to the settings CSV (default `10.0.2.2:9339`). |
| `--server-public-key` | 64 hex characters, your server's X25519 public key. |
| `--allow-local-ranges` | Allow private-IPv4 servers (needs the key option). |
| `--bootstrap-url` | Replace the native `/env_settings` base URL (needs the key option). |
| `--keystore`, `--storepass`, `--alias` | PKCS#12 signing keystore (defaults: `debug.keystore`, `android`, `haydaydebug`), created if absent. Keystores made by `keytool` (PKCS#12, its default since JDK 9) work; convert a legacy JKS one with `keytool -importkeystore -deststoretype pkcs12`. Debug defaults only; use your own key for anything else. |

Without `--server-public-key` only the CSV edit is applied.

The patched app is signed with your key, so it cannot update over, or be
installed on top of, the original; uninstall the original first.

## Limitations

- `--port` is broken on ARM64: the patcher writes the port, but the client
  ignores it and always connects to 9339.
- The game occasionally instantly crashes on startup on x86, right after the supercell logo, or during the "loading..." menu. This is fixed by simply restarting the app, sometimes multiple times. The reason for the crash is unknown,but it's probably some kind of rarely activated undefeated security check. No similar startup crash has been observed on ARM64.

## Tests

```sh
cargo test
```

Tests that need real game files are skipped unless you point them at your own
copies: `HD_ARM64_APK` and `HD_X86_APK` (APKs), `HD_X86_LIBG` and
`HD_ARM64_LIBG` (extracted `libg.so`). When the Android SDK is installed
(`ANDROID_HOME`, or `~/Android/Sdk`), every APK the tests produce is also
checked with `apksigner verify`; with a JDK, keystores are cross-checked with
`keytool`.

## AI Usage

This project was almost exclusively written by AI, including code, comments and
documentation. I reviewed everything, but since some people are uncomfortable
with AI-written code, I'm pointing it out.

### Details

- Deepseek v4.1 Flash 1017: bulk ASM scanning
- Kimi 3.1 Pro: more difficult analysis and writing most of the patcher
- Claude Sonnet 5.5: documentation, review, and some patcher code
- Human: review, testing, and writing some of this README

All models were run through [Hermes](https://github.com/NousResearch/hermes-agent)
with access to [REA (Reverse Engineer Anything)](https://github.com/morluto/rea),
[Ghidra](https://github.com/NationalSecurityAgency/ghidra),
[Waydroid](https://github.com/waydroid/waydroid), and an ARM64 Android emulator.
