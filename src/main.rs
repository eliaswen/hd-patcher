//! Repackage and sign a Hay Day APK so it connects to a custom server.
//!
//! - [`apk`]: repackaging and the settings-CSV edit.
//! - [`native`]: edits to `libg.so` (server key, integrity check, bootstrap URL,
//!   local-range filters) for the supported 1.43.150 build 1598, x86 and arm64-v8a.
//! - [`signing`]: zipalign + apksigner, with a jarsigner fallback.

mod apk;
mod native;
mod signing;

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "hd-patcher",
    about = "Patch a Hay Day APK to connect to a custom server/proxy"
)]
struct Args {
    /// Input APK path.
    #[arg(long)]
    apk: PathBuf,

    /// Output (patched, signed) APK path.
    #[arg(long, short = 'o')]
    out: PathBuf,

    /// Proxy/server host to redirect the client to.
    #[arg(long, default_value = "10.0.2.2")]
    host: String,

    /// Proxy/server port.
    #[arg(long, default_value_t = 9339)]
    port: u16,

    /// Replace the embedded server key (64 hex characters); x86 and arm64-v8a build 1598.
    #[arg(long)]
    server_public_key: Option<String>,

    /// ARM64: bypass the native private-IPv4 address filters in both game TCP
    /// connect paths. x86: the client integrity-checks its connect path, so no
    /// binary bypass is applied; instead the env's `serverHost` must be the
    /// IPv4-mapped IPv6 form (`::ffff:a.b.c.d`), which the AF_INET-only filter
    /// skips. Requires --server-public-key.
    #[arg(long)]
    allow_local_ranges: bool,

    /// x86 and ARM64: rewrite the native `/env_settings` bootstrap URL to this
    /// base (`scheme://host[:port]`). The path/query and format placeholders are
    /// preserved; the host:port must not be longer than the original. Requires
    /// --server-public-key. On ARM64 the checked region is extracted from the
    /// input library, copied and retargeted, and the integrity VM's failure-only
    /// trap is routed to its safe exit; on x86 the two `lea` refs are redirected.
    #[arg(long)]
    bootstrap_url: Option<String>,

    /// Keystore path to sign with (created if absent).
    #[arg(long, default_value = "debug.keystore")]
    keystore: PathBuf,

    /// Keystore + key password (debug only).
    #[arg(long, default_value = "android")]
    storepass: String,

    /// Key alias.
    #[arg(long, default_value = "haydaydebug")]
    alias: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if !args.apk.exists() {
        bail!("input APK does not exist: {}", args.apk.display());
    }

    let native = match args.server_public_key.as_deref() {
        Some(hex) => Some(native::Options {
            key: native::parse_key(hex)?,
            host: args.host.clone(),
            allow_local_ranges: args.allow_local_ranges,
            bootstrap_url: args.bootstrap_url.clone(),
        }),
        None => {
            if args.allow_local_ranges {
                bail!("--allow-local-ranges requires --server-public-key");
            }
            if args.bootstrap_url.is_some() {
                bail!("--bootstrap-url requires --server-public-key");
            }
            None
        }
    };

    // 1. Repackage into an unsigned, patched APK (old signature stripped).
    let unsigned = args.out.with_extension("unsigned.apk");
    let options = apk::Options {
        host: args.host.clone(),
        port: args.port,
        native,
    };
    let report = apk::repackage(&args.apk, &unsigned, &options).context("repackaging APK")?;

    println!("Repackaged {} entries.", report.total);
    for note in &report.edits {
        println!("  edit: {note}");
    }
    if report.edits.is_empty() {
        bail!("no redirection edit was applied — refusing to produce an APK that still points at the original servers");
    }

    // 2. Align and sign.
    let keystore = signing::Keystore {
        path: args.keystore,
        password: args.storepass,
        alias: args.alias,
    };
    signing::sign(&unsigned, &args.out, &keystore)?;
    let _ = std::fs::remove_file(&unsigned);

    println!("\nPatched + signed APK: {}", args.out.display());
    println!("Configured CSV endpoint: {}:{}", args.host, args.port);
    if let Some(base) = &args.bootstrap_url {
        println!("Bootstrap /env_settings will be fetched from {base}");
    }
    Ok(())
}
