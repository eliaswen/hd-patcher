//! Command-line front end of the [`hd_patcher`] library.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Result, bail};
use clap::Parser;

use hd_patcher::progress::{self, Console, Progress};
use hd_patcher::signing::{self, SigningKey};

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

    /// Bypass the native private-IPv4 address filters in both game TCP connect
    /// paths. On x86 this wraps getaddrinfo; on ARM64 it patches both filters
    /// while preserving their integrity-check bytes. Requires --server-public-key.
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

    /// PKCS#12 keystore to sign with (created with a new RSA key if absent).
    #[arg(long, default_value = "debug.keystore")]
    keystore: PathBuf,

    /// Keystore + key password (debug only).
    #[arg(long, default_value = signing::DEFAULT_PASSWORD)]
    storepass: String,

    /// Key alias.
    #[arg(long, default_value = signing::DEFAULT_ALIAS)]
    alias: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let started = Instant::now();
    let mut console = Console::new();

    let native = match args.server_public_key.as_deref() {
        Some(hex) => Some(hd_patcher::NativeOptions {
            key: hd_patcher::parse_key(hex)?,
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

    println!("hd-patcher: {} -> {}", args.apk.display(), args.out.display());
    console.info(&format!("target {}:{}", args.host, args.port));

    let (key, created) = SigningKey::load_or_create(&args.keystore, &args.storepass, &args.alias)?;
    if created {
        console.info(&format!("generated a new signing key in {}", args.keystore.display()));
    }

    let options = hd_patcher::Options {
        host: args.host.clone(),
        port: args.port,
        native,
    };
    hd_patcher::patch(&args.apk, &args.out, &options, &key, &mut console)?;

    println!(
        "\nDone in {}. Patched + signed APK: {}",
        progress::fmt_duration(started.elapsed()),
        args.out.display()
    );
    println!("Configured CSV endpoint: {}:{}", args.host, args.port);
    if let Some(base) = &args.bootstrap_url {
        println!("Bootstrap /env_settings will be fetched from {base}");
    }
    Ok(())
}
