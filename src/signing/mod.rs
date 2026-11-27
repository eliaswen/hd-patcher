//! APK signing, entirely in Rust: no JDK or Android SDK is needed, so the same
//! code signs on Linux, macOS, Windows and Android itself.
//!
//! - [`SigningKey`]: an RSA key and its certificate, read from or written to a
//!   PKCS#12 keystore (the format `keytool` creates by default since JDK 9).
//! - [`v1`]: JAR signing (`META-INF/MANIFEST.MF`, `CERT.SF`, `CERT.RSA`), which
//!   Android before 7.0 verifies. Written into the archive while it is built.
//! - [`v2`]: APK Signature Scheme v2, which Android 7.0+ verifies and Android
//!   11+ requires. Inserted into the finished archive.
//!
//! Like `apksigner`, the v1 digests are SHA-1 when the APK's `minSdkVersion` is
//! below 18 (Android 4.3 added SHA-256 to JAR verification) and SHA-256
//! otherwise; v2 always uses RSASSA-PKCS1-v1_5 with SHA-256.

mod cert;
mod der;
pub(crate) mod v1;
pub(crate) mod v2;

use std::path::Path;

use anyhow::{Context, Result, bail};
use p12_keystore::{
    Certificate, KeyStore, KeyStoreEntry, Pkcs12ImportPolicy, PrivateKey, PrivateKeyChain,
};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use sha2::{Digest, Sha256};

/// Default keystore password, as earlier releases passed to `keytool`.
pub const DEFAULT_PASSWORD: &str = "android";
/// Default key alias, as earlier releases passed to `keytool`.
pub const DEFAULT_ALIAS: &str = "haydaydebug";

/// RSA modulus size of generated keys.
const KEY_BITS: usize = 2048;

/// An RSA signing key with its X.509 certificate.
#[derive(Clone)]
pub struct SigningKey {
    key: rsa::PrivateKey,
    certificate: Vec<u8>,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("certificate_sha256", &self.certificate_sha256())
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Generate a new 2048-bit RSA key with a self-signed certificate.
    pub fn generate() -> Result<Self> {
        let mut rng = getrandom::SysRng;
        let key = rsa::PrivateKey::new(&mut rng, KEY_BITS).context("generating an RSA key")?;
        let mut serial = [0u8; 8];
        getrandom::fill(&mut serial).map_err(|e| anyhow::anyhow!("reading OS randomness: {e}"))?;
        let certificate = cert::self_signed(&key, serial)?;
        Ok(Self { key, certificate })
    }

    /// Build a key from a PKCS#8 DER private key and a DER certificate.
    pub fn from_der(pkcs8: &[u8], certificate: &[u8]) -> Result<Self> {
        let key = rsa::PrivateKey::from_pkcs8_der(pkcs8)
            .context("the private key is not an RSA key (only RSA keys are supported)")?;
        cert::issuer_and_serial(certificate).context("parsing the signing certificate")?;
        Ok(Self {
            key,
            certificate: certificate.to_vec(),
        })
    }

    /// Read the key stored under `alias` from a PKCS#12 keystore.
    pub fn from_pkcs12(data: &[u8], password: &str, alias: &str) -> Result<Self> {
        if data.starts_with(&[0xfe, 0xed, 0xfe, 0xed]) {
            bail!(
                "this is a legacy JKS keystore; convert it to PKCS#12 first:\n  \
                 keytool -importkeystore -srckeystore <old> -destkeystore <new> -deststoretype pkcs12"
            );
        }
        let store = KeyStore::from_pkcs12(data, password, Pkcs12ImportPolicy::Relaxed)
            .map_err(|e| anyhow::anyhow!("reading the PKCS#12 keystore (wrong password?): {e}"))?;
        let chain = match store.entry(alias) {
            Some(KeyStoreEntry::PrivateKeyChain(chain)) => chain,
            Some(_) => bail!("keystore entry {alias:?} is not a private key"),
            None => {
                let aliases: Vec<&str> = store
                    .entries()
                    .filter(|(_, entry)| matches!(entry, KeyStoreEntry::PrivateKeyChain(_)))
                    .map(|(alias, _)| alias.as_str())
                    .collect();
                bail!(
                    "keystore has no key {alias:?} (keys: {})",
                    aliases.join(", ")
                );
            }
        };
        let certificate = chain
            .certs()
            .first()
            .with_context(|| format!("keystore key {alias:?} has no certificate"))?;
        Self::from_der(chain.key().as_der(), certificate.as_der())
    }

    /// Encode as a PKCS#12 keystore holding this key under `alias`, encrypted
    /// the way current JDKs write them (PBES2 AES-256, HMAC-SHA256), so
    /// `keytool`, `apksigner` and `jarsigner` can read it.
    pub fn to_pkcs12(&self, password: &str, alias: &str) -> Result<Vec<u8>> {
        let pkcs8 = self
            .key
            .to_pkcs8_der()
            .context("encoding the private key")?;
        let key = PrivateKey::from_der(pkcs8.as_bytes())
            .map_err(|e| anyhow::anyhow!("encoding the private key: {e}"))?;
        let certificate = Certificate::from_der(&self.certificate)
            .map_err(|e| anyhow::anyhow!("encoding the certificate: {e}"))?;
        let local_key_id = Sha256::digest(&self.certificate)[..20].to_vec();
        let mut store = KeyStore::new();
        store.add_entry(
            alias,
            KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(local_key_id, key, [certificate])),
        );
        store
            .writer(password)
            .write()
            .map_err(|e| anyhow::anyhow!("writing the PKCS#12 keystore: {e}"))
    }

    /// Read the keystore at `path`, or create one with a new key when the file
    /// does not exist. Returns the key and whether it was created.
    pub fn load_or_create(path: &Path, password: &str, alias: &str) -> Result<(Self, bool)> {
        match std::fs::read(path) {
            Ok(data) => Self::from_pkcs12(&data, password, alias)
                .with_context(|| format!("loading keystore {}", path.display()))
                .map(|key| (key, false)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let key = Self::generate()?;
                let data = key.to_pkcs12(password, alias)?;
                if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("creating {}", parent.display()))?;
                }
                // `create_new` so two concurrent runs cannot both write a key.
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .with_context(|| format!("creating keystore {}", path.display()))?;
                file.write_all(&data)
                    .with_context(|| format!("writing keystore {}", path.display()))?;
                Ok((key, true))
            }
            Err(error) => {
                Err(error).with_context(|| format!("reading keystore {}", path.display()))
            }
        }
    }

    /// The DER-encoded X.509 certificate.
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate
    }

    /// SHA-256 of the certificate, hex: the fingerprint Android shows and
    /// `apksigner verify --print-certs` prints.
    pub fn certificate_sha256(&self) -> String {
        hex(&Sha256::digest(&self.certificate))
    }

    fn sign_sha256(&self, message: &[u8]) -> Vec<u8> {
        use rsa::signature::{SignatureEncoding, Signer};
        rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(self.key.clone())
            .sign(message)
            .to_vec()
    }

    fn sign_sha1(&self, message: &[u8]) -> Vec<u8> {
        use rsa::signature::{SignatureEncoding, Signer};
        rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new(self.key.clone())
            .sign(message)
            .to_vec()
    }

    fn public_key_der(&self) -> Result<Vec<u8>> {
        use rsa::pkcs8::EncodePublicKey;
        Ok(self
            .key
            .to_public_key()
            .to_public_key_der()
            .context("encoding the public key")?
            .into_vec())
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// One generated key shared by every test, since generation is slow.
    pub fn key() -> &'static SigningKey {
        static KEY: OnceLock<SigningKey> = OnceLock::new();
        KEY.get_or_init(|| SigningKey::generate().unwrap())
    }

    #[test]
    fn pkcs12_round_trips() {
        let key = key();
        let data = key.to_pkcs12("secret", "alias").unwrap();
        let back = SigningKey::from_pkcs12(&data, "secret", "alias").unwrap();
        assert_eq!(back.certificate_der(), key.certificate_der());
        assert_eq!(back.sign_sha256(b"x"), key.sign_sha256(b"x"));
        assert!(SigningKey::from_pkcs12(&data, "wrong", "alias").is_err());
        let missing = SigningKey::from_pkcs12(&data, "secret", "other").unwrap_err();
        assert!(format!("{missing:#}").contains("alias"), "{missing:#}");
    }

    #[test]
    fn rejects_jks_with_a_conversion_hint() {
        let error =
            SigningKey::from_pkcs12(&[0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 2], "a", "b").unwrap_err();
        assert!(format!("{error:#}").contains("-importkeystore"));
    }

    /// `keytool` must accept the keystores this crate writes, and this crate
    /// must read the ones `keytool` writes. Skipped without a JDK.
    #[test]
    fn interoperates_with_keytool() {
        if std::process::Command::new("keytool")
            .arg("-help")
            .output()
            .is_err()
        {
            eprintln!("keytool not found; skipping");
            return;
        }
        let dir = std::env::temp_dir().join(format!("hd-patcher-keytool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let ours = dir.join("ours.p12");
        std::fs::write(&ours, key().to_pkcs12("android", "haydaydebug").unwrap()).unwrap();
        let listed = std::process::Command::new("keytool")
            .args(["-list", "-storepass", "android", "-keystore"])
            .arg(&ours)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&listed.stdout);
        assert!(listed.status.success(), "{text}");
        assert!(text.contains("haydaydebug"), "{text}");

        let theirs = dir.join("theirs.keystore");
        let status = std::process::Command::new("keytool")
            .args(["-genkeypair", "-keystore"])
            .arg(&theirs)
            .args([
                "-storepass",
                "android",
                "-keypass",
                "android",
                "-alias",
                "haydaydebug",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "10000",
                "-dname",
                "CN=Hay Day Debug, OU=Dev, O=HayDayCustomServer, C=US",
            ])
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        SigningKey::from_pkcs12(&std::fs::read(&theirs).unwrap(), "android", "haydaydebug")
            .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
