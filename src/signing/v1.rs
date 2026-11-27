//! v1 (JAR) signing: `META-INF/MANIFEST.MF`, `META-INF/CERT.SF` and the PKCS#7
//! signature block `META-INF/CERT.RSA`, laid out the way `apksigner` writes
//! them.

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};

use super::{SigningKey, cert, der};

pub const MANIFEST: &str = "META-INF/MANIFEST.MF";
const SIGNATURE_FILE: &str = "META-INF/CERT.SF";
const SIGNATURE_BLOCK: &str = "META-INF/CERT.RSA";
const CREATED_BY: &str = concat!(env!("CARGO_PKG_VERSION"), " (hd-patcher)");

/// Digest of the v1 entries, chosen from the APK's `minSdkVersion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Sha1,
    Sha256,
}

impl DigestAlgorithm {
    /// Android verifies SHA-256 JAR signatures from API level 18 on.
    pub fn for_min_sdk(min_sdk: u32) -> Self {
        if min_sdk < 18 {
            Self::Sha1
        } else {
            Self::Sha256
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
        }
    }

    fn attribute(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA-256",
        }
    }

    fn oid(self) -> &'static [u64] {
        match self {
            Self::Sha1 => der::SHA1,
            Self::Sha256 => der::SHA256,
        }
    }
}

/// True for the files a v1 signature consists of, which are dropped from the
/// input and regenerated: `META-INF/MANIFEST.MF`, and `*.SF`, `*.RSA`, `*.DSA`,
/// `*.EC` and `SIG-*` directly in `META-INF/`.
pub fn is_signature_file(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let Some(file) = upper.strip_prefix("META-INF/") else {
        return false;
    };
    if file.contains('/') {
        return false;
    }
    file == "MANIFEST.MF"
        || file.starts_with("SIG-")
        || [".SF", ".RSA", ".DSA", ".EC"]
            .iter()
            .any(|ext| file.ends_with(ext))
}

/// Whether an entry is listed in the manifest: every file entry that is not
/// itself part of the signature.
pub fn is_signed_entry(name: &str) -> bool {
    !name.ends_with('/') && !is_signature_file(name)
}

/// Build the three signature files for `entries` (name, digest of the
/// uncompressed contents, in archive order). `v2_signed` adds the
/// `X-Android-APK-Signed` attribute that stops v2 from being stripped.
pub fn signature_files(
    entries: &[(String, Vec<u8>)],
    algorithm: DigestAlgorithm,
    key: &SigningKey,
    v2_signed: bool,
) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let digest_attribute = format!("{}-Digest", algorithm.attribute());

    let mut manifest = Vec::new();
    attribute(&mut manifest, "Manifest-Version", "1.0");
    attribute(&mut manifest, "Created-By", CREATED_BY);
    manifest.extend_from_slice(b"\r\n");

    let mut sections = Vec::with_capacity(entries.len());
    for (name, digest) in entries {
        let mut section = Vec::new();
        attribute(&mut section, "Name", name);
        attribute(&mut section, &digest_attribute, &BASE64.encode(digest));
        section.extend_from_slice(b"\r\n");
        manifest.extend_from_slice(&section);
        sections.push((name, algorithm.digest(&section)));
    }

    let mut signature_file = Vec::new();
    attribute(&mut signature_file, "Signature-Version", "1.0");
    attribute(&mut signature_file, "Created-By", CREATED_BY);
    attribute(
        &mut signature_file,
        &format!("{}-Digest-Manifest", algorithm.attribute()),
        &BASE64.encode(algorithm.digest(&manifest)),
    );
    if v2_signed {
        attribute(&mut signature_file, "X-Android-APK-Signed", "2");
    }
    signature_file.extend_from_slice(b"\r\n");
    for (name, digest) in sections {
        attribute(&mut signature_file, "Name", name);
        attribute(
            &mut signature_file,
            &digest_attribute,
            &BASE64.encode(digest),
        );
        signature_file.extend_from_slice(b"\r\n");
    }

    let block = signature_block(&signature_file, algorithm, key)?;
    Ok(vec![
        (MANIFEST, manifest),
        (SIGNATURE_FILE, signature_file),
        (SIGNATURE_BLOCK, block),
    ])
}

/// One `Name: value` line, wrapped at 72 bytes with single-space continuation
/// lines as the JAR specification requires.
fn attribute(out: &mut Vec<u8>, name: &str, value: &str) {
    let line = format!("{name}: {value}");
    let bytes = line.as_bytes();
    let (first, mut rest) = bytes.split_at(bytes.len().min(72));
    out.extend_from_slice(first);
    out.extend_from_slice(b"\r\n");
    while !rest.is_empty() {
        let (chunk, tail) = rest.split_at(rest.len().min(71));
        out.push(b' ');
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
        rest = tail;
    }
}

/// PKCS#7 `SignedData` over `signature_file`, detached, with the signing
/// certificate and one `SignerInfo` that signs the file directly (no signed
/// attributes), as `apksigner` writes it.
fn signature_block(
    signature_file: &[u8],
    algorithm: DigestAlgorithm,
    key: &SigningKey,
) -> Result<Vec<u8>> {
    let signature = match algorithm {
        DigestAlgorithm::Sha1 => key.sign_sha1(signature_file),
        DigestAlgorithm::Sha256 => key.sign_sha256(signature_file),
    };
    let (issuer, serial) = cert::issuer_and_serial(key.certificate_der())?;
    let digest_algorithm = der::algorithm(algorithm.oid());
    let signer_info = der::seq(&[
        &der::small_integer(1),
        &der::seq(&[&issuer, &serial]),
        &digest_algorithm,
        &der::algorithm(der::RSA_ENCRYPTION),
        &der::tlv(der::OCTET_STRING, &signature),
    ]);
    let signed_data = der::seq(&[
        &der::small_integer(1),
        &der::set(&[&digest_algorithm]),
        &der::seq(&[&der::oid(der::PKCS7_DATA)]),
        &der::tlv(der::context(0), key.certificate_der()),
        &der::set(&[&signer_info]),
    ]);
    Ok(der::seq(&[
        &der::oid(der::PKCS7_SIGNED_DATA),
        &der::tlv(der::context(0), &signed_data),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_attributes_wrap_at_72_bytes() {
        let mut out = Vec::new();
        let name = "a".repeat(150);
        attribute(&mut out, "Name", &name);
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert_eq!(lines.last(), Some(&""));
        assert_eq!(lines[0].len(), 72);
        assert!(
            lines[1..lines.len() - 1]
                .iter()
                .all(|l| l.starts_with(' ') && l.len() <= 72)
        );
        let joined: String = lines
            .iter()
            .enumerate()
            .map(|(i, l)| {
                if i == 0 {
                    *l
                } else {
                    l.strip_prefix(' ').unwrap_or(l)
                }
            })
            .collect();
        assert_eq!(joined, format!("Name: {name}"));
    }

    #[test]
    fn signature_files_are_recognised() {
        for name in [
            "META-INF/MANIFEST.MF",
            "META-INF/CERT.SF",
            "meta-inf/foo.rsa",
            "META-INF/X.EC",
            "META-INF/SIG-A",
        ] {
            assert!(is_signature_file(name), "{name}");
        }
        for name in [
            "META-INF/services/a.RSA",
            "assets/CERT.SF",
            "META-INF/com/android/build",
        ] {
            assert!(!is_signature_file(name), "{name}");
        }
        assert!(!is_signed_entry("assets/"));
        assert!(is_signed_entry("assets/a.csv"));
    }

    #[test]
    fn section_digests_cover_the_manifest_sections() {
        let key = super::super::tests::key();
        let entries = vec![("a.txt".to_string(), vec![1u8; 32])];
        let files = signature_files(&entries, DigestAlgorithm::Sha256, key, true).unwrap();
        let manifest = String::from_utf8(files[0].1.clone()).unwrap();
        let sf = String::from_utf8(files[1].1.clone()).unwrap();
        let section = &manifest[manifest.find("Name: a.txt").unwrap()..];
        let expected = BASE64.encode(Sha256::digest(section.as_bytes()));
        assert!(
            sf.contains(&format!("Name: a.txt\r\nSHA-256-Digest: {expected}\r\n")),
            "{sf}"
        );
        assert!(sf.contains("X-Android-APK-Signed: 2\r\n"));
    }
}
