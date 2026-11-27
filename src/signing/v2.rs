//! APK Signature Scheme v2: an APK Signing Block, inserted between the last
//! entry and the central directory, that signs a chunked SHA-256 digest of the
//! rest of the file.
//!
//! <https://source.android.com/docs/security/features/apksigning/v2>

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};

use super::SigningKey;

const BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
const V2_BLOCK_ID: u32 = 0x7109_871a;
/// RSASSA-PKCS1-v1_5 with SHA2-256 digest.
const RSA_PKCS1_SHA256: u32 = 0x0103;
const CHUNK: usize = 1024 * 1024;
const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const EOCD_MIN: usize = 22;

/// Where the parts of a ZIP file are.
struct Layout {
    central_directory: u64,
    eocd: u64,
    eocd_bytes: Vec<u8>,
}

/// Copy the unsigned (but v1-signed, if wanted) APK at `input` to `output`
/// with a v2 signature block inserted.
pub fn sign(input: &Path, output: &Path, key: &SigningKey) -> Result<()> {
    let mut file = File::open(input).with_context(|| format!("opening {}", input.display()))?;
    let layout = locate(&mut file)?;

    let digest = content_digest(&mut file, &layout)?;
    let block = signing_block(&digest, key)?;

    let mut out = BufWriter::new(
        File::create(output).with_context(|| format!("creating {}", output.display()))?,
    );
    file.seek(SeekFrom::Start(0))?;
    std::io::copy(&mut (&mut file).take(layout.central_directory), &mut out)?;
    out.write_all(&block)?;
    file.seek(SeekFrom::Start(layout.central_directory))?;
    std::io::copy(
        &mut (&mut file).take(layout.eocd - layout.central_directory),
        &mut out,
    )?;
    let mut eocd = layout.eocd_bytes.clone();
    let moved = u32::try_from(layout.central_directory + block.len() as u64)
        .context("APK is too large for a non-ZIP64 central directory offset")?;
    eocd[16..20].copy_from_slice(&moved.to_le_bytes());
    out.write_all(&eocd)?;
    out.into_inner()
        .map_err(|e| e.into_error())?
        .sync_all()
        .with_context(|| format!("writing {}", output.display()))?;
    Ok(())
}

/// Find the end-of-central-directory record and check the archive is one a v2
/// signature can be added to.
fn locate(file: &mut File) -> Result<Layout> {
    let len = file.seek(SeekFrom::End(0))?;
    ensure!(len >= EOCD_MIN as u64, "not a ZIP file (too short)");
    let tail_len = len.min((EOCD_MIN + u16::MAX as usize) as u64) as usize;
    let mut tail = vec![0u8; tail_len];
    file.seek(SeekFrom::Start(len - tail_len as u64))?;
    file.read_exact(&mut tail)?;

    let eocd_at = (0..=tail_len - EOCD_MIN)
        .rev()
        .find(|&i| {
            u32::from_le_bytes(tail[i..i + 4].try_into().unwrap()) == EOCD_SIGNATURE
                && i + EOCD_MIN + u16::from_le_bytes([tail[i + 20], tail[i + 21]]) as usize
                    == tail_len
        })
        .context("no ZIP end-of-central-directory record")?;
    let eocd_bytes = tail[eocd_at..].to_vec();
    let eocd = len - (tail_len - eocd_at) as u64;
    let cd_size = u32::from_le_bytes(eocd_bytes[12..16].try_into().unwrap()) as u64;
    let cd_offset = u32::from_le_bytes(eocd_bytes[16..20].try_into().unwrap());
    if cd_offset == u32::MAX {
        bail!("ZIP64 APKs are not supported");
    }
    let central_directory = cd_offset as u64;
    ensure!(
        central_directory + cd_size == eocd,
        "the central directory does not end at the end-of-central-directory record"
    );

    if central_directory >= 32 {
        let mut magic = [0u8; 16];
        file.seek(SeekFrom::Start(central_directory - 16))?;
        file.read_exact(&mut magic)?;
        ensure!(&magic != BLOCK_MAGIC, "the APK already has a signing block");
    }
    Ok(Layout {
        central_directory,
        eocd,
        eocd_bytes,
    })
}

/// The v2 content digest: every 1 MiB chunk of the entries, the central
/// directory and the end-of-central-directory record (whose offset field
/// already names the signing block's position, the central directory's
/// position before insertion) is hashed, then the chunk hashes are hashed.
fn content_digest(file: &mut File, layout: &Layout) -> Result<[u8; 32]> {
    let mut chunk_digests = Vec::new();
    let mut count = 0u32;
    let mut buffer = vec![0u8; CHUNK];
    let mut push = |chunk: &[u8]| {
        let mut hasher = Sha256::new();
        hasher.update([0xa5]);
        hasher.update((chunk.len() as u32).to_le_bytes());
        hasher.update(chunk);
        chunk_digests.extend_from_slice(&hasher.finalize());
        count += 1;
    };

    for (start, end) in [
        (0, layout.central_directory),
        (layout.central_directory, layout.eocd),
    ] {
        file.seek(SeekFrom::Start(start))?;
        let mut left = end - start;
        while left > 0 {
            let take = left.min(CHUNK as u64) as usize;
            file.read_exact(&mut buffer[..take])?;
            push(&buffer[..take]);
            left -= take as u64;
        }
    }
    for chunk in layout.eocd_bytes.chunks(CHUNK) {
        push(chunk);
    }

    let mut top = Sha256::new();
    top.update([0x5a]);
    top.update(count.to_le_bytes());
    top.update(&chunk_digests);
    Ok(top.finalize().into())
}

fn length_prefixed(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 4);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out
}

/// The complete APK Signing Block holding one v2 signer.
fn signing_block(digest: &[u8; 32], key: &SigningKey) -> Result<Vec<u8>> {
    let mut digest_entry = RSA_PKCS1_SHA256.to_le_bytes().to_vec();
    digest_entry.extend(length_prefixed(digest));
    let digests = length_prefixed(&length_prefixed(&digest_entry));
    let certificates = length_prefixed(&length_prefixed(key.certificate_der()));
    let attributes = length_prefixed(&[]);
    let signed_data = [digests, certificates, attributes].concat();

    let mut signature_entry = RSA_PKCS1_SHA256.to_le_bytes().to_vec();
    signature_entry.extend(length_prefixed(&key.sign_sha256(&signed_data)));
    let signatures = length_prefixed(&length_prefixed(&signature_entry));
    let public_key = length_prefixed(&key.public_key_der()?);
    let signer = [length_prefixed(&signed_data), signatures, public_key].concat();
    let value = length_prefixed(&length_prefixed(&signer));

    let mut pair = Vec::with_capacity(value.len() + 12);
    pair.extend_from_slice(&((value.len() + 4) as u64).to_le_bytes());
    pair.extend_from_slice(&V2_BLOCK_ID.to_le_bytes());
    pair.extend_from_slice(&value);

    // The size fields count everything after the leading one.
    let size = (pair.len() + 8 + BLOCK_MAGIC.len()) as u64;
    let mut block = Vec::with_capacity(size as usize + 8);
    block.extend_from_slice(&size.to_le_bytes());
    block.extend_from_slice(&pair);
    block.extend_from_slice(&size.to_le_bytes());
    block.extend_from_slice(BLOCK_MAGIC);
    Ok(block)
}
