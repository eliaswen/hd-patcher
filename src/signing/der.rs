//! The little DER this crate writes and reads: X.509 certificates and the
//! PKCS#7 `SignedData` of a v1 (JAR) signature. Only definite-length encodings
//! of the handful of types those structures use are supported.

use anyhow::{Result, bail, ensure};

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const UTF8_STRING: u8 = 0x0c;
pub const PRINTABLE_STRING: u8 = 0x13;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;

/// `[n]` context-specific, constructed.
pub const fn context(n: u8) -> u8 {
    0xa0 | n
}

/// One TLV with the given tag and contents.
pub fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(contents.len() + 6);
    out.push(tag);
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(contents);
    out
}

/// A constructed TLV over the concatenation of `parts`.
pub fn cons(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag, &parts.concat())
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    cons(SEQUENCE, parts)
}

pub fn set(parts: &[&[u8]]) -> Vec<u8> {
    cons(SET, parts)
}

/// A non-negative INTEGER from big-endian magnitude bytes.
pub fn unsigned_integer(magnitude: &[u8]) -> Vec<u8> {
    let trimmed: &[u8] = match magnitude.iter().position(|&b| b != 0) {
        Some(start) => &magnitude[start..],
        None => &[0],
    };
    let mut contents = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        contents.push(0);
    }
    contents.extend_from_slice(trimmed);
    tlv(INTEGER, &contents)
}

pub fn small_integer(value: u8) -> Vec<u8> {
    unsigned_integer(&[value])
}

/// An OBJECT IDENTIFIER from its dotted arcs.
pub fn oid(arcs: &[u64]) -> Vec<u8> {
    assert!(arcs.len() >= 2 && arcs[0] <= 2);
    let mut contents = Vec::new();
    let mut push_arc = |mut arc: u64| {
        let mut groups = vec![(arc & 0x7f) as u8];
        arc >>= 7;
        while arc > 0 {
            groups.push(0x80 | (arc & 0x7f) as u8);
            arc >>= 7;
        }
        groups.reverse();
        contents.extend_from_slice(&groups);
    };
    push_arc(arcs[0] * 40 + arcs[1]);
    for &arc in &arcs[2..] {
        push_arc(arc);
    }
    tlv(OID, &contents)
}

/// `AlgorithmIdentifier { algorithm, parameters NULL }`.
pub fn algorithm(arcs: &[u64]) -> Vec<u8> {
    seq(&[&oid(arcs), &tlv(NULL, &[])])
}

pub const SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
pub const SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
pub const RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
pub const SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
pub const PKCS7_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
pub const PKCS7_SIGNED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 2];

/// A parsed TLV borrowing its input.
#[derive(Debug, Clone, Copy)]
pub struct Element<'a> {
    pub tag: u8,
    /// The contents, without tag and length.
    pub contents: &'a [u8],
    /// The whole encoding, tag and length included.
    pub raw: &'a [u8],
}

/// Reads consecutive TLVs out of a byte slice.
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { rest: data }
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    pub fn next(&mut self) -> Result<Element<'a>> {
        let data = self.rest;
        ensure!(data.len() >= 2, "truncated DER");
        let tag = data[0];
        ensure!(tag & 0x1f != 0x1f, "multi-byte DER tags are not supported");
        let (len, header) = match data[1] {
            short @ 0..=0x7f => (short as usize, 2),
            0x80 => bail!("indefinite-length DER is not supported"),
            long => {
                let count = (long & 0x7f) as usize;
                ensure!(count <= 8 && data.len() >= 2 + count, "bad DER length");
                let len = data[2..2 + count]
                    .iter()
                    .fold(0usize, |acc, &b| (acc << 8) | b as usize);
                (len, 2 + count)
            }
        };
        ensure!(data.len() - header >= len, "truncated DER element");
        let end = header + len;
        self.rest = &data[end..];
        Ok(Element {
            tag,
            contents: &data[header..end],
            raw: &data[..end],
        })
    }

    /// The next element, which must carry `tag`.
    pub fn expect(&mut self, tag: u8, what: &str) -> Result<Element<'a>> {
        let element = self.next()?;
        ensure!(
            element.tag == tag,
            "{what}: expected DER tag {tag:#04x}, found {:#04x}",
            element.tag
        );
        Ok(element)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_and_integers() {
        assert_eq!(tlv(OCTET_STRING, &[1, 2]), [0x04, 2, 1, 2]);
        let long = tlv(OCTET_STRING, &[0; 300]);
        assert_eq!(&long[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(unsigned_integer(&[0, 0, 0x80]), [0x02, 2, 0, 0x80]);
        assert_eq!(unsigned_integer(&[0, 0]), [0x02, 1, 0]);
        assert_eq!(small_integer(2), [0x02, 1, 2]);
    }

    #[test]
    fn oids_match_their_known_encodings() {
        assert_eq!(
            oid(SHA256_WITH_RSA),
            [
                0x06, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b
            ]
        );
        assert_eq!(oid(SHA1), [0x06, 5, 0x2b, 0x0e, 0x03, 0x02, 0x1a]);
    }

    #[test]
    fn reader_round_trips() {
        let inner = seq(&[&small_integer(1), &tlv(OCTET_STRING, &[0; 200])]);
        let mut reader = Reader::new(&inner);
        let outer = reader.expect(SEQUENCE, "outer").unwrap();
        assert!(reader.is_empty());
        assert_eq!(outer.raw, &inner[..]);
        let mut fields = Reader::new(outer.contents);
        assert_eq!(fields.expect(INTEGER, "int").unwrap().contents, [1]);
        assert_eq!(
            fields
                .expect(OCTET_STRING, "octets")
                .unwrap()
                .contents
                .len(),
            200
        );
        assert!(fields.next().is_err());
    }
}
