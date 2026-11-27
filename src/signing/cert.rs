//! Self-signed X.509 certificates for new signing keys, and the fields of a
//! certificate a PKCS#7 signer has to name.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};

use super::der::{self, Reader};

/// The distinguished name `keytool` was given by earlier releases, kept so new
/// keys look the same as the ones those releases created.
const SUBJECT: [(&[u64], u8, &str); 4] = [
    (&[2, 5, 4, 6], der::PRINTABLE_STRING, "US"),
    (&[2, 5, 4, 10], der::UTF8_STRING, "HayDayCustomServer"),
    (&[2, 5, 4, 11], der::UTF8_STRING, "Dev"),
    (&[2, 5, 4, 3], der::UTF8_STRING, "Hay Day Debug"),
];

/// Validity of a new certificate, as `keytool -validity 10000` gave it.
const VALIDITY_DAYS: i64 = 10_000;

/// Build a self-signed `sha256WithRSAEncryption` certificate for `key`.
pub fn self_signed(key: &rsa::PrivateKey, serial: [u8; 8]) -> Result<Vec<u8>> {
    let name = {
        let rdns: Vec<Vec<u8>> = SUBJECT
            .iter()
            .map(|(arcs, kind, value)| {
                der::set(&[&der::seq(&[
                    &der::oid(arcs),
                    &der::tlv(*kind, value.as_bytes()),
                ])])
            })
            .collect();
        let parts: Vec<&[u8]> = rdns.iter().map(Vec::as_slice).collect();
        der::seq(&parts)
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before 1970")?
        .as_secs() as i64;
    let validity = der::seq(&[&time(now), &time(now + VALIDITY_DAYS * 86_400)]);
    let spki = key
        .to_public_key()
        .to_public_key_der()
        .context("encoding the public key")?;
    // A positive serial: clear the top bit so the INTEGER needs no sign byte.
    let mut serial = serial;
    serial[0] &= 0x7f;
    serial[0] |= 0x01;

    let tbs = der::seq(&[
        &der::tlv(der::context(0), &der::small_integer(2)),
        &der::unsigned_integer(&serial),
        &der::algorithm(der::SHA256_WITH_RSA),
        &name,
        &validity,
        &name,
        spki.as_bytes(),
    ]);
    let signature = SigningKey::<Sha256>::new(key.clone()).sign(&tbs).to_vec();
    let mut bits = Vec::with_capacity(signature.len() + 1);
    bits.push(0);
    bits.extend_from_slice(&signature);
    Ok(der::seq(&[
        &tbs,
        &der::algorithm(der::SHA256_WITH_RSA),
        &der::tlv(der::BIT_STRING, &bits),
    ]))
}

/// `UTCTime` through 2049 and `GeneralizedTime` after it, as RFC 5280 asks.
fn time(unix: i64) -> Vec<u8> {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    if (1950..2050).contains(&year) {
        let text = format!("{:02}{month:02}{day:02}{h:02}{m:02}{s:02}Z", year % 100);
        der::tlv(der::UTC_TIME, text.as_bytes())
    } else {
        let text = format!("{year:04}{month:02}{day:02}{h:02}{m:02}{s:02}Z");
        der::tlv(der::GENERALIZED_TIME, text.as_bytes())
    }
}

/// Proleptic Gregorian date of a day count since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// The issuer `Name` and serial-number `INTEGER` of a certificate, both as
/// their complete DER encodings, for a PKCS#7 `IssuerAndSerialNumber`.
pub fn issuer_and_serial(cert: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let certificate = Reader::new(cert).expect(der::SEQUENCE, "certificate")?;
    let tbs = Reader::new(certificate.contents).expect(der::SEQUENCE, "tbsCertificate")?;
    let mut fields = Reader::new(tbs.contents);
    let mut serial = fields.next()?;
    if serial.tag == der::context(0) {
        serial = fields.next()?;
    }
    anyhow::ensure!(
        serial.tag == der::INTEGER,
        "certificate serial is not an INTEGER"
    );
    fields.expect(der::SEQUENCE, "certificate signature algorithm")?;
    let issuer = fields.expect(der::SEQUENCE, "certificate issuer")?;
    Ok((issuer.raw.to_vec(), serial.raw.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_convert() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(time(0), der::tlv(der::UTC_TIME, b"700101000000Z"));
        // 2050-01-01 switches to GeneralizedTime.
        assert_eq!(
            time(2_524_608_000),
            der::tlv(der::GENERALIZED_TIME, b"20500101000000Z")
        );
    }
}
