//! Native writer for certificate-only PKCS#12 truststores (RFC 7292).
//!
//! Used when the openssl binary cannot add the Oracle trusted-key-usage
//! attribute itself: `pkcs12 -jdktrust` is OpenSSL 3.2+, and LibreSSL has no
//! equivalent. The output matches what `openssl pkcs12 -export -nokeys
//! -jdktrust anyExtendedKeyUsage -caname <alias>` produces, except that the
//! certificate bag is stored unencrypted (it is a public certificate); the
//! store is still integrity-protected by an HMAC-SHA256 MAC over the password.

use anyhow::{bail, Context, Result};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

const OID_DATA: &str = "1.2.840.113549.1.7.1";
const OID_CERT_BAG: &str = "1.2.840.113549.1.12.10.1.3";
const OID_X509_CERTIFICATE: &str = "1.2.840.113549.1.9.22.1";
const OID_FRIENDLY_NAME: &str = "1.2.840.113549.1.9.20";
const OID_ORACLE_TRUSTED_KEY_USAGE: &str = "2.16.840.1.113894.746875.1.1";
const OID_ANY_EXTENDED_KEY_USAGE: &str = "2.5.29.37.0";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";

/// OpenSSL's defaults for the MAC.
const MAC_ITERATIONS: u32 = 2048;
const MAC_SALT_LEN: usize = 8;

/// A PKCS#12 truststore holding `cert_pem` under `alias`, marked trusted for
/// any purpose so Java loads it as a `trustedCertEntry`.
pub fn truststore(cert_pem: &[u8], alias: &str, password: &str) -> Result<Vec<u8>> {
    let cert_der = pem_to_der(cert_pem)?;
    let attributes = set_of(vec![
        attribute(OID_FRIENDLY_NAME, &bmp_string(alias)),
        attribute(OID_ORACLE_TRUSTED_KEY_USAGE, &oid(OID_ANY_EXTENDED_KEY_USAGE)),
    ]);
    let cert_bag = sequence(&[
        &oid(OID_X509_CERTIFICATE),
        &explicit(0, &octet_string(&cert_der)),
    ]);
    let safe_bag = sequence(&[&oid(OID_CERT_BAG), &explicit(0, &cert_bag), &attributes]);
    let safe_contents = sequence(&[&safe_bag]);
    let authenticated_safe = sequence(&[&data_content_info(&safe_contents)]);

    let mut salt = [0u8; MAC_SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    let key = pkcs12_kdf(&bmp_password(password), &salt, 3, MAC_ITERATIONS, 32);
    let mac = hmac_sha256(&key, &authenticated_safe);
    let mac_data = sequence(&[
        &sequence(&[
            &sequence(&[&oid(OID_SHA256), &[0x05, 0x00]]),
            &octet_string(&mac),
        ]),
        &octet_string(&salt),
        &integer(MAC_ITERATIONS),
    ]);
    Ok(sequence(&[
        &integer(3),
        &data_content_info(&authenticated_safe),
        &mac_data,
    ]))
}

/// The DER bytes of the first CERTIFICATE block in `pem`.
fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(pem).context("certificate PEM is not UTF-8")?;
    let body = text
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)
        .and_then(|rest| rest.split("-----END CERTIFICATE-----").next())
        .context("no CERTIFICATE block in PEM")?;
    let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("certificate PEM is not valid base64")?;
    if der.first() != Some(&0x30) {
        bail!("certificate PEM does not hold a DER SEQUENCE");
    }
    Ok(der)
}

/// The password as PKCS#12 wants it: big-endian UTF-16 with a 0x0000 terminator.
fn bmp_password(password: &str) -> Vec<u8> {
    password
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_be_bytes)
        .collect()
}

/// RFC 7292 appendix B.2 key derivation, with SHA-256 (u = 32, v = 64).
fn pkcs12_kdf(password: &[u8], salt: &[u8], id: u8, iterations: u32, len: usize) -> Vec<u8> {
    const U: usize = 32;
    const V: usize = 64;
    let fill = |src: &[u8]| -> Vec<u8> {
        let n = V * src.len().div_ceil(V);
        src.iter().copied().cycle().take(n).collect()
    };
    let d = [id; V];
    let mut i = fill(salt);
    i.extend(fill(password));

    let mut out = Vec::with_capacity(len.div_ceil(U) * U);
    while out.len() < len {
        let mut a: [u8; U] = Sha256::new().chain_update(d).chain_update(&i).finalize().into();
        for _ in 1..iterations {
            a = Sha256::digest(a).into();
        }
        out.extend_from_slice(&a);
        // I_j = (I_j + B + 1) mod 2^(8v) for each v-byte block, B = A repeated.
        let b: Vec<u8> = a.iter().copied().cycle().take(V).collect();
        for block in i.chunks_mut(V) {
            let mut carry = 1u16;
            for (x, y) in block.iter_mut().rev().zip(b.iter().rev()) {
                let sum = *x as u16 + *y as u16 + carry;
                *x = sum as u8;
                carry = sum >> 8;
            }
        }
    }
    out.truncate(len);
    out
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| block.map(|k| k ^ byte);
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(message).finalize();
    Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize().into()
}

// Minimal DER encoding.

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().into_iter().skip_while(|&b| b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

fn sequence(items: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &items.concat())
}

/// DER SET OF: elements sorted by their encoding.
fn set_of(mut items: Vec<Vec<u8>>) -> Vec<u8> {
    items.sort();
    tlv(0x31, &items.concat())
}

fn explicit(tag: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | tag, content)
}

fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

fn bmp_string(text: &str) -> Vec<u8> {
    let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
    tlv(0x1e, &bytes)
}

fn integer(value: u32) -> Vec<u8> {
    let mut bytes: Vec<u8> = value.to_be_bytes().into_iter().skip_while(|&b| b == 0).collect();
    if bytes.first().is_none_or(|&b| b & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    tlv(0x02, &bytes)
}

fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|arc| arc.parse().expect("valid OID")).collect();
    let mut body = Vec::new();
    for arc in std::iter::once(arcs[0] * 40 + arcs[1]).chain(arcs[2..].iter().copied()) {
        let mut chunk = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            chunk.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        body.extend(chunk.into_iter().rev());
    }
    tlv(0x06, &body)
}

fn attribute(oid_text: &str, value: &[u8]) -> Vec<u8> {
    sequence(&[&oid(oid_text), &set_of(vec![value.to_vec()])])
}

fn data_content_info(content: &[u8]) -> Vec<u8> {
    sequence(&[&oid(OID_DATA), &explicit(0, &octet_string(content))])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_encoding_matches_der() {
        assert_eq!(oid("1.2.840.113549.1.7.1"), hex::decode("06092a864886f70d010701").unwrap());
        assert_eq!(oid("2.5.29.37.0"), hex::decode("0604551d2500").unwrap());
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// `openssl pkcs12 -info` reads the store with the right password (MAC
    /// verified) and sees the alias and the Oracle trust attribute.
    #[test]
    fn openssl_reads_the_native_truststore() {
        let dir = std::env::temp_dir().join(format!("minica-pkcs12-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let openssl = |args: &[&str]| {
            std::process::Command::new("/usr/bin/openssl")
                .args(args)
                .current_dir(&dir)
                .output()
                .expect("run openssl")
        };
        let cert = openssl(&[
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=native.truststore.test",
            "-keyout", "key.pem", "-out", "cert.pem",
        ]);
        assert!(cert.status.success(), "{}", String::from_utf8_lossy(&cert.stderr));
        let pem = std::fs::read(dir.join("cert.pem")).unwrap();
        std::fs::write(dir.join("store.p12"), truststore(&pem, "minica-alias", "changeit").unwrap())
            .unwrap();

        let info = openssl(&["pkcs12", "-info", "-nokeys", "-passin", "pass:changeit", "-in", "store.p12"]);
        let text = String::from_utf8_lossy(&info.stdout);
        assert!(info.status.success(), "{}", String::from_utf8_lossy(&info.stderr));
        assert!(text.contains("friendlyName: minica-alias"), "{text}");
        assert!(text.contains("Trusted key usage (Oracle): Any Extended Key Usage"), "{text}");
        assert!(text.contains(std::str::from_utf8(&pem).unwrap().trim()), "{text}");

        let wrong = openssl(&["pkcs12", "-info", "-nokeys", "-passin", "pass:wrong", "-in", "store.p12"]);
        assert!(!wrong.status.success(), "wrong password must fail the MAC check");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn long_lengths_use_the_long_form() {
        let content = vec![0u8; 300];
        assert_eq!(&tlv(0x04, &content)[..4], &[0x04, 0x82, 0x01, 0x2c]);
    }
}
