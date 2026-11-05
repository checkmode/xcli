//! Legacy administrator credential and encrypted-state compatibility.
//!
//! Authentication, rate limiting, session management and database transactions
//! must be implemented by the caller. This library is not an auth service.
use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit, Nonce, Tag};
use hmac::{Hmac, Mac};
use scrypt::{scrypt, Params};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidData;

/// Verify the legacy `hex(salt):hex(scrypt)` format without upgrading it.
pub fn verify_password(password: &str, encoded: &str) -> bool {
    if encoded.len() != 97 || encoded.as_bytes().get(32) != Some(&b':') {
        return false;
    }
    let Ok(salt) = hex::decode(&encoded[..32]) else {
        return false;
    };
    let Ok(expected) = hex::decode(&encoded[33..]) else {
        return false;
    };
    if salt.len() != 16 || expected.len() != 32 {
        return false;
    }
    let mut actual = Zeroizing::new([0u8; 32]);
    let Ok(params) = Params::new(14, 8, 1, 32) else {
        return false;
    };
    if scrypt(password.as_bytes(), &salt, &params, actual.as_mut()).is_err() {
        return false;
    }
    bool::from(actual.as_ref().ct_eq(expected.as_slice()))
}

/// Generate the exact legacy scrypt format using an independent random salt.
pub fn hash_password(password: &str) -> Result<Zeroizing<String>, InvalidData> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| InvalidData)?;
    let mut digest = Zeroizing::new([0u8; 32]);
    let params = Params::new(14, 8, 1, 32).map_err(|_| InvalidData)?;
    scrypt(password.as_bytes(), &salt, &params, digest.as_mut()).map_err(|_| InvalidData)?;
    Ok(Zeroizing::new(format!(
        "{}:{}",
        hex::encode(salt),
        hex::encode(digest.as_ref())
    )))
}

fn base32_decode(value: &str) -> Result<Zeroizing<Vec<u8>>, InvalidData> {
    let mut out = Zeroizing::new(Vec::new());
    let mut bits = 0u32;
    let mut acc = 0u32;
    for c in value.bytes() {
        let digit = match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'2'..=b'7' => u32::from(c - b'2' + 26),
            _ => return Err(InvalidData),
        };
        acc = acc.wrapping_shl(5) | digit;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 255) as u8);
        }
    }
    Ok(out)
}

/// Verify the existing six-digit SHA-1 TOTP window and return the matched step.
/// The caller must update `last_step` transactionally before accepting a login.
pub fn verify_totp(
    secret: &str,
    code: &str,
    timestamp: i64,
    last_step: i64,
) -> Result<Option<i64>, InvalidData> {
    if code.len() != 6 || !code.bytes().all(|c| c.is_ascii_digit()) || timestamp < 0 {
        return Ok(None);
    }
    let key = base32_decode(secret)?;
    for shift in [0i64, -1, 1] {
        let Some(step) = (timestamp / 30).checked_add(shift) else {
            continue;
        };
        if step <= last_step || step < 0 {
            continue;
        }
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&key).map_err(|_| InvalidData)?;
        mac.update(&(step as u64).to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = (digest[19] & 15) as usize;
        let number = ((u32::from(digest[offset]) & 127) << 24)
            | (u32::from(digest[offset + 1]) << 16)
            | (u32::from(digest[offset + 2]) << 8)
            | u32::from(digest[offset + 3]);
        let candidate = format!("{:06}", number % 1_000_000);
        if bool::from(candidate.as_bytes().ct_eq(code.as_bytes())) {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

/// Decrypt `XGB1 || nonce[12] || tag[16] || ciphertext` using the existing AAD.
pub fn open_xgb1(
    data: &[u8],
    key: &[u8],
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, InvalidData> {
    if key.len() != 32 || data.len() < 32 || data.len() > 128 * 1024 * 1024 || &data[..4] != b"XGB1"
    {
        return Err(InvalidData);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| InvalidData)?;
    let mut plaintext = Zeroizing::new(data[32..].to_vec());
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&data[4..16]),
            context,
            &mut plaintext,
            Tag::from_slice(&data[16..32]),
        )
        .map_err(|_| InvalidData)?;
    Ok(plaintext)
}

/// Seal using the legacy authenticated envelope and a fresh random nonce.
/// The ciphertext can be read by the existing C++ panel and Python services.
pub fn seal_xgb1(plaintext: &[u8], key: &[u8], context: &[u8]) -> Result<Vec<u8>, InvalidData> {
    if key.len() != 32 || plaintext.len() > 128 * 1024 * 1024 {
        return Err(InvalidData);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| InvalidData)?;
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|_| InvalidData)?;
    let mut ciphertext = Zeroizing::new(plaintext.to_vec());
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), context, &mut ciphertext)
        .map_err(|_| InvalidData)?;
    let mut output = Vec::with_capacity(32 + ciphertext.len());
    output.extend_from_slice(b"XGB1");
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&tag);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}
