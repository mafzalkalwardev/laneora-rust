//! CryptoJS / OpenSSL `Salted__` AES-256-CBC, matching the Python client.
//!
//! The compatibility `/authenticate` response still uses this format so the
//! existing Laneora.exe can decrypt it. New clients use AES-256-GCM.

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD, Engine};
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use md5::{Digest, Md5};
use rand::RngCore;

use crate::crypto::CryptoError;

pub const LEGACY_PASSPHRASE: &str = "raw_value";

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

fn evp_bytes(passphrase: &[u8], salt: &[u8], len: usize) -> Vec<u8> {
    let mut derived = Vec::with_capacity(len + 16);
    let mut block: Vec<u8> = Vec::new();
    while derived.len() < len {
        let mut hasher = Md5::new();
        hasher.update(&block);
        hasher.update(passphrase);
        hasher.update(salt);
        block = hasher.finalize().to_vec();
        derived.extend_from_slice(&block);
    }
    derived.truncate(len);
    derived
}

fn key_iv(passphrase: &str, salt: &[u8]) -> ([u8; 32], [u8; 16]) {
    let derived = evp_bytes(passphrase.as_bytes(), salt, 48);
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&derived[..32]);
    iv.copy_from_slice(&derived[32..48]);
    (key, iv)
}

pub fn seal_salted(passphrase: &str, plaintext: &str) -> Result<String, CryptoError> {
    let mut salt = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    seal_salted_with_salt(passphrase, plaintext, &salt)
}

pub fn seal_salted_with_salt(
    passphrase: &str,
    plaintext: &str,
    salt: &[u8],
) -> Result<String, CryptoError> {
    if salt.len() != 8 {
        return Err(CryptoError::Legacy);
    }
    let (key, iv) = key_iv(passphrase, salt);
    let enc = Aes256CbcEnc::new_from_slices(&key, &iv).map_err(|_| CryptoError::Key)?;
    let ct = enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());
    let mut raw = Vec::with_capacity(16 + ct.len());
    raw.extend_from_slice(b"Salted__");
    raw.extend_from_slice(salt);
    raw.extend_from_slice(&ct);
    Ok(STANDARD.encode(raw))
}

pub fn open_salted(passphrase: &str, encrypted: &str) -> Result<String, CryptoError> {
    let raw = STANDARD
        .decode(encrypted.trim())
        .map_err(|_| CryptoError::Legacy)?;
    if raw.len() < 16 || &raw[..8] != b"Salted__" {
        return Err(CryptoError::Legacy);
    }
    let salt = &raw[8..16];
    let ct = &raw[16..];
    let (key, iv) = key_iv(passphrase, salt);
    let dec = Aes256CbcDec::new_from_slices(&key, &iv).map_err(|_| CryptoError::Key)?;
    let pt = dec
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|_| CryptoError::Open)?;
    String::from_utf8(pt).map_err(|_| CryptoError::Utf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_python_vector() {
        // Generated with the Python client's EVP_BytesToKey + AES-256-CBC.
        let cipher = "U2FsdGVkX18AESIzRFVmd8ldjENNomhiDHma8Nn9V4M=";
        let plain = open_salted(LEGACY_PASSPHRASE, cipher).unwrap();
        assert_eq!(plain, r#"{"ok":true}"#);
    }

    #[test]
    fn roundtrip() {
        let sealed = seal_salted(LEGACY_PASSPHRASE, "laneora").unwrap();
        assert_eq!(open_salted(LEGACY_PASSPHRASE, &sealed).unwrap(), "laneora");
    }
}
