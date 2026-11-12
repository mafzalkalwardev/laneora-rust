use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use thiserror::Error;

const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const AAD: &[u8] = b"laneora-rust-v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("data key must be 32 bytes (64 hex characters)")]
    Key,
    #[error("sealed payload is too short or an unknown version")]
    Format,
    #[error("sealed payload failed authentication")]
    Open,
    #[error("could not seal the payload")]
    Seal,
    #[error("legacy payload is not valid base64 or Salted__ ciphertext")]
    Legacy,
    #[error("legacy payload is not utf-8")]
    Utf8,
}

/// Seal `plaintext` as `version || nonce || ciphertext+tag`.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Key)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| CryptoError::Seal)?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(VERSION);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < 1 + NONCE_LEN + 16 || blob[0] != VERSION {
        return Err(CryptoError::Format);
    }
    let (nonce, ct) = blob[1..].split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Key)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload { msg: ct, aad: AAD },
        )
        .map_err(|_| CryptoError::Open)
}

pub fn seal_b64(key: &[u8; 32], plaintext: &[u8]) -> Result<String, CryptoError> {
    Ok(STANDARD.encode(seal(key, plaintext)?))
}

pub fn open_b64(key: &[u8; 32], text: &str) -> Result<Vec<u8>, CryptoError> {
    let blob = STANDARD.decode(text.trim()).map_err(|_| CryptoError::Format)?;
    open(key, &blob)
}

/// Accept a 64-character hex key or standard base64 of 32 bytes.
pub fn parse_data_key(raw: &str) -> Result<[u8; 32], CryptoError> {
    let text = raw.trim();
    if let Ok(bytes) = hex::decode(text) {
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }
    }
    if let Ok(bytes) = STANDARD.decode(text) {
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }
    }
    Err(CryptoError::Key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn roundtrip() {
        let blob = seal(&key(), b"cookies").unwrap();
        assert_eq!(open(&key(), &blob).unwrap(), b"cookies");
    }

    #[test]
    fn rejects_tamper() {
        let mut blob = seal(&key(), b"cookies").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert_eq!(open(&key(), &blob), Err(CryptoError::Open));
    }

    #[test]
    fn parses_hex_key() {
        let hex_key = "11".repeat(32);
        assert_eq!(parse_data_key(&hex_key).unwrap(), [0x11; 32]);
        assert!(parse_data_key("abcd").is_err());
    }
}
