use std::fs;
use std::path::Path;
use std::io::{Result, Error, ErrorKind};

use reed_solomon_erasure::galois_8::ReedSolomon;

use blake3;
use argon2::Argon2;

use chacha20poly1305::{
    XChaCha20Poly1305,
    XNonce,
    Key,
    aead::{Aead, KeyInit}
};

use rand::{RngCore, rngs::OsRng};

use crate::format::{DATA_SHARDS, PARITY_SHARDS, CHUNK_SIZE};

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {

    let mut key = [0u8; 32];
    let argon = Argon2::default();

    argon.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| Error::new(ErrorKind::Other, "argon2 failed"))
        .unwrap();

    key
}

pub fn encrypt(input: &Path, output: &Path, password: &str) -> Result<()> {

    let data = fs::read(input)?;

    let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
        .map_err(|_| Error::new(ErrorKind::Other, "rs init failed"))?;

    let mut out = Vec::new();

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    out.extend_from_slice(&salt);

    let key = derive_key(password, &salt);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));

    let mut pos = 0;

    while pos < data.len() {

        let end = (pos + CHUNK_SIZE).min(data.len());
        let chunk = &data[pos..end];

        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);

        let nonce = XNonce::from_slice(&nonce_bytes);

        let encrypted =
            cipher.encrypt(nonce, chunk)
                .map_err(|_| Error::new(ErrorKind::Other, "encrypt failed"))?;

        let enc_len = encrypted.len();

        out.extend_from_slice(&(enc_len as u32).to_le_bytes());
        out.extend_from_slice(&nonce_bytes);

        let hash = blake3::hash(&encrypted);
        out.extend_from_slice(hash.as_bytes());

        let shard_size = (enc_len + DATA_SHARDS - 1) / DATA_SHARDS;

        let mut shards: Vec<Vec<u8>> =
            (0..DATA_SHARDS + PARITY_SHARDS)
            .map(|_| vec![0u8; shard_size])
            .collect();

        for i in 0..DATA_SHARDS {

            let start = i * shard_size;
            let end = (start + shard_size).min(enc_len);

            if start < enc_len {
                shards[i][..end-start]
                    .copy_from_slice(&encrypted[start..end]);
            }
        }

        rs.encode(&mut shards)
            .map_err(|_| Error::new(ErrorKind::Other, "rs encode failed"))?;

        for shard in shards {
            out.extend_from_slice(&shard);
        }

        pos += CHUNK_SIZE;
    }

    fs::write(output, out)?;

    Ok(())
}

pub fn decrypt(input: &Path, output: &Path, password: &str) -> Result<()> {

    let data = fs::read(input)?;

    let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
        .map_err(|_| Error::new(ErrorKind::Other, "rs init failed"))?;

    let mut pos = 0;

    if pos + 16 > data.len() {
        return Err(Error::new(ErrorKind::Other, "invalid file"));
    }

    let salt = &data[pos..pos+16];
    pos += 16;

    let key = derive_key(password, salt);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));

    let shard_count = DATA_SHARDS + PARITY_SHARDS;

    let mut result = Vec::new();

    while pos < data.len() {

        let enc_len =
            u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;

        pos += 4;

        let nonce = XNonce::from_slice(&data[pos..pos+24]);
        pos += 24;

        let stored_hash = &data[pos..pos+32];
        pos += 32;

        let shard_size = (enc_len + DATA_SHARDS - 1) / DATA_SHARDS;

        let mut shards: Vec<Option<Vec<u8>>> = Vec::new();

        for _ in 0..shard_count {

            if pos + shard_size <= data.len() {
                shards.push(Some(data[pos..pos+shard_size].to_vec()));
            } else {
                shards.push(None);
            }

            pos += shard_size;
        }

        let mut reconstructed = None;

        /* first try without repair */

        {
            let mut enc = Vec::new();

            for i in 0..DATA_SHARDS {
                if let Some(ref shard) = shards[i] {
                    enc.extend_from_slice(shard);
                }
            }

            enc.truncate(enc_len);

            if blake3::hash(&enc).as_bytes() == stored_hash {
                reconstructed = Some(enc);
            }
        }

        /* if corrupted try repairing each shard */

        if reconstructed.is_none() {

            for missing in 0..shard_count {

                let mut attempt = shards.clone();
                attempt[missing] = None;

                if rs.reconstruct(&mut attempt).is_ok() {

                    let mut enc = Vec::new();

                    for i in 0..DATA_SHARDS {
                        if let Some(ref shard) = attempt[i] {
                            enc.extend_from_slice(shard);
                        }
                    }

                    enc.truncate(enc_len);

                    if blake3::hash(&enc).as_bytes() == stored_hash {
                        reconstructed = Some(enc);
                        break;
                    }
                }
            }
        }

        let encrypted =
            reconstructed.ok_or_else(|| Error::new(ErrorKind::Other, "rs reconstruct failed"))?;

        let decrypted =
            cipher.decrypt(nonce, encrypted.as_ref())
                .map_err(|_| Error::new(ErrorKind::Other, "decrypt failed"))?;

        result.extend_from_slice(&decrypted);
    }

    fs::write(output, result)?;

    Ok(())
}