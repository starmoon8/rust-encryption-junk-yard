use std::fs;
use std::path::Path;
use std::io::{Result, Error, ErrorKind};

use reed_solomon_erasure::galois_8::ReedSolomon;
use blake3;

use crate::format::{DATA_SHARDS, PARITY_SHARDS};

pub fn repair(input: &Path, output: &Path) -> Result<()> {

    let data = fs::read(input)?;

    let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
        .map_err(|_| Error::new(ErrorKind::Other, "rs init failed"))?;

    let shard_count = DATA_SHARDS + PARITY_SHARDS;

    let mut pos = 0;

    let mut out = Vec::new();

    if data.len() < 16 {
        return Err(Error::new(ErrorKind::Other, "invalid file"));
    }

    /* copy salt */
    out.extend_from_slice(&data[0..16]);
    pos += 16;

    while pos < data.len() {

        let enc_len =
            u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;

        pos += 4;

        let nonce = &data[pos..pos+24];
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

        let mut repaired = None;

        /* try original */
        {
            let mut enc = Vec::new();

            for i in 0..DATA_SHARDS {
                if let Some(ref shard) = shards[i] {
                    enc.extend_from_slice(shard);
                }
            }

            enc.truncate(enc_len);

            if blake3::hash(&enc).as_bytes() == stored_hash {
                repaired = Some(shards.clone());
            }
        }

        /* attempt RS repair */
        if repaired.is_none() {

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
                        repaired = Some(attempt);
                        break;
                    }
                }
            }
        }

        let repaired =
            repaired.ok_or_else(|| Error::new(ErrorKind::Other, "rs reconstruct failed"))?;

        /* write repaired chunk */

        out.extend_from_slice(&(enc_len as u32).to_le_bytes());
        out.extend_from_slice(nonce);
        out.extend_from_slice(stored_hash);

        for shard in repaired {
            if let Some(s) = shard {
                out.extend_from_slice(&s);
            }
        }
    }

    fs::write(output, out)?;

    Ok(())
}