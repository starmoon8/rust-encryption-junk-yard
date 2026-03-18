// Minimal Linux-only XChaCha20-Poly1305 file encrypt/decrypt tool
// Password-based (no key file)
// Usage: xcha <filename>
//   - Encrypt: asks password twice
//   - Decrypt: asks password once

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use clap::{Arg, Command};
use rand::{rngs::OsRng, RngCore};
use rpassword;
use scrypt::{scrypt, Params};
use tempfile;

// ────────────────────────────────────────────────
// Scrypt parameters (very strong)
const SCRYPT_LOG_N: u8   = 23;
const SCRYPT_R: u32      = 8;
const SCRYPT_P: u32      = 1;

// Other constants
const MAGIC_HEADER: &[u8] = b"XCHACHA_ENC_v1";
const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const MAX_FILE_SIZE: u64 = 32 * 1024 * 1024 * 1024;

const FIXED_SALT: &[u8] = b"xcha_password_mode_fixed_salt_v1";

fn main() {
    let matches = Command::new("xcha")
        .version("")
        .about("")
        .disable_help_flag(true)
        .disable_version_flag(true)
        .arg(
            Arg::new("file")
                .required(true)
                .index(1)
                .help("File to encrypt or decrypt"),
        )
        .get_matches();

    let file = matches.get_one::<String>("file").unwrap();
    if let Err(e) = process_file(file.clone()) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn process_file(path_str: String) -> io::Result<()> {
    let path = Path::new(&path_str);

    if !path.exists() {
        eprintln!("file not found");
        std::process::exit(1);
    }

    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_FILE_SIZE {
        eprintln!("file too large");
        std::process::exit(1);
    }

    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    let is_encrypted = data.starts_with(MAGIC_HEADER);

    let mut key_bytes = [0u8; KEY_SIZE];
    if !is_encrypted {
        let pass1 = rpassword::prompt_password("Password: ")?;
        let pass2 = rpassword::prompt_password("Confirm: ")?;
        if pass1 != pass2 {
            eprintln!("passwords do not match");
            std::process::exit(1);
        }
        if pass1.is_empty() {
            eprintln!("password cannot be empty");
            std::process::exit(1);
        }
        derive_key(pass1.as_bytes(), &mut key_bytes)?
    } else {
        let pass = rpassword::prompt_password("Password: ")?;
        derive_key(pass.as_bytes(), &mut key_bytes)?
    };

    let key = chacha20poly1305::Key::from_slice(&key_bytes);

    let result = if !is_encrypted {
        encrypt(&data, key)?
    } else {
        decrypt(&data, key)?
    };

    let parent = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(&result)?;
    tmp.flush()?;
    tmp.persist(path)?;

    println!("ok");

    Ok(())
}

fn derive_key(password: &[u8], key_bytes: &mut [u8; KEY_SIZE]) -> io::Result<()> {
    let params = Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Scrypt params error: {}", e)))?;

    scrypt(password, FIXED_SALT, &params, key_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Scrypt derivation failed: {}", e)))?;

    Ok(())
}

fn encrypt(plaintext: &[u8], key: &chacha20poly1305::Key) -> io::Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);

    let cipher = XChaCha20Poly1305::new(key);
    let ciphertext = cipher.encrypt(&nonce, plaintext)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let mut out = Vec::with_capacity(MAGIC_HEADER.len() + NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(MAGIC_HEADER);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

fn decrypt(data: &[u8], key: &chacha20poly1305::Key) -> io::Result<Vec<u8>> {
    let min_len = MAGIC_HEADER.len() + NONCE_SIZE + TAG_SIZE;
    if data.len() < min_len {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too short"));
    }

    if !data.starts_with(MAGIC_HEADER) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not encrypted"));
    }

    let nonce_start = MAGIC_HEADER.len();
    let nonce = XNonce::from_slice(&data[nonce_start..nonce_start + NONCE_SIZE]);
    let ciphertext = &data[nonce_start + NONCE_SIZE..];

    let cipher = XChaCha20Poly1305::new(key);
    cipher.decrypt(nonce, ciphertext)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption failed — wrong password?"))
}