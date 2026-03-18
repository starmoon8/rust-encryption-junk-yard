// Minimal Linux-only XChaCha20-Poly1305 file encrypt/decrypt tool
// Uses ./key.key (32-byte raw key derived from password via scrypt)
// Extremely quiet — almost no output except "ok" or very short errors

use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
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
// Scrypt parameters – adjust here to change security vs speed
// Higher logN / r / p = stronger but slower keygen
// Current defaults: strong but still fast on high-end hardware
// logN=18 → ~250–400 MiB memory cost, ~2–10 seconds
// ────────────────────────────────────────────────
const SCRYPT_LOG_N: u8   = 23;     // N = 2^18 = 262144
const SCRYPT_R: u32      = 8;      // block size factor
const SCRYPT_P: u32      = 1;      // parallelization factor (1 = single-threaded = reliable)

// Other constants
const MAGIC_HEADER: &[u8] = b"XCHACHA_ENC_v1";
const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const MAX_FILE_SIZE: u64 = 32 * 1024 * 1024 * 1024; // 32 GiB

// Fixed salt for deterministic derivation
const FIXED_SALT: &[u8] = b"xcha_keygen_fixed_salt_v1";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let cmd = Command::new("xcha")
        .no_binary_name(true)
        .version("")
        .about("")
        .propagate_version(false)
        .subcommand_required(false)
        .arg_required_else_help(false)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .subcommand(
            Command::new("keygen")
                .about("")
                .disable_help_flag(true),
        )
        .subcommand(
            Command::new("pf")
                .about("")
                .disable_help_flag(true)
                .arg(
                    Arg::new("file")
                        .required(true)
                        .help(""),
                ),
        );

    let matches = match cmd.try_get_matches_from(&args[1..]) {
        Ok(m) => m,
        Err(_) => std::process::exit(1),
    };

    match matches.subcommand() {
        Some(("keygen", _)) => {
            if let Err(e) = keygen() {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
        Some(("pf", sub_matches)) => {
            if let Some(file) = sub_matches.get_one::<String>("file") {
                if let Err(e) = process_file(file.clone()) {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            } else {
                std::process::exit(1);
            }
        }
        _ => std::process::exit(1),
    }
}

fn keygen() -> io::Result<()> {
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

    let key = derive_key(pass1.as_bytes())?;

    let mut f = BufWriter::new(File::create("key.key")?);
    f.write_all(&key)?;
    f.flush()?;

    println!("ok");

    Ok(())
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

    let mut key_bytes = [0u8; KEY_SIZE];
    let mut key_file = File::open("key.key")
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "key.key missing or invalid"))?;
    key_file.read_exact(&mut key_bytes)?;
    let key = chacha20poly1305::Key::from_slice(&key_bytes);

    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    let is_encrypted = data.starts_with(MAGIC_HEADER);

    let result = if !is_encrypted {
        encrypt(&data, &key)?
    } else {
        decrypt(&data, &key)?
    };

    let parent = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(&result)?;
    tmp.flush()?;
    tmp.persist(path)?;

    println!("ok");

    Ok(())
}

fn derive_key(password: &[u8]) -> io::Result<[u8; KEY_SIZE]> {
    let params = Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Scrypt params error: {}", e)))?;

    let mut key = [0u8; KEY_SIZE];
    scrypt(password, FIXED_SALT, &params, &mut key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Scrypt derivation failed: {}", e)))?;

    Ok(key)
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
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption failed"))
}