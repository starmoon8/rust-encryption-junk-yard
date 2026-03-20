use anyhow::{bail, Context, Result};
use argon2::{self, Algorithm, Argon2, Params, Version};
use byte_unit::Byte;
use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher};
use rpassword::prompt_password;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MiB chunks
const MAX_KEY_SIZE_BYTES: u64 = 20 * 1024 * 1024 * 1024; // 20 GiB cap

pub fn run_keygen(
    size_str: String,
    force: bool,
    output: Option<PathBuf>,
) -> Result<()> {
    let size = Byte::parse_str(&size_str, true)
        .context("Invalid size format. Examples: 1GB, 500MiB, 2147483648")?
        .as_u64();

    if size == 0 {
        bail!("Size must be > 0 bytes");
    }
    if size > MAX_KEY_SIZE_BYTES {
        bail!("Maximum supported key size is 20 GiB");
    }

    let output_path = output.unwrap_or_else(|| PathBuf::from("./key.key"));

    if output_path.exists() && !force {
        bail!(
            "Output file already exists: {}\nUse --force to overwrite.",
            output_path.display()
        );
    }

    // Password input
    let pw1 = prompt_password("Enter password: ")?;
    if pw1.is_empty() {
        bail!("Password cannot be empty");
    }
    let pw2 = prompt_password("Confirm password: ")?;
    if pw1 != pw2 {
        bail!("Passwords do not match");
    }
    let password = pw1.as_bytes();

    // Argon2id → 256-bit master key
    let salt = b"otp-rs-salt-v1-2026";
    let pepper: &[u8] = b"otp-rs-pepper-2026";
    let nonce: [u8; 12] = *b"otpRSkgnonce";

    let mut master_key = [0u8; 32];
    let params = Params::new(131_072, 4, 8, None)?;
    let argon = Argon2::new_with_secret(
        pepper,
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    )?;
    argon.hash_password_into(password, salt, &mut master_key)?;

    // ChaCha20 keystream generator
    let mut cipher = ChaCha20::new((&master_key).into(), (&nonce).into());

    // Write key file
    let file = OpenOptions::new()           // ← mut removed here
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output_path)
        .context("Failed to create key file")?;

    let mut writer = BufWriter::with_capacity(16 * 1024 * 1024, file);

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut remaining = size;

    println!("Generating {} ({:.1} GiB) key file...", size_str, size as f64 / 1e9);

    while remaining > 0 {
        let this_chunk = std::cmp::min(CHUNK_SIZE as u64, remaining) as usize;
        cipher.apply_keystream(&mut buffer[..this_chunk]);
        writer.write_all(&buffer[..this_chunk])?;
        remaining -= this_chunk as u64;

        // Progress feedback every ~500 MiB
        if remaining % (500 * 1024 * 1024) < this_chunk as u64 || remaining == 0 {
            let done = size - remaining;
            eprintln!("  {:>6.1} GiB / {:.1} GiB", done as f64 / 1e9, size as f64 / 1e9);
        }
    }

    writer.flush()?;
    println!("\nKey file created successfully: {}", output_path.display());

    eprintln!("\n⚠️  SECURITY IMPORTANT");
    eprintln!("  This is a **deterministic key derived from your password**.");
    eprintln!("  It provides **good symmetric key security**, but **NOT** information-theoretic OTP security.");
    eprintln!("  For perfect OTP, use true randomness (dice, hardware RNG, etc.).");
    eprintln!("  Never reuse this key for multiple messages.");

    Ok(())
}