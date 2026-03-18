// stardust-keygen-linux.rs
// ────────────────────────────────────────────────
// Linux-optimized deterministic key file generator
// Uses fallocate() for fast space preallocation, larger chunks, BufWriter
// NOT portable to Windows (fallocate + O_LARGEFILE assumptions)
// Compile with: cargo build --release
// ────────────────────────────────────────────────

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use clap::Parser;
use rpassword::prompt_password;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher};

use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::sys::fs::{fallocate, FallocateFlags};

const CHUNK_SIZE: usize = 4 * 1024 * 1024;      // 4 MiB – sweet spot on most modern Linux SSDs/NVMe
const MAX_SIZE: u64 = 20 * 1024 * 1024 * 1024;  // 20 GiB
const DEFAULT_BUFFER_CAPACITY: usize = 16 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "stardust-keygen-linux",
    version = "0.1.1-linux",
    about = "Linux-optimized: password → non-repeating key up to 20GB (uses fallocate)",
    author = "Mark"
)]
struct Cli {
    /// Key size in bytes (1 to 20GB)
    #[arg(index = 1)]
    size: u64,

    /// Output file path (default: key.key next to executable)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Salt for Argon2 key derivation (default: ultimate-salt-v1-2026)
    #[arg(long, value_name = "SALT")]
    salt: Option<String>,

    /// Pepper secret for Argon2 (default: secret-pepper-masterkey)
    #[arg(long, value_name = "PEPPER")]
    pepper: Option<String>,

    /// 12-character nonce for ChaCha20 (default: JohnDoeXYZ12)
    #[arg(long, value_name = "NONCE")]
    nonce: Option<String>,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    if cli.size == 0 || cli.size > MAX_SIZE {
        eprintln!("Size must be between 1 byte and 20 GiB ({MAX_SIZE} bytes)");
        std::process::exit(1);
    }

    // Determine output path
    let output_path = cli.output.unwrap_or_else(|| {
        let mut exe = env::current_exe().expect("Cannot get executable path");
        exe.pop();
        exe.push("key.key");
        exe
    });

    if output_path.exists() {
        eprintln!("Refusing to overwrite existing file: {}", output_path.display());
        std::process::exit(1);
    }

    // ─── Config: CLI > ENV > default ────────────────────────────────────────
    let salt = cli
        .salt
        .or_else(|| env::var("STARDUST_SALT").ok())
        .unwrap_or_else(|| "ultimate-salt-v1-2026".into())
        .into_bytes();

    let pepper = cli
        .pepper
        .or_else(|| env::var("STARDUST_PEPPER").ok())
        .unwrap_or_else(|| "secret-pepper-masterkey".into())
        .into_bytes();

    let nonce_str = cli
        .nonce
        .or_else(|| env::var("STARDUST_NONCE").ok())
        .unwrap_or_else(|| "JohnDoeXYZ12".into());

    if nonce_str.len() != 12 {
        eprintln!("Nonce must be exactly 12 characters");
        std::process::exit(1);
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_str.as_bytes());

    // ─── Password input ──────────────────────────────────────────────────────
    let pw1 = prompt_password("Enter password: ")?;
    let pw2 = prompt_password("Confirm password: ")?;
    if pw1 != pw2 {
        eprintln!("Passwords do not match!");
        std::process::exit(1);
    }
    let password = pw1.into_bytes();

    // ─── Argon2id → 256-bit master key ──────────────────────────────────────
    let mut master_key = [0u8; 32];
    let params = Params::new(131_072, 4, 8, None).expect("Invalid Argon2 params");
    let argon2 = Argon2::new_with_secret(
        &pepper,
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    )
    .expect("Failed to initialize Argon2");

    argon2
        .hash_password_into(&password, &salt, &mut master_key)
        .expect("Argon2 hashing failed");

    // ─── ChaCha20 setup ─────────────────────────────────────────────────────
    let mut cipher = ChaCha20::new((&master_key).into(), (&nonce).into());

    // ─── Linux-specific: open + fallocate preallocation ─────────────────────
    let fd = open(
        output_path.as_path(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_LARGEFILE,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // Pre-reserve space (fast on ext4/XFS/btrfs – avoids extent fragmentation)
    fallocate(
        fd,
        FallocateFlags::FALLOC_FL_KEEP_SIZE,
        0,
        cli.size as i64,
    )
    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("fallocate failed: {e}")))?;

    // Convert raw fd → std::fs::File
    let file = unsafe { File::from_raw_fd(fd) };

    // ─── Buffered writer ────────────────────────────────────────────────────
    let mut writer = BufWriter::with_capacity(DEFAULT_BUFFER_CAPACITY, file);

    // ─── Generate & write in chunks ─────────────────────────────────────────
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut remaining = cli.size;

    println!("Generating {} bytes → {}", cli.size, output_path.display());

    while remaining > 0 {
        let this_chunk = std::cmp::min(CHUNK_SIZE as u64, remaining) as usize;

        cipher.apply_keystream(&mut buffer[..this_chunk]);
        writer.write_all(&buffer[..this_chunk])?;

        remaining -= this_chunk as u64;

        // Optional: simple progress every GiB
        if remaining % (1 << 30) > (this_chunk as u64) || remaining == 0 {
            let written = cli.size - remaining;
            eprintln!("  {:>5.1} GiB / {:.1} GiB", written as f64 / 1e9, cli.size as f64 / 1e9);
        }
    }

    writer.flush()?;

    // Optional: fsync if you really want durability (costs ~1–3 seconds on SSD)
    // file.sync_all()?;

    println!("\nDone. Key file created: {}", output_path.display());
    Ok(())
}