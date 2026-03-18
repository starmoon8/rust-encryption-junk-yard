#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use anyhow::{Result, anyhow};
use ascon_aead::{aead::{Aead, KeyInit, Payload}, AsconAead128, AsconAead128Nonce};
use clap::{Parser, Subcommand};
use fs_err as fserr;
use hex;
use indicatif::{ProgressBar, ProgressStyle};
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAGIC: &[u8] = b"ASCN";
const VERSION: u8 = 2;
const SALT_SIZE: usize = 32;
const NONCE_SIZE: usize = 16;
const EXT_MAX: usize = 32;

const DEFAULT_MEMORY_KIB: u32 = 512 * 1024;
const DEFAULT_TIME: u32 = 10;
const DEFAULT_PARALLEL: u32 = 4;

#[derive(Parser)]
#[command(author, version, about = "Strong Ascon-128 file encryptor with maximum-strength Argon2id — Linux only")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
    Info(InfoArgs),
}

#[derive(Parser)]
struct EncryptArgs {
    #[arg(value_name = "FILE")]
    input: PathBuf,
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(short = 'k', long, value_name = "KEYFILE")]
    keyfile: Option<PathBuf>,
    #[arg(short = 's', long)]
    shred: bool,
}

#[derive(Parser)]
struct DecryptArgs {
    #[arg(value_name = "FILE")]
    input: PathBuf,
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(short = 'k', long, value_name = "KEYFILE")]
    keyfile: Option<PathBuf>,
}

#[derive(Parser)]
struct InfoArgs {
    #[arg(value_name = "FILE")]
    input: PathBuf,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Key([u8; 16]);

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encrypt(args) => encrypt(args),
        Commands::Decrypt(args) => decrypt(args),
        Commands::Info(args) => show_info(args),
    }
}

fn derive_key(password: &str, salt: &[u8; SALT_SIZE], m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Key> {
    let mut key = [0u8; 16];
    let params = argon2::ParamsBuilder::new()
        .m_cost(m_cost)
        .t_cost(t_cost)
        .p_cost(p_cost)
        .build()
        .map_err(|e| anyhow!("invalid argon2 params: {}", e))?;

    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    )
    .hash_password_into(password.as_bytes(), salt, &mut key)
    .map_err(|e| anyhow!("argon2 failed: {}", e))?;

    Ok(Key(key))
}

fn get_key(keyfile: Option<&Path>, salt: Option<[u8; SALT_SIZE]>, m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Key> {
    if let Some(kf) = keyfile {
        let data = fserr::read(kf)?;
        if data.len() != 16 {
            return Err(anyhow!("keyfile must be exactly 16 bytes"));
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&data);
        Ok(Key(buf))
    } else {
        let pass = rpassword::prompt_password("Password: ")?;
        let salt = salt.ok_or_else(|| anyhow!("internal error: salt required for password mode"))?;
        let key = derive_key(&pass, &salt, m_cost, t_cost, p_cost)?;
        let mut pass_zero = pass;
        pass_zero.zeroize();
        Ok(key)
    }
}

fn encrypt(args: EncryptArgs) -> Result<()> {
    let mut plain = Vec::new();
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner} Reading input...")?);

    if args.input.to_string_lossy() == "-" {
        io::stdin().read_to_end(&mut plain)?;
    } else {
        fserr::File::open(&args.input)?.read_to_end(&mut plain)?;
    }
    pb.finish_with_message("Input read");

    let original_len = plain.len();

    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);

    let mut key = if args.keyfile.is_some() {
        get_key(args.keyfile.as_deref(), Some(salt), DEFAULT_MEMORY_KIB, DEFAULT_TIME, DEFAULT_PARALLEL)?
    } else {
        let pass = rpassword::prompt_password("Enter password: ")?;
        let confirm = rpassword::prompt_password("Confirm password: ")?;
        if pass != confirm {
            return Err(anyhow!("Passwords do not match"));
        }
        let key = derive_key(&pass, &salt, DEFAULT_MEMORY_KIB, DEFAULT_TIME, DEFAULT_PARALLEL)?;
        let mut p = pass;
        p.zeroize();
        key
    };

    let ext = args.input
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_string();
    if ext.len() > EXT_MAX {
        return Err(anyhow!("original extension too long (>32 bytes)"));
    }

    let cipher = AsconAead128::new_from_slice(&key.0)
        .map_err(|e| anyhow!("cipher init failed: {}", e))?;

    let ad = b"ascon-v2";
    let payload = Payload { msg: &plain, aad: ad };
    let ct = cipher.encrypt(AsconAead128Nonce::from_slice(&nonce), payload)
        .map_err(|e| anyhow!("encryption failed: {}", e))?;

    plain.zeroize();

    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&DEFAULT_MEMORY_KIB.to_le_bytes());
    header.extend_from_slice(&DEFAULT_TIME.to_le_bytes());
    header.extend_from_slice(&DEFAULT_PARALLEL.to_le_bytes());
    header.extend_from_slice(&nonce);
    header.push(ext.len() as u8);
    header.extend_from_slice(ext.as_bytes());

    let mut out = header;
    out.extend_from_slice(&ct);

    let out_path = args.output.unwrap_or_else(|| {
        let stem = args.input.file_stem().and_then(|s| s.to_str()).unwrap_or("output");
        args.input.with_file_name(format!("{}.ascon", stem))
    });

    let tmp = tempfile::NamedTempFile::new_in(
        out_path.parent().ok_or_else(|| anyhow!("no parent directory"))?
    )?;
    tmp.as_file().write_all(&out)?;
    tmp.as_file().sync_all()?;
    fserr::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600))?;
    tmp.persist(&out_path)?;

    if args.shred && args.input.to_string_lossy() != "-" {
        shred_file(&args.input, original_len)?;
    }

    key.zeroize();
    Ok(())
}

fn decrypt(args: DecryptArgs) -> Result<()> {
    let data = if args.input.to_string_lossy() == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        fserr::read(&args.input)?
    };

    if data.len() < 4 + 1 + SALT_SIZE + 12 + NONCE_SIZE + 1 {
        return Err(anyhow!("file too small to be valid ascon file"));
    }

    let mut pos = 0usize;
    if &data[..4] != MAGIC {
        return Err(anyhow!("not an ascon file (magic mismatch)"));
    }
    pos += 4;
    if data[pos] != VERSION {
        return Err(anyhow!("unsupported version"));
    }
    pos += 1;

    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&data[pos..pos + SALT_SIZE]);
    pos += SALT_SIZE;

    let mem = u32::from_le_bytes(data[pos..pos + 4].try_into()?); pos += 4;
    let time = u32::from_le_bytes(data[pos..pos + 4].try_into()?); pos += 4;
    let parallel = u32::from_le_bytes(data[pos..pos + 4].try_into()?); pos += 4;

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&data[pos..pos + NONCE_SIZE]);
    pos += NONCE_SIZE;

    let ext_len = data[pos] as usize;
    pos += 1;
    if ext_len > EXT_MAX {
        return Err(anyhow!("invalid extension length"));
    }
    let ext = String::from_utf8(data[pos..pos + ext_len].to_vec())?;
    pos += ext_len;

    let ct = &data[pos..];

    let mut key = get_key(args.keyfile.as_deref(), Some(salt), mem, time, parallel)?;

    let cipher = AsconAead128::new_from_slice(&key.0)
        .map_err(|e| anyhow!("cipher init failed: {}", e))?;

    let ad = b"ascon-v2";
    let payload = Payload { msg: ct, aad: ad };
    let plain = cipher.decrypt(AsconAead128Nonce::from_slice(&nonce), payload)
        .map_err(|e| anyhow!("decryption failed (wrong key or corrupted file): {}", e))?;

    let out_path = args.output.unwrap_or_else(|| {
        let stem = args.input.file_stem().and_then(|s| s.to_str()).unwrap_or("decrypted");
        if ext.is_empty() {
            args.input.with_file_name(stem)
        } else {
            args.input.with_file_name(format!("{}.{}", stem, ext))
        }
    });

    let tmp = tempfile::NamedTempFile::new_in(
        out_path.parent().ok_or_else(|| anyhow!("no parent directory"))?
    )?;
    tmp.as_file().write_all(&plain)?;
    tmp.as_file().sync_all()?;
    fserr::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600))?;
    tmp.persist(&out_path)?;

    key.zeroize();
    Ok(())
}

fn show_info(args: InfoArgs) -> Result<()> {
    let data = fserr::read(&args.input)?;
    if data.len() < 4 + 1 + SALT_SIZE + 12 + NONCE_SIZE + 1 {
        println!("File too small — not a valid ascon file");
        return Ok(());
    }
    let mut pos = 0;
    if &data[..4] != MAGIC {
        println!("Not an ascon file (magic mismatch)");
        return Ok(());
    }
    pos += 4;
    let version = data[pos];
    pos += 1;
    let salt_hex = hex::encode(&data[pos..pos + SALT_SIZE]);
    pos += SALT_SIZE;
    let mem = u32::from_le_bytes(data[pos..pos + 4].try_into()?);
    pos += 4;
    let time = u32::from_le_bytes(data[pos..pos + 4].try_into()?);
    pos += 4;
    let parallel = u32::from_le_bytes(data[pos..pos + 4].try_into()?);
    pos += 4;
    pos += NONCE_SIZE;
    let ext_len = data[pos] as usize;
    pos += 1;
    let ext = if pos + ext_len <= data.len() {
        String::from_utf8_lossy(&data[pos..pos + ext_len]).to_string()
    } else {
        "(corrupted)".to_string()
    };
    println!("ascon file v{}", version);
    println!("Salt (hex): {}", salt_hex);
    println!("Argon2id parameters: {} MiB / {} iterations / {} lanes", mem / 1024, time, parallel);
    println!("Original extension: {}", if ext.is_empty() { "(none)" } else { &ext });
    Ok(())
}

fn shred_file(path: &Path, original_len: usize) -> Result<()> {
    if original_len == 0 {
        return Ok(());
    }
    let mut f = fserr::OpenOptions::new().write(true).open(path)?;
    for _pass in 0..3 {
        f.set_len(original_len as u64)?;
        let mut buf = vec![0u8; 65536];
        let mut written = 0usize;
        while written < original_len {
            OsRng.fill_bytes(&mut buf);
            let to_write = (original_len - written).min(buf.len());
            f.write_all(&buf[..to_write])?;
            written += to_write;
        }
        f.sync_all()?;
    }
    fserr::remove_file(path)?;
    Ok(())
}