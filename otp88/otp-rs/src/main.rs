use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use reed_solomon::{Decoder, Encoder};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(not(target_os = "linux"))]
compile_error!("This app is Linux-only.");

const ECC_LEN: usize = 32; // Corrects up to 16 errors per block
const MAX_DATA_PER_BLOCK: usize = 255 - ECC_LEN; // 223 bytes
const KEY_FILE: &str = "./key.key";
const HEADER_LEN: usize = 8; // u64 for original plaintext length

#[derive(Parser)]
#[command(name = "otp-rs")]
#[command(about = "OTP-style XOR encryption with Reed-Solomon error correction")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Enable verbose output (shows block-level info)
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt the input file (XOR + RS encode)
    Encrypt {
        /// Path to input plaintext file
        input: PathBuf,
        /// Path to output encrypted file
        output: PathBuf,
    },
    /// Decrypt the input file (RS decode + XOR)
    Decrypt {
        /// Path to input encrypted file
        input: PathBuf,
        /// Path to output decrypted file
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, output } => encrypt(&input, &output, cli.verbose),
        Commands::Decrypt { input, output } => decrypt(&input, &output, cli.verbose),
    }
}

fn load_key() -> Result<Vec<u8>> {
    let key_path = Path::new(KEY_FILE);

    if !key_path.exists() {
        bail!("ERROR: key.key not found in current directory.\nPlace your one-time pad file named exactly 'key.key' here and try again.");
    }
    if !key_path.is_file() {
        bail!("ERROR: 'key.key' exists but is not a regular file.");
    }

    let key = fs::read(key_path).context("Failed to read key.key")?;
    Ok(key)
}

fn encrypt(input_path: &PathBuf, output_path: &PathBuf, verbose: bool) -> Result<()> {
    let key = load_key()?;
    let plaintext = fs::read(input_path).context("Failed to read input file")?;
    let orig_len = plaintext.len() as u64;

    // Append header with original length
    let mut data = plaintext.clone();
    data.extend_from_slice(&orig_len.to_be_bytes());
    let data_len = data.len();

    // Strict key length check
    if key.len() < data_len {
        bail!("ERROR: key.key is too short.\nIt must be at least {} bytes (input + header).", data_len);
    }

    // XOR (plaintext + header) with key
    let xor_data: Vec<u8> = data.iter().zip(key.iter()).map(|(&d, &k)| d ^ k).collect();

    // RS encode (variable-length blocks)
    let enc = Encoder::new(ECC_LEN);
    let mut encoded = Vec::with_capacity(xor_data.len() + (xor_data.len() / MAX_DATA_PER_BLOCK + 1) * ECC_LEN);

    for (i, chunk) in xor_data.chunks(MAX_DATA_PER_BLOCK).enumerate() {
        let block_encoded = enc.encode(chunk);
        encoded.extend_from_slice(&*block_encoded);
        if verbose {
            println!("Block {}: {} bytes encoded", i, block_encoded.len());
        }
    }

    fs::write(output_path, &encoded).context("Failed to write output file")?;
    println!("Encryption successful: {}", output_path.display());
    Ok(())
}

fn decrypt(input_path: &PathBuf, output_path: &PathBuf, verbose: bool) -> Result<()> {
    let key = load_key()?;
    let encoded = fs::read(input_path).context("Failed to read input file")?;
    let dec = Decoder::new(ECC_LEN);

    let mut recovered_xor = Vec::new();
    let mut offset = 0;
    let mut block_index = 0;

    while offset < encoded.len() {
        let remaining = encoded.len() - offset;
        let block_len = remaining.min(255);
        if block_len < ECC_LEN + 1 {
            bail!("Invalid/corrupted block at offset {}", offset);
        }

        let mut block = encoded[offset..offset + block_len].to_vec();
        let corrected = dec
            .correct(&mut block, None)
            .map_err(|e| anyhow::anyhow!("Unrecoverable errors in block {}: {:?}", block_index, e))?;

        recovered_xor.extend_from_slice(corrected.data());

        if verbose {
            println!("Block {}: {} bytes recovered", block_index, corrected.data().len());
        }

        offset += block_len;
        block_index += 1;
    }

    // Key length check
    if key.len() < recovered_xor.len() {
        bail!("ERROR: key.key is too short for the recovered data.");
    }

    // XOR back
    let data: Vec<u8> = recovered_xor.iter().zip(key.iter()).map(|(&c, &k)| c ^ k).collect();

    // Extract header safely
    if data.len() < HEADER_LEN {
        bail!("Recovered data too short for header");
    }
    let header: [u8; HEADER_LEN] = data[data.len() - HEADER_LEN..].try_into()?;
    let orig_len = u64::from_be_bytes(header) as usize;

    if data.len() != orig_len + HEADER_LEN {
        bail!("Recovered data length mismatch — possible corruption or wrong key");
    }

    let plaintext = &data[0..orig_len];
    fs::write(output_path, plaintext).context("Failed to write output file")?;
    println!("Decryption successful (Reed-Solomon recovery applied automatically): {}", output_path.display());
    Ok(())
}