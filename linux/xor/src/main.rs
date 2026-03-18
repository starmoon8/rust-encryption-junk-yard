use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use clap::Parser;
use tempfile::NamedTempFile;

const BUFFER_SIZE: usize = 64 * 1024; // 64 KiB

#[derive(Parser)]
#[command(
    name = "xor",
    version = "0.1.0",
    about = "XOR-obfuscate a file using a repeating key file",
    author = "Mark"
)]
struct Cli {
    /// Input file to transform (will be overwritten atomically)
    #[arg(index = 1)]
    file: PathBuf,

    /// Path to key file (default: key.key in current directory)
    #[arg(short, long, value_name = "KEY_FILE")]
    key: Option<PathBuf>,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    let key_path = cli.key.unwrap_or_else(|| default_key_path());

    if !cli.file.exists() {
        eprintln!("Error: Input file does not exist: {:?}", cli.file);
        std::process::exit(1);
    }
    if !key_path.exists() {
        eprintln!("Error: Key file does not exist: {:?}", key_path);
        std::process::exit(1);
    }

    let input_metadata = cli.file.metadata()?;
    let input_len = input_metadata.len();

    let key_bytes = fs::read(&key_path)?;

    run(&cli.file, &key_bytes)?;

    let key_len = key_bytes.len() as u64;

    if key_len < input_len {
        println!("key < file");
        println!("ok");
    } else {
        println!("ok");
    }

    Ok(())
}

/// Default key path: key.key in the current working directory
fn default_key_path() -> PathBuf {
    PathBuf::from("key.key")
}

/// Main XOR transform: reads input + key, writes to temp file, then atomically replaces
fn run(input_path: &Path, key_bytes: &[u8]) -> io::Result<()> {
    let mut input = BufReader::new(File::open(input_path)?);

    if key_bytes.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "Key file is empty"));
    }
    let key_len = key_bytes.len();

    // Create temp file in same directory for atomic move
    let parent_dir = input_path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = NamedTempFile::new_in(parent_dir)?;
    let mut output = BufWriter::new(temp_file.as_file_mut());

    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut key_pos = 0usize;

    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        for i in 0..n {
            buffer[i] ^= key_bytes[key_pos];
            key_pos = (key_pos + 1) % key_len; // Use modulo for cleaner wrap-around
        }

        output.write_all(&buffer[..n])?;
    }

    output.flush()?;
    drop(output); // release handle before persist
    temp_file.persist(input_path)?;

    Ok(())
}