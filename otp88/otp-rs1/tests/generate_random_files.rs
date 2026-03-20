use std::fs;
use std::path::Path;
use rand::Rng;

/// Generate a random file of `size_bytes` and a matching key
fn generate_file(file_path: &Path, size_bytes: usize) -> std::io::Result<()> {
    // Generate random file content
    let mut rng = rand::thread_rng();
    let mut data = vec![0u8; size_bytes];
    rng.fill(&mut data[..]);
    fs::write(file_path, &data)?;

    // Generate key of length = file + 8 bytes header
    let key_path = file_path.parent().unwrap().join("key.key");
    let mut key = vec![0u8; size_bytes + 8];
    rng.fill(&mut key[..]);
    fs::write(key_path, &key)?;

    Ok(())
}

fn main() -> std::io::Result<()> {
    let dir = Path::new("tests/data/random_files");
    fs::create_dir_all(dir)?;

    // Example sizes: 1 KB, 1 MB, 10 MB, 100 MB (or up to 2 GB)
    let sizes = [
        1 * 1024,
        1 * 1024 * 1024,
        10 * 1024 * 1024,
        100 * 1024 * 1024,
        // 1 * 1024 * 1024 * 1024, // 1 GB (uncomment to stress test)
    ];

    for &size in &sizes {
        let file_path = dir.join(format!("file_{}B.bin", size));
        println!("Generating random file: {} bytes", size);
        generate_file(&file_path, size)?;
    }

    Ok(())
}