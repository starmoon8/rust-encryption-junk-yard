use assert_cmd::Command;
use rayon::prelude::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Run a single test for a given file and its existing key
fn run_test(file: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tmp = TempDir::new()?;

    let input_path = PathBuf::from(file);
    let tmp_input_path = tmp.path().join("input.txt");
    let enc_path = tmp.path().join("file.enc");
    let dec_path = tmp.path().join("file.dec");
    let key_path = tmp.path().join("key.key");

    // Copy input file and key
    fs::copy(&input_path, &tmp_input_path)?;
    let original_key_path = input_path.parent().unwrap().join("key.key");
    fs::copy(&original_key_path, &key_path)?;

    // Encrypt
    Command::cargo_bin("otp-rs")?
        .current_dir(&tmp)
        .args(["encrypt", "input.txt", "file.enc"])
        .assert()
        .success();

    // Inject minor corruption
    let mut enc_data = fs::read(&enc_path)?;
    if enc_data.len() > 2 {
        enc_data[1] ^= 0xAA;
        enc_data[2] ^= 0x55;
        fs::write(&enc_path, &enc_data)?;
    }

    // Decrypt
    Command::cargo_bin("otp-rs")?
        .current_dir(&tmp)
        .args(["decrypt", "file.enc", "file.dec"])
        .assert()
        .success();

    // Verify
    let orig = fs::read(&tmp_input_path)?;
    let dec = fs::read(&dec_path)?;
    assert_eq!(orig, dec, "Decrypted file does not match original");

    Ok(())
}

#[test]
fn run_all_samples_parallel() {
    let data_dir = PathBuf::from("tests/data/random_files");
    let files: Vec<_> = fs::read_dir(&data_dir)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.is_file() && path.extension().map(|e| e == "bin").unwrap_or(false) {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    // Use rayon to test multiple files in parallel
    let results: Vec<_> = files
        .par_iter()
        .map(|file| run_test(file.to_str().unwrap()))
        .collect();

    // Check for any failures and panic with the first one
    for result in results {
        if let Err(e) = result {
            panic!("Test failed: {}", e);
        }
    }
}