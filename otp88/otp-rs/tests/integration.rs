use assert_cmd::Command;

use std::fs;
use tempfile::TempDir;

#[test]
fn test_encrypt_decrypt_small_file() -> Result<(), Box<dyn std::error::Error>> {
    // Create a temporary directory for files
    let tmp = TempDir::new()?;
    let plaintext_path = tmp.path().join("test.txt");
    let enc_path = tmp.path().join("test.enc");
    let dec_path = tmp.path().join("test.dec");
    let key_path = tmp.path().join("key.key");

    // Create a small test file
    fs::write(&plaintext_path, b"Hello OTP-RS Testing!")?;

    // Generate a key (length = file + 8)
    let data_len = fs::read(&plaintext_path)?.len() + 8;
    let key: Vec<u8> = (0..data_len).map(|_| rand::random::<u8>()).collect();
    fs::write(&key_path, &key)?;

    // Encrypt
    Command::cargo_bin("otp-rs")?
        .args(["encrypt", plaintext_path.to_str().unwrap(), enc_path.to_str().unwrap()])
        .assert()
        .success();

    // Decrypt
    Command::cargo_bin("otp-rs")?
        .args(["decrypt", enc_path.to_str().unwrap(), dec_path.to_str().unwrap()])
        .assert()
        .success();

    // Verify decrypted matches original
    let orig = fs::read(&plaintext_path)?;
    let dec = fs::read(&dec_path)?;
    assert_eq!(orig, dec);

    Ok(())
}

#[test]
fn test_rs_error_correction() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let plaintext_path = tmp.path().join("test2.txt");
    let enc_path = tmp.path().join("test2.enc");
    let dec_path = tmp.path().join("test2.dec");
    let key_path = tmp.path().join("key.key");

    fs::write(&plaintext_path, b"Reed-Solomon error recovery test")?;
    let data_len = fs::read(&plaintext_path)?.len() + 8;
    let key: Vec<u8> = (0..data_len).map(|_| rand::random::<u8>()).collect();
    fs::write(&key_path, &key)?;

    // Encrypt
    Command::cargo_bin("otp-rs")?
        .args(["encrypt", plaintext_path.to_str().unwrap(), enc_path.to_str().unwrap()])
        .assert()
        .success();

    // Corrupt some bytes
    let mut enc_data = fs::read(&enc_path)?;
    if enc_data.len() > 2 {
        enc_data[1] ^= 0xFF; // flip one byte
        enc_data[2] ^= 0xAA; // flip another
        fs::write(&enc_path, &enc_data)?;
    }

    // Decrypt (RS should correct)
    Command::cargo_bin("otp-rs")?
        .args(["decrypt", enc_path.to_str().unwrap(), dec_path.to_str().unwrap()])
        .assert()
        .success();

    // Verify decrypted matches original
    let orig = fs::read(&plaintext_path)?;
    let dec = fs::read(&dec_path)?;
    assert_eq!(orig, dec);

    Ok(())
}