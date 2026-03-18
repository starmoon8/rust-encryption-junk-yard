// tests/roundtrip.rs
use aix8_lib::{encrypt, decrypt};
use tempfile::tempdir;
use std::fs::File;
use std::io::{Write, Read}; // <-- fix: import traits

const PASSWORD: &str = "correct horse battery staple";

#[test]
fn encrypt_decrypt_roundtrip() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.txt");
    let mut f = File::create(&input_path).unwrap();
    f.write_all(b"hello aix8 reliability test").unwrap(); // works now
    f.flush().unwrap();

    let enc_path = dir.path().join("encrypted.ai");
    encrypt(&input_path, &enc_path, PASSWORD).unwrap();

    let out_path = dir.path().join("out.txt");
    decrypt(&enc_path, &out_path, PASSWORD).unwrap();

    let mut original = Vec::new();
    File::open(&input_path).unwrap().read_to_end(&mut original).unwrap();

    let mut decrypted = Vec::new();
    File::open(&out_path).unwrap().read_to_end(&mut decrypted).unwrap();

    assert_eq!(original, decrypted);
}