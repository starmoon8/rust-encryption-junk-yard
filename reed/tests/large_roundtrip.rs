// tests/large_roundtrip.rs
use aix8_lib::{encrypt, decrypt};
use tempfile::tempdir;
use rand::Rng;
use std::fs::File;
use std::io::{Write, Read}; // fix
const PASSWORD: &str = "correct horse battery staple";

#[test]
fn large_encrypt_decrypt_roundtrip() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input_large.txt");
    let mut f = File::create(&input_path).unwrap();

    let mut rng = rand::thread_rng();
    for _ in 0..(1024 * 1024) { // 1 MB
        f.write_all(&[rng.r#gen()]).unwrap();
    }
    f.flush().unwrap();

    let enc_path = dir.path().join("encrypted_large.ai");
    encrypt(&input_path, &enc_path, PASSWORD).unwrap();

    let out_path = dir.path().join("out_large.txt");
    decrypt(&enc_path, &out_path, PASSWORD).unwrap();

    let mut original = Vec::new();
    File::open(&input_path).unwrap().read_to_end(&mut original).unwrap();

    let mut decrypted = Vec::new();
    File::open(&out_path).unwrap().read_to_end(&mut decrypted).unwrap();

    assert_eq!(original, decrypted);
}