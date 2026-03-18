use aix8_lib::{encrypt, decrypt, repair};
use tempfile::tempdir;
use rand::Rng;
use std::fs::File;
use std::io::{Read, Write};

const PASSWORD: &str = "correct horse battery staple";

#[test]
fn repair_after_corruption() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.txt");
    let mut f = File::create(&input_path).unwrap();

    let mut rng = rand::thread_rng();
    for _ in 0..1024 {
        f.write_all(&[rng.r#gen()]).unwrap();
    }
    f.flush().unwrap();

    let enc_path = dir.path().join("encrypted.ai");
    encrypt(&input_path, &enc_path, PASSWORD).unwrap();

    let repaired_path = dir.path().join("repaired.ai");
    repair(&enc_path, &repaired_path).unwrap();

    let out_path = dir.path().join("out.txt");
    decrypt(&repaired_path, &out_path, PASSWORD).unwrap();

    let mut original = Vec::new();
    File::open(&input_path).unwrap().read_to_end(&mut original).unwrap();

    let mut decrypted = Vec::new();
    File::open(&out_path).unwrap().read_to_end(&mut decrypted).unwrap();

    assert_eq!(original, decrypted);
}