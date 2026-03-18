use std::fs;
use std::io::{Seek, SeekFrom, Write};
use tempfile::tempdir;

use aix8_lib::crypto::{encrypt, decrypt};
use aix8_lib::repair::repair;

#[test]
fn corruption_repair_pipeline() {

    let dir = tempdir().unwrap();

    let input_path = dir.path().join("original.txt");
    let encrypted_path = dir.path().join("file.aix");
    let corrupted_path = dir.path().join("file_corrupt.aix");
    let repaired_path = dir.path().join("file_repaired.aix");
    let output_path = dir.path().join("recovered.txt");

    let password = "testpassword";

    /* create sample data */

    let mut original_data = Vec::new();
    for i in 0..200_000 {
        original_data.push((i % 256) as u8);
    }

    fs::write(&input_path, &original_data).unwrap();

    /* encrypt */

    encrypt(&input_path, &encrypted_path, password).unwrap();

    /* copy encrypted file so we can corrupt it */

    fs::copy(&encrypted_path, &corrupted_path).unwrap();

    /* corrupt bytes in the middle */

    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&corrupted_path)
        .unwrap();

    file.seek(SeekFrom::Start(500)).unwrap();

    let garbage = [0xAAu8; 64];
    file.write_all(&garbage).unwrap();

    /* repair */

    repair(&corrupted_path, &repaired_path).unwrap();

    /* decrypt repaired file */

    decrypt(&repaired_path, &output_path, password).unwrap();

    /* compare original and recovered */

    let recovered = fs::read(&output_path).unwrap();

    assert_eq!(original_data, recovered);
}