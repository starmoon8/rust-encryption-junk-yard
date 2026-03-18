use std::path::PathBuf;
use std::fs;

use aix8_lib::{encrypt, decrypt};

const PASSWORD: &str = "testpass";

#[test]
fn header_redundancy_works() {

    let input_path = PathBuf::from("test_input.txt");
    let enc_path = PathBuf::from("test_input.enc");
    let out_path = PathBuf::from("test_output.txt");

    fs::write(&input_path, b"Hello world").unwrap();

    encrypt(&input_path, &enc_path, PASSWORD).unwrap();

    decrypt(&enc_path, &out_path, PASSWORD).unwrap();

    let result = fs::read(&out_path).unwrap();

    assert_eq!(result, b"Hello world");
}