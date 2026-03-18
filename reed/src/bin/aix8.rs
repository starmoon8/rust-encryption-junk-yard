use std::path::PathBuf;

use aix8_lib::{encrypt, decrypt};

fn main() -> std::io::Result<()> {

    let input = PathBuf::from("input.txt");
    let output = PathBuf::from("output.enc");
    let password = "mypassword";

    encrypt(&input, &output, password)?;

    let decrypted = PathBuf::from("decrypted.txt");
    decrypt(&output, &decrypted, password)?;

    Ok(())
}