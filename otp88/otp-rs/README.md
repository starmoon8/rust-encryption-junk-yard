idk if grok is full of crap but it says this app is unique and creative - the self healing decryption idea. 

# OTP-RS

**Linux-only CLI application for OTP-style XOR encryption with Reed-Solomon error correction.**

Encrypt and decrypt files using a one-time pad (`key.key`) with automatic error recovery. No key files are ever created by the app — you must provide your own one-time pad.

---

## Features

* One-time pad (OTP) XOR encryption/decryption
* Full Reed-Solomon error correction and recovery
* Works with files of any size (1 KB → 1 GB+)
* Parallelized tests for fast verification
* Linux-only (compile-time check)

---

## Requirements

* **Linux** OS
* **Rust 1.94+**
* Enough RAM for file sizes you intend to encrypt (e.g., 1–2 GB files require corresponding free memory)

---

## Installation

Clone and build:

```bash
git clone <repo-url>
cd otp-rs
cargo build --release
```

Or run directly with Cargo:

```bash
cargo run --bin otp-rs -- <COMMAND> <ARGS>
```

---

## Usage

> **Important:** Place your one-time pad file in the current directory as `key.key`. The key must be at least `input file size + 8 bytes` (header) long.

### Encrypt a file

```bash
cargo run --bin otp-rs -- encrypt path/to/input.txt path/to/output.enc
```

### Decrypt a file

```bash
cargo run --bin otp-rs -- decrypt path/to/input.enc path/to/output.txt
```

> Note: Encryption and decryption are symmetric — the same command works both ways.

---

## Examples

```bash
# Encrypt a 1MB file
cargo run --bin otp-rs -- encrypt tests/data/random_files/file_1048576B.bin file.enc

# Decrypt it back
cargo run --bin otp-rs -- decrypt file.enc file.dec
```

---

## Generating Random Test Files

The `generate_random_files` binary creates random files for testing:

```bash
cargo run --bin generate_random_files
```

It produces files like:

* `file_1024B.bin`
* `file_1048576B.bin` (1 MB)
* `file_10485760B.bin` (10 MB)
* `file_104857600B.bin` (100 MB)

> You can use these files to verify encryption and Reed-Solomon recovery.

---

## Testing

Run the integration tests (parallelized):

```bash
cargo test
```

This will:

1. Encrypt each file in `tests/data/random_files`
2. Introduce minor corruption
3. Decrypt and verify that the original content is fully recovered

> Large files are tested in parallel to speed up the process.

---

## Notes

* OTP-RS does **not generate keys**. You must provide `key.key`.
* The key must be longer than the plaintext plus an 8-byte header.
* Linux-only: compilation fails on other OSes.

---

## Dependencies

* [clap](https://crates.io/crates/clap) – CLI argument parsing
* [anyhow](https://crates.io/crates/anyhow) – error handling
* [reed-solomon](https://crates.io/crates/reed-solomon) – error correction
* [rand](https://crates.io/crates/rand) – random file generation (tests)
* [rayon](https://crates.io/crates/rayon) – parallelized tests
* [assert_cmd](https://crates.io/crates/assert_cmd) – integration tests

---

## License

[MIT](LICENSE)


