
# XOR File Obfuscator

A simple command-line tool written in Rust to XOR-obfuscate a file using a repeating key file. The operation is performed in-place with atomic overwrite to ensure safety (e.g., no partial corruption on failure).

This tool is useful for basic file obfuscation or encryption with a shared key. Note: XOR with a repeating key is not cryptographically secure for sensitive data—use it for casual purposes only. However, if the key is truly random, at least as long as the file, and used only once (never reused), this tool can implement a one-time pad, which is information-theoretically secure and unbreakable when used correctly.

## Features
- XORs the input file byte-by-byte with a repeating key from a separate file (or non-repeating if key >= file length, enabling one-time pad usage).
- Atomic overwrite: Writes to a temporary file and replaces the original only on success.
- Efficient buffering for large files.
- Defaults to `key.key` in the current working directory if no key is specified.
- Checks for file existence and non-empty key.
- Outputs status messages like "key < file" and "ok" based on key vs. file length.

## Installation

### Prerequisites
- Rust 1.94 or later (uses 2024 edition).

### Building from Source
1. Clone the repository (or copy the source files).
2. Run:
   ```
   cargo build --release
   ```
3. The binary will be in `target/release/xor`.

For Linux users, this is optimized for POSIX systems (e.g., atomic temp files in the same directory).

## Usage
```
xor <file> [OPTIONS]
```

### Options
- `-k, --key <KEY_FILE>`: Path to the key file (default: `key.key` in current directory).

The tool overwrites the input file in place. Run it twice with the same key to revert the obfuscation (since XOR is involutive).

### Examples
1. Obfuscate `example.txt` using default `key.key`:
   ```
   ./xor example.txt
   ```
   Output (if key shorter than file):
   ```
   key < file
   ok
   ```

2. Use a custom key file:
   ```
   ./xor secret.pdf --key /path/to/mykey.key
   ```
   Output (if key >= file length):
   ```
   ok
   ```

3. If files are missing:
   ```
   Error: Input file does not exist: "missing.txt"
   ```

## Generating a Key
You can create a random key file manually, e.g., using OpenSSL:
```
openssl rand -out key.key 1024  # 1 KiB random key
```
For one-time pad usage, ensure the key is at least as long as your file:
```
dd if=/dev/urandom of=key.key bs=1 count=$(stat -c %s yourfile.txt)
```

## License
Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.