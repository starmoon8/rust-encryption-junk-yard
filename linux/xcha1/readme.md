
# xcha

xcha is a minimal command-line tool for encrypting and decrypting files using XChaCha20-Poly1305 with password-derived keys (via scrypt). It operates in-place with atomic overwrites for safety on Linux.

## Features

- Password-based encryption/decryption (no key file needed)
- Auto-detects whether to encrypt or decrypt based on file header
- Encrypt mode: prompts for password twice
- Decrypt mode: prompts for password once
- In-memory processing (max 32 GiB files)
- Atomic overwrite using tempfile + rename (crash-safe on Linux)
- Extremely minimal CLI — just `xcha <file>`

## Installation

Clone the repository and build with Cargo:

```bash
git clone <your-repo-url>
cd xcha
cargo build --release
```

The binary will be at `target/release/xcha`. Optionally, add it to your PATH:

```bash
sudo cp target/release/xcha /usr/local/bin/
```

## Usage

Run the tool with a filename:

```bash
xcha secret.txt
```

- If the file is plaintext: prompts for password twice, encrypts it.
- If the file is encrypted: prompts for password once, decrypts it (fails with "decryption failed — wrong password?" if wrong).

Example:

```bash
echo "My secret message" > note.txt
xcha note.txt  # encrypt: prompts twice
cat note.txt   # now binary (starts with XCHACHA_ENC_v1)
xcha note.txt  # decrypt: prompts once
cat note.txt   # back to original
```

If no filename or invalid input: silent exit.

## Security

- **Cipher**: XChaCha20-Poly1305 (AEAD with 256-bit key, 192-bit nonce)
- **Key derivation**: scrypt (tunable, defaults to very strong: logN=23, r=8, p=1 — ~5s on high-end machines, ~6–12 GiB memory cost)
- **Nonce**: Fresh random per encryption (OsRng)
- **File format**: Magic header + nonce + ciphertext (including tag)
- Tune scrypt in `src/main.rs` constants and rebuild for stronger/faster derivation
- Protect your password — tool doesn't store it

## Limitations

- Linux only (relies on POSIX atomic rename)
- Max file size: 32 GiB (in-memory)
- No streaming (all in RAM)
- No compression or advanced features (minimal design)

## Tuning Scrypt (optional)

Edit constants in `src/main.rs` (near top) and rebuild:

```rust
const SCRYPT_LOG_N: u8   = 23;  // N = 2^23 (higher = stronger/slower)
const SCRYPT_R: u32      = 8;
const SCRYPT_P: u32      = 1;
```

- Higher logN increases security but key derivation time (test on your machine).

## License

MIT OR Apache-2.0
