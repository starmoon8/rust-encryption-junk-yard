
# xcha

**xcha** is a minimal, fast, and secure command-line tool for in-place encryption and decryption of files using **XChaCha20-Poly1305** with a password-derived key (via scrypt).

It overwrites files atomically (safe on Linux), keeps everything in memory (up to 32 GiB), and has an ultra-minimal interface.

## Features

- Encrypt/decrypt files in place (`pf` command)
- Password → key derivation with scrypt (strong, tunable, deterministic)
- Atomic overwrite using tempfile + rename (crash-safe on POSIX)
- Extremely quiet output (only "ok" on success, short errors otherwise)
- Fixed 32-byte key stored in `./key.key`
- Single binary, Linux-only

## Installation

```bash
# Clone and build
git clone https://github.com/yourusername/xcha.git
cd xcha
cargo build --release

# Move binary to PATH (optional)
sudo cp target/release/xcha /usr/local/bin/
```

Or just use the binary from `target/release/xcha` directly.

## Usage

### 1. Generate key from password

```bash
xcha keygen
```

```
Password: 
Confirm: 
ok
```

→ Creates `./key.key` (32-byte raw key derived from password via scrypt)

### 2. Encrypt or decrypt a file

```bash
xcha pf secret.txt
```

- If the file is **not** encrypted → encrypts it
- If it **is** encrypted → decrypts it
- Output: `encrypting...` or `decrypting...` then `ok`

Example flow:

```bash
echo "My super secret note" > note.txt
xcha pf note.txt          # encrypts → note.txt now binary
cat note.txt              # gibberish + magic header
xcha pf note.txt          # decrypts → back to original text
```

## Security

- **Cipher**: XChaCha20-Poly1305 (256-bit key, 192-bit nonce, AEAD)
- **Key derivation**: scrypt with strong defaults (logN=23, r=8, p=1)
  - ~6–12 GiB memory cost, ~5 seconds on high-end CPU
  - Tunable at the top of `src/main.rs`
- **Nonce**: Random per encryption (OsRng), never reused
- **In-place atomic**: tempfile + rename (safe on Linux)
- **No streaming yet** — fully in-memory (max 32 GiB file size)

**Keep `./key.key` secure**:
```bash
chmod 600 key.key
# or move it somewhere safe and symlink
```

## Tuning scrypt security

Edit these constants in `src/main.rs` and rebuild:

```rust
const SCRYPT_LOG_N: u8   = 23;  // N = 2^23 ≈ 8M → ~6–12 GiB memory
const SCRYPT_R: u32      = 8;
const SCRYPT_P: u32      = 1;
```

Higher values = stronger protection against brute-force, but longer keygen time.

## Limitations

- Linux only (uses POSIX atomic rename semantics)
- Max file size: 32 GiB (in-memory processing)
- No streaming mode (yet)
- Single key file (`./key.key`)
- No compression, no multi-recipient, no public-key support

## License

MIT or Apache-2.0 (your choice)

