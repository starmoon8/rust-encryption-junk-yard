
# Keygen

**Deterministic large key generator from a password**  
Generate cryptographically secure, non-repeating random keys (up to 20 GB) derived from your password using Argon2id + ChaCha20 stream cipher.

This tool is useful for:
- Creating large deterministic entropy files (e.g., for testing, simulations, or seeding other systems)
- Generating one-time pads or massive keys from a memorable passphrase
- Reproducible randomness without storing huge seeds

**Security note**: The output is **deterministic** — same password + salt + nonce + pepper → always the same key. Do **not** use this for real cryptographic secrets unless you fully understand the implications (e.g., if the inputs leak, the key is compromised). For production secrets, prefer true randomness.

## Features

- Password-based key derivation with **Argon2id** (memory-hard, resistant to GPU attacks)
- Pepper (secret added to Argon2) for extra protection
- ChaCha20 stream cipher to expand the 32-byte derived key into arbitrary length
- Chunked writing for efficiency (1 MiB chunks)
- CLI flags + environment variable fallbacks
- Safe defaults with 128 MiB memory cost for Argon2
- Built with modern Rust (edition 2024, Rust 1.94+)

## Requirements

- Rust 1.94 or newer (edition 2024)

## Installation

1. Clone the repo:
   ```bash
   git clone https://github.com/yourusername/stardust-keygen.git
   cd stardust-keygen
   ```

2. Build and install:
   ```bash
   cargo install --path .
   ```
   Or build release binary:
   ```bash
   cargo build --release
   ```
   The binary will be at `target/release/stardust-keygen.exe` (Windows) or `target/release/stardust-keygen` (Unix).

(If you publish to crates.io later: `cargo install stardust-keygen`)

## Usage

Basic usage (generates a 100 MiB key):

```bash
stardust-keygen 104857600
```

Full options:

```text
Deterministic key generator: password → non-repeating key up to 20GB

Usage: stardust-keygen [OPTIONS] <SIZE>

Arguments:
  <SIZE>  Key size in bytes (1 to 20GB)

Options:
  -o, --output <FILE>     Output file path (default: key.key next to executable)
      --salt <SALT>       Salt for Argon2 key derivation (default: ultimate-salt-v1-2026)
      --pepper <PEPPER>   Pepper secret for Argon2 (default: secret-pepper-masterkey)
      --nonce <NONCE>     12-character nonce for ChaCha20 (default: JohnDoeXYZ12)
  -h, --help              Print help
  -V, --version           Print version
```

### Examples

1. **Custom output + size**:
   ```bash
   stardust-keygen 1073741824 -o my-big-key.bin
   ```

2. **Using environment variables** (overrides defaults, but CLI flags win):
   ```bash
   export STARDUST_SALT="my-custom-salt-2026"
   export STARDUST_PEPPER="super-secret-value"
   export STARDUST_NONCE="CustomNonce42"
   stardust-keygen 524288000
   ```

3. **Generate 1 GiB key with custom values**:
   ```bash
   stardust-keygen 1073741824 \
     --salt "personal-salt-xyz" \
     --pepper "hidden-pepper-123" \
     --nonce "MarkSec2026AB"
   ```

It will prompt twice for your password (confirmation check) and write the file if it doesn't already exist.

## Security Considerations

- **Argon2id params**: 131072 KiB memory, 4 iterations, 8 lanes (~moderate cost, ~few seconds on modern hardware).
- Change defaults (`--salt`, `--pepper`, `--nonce`) to your own values — never commit them!
- Pepper should be a high-entropy secret (not stored in code or env in production).
- Nonce must be **exactly 12 bytes** (fixed for ChaCha20 IETF).
- Output is **not encrypted** — it's raw keystream. Protect the file!
- For real crypto use-cases, prefer hardware RNG or `/dev/urandom` unless determinism is explicitly required.

## Building from Source

```bash
git clone https://github.com/yourusername/stardust-keygen.git
cd stardust-keygen
cargo build --release
```

Dependencies (latest as of March 2026):
- clap ^4.5 (CLI parsing)
- rpassword ^7.4 (secure password prompt)
- argon2 ^0.5 (key derivation)
- chacha20 ^0.10 + cipher ^0.5 (stream cipher)

## Contributing

Pull requests welcome! Especially:
- Better Argon2 param tuning options
- Progress bar for large keys
- Tests for determinism / edge cases

1. Fork & branch
2. `cargo fmt && cargo clippy --fix --allow-dirty`
3. Add tests if possible
4. Open PR

## License

MIT OR Apache-2.0 (your choice)


