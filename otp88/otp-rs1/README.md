
# OTP-RS: Self-Healing One-Time Pad Encryption with Reed-Solomon

**The only simple CLI tool that gives you true one-time-pad security + automatic self-healing on decryption.**

## Why "self-healing" is special

Most encryption tools (AES, ChaCha20, etc.) completely break when the encrypted file gets even a few corrupted bytes.  
Reed-Solomon error correction can fix that — **but only if the encryption algorithm is perfectly linear**.

XOR (one-time pad) is the only common algorithm that satisfies this perfectly. Because of that, OTP-RS can:

- Encrypt with perfect one-time-pad security
- Automatically detect and repair bit flips / small damage during decryption
- Recover the original file even if the `.enc` file is partially corrupted

> **Picocrypt is the only other known tool that does this cleanly.**  
> Everything else either breaks Reed-Solomon math or uses much slower/heavier methods.

## What is OTP-RS?

A tiny, Linux-only Rust CLI that combines:

- **Pure one-time pad (OTP) XOR encryption** — information-theoretically secure when using a truly random key
- **Built-in Reed-Solomon error correction** — self-healing on decrypt (up to 16 errors per 223-byte block)
- **Convenient password-based key generator** (Argon2id + ChaCha20)

> **⚠️ Security reminder**  
> The built-in keygen is convenient but **not** true OTP security — it is only as strong as your password.  
> For maximum security, generate truly random keys with external tools.

## Usage (after compiling)

First build the app once:

```bash
cargo build --release
```

After that you can run it directly from the project folder:

### 1. Create a test file

```bash
echo "This is my super secret message!" > example.txt
```

### 2. Generate a key (convenience mode)

```bash
./target/release/otp-rs keygen 500MiB
```

(It will prompt for a password twice and create `key.key` in the current directory.)

### 3. Encrypt

```bash
./target/release/otp-rs encrypt example.txt example.enc
```

### 4. (Optional) Simulate damage

```bash
# Flip a few random bytes to test self-healing
python3 -c 'import random; d=open("example.enc","rb").read(); open("example.enc","wb").write(d[:100] + bytes([b^0xFF for b in d[100:103]]) + d[103:])'
```

### 5. Decrypt (self-healing happens automatically)

```bash
./target/release/otp-rs decrypt example.enc recovered.txt
```

You will see:  
`Decryption successful (Reed-Solomon recovery applied automatically)`

## Keygen Command Reference

```bash
./target/release/otp-rs keygen <SIZE> [--force] [--output <PATH>]
```

Examples:

```bash
./target/release/otp-rs keygen 1GiB
./target/release/otp-rs keygen 2GB --force
./target/release/otp-rs keygen 500MiB --output my-secret-pad.key
```

Supported sizes: `1GB`, `500MiB`, `2.5GiB`, or raw bytes like `1073741824`.

> The built-in keygen is fast and convenient for everyday use.  
> For maximum security you can still drop in a truly random key made by any other tool (stardust-keygen, dice rolls, hardware RNG, etc.).

## Built-in Testing

OTP-RS comes with two levels of testing:

### 1. Quick integration tests (cargo test)

```bash
# 1. Generate test files + matching keys
cargo run --bin generate_random_files

# 2. Run all tests (encrypt → corrupt → decrypt + verify)
cargo test
```

These tests run in parallel and intentionally corrupt files to prove Reed-Solomon recovery works.

### 2. Manual large-file testing

You can also manually test any file the same way:

```bash
./target/release/otp-rs encrypt tests/data/random_files/file_1048576B.bin test.enc
./target/release/otp-rs decrypt test.enc recovered.bin
diff tests/data/random_files/file_1048576B.bin recovered.bin
```

---

**OTP-RS** — March 2026  
Linux-only • MIT licensed • Pure Rust  
Questions or ideas? Just open an issue on GitHub.
```

