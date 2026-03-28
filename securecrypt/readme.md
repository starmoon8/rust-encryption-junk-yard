# SecureCrypt

A simple, secure, and flexible file encryption CLI written in Rust.

SecureCrypt is designed for **reliable local encryption** of files before storage or upload (e.g., cloud backups). It focuses on strong cryptography, predictable behavior, and a minimal interface.

---

## 🔐 Features

* **Authenticated encryption (AEAD)** using XChaCha20-Poly1305
* **Argon2id key derivation** (resistant to brute-force attacks)
* **Streaming encryption** (handles large files efficiently)
* **Three key modes:**

  * Password-based
  * Keyfile-based
  * Built-in default key (`-d`)
* **Tamper detection** (any modification causes decryption failure)
* **Atomic file writes** (prevents partial/corrupt output)
* **Minimal, silent CLI** (no help/usage output)

---

## ⚙️ Installation

```bash
git clone <your-repo>
cd securecrypt
cargo build --release
```

Binary:

```text
target/release/securecrypt
```

---

## 🚀 Usage

SecureCrypt has **two commands only**:

```bash
securecrypt encrypt <input> <output>
securecrypt decrypt <input> <output>
```

Optional flags modify how the encryption key is derived.

---

# 🔑 Key Modes (IMPORTANT)

Exactly **one** of the following is used:

| Mode        | Flag      | Description               |
| ----------- | --------- | ------------------------- |
| Password    | (default) | Prompts user for password |
| Keyfile     | `-k`      | Uses `key.key` file       |
| Default Key | `-d`      | Uses built-in static key  |

⚠️ You **cannot combine flags** (`-k` and `-d` together will fail).

---

## 🔐 1. Password Mode (Default)

### Usage

```bash
securecrypt encrypt file.txt file.enc
securecrypt decrypt file.enc file.txt
```

### Behavior

* You are prompted for a password
* Encryption requires confirmation (type twice)
* Decryption requires the same password

### Internals

* Password is passed through **Argon2id**
* A **random salt (16 bytes)** is used per file
* Final encryption key is derived from:

  ```
  Argon2(password, salt)
  ```

### Security Notes

* Security depends on password strength
* Argon2 slows down brute-force attacks significantly
* Recommended: use a **long passphrase**, not a short password

---

## 📁 2. Keyfile Mode (`-k`)

### Usage

```bash
securecrypt encrypt file.txt file.enc -k
securecrypt decrypt file.enc file.txt -k
```

### Keyfile Requirements

* File must be named: `key.key`
* Must be located in:

  ```
  same directory as the executable
  ```
* Must be **exactly 32 bytes**

If not exactly 32 bytes → program exits.

---

### Creating a valid keyfile

```bash
head -c 32 /dev/urandom > key.key
chmod 600 key.key
```

---

### Internals

Even though the keyfile is already 32 bytes:

* It is **NOT used directly**
* It is still processed through Argon2:

```
Argon2(keyfile_bytes, salt)
```

This ensures:

* Consistent key derivation behavior across all modes
* Protection against weak or structured keyfiles
* Per-file uniqueness via salt

---

### Security Notes

* Strongest mode if keyfile is truly random
* No brute-force weakness like passwords
* If keyfile is lost → **data is permanently lost**
* If keyfile is copied → attacker can decrypt files

---

## ⚡ 3. Default Key Mode (`-d`)

### Usage

```bash
securecrypt encrypt file.txt file.enc -d
securecrypt decrypt file.enc file.txt -d
```

### Behavior

* Uses a **hardcoded key embedded in the binary**
* Still passed through Argon2 with salt

```
Argon2(DEFAULT_KEY, salt)
```

---

### ⚠️ Security Reality

This mode is **NOT secure against attackers**.

Anyone can:

* Extract the key from the binary
* Decrypt any file created with `-d`

---

### Intended Use

* Convenience
* Quick obfuscation
* Non-sensitive data
* Situations with **no adversary**

---

## 📦 File Format

```
[MAGIC][VERSION][SALT][NONCE_BASE][CHUNK_SIZE][CHUNKS...][END]
```

### Components

* **MAGIC**: File identifier (`SCRYPT`)
* **VERSION**: Format version
* **SALT (16 bytes)**: For Argon2
* **NONCE_BASE (24 bytes)**: Base for per-chunk nonces
* **CHUNK_SIZE (u32)**: Stored for compatibility
* **CHUNKS**: Encrypted data blocks
* **END marker**: `0-length chunk`

---

### Chunk Structure

```
[length][ciphertext + authentication tag]
```

Each chunk:

* Uses a unique nonce (derived from counter)
* Is authenticated independently
* Includes header as AAD

---

## 🔐 Cryptography Details

### Encryption

* Algorithm: **XChaCha20-Poly1305**
* Provides:

  * Confidentiality
  * Integrity
  * Authenticity

### Key Derivation

* Algorithm: **Argon2id**
* Parameters:

  * Memory: ~64 MB
  * Iterations: 3
  * Parallelism: 1

### Nonce Strategy

* Random base nonce per file
* Per-chunk counter embedded into nonce
* Prevents nonce reuse

---

## 🧼 Reliability Features

* **Atomic writes**

  * Uses temporary file + rename
* **fsync before rename**

  * Prevents data loss on crash
* **End-of-file marker**

  * Detects truncation
* **Strict validation**

  * Rejects malformed or corrupted input

---

## ❗ Important Warnings

* **Wrong password/key = decryption failure**
* **Lost password/keyfile = permanent data loss**
* No recovery, no backdoors
* Do not modify encrypted files manually
* Do not mix modes when decrypting

---

## 📊 Performance

* Chunk size: **1 MB**
* Streaming design:

  * Low memory usage
  * Works on very large files
* Optimized for:

  * Reliability
  * Predictability
  * Safety

---

## 🛠 Future Ideas

* Password + keyfile combined mode
* Progress indicator
* Configurable Argon2 parameters
* Secure file overwrite

---

## 📄 License

MIT License

---

## 💡 Summary

SecureCrypt provides:

* Modern authenticated encryption
* Consistent key derivation across modes
* Reliable file handling
* Minimal, silent CLI design

Best suited for:

* Personal encryption workflows
* Secure backups
* Local file protection
