#!/bin/bash

# Usage: ./encrypt_decrypt.sh <filename>
# Assumes ./rage is in the current working directory.
# Toggles encryption/decryption in place by overwriting the original file.
# Prompts for passphrase via rage itself.

if [ $# -ne 1 ]; then
    echo "Usage: $0 <filename>"
    exit 1
fi

FILE="$1"
TMP_FILE="$FILE.tmp"

if [ ! -f "$FILE" ]; then
    echo "File not found: $FILE"
    exit 1
fi

# Get the first 22 bytes, preserving trailing newline if present
_tmp=$(head -c 22 "$FILE"; echo .)
HEADER=${_tmp%.}

if [ "$HEADER" = "age-encryption.org/v1"$'\n' ]; then
    # Decrypt
    ./rage --decrypt "$FILE" -o "$TMP_FILE"
    if [ $? -eq 0 ]; then
        rm "$FILE"
        mv "$TMP_FILE" "$FILE"
        echo "File decrypted in place."
    else
        rm -f "$TMP_FILE"
        echo "Decryption failed."
        exit 1
    fi
else
    # Optional: Add a warning if it looks like it's already encrypted (partial check)
    _partial=$(head -c 21 "$FILE")
    if [ "$_partial" = "age-encryption.org/v1" ]; then
        echo "Warning: Encrypting an already-encrypted file"
    fi
    # Encrypt
    ./rage --passphrase "$FILE" -o "$TMP_FILE"
    if [ $? -eq 0 ]; then
        rm "$FILE"
        mv "$TMP_FILE" "$FILE"
        echo "File encrypted in place."
    else
        rm -f "$TMP_FILE"
        echo "Encryption failed."
        exit 1
    fi
fi