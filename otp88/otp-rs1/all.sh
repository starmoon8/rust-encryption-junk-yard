#!/usr/bin/env bash

# dump.sh - Updated to include src/keygen.rs
# Dumps key source files of otp-rs into all.txt
# Place this file next to Cargo.toml and run: bash dump.sh

set -euo pipefail

OUTPUT="all.txt"

echo "Dumping otp-rs source files to $OUTPUT ..."
echo "=========================================" > "$OUTPUT"

# ──────────────────────────────────────────────
# 1. Cargo.toml
# ──────────────────────────────────────────────
if [[ -f "Cargo.toml" ]]; then
    echo "" >> "$OUTPUT"
    echo "===== Cargo.toml =====" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    cat "Cargo.toml" >> "$OUTPUT"
else
    echo "Warning: Cargo.toml not found" >> "$OUTPUT"
fi

# ──────────────────────────────────────────────
# 2. src/main.rs
# ──────────────────────────────────────────────
if [[ -f "src/main.rs" ]]; then
    echo "" >> "$OUTPUT"
    echo "===== src/main.rs =====" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    cat "src/main.rs" >> "$OUTPUT"
else
    echo "Warning: src/main.rs not found" >> "$OUTPUT"
fi

# ──────────────────────────────────────────────
# 3. src/keygen.rs  (NEW)
# ──────────────────────────────────────────────
if [[ -f "src/keygen.rs" ]]; then
    echo "" >> "$OUTPUT"
    echo "===== src/keygen.rs =====" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    cat "src/keygen.rs" >> "$OUTPUT"
else
    echo "Warning: src/keygen.rs not found" >> "$OUTPUT"
fi

# ──────────────────────────────────────────────
# 4. src/bin/generate_random_files.rs
# ──────────────────────────────────────────────
if [[ -f "src/bin/generate_random_files.rs" ]]; then
    echo "" >> "$OUTPUT"
    echo "===== src/bin/generate_random_files.rs =====" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    cat "src/bin/generate_random_files.rs" >> "$OUTPUT"
else
    echo "Warning: src/bin/generate_random_files.rs not found" >> "$OUTPUT"
fi

# ──────────────────────────────────────────────
# 5. All *.rs files in tests/
# ──────────────────────────────────────────────
echo "" >> "$OUTPUT"
echo "===== Test files (*.rs in tests/) =====" >> "$OUTPUT"

if [[ -d "tests" ]]; then
    find "tests" -type f -name "*.rs" | sort | while read -r file; do
        echo "" >> "$OUTPUT"
        echo "===== $file =====" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
        cat "$file" >> "$OUTPUT"
    done
else
    echo "No tests/ directory found" >> "$OUTPUT"
fi

# Footer
echo "" >> "$OUTPUT"
echo "=========================================" >> "$OUTPUT"
echo "Dump finished → see $OUTPUT" >> "$OUTPUT"

echo "Done. Check $OUTPUT"