#!/bin/bash
OUT="all.txt"
rm -f "$OUT"

echo "AIX8 PROJECT SOURCE DUMP" >> "$OUT"
echo "========================" >> "$OUT"
echo "" >> "$OUT"

dump () {
    if [ -f "$1" ]; then
        echo "" >> "$OUT"
        echo "==================================" >> "$OUT"
        echo "FILE: $1" >> "$OUT"
        echo "==================================" >> "$OUT"
        cat "$1" >> "$OUT"
        echo "" >> "$OUT"
    fi
}

# Cargo config
dump Cargo.toml

# Dump Rust files from src, src/bin, and tests
find src src/bin tests -type f -name "*.rs" 2>/dev/null | sort | while read -r file; do
    dump "$file"
done

echo "Done. Output written to $OUT"