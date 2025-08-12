#!/bin/bash

# 인자 확인
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <binary> <libc_path> <ld_path>"
    echo "Example: $0 ./a.out ./libc.so.6 ./ld-2.23.so"
    exit 1
fi

binary="$1"
libc_path="$2"
ld_path="$3"

# 1. set interpreter
patchelf --set-interpreter "$ld_path" "$binary"

# 2. replace needed libc
patchelf --replace-needed libc.so.6 "$libc_path" "$binary"

echo "[+] Patchelf completed for $binary"
