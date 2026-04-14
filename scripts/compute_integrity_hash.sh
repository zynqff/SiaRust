#!/bin/bash
# compute_integrity_hash.sh — Compute runtime integrity hash for a GuardLib binary.
#
# Usage:
#   ./scripts/compute_integrity_hash.sh <path/to/libguardlib.so>
#
# Requires: nm, objdump or llvm-objdump, python3

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <path/to/libguardlib.so>"
    exit 1
fi

LIB="$1"

if [ ! -f "$LIB" ]; then
    echo "❌ File not found: $LIB"
    exit 1
fi

echo "Computing integrity hash for: $LIB"
echo ""

python3 - "$LIB" << 'PYEOF'
import sys
import struct
import hashlib
import subprocess

lib_path = sys.argv[1]

# Find the offset of verify_self_integrity in the binary
# We use nm to get symbol addresses
try:
    result = subprocess.run(
        ['nm', '--defined-only', '--demangle', lib_path],
        capture_output=True, text=True
    )
    lines = result.stdout.splitlines()
    target_sym = None
    for line in lines:
        if 'verify_self_integrity' in line or 'guard_init' in line:
            parts = line.split()
            if len(parts) >= 3:
                try:
                    addr = int(parts[0], 16)
                    target_sym = (parts[2], addr)
                    break
                except ValueError:
                    continue
except FileNotFoundError:
    print("❌ 'nm' not found. Install binutils.")
    sys.exit(1)

if not target_sym:
    print("❌ Could not find verify_self_integrity or guard_init symbol.")
    print("   Make sure the binary was built with debug symbols (or not stripped).")
    print("   For stripped release: set a fixed REGION_OFFSET in integrity.rs instead.")
    sys.exit(1)

sym_name, sym_addr = target_sym
print(f"Found symbol: {sym_name} @ 0x{sym_addr:x}")

# Read 4096 bytes from that offset
region_size = 4096
with open(lib_path, 'rb') as f:
    # For .so files, virtual address != file offset
    # We need to find the file offset from ELF LOAD segment
    data = f.read()

# Parse ELF to find load offset
def find_file_offset(elf_data, vaddr):
    # ELF magic check
    if elf_data[:4] != b'\x7fELF':
        return vaddr  # Not ELF, assume flat binary
    
    bits = 64 if elf_data[4] == 2 else 32
    little = elf_data[5] == 1
    fmt = '<' if little else '>'
    
    if bits == 64:
        e_phoff = struct.unpack_from(fmt + 'Q', elf_data, 32)[0]
        e_phentsize = struct.unpack_from(fmt + 'H', elf_data, 54)[0]
        e_phnum = struct.unpack_from(fmt + 'H', elf_data, 56)[0]
        
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type = struct.unpack_from(fmt + 'I', elf_data, off)[0]
            if p_type == 1:  # PT_LOAD
                p_offset = struct.unpack_from(fmt + 'Q', elf_data, off + 8)[0]
                p_vaddr  = struct.unpack_from(fmt + 'Q', elf_data, off + 16)[0]
                p_filesz = struct.unpack_from(fmt + 'Q', elf_data, off + 32)[0]
                if p_vaddr <= vaddr < p_vaddr + p_filesz:
                    return p_offset + (vaddr - p_vaddr)
    return vaddr

file_offset = find_file_offset(data, sym_addr)
print(f"File offset: 0x{file_offset:x}")
print(f"Region size: {region_size} bytes")
print()

region = data[file_offset:file_offset + region_size]
if len(region) < region_size:
    print(f"⚠️  Could only read {len(region)} bytes (end of file)")

digest = hashlib.sha256(region).digest()
hex_bytes = ', '.join(f'0x{b:02X}' for b in digest)

print("SHA-256 of region:")
print(f"  {digest.hex()}")
print()

# Detect target arch from ELF
arch = "unknown"
if data[:4] == b'\x7fELF':
    e_machine = struct.unpack_from('<H', data, 18)[0]
    arch_map = {0x28: "arm", 0xB7: "aarch64", 0x3E: "x86_64", 0x03: "x86"}
    arch = arch_map.get(e_machine, f"0x{e_machine:04x}")

print(f"Target architecture: {arch}")
print()
print("══════════════════════════════════════════════════════")
print("  Paste into src/integrity.rs:")
print("══════════════════════════════════════════════════════")
print()

cfg_arch = {
    "aarch64": '#[cfg(all(target_arch = "aarch64", target_os = "android"))]',
    "arm":     '#[cfg(all(target_arch = "arm", target_os = "android"))]',
    "x86_64":  '#[cfg(all(target_arch = "x86_64", target_os = "linux"))]',
}.get(arch, f'// arch: {arch}')

print(cfg_arch)
print(f'static EXPECTED_HASH: [u8; 32] = [')
# 8 bytes per line
for i in range(0, 32, 8):
    chunk = list(digest)[i:i+8]
    line = ', '.join(f'0x{b:02X}' for b in chunk)
    print(f'    {line},')
print('];')
print()
print("Also set:")
print("  const INTEGRITY_CHECK_DISABLED: bool = false;")
print("══════════════════════════════════════════════════════")
PYEOF
