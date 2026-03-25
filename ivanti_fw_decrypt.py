#!/usr/bin/env python3
"""
Ivanti Connect Secure Firmware Decryption Tool

Decrypts coreboot.img (encrypted initramfs) from Ivanti ICS firmware.
Supports automatic key extraction from vmlinux or vmlinux-with-symbols ELF.

Usage:
  python3 ivanti_fw_decrypt.py <vmlinux_or_syms_elf> <coreboot.img> <output>

The tool:
1. Extracts DSRAMFS_AES_KEY from the vmlinux binary
2. Finds XOR deobfuscation constants from populate_rootfs()
3. Derives the actual AES-128 key
4. Decrypts using the custom Ivanti cipher mode

Cipher mode (verified via kernel disassembly):
- AES-128 ECB used as building block
- Data processed in 512-byte sectors
- Per sector: keystream = AES_Decrypt(sector_counter) computed ONCE
- Per 16-byte block within sector:
    intermediate = ciphertext XOR keystream (same keystream for all blocks)
    result = AES_Decrypt(intermediate)
    plaintext = result XOR counter
    counter = intermediate (chained for next block)
"""

import struct
import sys
import os
import subprocess
from Crypto.Cipher import AES


def find_key_and_constants(vmlinux_path):
    """Extract DSRAMFS_AES_KEY and XOR constants from vmlinux."""

    # Try symbol-based lookup first
    key_va = None
    populate_va = None

    try:
        result = subprocess.run(
            ['readelf', '-s', vmlinux_path],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.split('\n'):
            if 'DSRAMFS_AES_KEY' in line and ('OBJECT' in line or 'NOTYPE' in line):
                parts = line.split()
                key_va = int(parts[1], 16)
            if 'populate_rootfs' in line and 'FUNC' in line and 'GLOBAL' in line:
                populate_va = int(parts[1], 16)
    except Exception:
        pass

    with open(vmlinux_path, 'rb') as f:
        data = f.read()

    # Find section mapping
    sections = []
    try:
        result = subprocess.run(
            ['readelf', '-S', vmlinux_path],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.split('\n'):
            if 'PROGBITS' in line:
                parts = line.strip().split()
                # Find the section name, address, offset
                idx = line.index('PROGBITS')
                before = line[:idx].strip()
                after = line[idx+8:].strip().split()
                name = before.split()[-1] if before.split() else ''
                if len(after) >= 2:
                    sec_va = int(after[0], 16)
                    sec_off = int(after[1], 16)
                    sec_size = int(after[2], 16) if len(after) > 2 else 0
                    sections.append((name, sec_va, sec_off, sec_size))
    except Exception:
        pass

    def va_to_offset(va):
        for name, sec_va, sec_off, sec_size in sections:
            if sec_va <= va < sec_va + sec_size:
                return sec_off + (va - sec_va)
        return None

    # Extract key bytes
    if key_va:
        key_offset = va_to_offset(key_va)
        if key_offset:
            raw_key = data[key_offset:key_offset + 16]
            print(f"[+] DSRAMFS_AES_KEY at VA 0x{key_va:x}, file offset 0x{key_offset:x}")
            print(f"[+] Raw key: {raw_key.hex()}")
        else:
            print(f"[-] Could not map VA 0x{key_va:x} to file offset")
            raw_key = None
    else:
        # Fallback: search for string marker
        marker = b'rDSRAMFS_AES_KEY'
        idx = data.find(marker)
        if idx != -1:
            print(f"[!] Found string marker at 0x{idx:x}, but need symbol table for actual key location")
            raw_key = None
        else:
            raw_key = None

    if raw_key is None:
        raise ValueError("Could not extract DSRAMFS_AES_KEY from vmlinux")

    # Find XOR constants from populate_rootfs
    # Look for the pattern: xor $IMM32, %edx  (81 f2 XX XX XX XX)
    # and: xor $IMM32, %esi  (81 f6 XX XX XX XX)
    # and: xor $IMM32, %eax  (35 XX XX XX XX)

    xor_constants = None

    if populate_va:
        pop_offset = va_to_offset(populate_va)
        if pop_offset:
            # Search in a window around populate_rootfs
            search_start = pop_offset
            search_end = min(pop_offset + 2048, len(data))
            window = data[search_start:search_end]

            # Find the XOR pattern sequence
            # Pattern: 81 f2 (xor edx, imm32) ... 81 f6 (xor esi, imm32) ... 81 f2 (xor edx, imm32) ... 35 (xor eax, imm32)
            xor_edx = []
            xor_esi = []
            xor_eax = []

            i = 0
            while i < len(window) - 6:
                if window[i:i+2] == b'\x81\xf2':
                    val = struct.unpack('<I', window[i+2:i+6])[0]
                    xor_edx.append(val)
                    i += 6
                elif window[i:i+2] == b'\x81\xf6':
                    val = struct.unpack('<I', window[i+2:i+6])[0]
                    xor_esi.append(val)
                    i += 6
                elif window[i] == 0x35 and len(window) > i + 4:
                    val = struct.unpack('<I', window[i+1:i+5])[0]
                    xor_eax.append(val)
                    i += 5
                else:
                    i += 1

            # The order in the code is: xor edx, xor esi, [store], xor edx, xor eax
            if len(xor_esi) >= 1 and len(xor_edx) >= 2 and len(xor_eax) >= 1:
                # Constants order: esi (lower32 of qword1), edx[0] (upper32 of qword1),
                #                  edx[1] (lower32 of qword2), eax (upper32 of qword2)
                xor_constants = [xor_esi[0], xor_edx[0], xor_edx[1], xor_eax[0]]
                print(f"[+] XOR constants: {[hex(c) for c in xor_constants]}")

    if xor_constants is None:
        # Try default constants from 22.7R2.3
        print("[!] Could not find XOR constants, trying known defaults for 22.7R2.x")
        xor_constants = [0x99ed2bf2, 0xaeef41fe, 0x141058c7, 0xd2ed180e]

    return raw_key, xor_constants


def derive_aes_key(raw_key, xor_constants):
    """Derive the actual AES-128 key from raw key bytes and XOR constants."""
    qword1, qword2 = struct.unpack('<QQ', raw_key)
    dwords = [
        (qword1 & 0xFFFFFFFF) ^ xor_constants[0],
        ((qword1 >> 32) & 0xFFFFFFFF) ^ xor_constants[1],
        (qword2 & 0xFFFFFFFF) ^ xor_constants[2],
        ((qword2 >> 32) & 0xFFFFFFFF) ^ xor_constants[3],
    ]
    aes_key = struct.pack('<IIII', *dwords)
    print(f"[+] Derived AES key: {aes_key.hex()}")
    return aes_key


def decrypt_coreboot(coreboot_path, aes_key, output_path):
    """Decrypt coreboot.img using the corrected Ivanti cipher mode."""
    with open(coreboot_path, 'rb') as f:
        data = bytearray(f.read())

    total = len(data)
    print(f"[*] Decrypting {total} bytes ({total / 1024 / 1024:.1f} MB)")

    cipher = AES.new(aes_key, AES.MODE_ECB)
    sector_size = 512
    block_size = 16
    blocks_per_sector = sector_size // block_size

    sector_num = 0
    offset = 0

    while offset + sector_size <= total:
        # Compute keystream ONCE per sector
        initial_counter = struct.pack('<I', sector_num) + b'\x00' * 12
        keystream = cipher.decrypt(initial_counter)
        counter = initial_counter

        for b in range(blocks_per_sector):
            boff = offset + b * block_size
            block = bytes(data[boff:boff + block_size])

            # XOR with keystream (same for all blocks in sector)
            intermediate = bytes(a ^ bb for a, bb in zip(block, keystream))

            # AES decrypt intermediate
            result = cipher.decrypt(intermediate)

            # XOR with counter
            plaintext = bytes(a ^ bb for a, bb in zip(result, counter))

            data[boff:boff + block_size] = plaintext
            counter = intermediate

        sector_num += 1
        offset += sector_size

        if sector_num % 20000 == 0:
            pct = offset * 100 / total
            print(f"    {pct:.0f}% ({offset / 1024 / 1024:.1f} MB)")

    # Handle partial last sector
    if offset < total:
        remaining = total - offset
        initial_counter = struct.pack('<I', sector_num) + b'\x00' * 12
        keystream = cipher.decrypt(initial_counter)
        counter = initial_counter

        full_blocks = remaining // block_size
        for b in range(full_blocks):
            boff = offset + b * block_size
            block = bytes(data[boff:boff + block_size])
            intermediate = bytes(a ^ bb for a, bb in zip(block, keystream))
            result = cipher.decrypt(intermediate)
            plaintext = bytes(a ^ bb for a, bb in zip(result, counter))
            data[boff:boff + block_size] = plaintext
            counter = intermediate

    with open(output_path, 'wb') as f:
        f.write(data)

    # Verify output
    magic = bytes(data[:4])
    if magic[:2] == b'\x1f\x8b':
        print(f"[+] Output: gzip compressed data")
    elif magic[:3] == b'BZh':
        print(f"[+] Output: bzip2 compressed data")
    elif magic[:6] == b'\xfd7zXZ\x00':
        print(f"[+] Output: xz compressed data")
    else:
        print(f"[!] Unknown output format: {magic.hex()}")

    print(f"[+] Saved to: {output_path}")
    return True


def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <vmlinux> <coreboot.img> <output>")
        print()
        print("  vmlinux     - Raw vmlinux or vmlinux-to-elf output (with symbols)")
        print("  coreboot.img - Encrypted initramfs from boot partition")
        print("  output      - Output path for decrypted file (gzip-compressed cpio)")
        print()
        print("After decryption, extract with: zcat <output> | cpio -idm")
        sys.exit(1)

    vmlinux = sys.argv[1]
    coreboot = sys.argv[2]
    output = sys.argv[3]

    print(f"[*] Ivanti ICS Firmware Decryption Tool")
    print(f"[*] vmlinux: {vmlinux}")
    print(f"[*] coreboot: {coreboot}")
    print()

    raw_key, xor_constants = find_key_and_constants(vmlinux)
    aes_key = derive_aes_key(raw_key, xor_constants)
    print()

    decrypt_coreboot(coreboot, aes_key, output)
    print("\n[+] Done!")


if __name__ == '__main__':
    main()
