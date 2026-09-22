#!/usr/bin/env python3
"""
Decrypts SecureVault-RE's bootstrap-encrypted vault/*.bin resources back
into plain .class files, using the AES-256-GCM key extracted from
VaultClassLoader's disassembled bytecode (see docs/RE-ANLEITUNG.md, step 2).

Usage:
    python3 dump_decrypt.py <extracted-jar-dir> <output-dir>

Each resource is stored as: 12-byte GCM IV || (ciphertext || 16-byte GCM tag).
This matches VaultClassLoader.decrypt()'s layout exactly.
"""
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Extracted from VaultClassLoader's static initializer bytecode
# (javap -c -p -v de/dhbw/securevault/loader/VaultClassLoader.class).
BOOTSTRAP_KEY = bytes.fromhex(
    "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe"
)
GCM_IV_LENGTH = 12


def decrypt_resource(data: bytes) -> bytes:
    iv = data[:GCM_IV_LENGTH]
    ciphertext_and_tag = data[GCM_IV_LENGTH:]
    aesgcm = AESGCM(BOOTSTRAP_KEY)
    return aesgcm.decrypt(iv, ciphertext_and_tag, None)


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <extracted-jar-dir> <output-dir>", file=sys.stderr)
        sys.exit(2)

    extracted_dir = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    output_dir.mkdir(parents=True, exist_ok=True)

    vault_dir = extracted_dir / "vault"
    bin_files = sorted(vault_dir.glob("*.bin"))
    if not bin_files:
        print(f"no .bin files found under {vault_dir}", file=sys.stderr)
        sys.exit(1)

    for bin_file in bin_files:
        encrypted = bin_file.read_bytes()
        class_bytes = decrypt_resource(encrypted)

        # resource name "de_dhbw_securevault_keyparts_b.bin" -> class file
        # path "de/dhbw/securevault/keyparts/b.class"
        class_name = bin_file.stem
        class_path = output_dir / (class_name.replace("_", "/") + ".class")
        class_path.parent.mkdir(parents=True, exist_ok=True)
        class_path.write_bytes(class_bytes)

        magic = class_bytes[:4].hex()
        ok = "OK (cafebabe)" if magic == "cafebabe" else f"UNEXPECTED MAGIC {magic}"
        print(f"{bin_file.name} -> {class_path} ({len(class_bytes)} bytes) [{ok}]")


if __name__ == "__main__":
    main()
