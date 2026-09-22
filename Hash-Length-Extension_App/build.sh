#!/usr/bin/env bash
set -e

echo "=== VaultAccess Build ==="

if ! command -v java &> /dev/null; then
    echo "Error: java not found. Install JDK 21+."
    exit 1
fi
if ! command -v javac &> /dev/null; then
    echo "Error: javac not found. Install JDK 21+."
    exit 1
fi

SRC="src/main/java"
BUILD="target/classes"
ENCRYPT_DIR="target/encrypted"

rm -rf target
mkdir -p "$BUILD/de/dhbw/ctf" "$ENCRYPT_DIR"

echo "[1/4] Compiling Crypto.java..."
javac -d "$BUILD" "$SRC/de/dhbw/ctf/Crypto.java"

echo "[2/4] Encrypting Crypto.class (descramble)..."
python3 - <<'PYEOF'
import os

path_in  = "target/classes/de/dhbw/ctf/Crypto.class"
path_out = "target/classes/de/dhbw/ctf/Crypto.class.encrypted"

with open(path_in, "rb") as f:
    data = bytearray(f.read())

n = len(data)
# descramble is its own inverse: swap outer bytes, XOR with 0x88
for i in range(n // 2):
    a, b = data[i], data[n - 1 - i]
    data[i]         = (b ^ 0x88) & 0xFF
    data[n - 1 - i] = (a ^ 0x88) & 0xFF

if n % 2 == 1:
    data[n // 2] = (data[n // 2] ^ 0x88) & 0xFF

with open(path_out, "wb") as f:
    f.write(data)

os.remove(path_in)
print(f"  Encrypted {n} bytes -> {path_out}")
PYEOF

echo "[3/4] Compiling Main.java..."
# Main.java references Crypto only via reflection — no compile-time dependency needed
# We provide a stub so javac is happy, then remove it before packaging
javac -d "$BUILD" "$SRC/de/dhbw/ctf/Main.java" 2>/dev/null || \
    javac -cp "$BUILD" -d "$BUILD" "$SRC/de/dhbw/ctf/Main.java"

echo "[4/4] Packaging JAR..."
mkdir -p target
cat > target/manifest.mf <<EOF
Manifest-Version: 1.0
Main-Class: de.dhbw.ctf.Main
EOF

jar cfm target/vault.jar target/manifest.mf -C "$BUILD" .

echo ""
echo "Build successful: target/vault.jar"
echo ""
echo "Run:    java -jar target/vault.jar --help"
echo "Sample: java -jar target/vault.jar --sample"
