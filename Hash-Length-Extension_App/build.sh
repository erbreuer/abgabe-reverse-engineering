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
if ! command -v proguard &> /dev/null; then
    echo "Error: proguard not found. Install ProGuard 7.9+ (e.g. 'brew install proguard')."
    exit 1
fi

SRC="src/main/java"
BUILD="target/classes"
OBF="target/obfuscated"

# Zweites Schlüsselfragment für die EncryptedClassLoader-Initialisierung
# (siehe Main.java: _key() = _K1 xor X-Build-Tag xor VersionInfo.BUILD_TAG).
# Muss mit den Konstanten in Main.java und VersionInfo.java übereinstimmen.
BUILD_TAG=81

rm -rf target
mkdir -p "$BUILD/de/dhbw/ctf" "$OBF/crypto" "$OBF/main"

echo "[1/7] Compiling Crypto.java..."
javac -d "$BUILD" "$SRC/de/dhbw/ctf/Crypto.java"

echo "[2/7] Obfuscating Crypto.class with ProGuard..."
proguard @proguard/crypto.pro

echo "[3/7] Encrypting Crypto.class (descramble)..."
python3 - <<'PYEOF'
import os

path_in  = "target/obfuscated/crypto/de/dhbw/ctf/Crypto.class"
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

os.remove("target/classes/de/dhbw/ctf/Crypto.class")
with open(path_out, "wb") as f:
    f.write(data)

print(f"  Encrypted {n} bytes -> {path_out}")
PYEOF

echo "[4/7] Compiling Main.java and VersionInfo.java..."
# Main.java references Crypto only via reflection — no compile-time dependency needed
javac -d "$BUILD" "$SRC/de/dhbw/ctf/VersionInfo.java" "$SRC/de/dhbw/ctf/Main.java"

echo "[5/7] Obfuscating Main.class with ProGuard..."
proguard @proguard/main.pro

# Die unobfuskierten Main/VersionInfo-Classfiles werden durch ihre
# ProGuard-Ausgabe ersetzt, damit nur eine Fassung ins JAR gelangt.
rm -f "$BUILD/de/dhbw/ctf/Main.class" \
      "$BUILD/de/dhbw/ctf/Main\$EncryptedClassLoader.class" \
      "$BUILD/de/dhbw/ctf/VersionInfo.class"

echo "[6/7] Packaging JAR..."
mkdir -p target
cat > target/manifest.mf <<EOF
Manifest-Version: 1.0
Main-Class: de.dhbw.ctf.Main
X-Build-Tag: $BUILD_TAG
EOF

# target/classes enthält jetzt nur noch Crypto.class.encrypted (das
# unobfuskierte Main/VersionInfo wurde oben entfernt); das obfuskierte
# Main kommt aus $OBF/main.
jar cfm target/vault.jar target/manifest.mf -C "$OBF/main" . -C "$BUILD" .

echo "[7/7] Syncing to ../Try/ (if present)..."
if [ -d "../Try" ]; then
    cp target/vault.jar ../Try/vault.jar
    echo "  Synced: ../Try/vault.jar"
fi

echo ""
echo "Build successful: target/vault.jar"
echo ""
echo "Run:    java -jar target/vault.jar --help"
echo "Sample: java -jar target/vault.jar --sample"
