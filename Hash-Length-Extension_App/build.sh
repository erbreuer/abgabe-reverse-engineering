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

# Manifestfragment für die EncryptedClassLoader-Initialisierung (siehe
# Main.java: _key() = _deriveKey(_K1, X-Build-Tag, VersionInfo.BUILD_TAG,
# RuntimeTag.SESSION_TAG), Hash-basiert statt XOR — siehe _deriveKey dort).
# Muss mit den Konstanten in Main.java, VersionInfo.java und
# RuntimeTag.java übereinstimmen.
BUILD_TAG=81

# Manifestfragment für die Secret-Rekonstruktion in Crypto._secret()
# (key = _deriveKey(_S1, X-Secret-Tag, Main.EncryptedClassLoader._key(),
# RuntimeTag.TRACE_TAG), ebenfalls Hash-basiert). SECRET_TAG wird als
# X-Secret-Tag ins Manifest geschrieben und zur Laufzeit aus dort
# gelesen. Der dritte Anteil ist bewusst kein weiteres Literal, sondern
# der bereits vorhandene Loader-Schlüssel (siehe Main.java) — dadurch
# lässt sich _S nicht ohne den Loader entschlüsseln.
SECRET_TAG=52

# Das eigentliche Secret. Wird NICHT ausgeliefert — nur zur Build-Zeit
# gebraucht, um _S (Crypto.java) und die keystream-verschlüsselte Flag
# (_F, Crypto.java) neu zu berechnen. Ändert sich dieser Wert, müssen
# beide Arrays über das Python-Werkzeug unten neu generiert werden.
SECRET="tr0ub4dor&_L3ngth_Ext3nsion_Secr3t!!"

# Der Flag-Klartext lebt ausschließlich hier, nicht mehr als Kommentar
# in Crypto.java.
FLAG="FLAG{h4sh_l3ngth_3xt3ns10n_pwn3d}"

rm -rf target
mkdir -p "$BUILD/de/dhbw/ctf" "$OBF/crypto" "$OBF/main"

echo "[1/8] Deriving _S (embedded secret) and _F (flag keystream) for Crypto.java..."
# Der Loader-Key (Main.EncryptedClassLoader._key()) wird hier rein
# arithmetisch nachgerechnet (_deriveKey(_K1, X-Build-Tag,
# VersionInfo.BUILD_TAG, RuntimeTag.SESSION_TAG) — dieselben vier Werte
# wie in Main.java/VersionInfo.java/RuntimeTag.java/oben), nicht durch
# einen echten Java-Aufruf. Muss mit Main.java (_K1=0x2C=44),
# VersionInfo.java (BUILD_TAG=245) und RuntimeTag.java
# (SESSION_TAG=197) übereinstimmen.
LOADER_K1=44
LOADER_VERSION_INFO_BUILD_TAG=245
LOADER_RUNTIME_SESSION_TAG=197
RUNTIME_TRACE_TAG=88  # muss mit RuntimeTag.java (TRACE_TAG) übereinstimmen

python3 - "$SECRET_TAG" "$LOADER_K1" "$BUILD_TAG" "$LOADER_VERSION_INFO_BUILD_TAG" "$LOADER_RUNTIME_SESSION_TAG" "$RUNTIME_TRACE_TAG" "$SECRET" "$FLAG" <<'PYEOF'
import hashlib, re, struct, sys

x_secret_tag  = int(sys.argv[1])  # wird als X-Secret-Tag ins Manifest geschrieben
loader_k1     = int(sys.argv[2])
loader_build_tag       = int(sys.argv[3])  # wird als X-Build-Tag ins Manifest geschrieben
loader_version_build   = int(sys.argv[4])
loader_session_tag     = int(sys.argv[5])
runtime_trace_tag      = int(sys.argv[6])
secret        = sys.argv[7].encode("utf-8")
flag          = sys.argv[8].encode("utf-8")

S1 = 0x6F  # muss mit Crypto.java (_S1) übereinstimmen
FREF = b"vault-flag"  # muss mit Crypto.java (_FREF) übereinstimmen

def java_array(bs):
    return "{" + ",".join(str(b if b < 128 else b - 256) for b in bs) + "}"

def derive_key(a, b, c, d):
    # Nachbau von Main.EncryptedClassLoader._deriveKey: vier signed 32-bit
    # Ints big-endian aneinandergehängt, SHA-256, erste 4 Bytes als
    # signed 32-bit big-endian Int interpretiert.
    buf = struct.pack(">iiii", a, b, c, d)
    h = hashlib.sha256(buf).digest()
    return struct.unpack(">i", h[:4])[0]

loader_key = derive_key(loader_k1, loader_build_tag, loader_version_build, loader_session_tag)
key = derive_key(S1, x_secret_tag, loader_key, runtime_trace_tag)
s_encoded = bytes((b ^ (key & 0xFF)) & 0xFF for b in secret)

# Schritt 5/8 (Crypto.class.encrypted) braucht denselben Loader-Key wie
# Main.EncryptedClassLoader._key() zur Laufzeit — hier zwischengespeichert,
# statt (wie zuvor) ein fixes Literal im Descramble-Schritt zu verwenden.
with open("target/loader-key.txt", "w") as fh:
    fh.write(str(loader_key & 0xFF))

def keystream(secret, fref, length):
    block = hashlib.sha256(secret + fref).digest()
    out = bytearray()
    while len(out) < length:
        if out:
            block = hashlib.sha256(block).digest()
        out.extend(block)
    return bytes(out[:length])

ks = keystream(secret, FREF, len(flag))
f_encoded = bytes(a ^ b for a, b in zip(flag, ks))

path = "src/main/java/de/dhbw/ctf/Crypto.java"
with open(path, "r", encoding="utf-8") as fh:
    src = fh.read()

src = re.sub(
    r'private static final byte\[\] _F = \{[^}]*\};',
    f'private static final byte[] _F = {java_array(f_encoded)};',
    src, count=1,
)
src = re.sub(
    r'private static final byte\[\] _S = \{[^}]*\};',
    f'private static final byte[] _S = {java_array(s_encoded)};',
    src, count=1,
)

with open(path, "w", encoding="utf-8") as fh:
    fh.write(src)

print(f"  _S ({len(s_encoded)} bytes) and _F ({len(f_encoded)} bytes) written to {path}")
PYEOF

echo "[2/8] Compiling Main.java, VersionInfo.java and Crypto.java..."
# Crypto.java referenziert jetzt Main.EncryptedClassLoader._key() direkt
# (Compile-Zeit-Abhängigkeit) — alle drei Klassen müssen deshalb in einem
# Durchgang kompiliert werden (Main.java selbst lädt Crypto weiterhin nur
# reflektiv, das bleibt unverändert).
javac -d "$BUILD" "$SRC/de/dhbw/ctf/VersionInfo.java" "$SRC/de/dhbw/ctf/RuntimeTag.java" "$SRC/de/dhbw/ctf/Main.java" "$SRC/de/dhbw/ctf/Crypto.java"

echo "[3/8] Obfuscating Main.class with ProGuard..."
# Muss vor crypto.pro laufen: schreibt das Umbenennungs-Mapping heraus,
# das crypto.pro per -applymapping übernimmt (siehe dort), damit
# Crypto.class dieselben verschleierten Namen für Main/Main$a referenziert
# wie das tatsächlich ausgelieferte Main.class.
proguard @proguard/main.pro

echo "[4/8] Obfuscating Crypto.class with ProGuard..."
proguard @proguard/crypto.pro

echo "[5/8] Encrypting Crypto.class (descramble)..."
# Verwendet denselben Hash-abgeleiteten Loader-Key wie
# Main.EncryptedClassLoader._key() zur Laufzeit (siehe Schritt 1/8,
# target/loader-key.txt) — kein fixes Literal mehr.
python3 - <<'PYEOF'
import os

path_in  = "target/obfuscated/crypto/de/dhbw/ctf/Crypto.class"
path_out = "target/classes/de/dhbw/ctf/Crypto.class.encrypted"

with open("target/loader-key.txt") as f:
    key = int(f.read().strip())

with open(path_in, "rb") as f:
    data = bytearray(f.read())

n = len(data)
# descramble is its own inverse: swap outer bytes, XOR with key
for i in range(n // 2):
    a, b = data[i], data[n - 1 - i]
    data[i]         = (b ^ key) & 0xFF
    data[n - 1 - i] = (a ^ key) & 0xFF

if n % 2 == 1:
    data[n // 2] = (data[n // 2] ^ key) & 0xFF

os.remove("target/classes/de/dhbw/ctf/Crypto.class")
with open(path_out, "wb") as f:
    f.write(data)

print(f"  Encrypted {n} bytes -> {path_out}")
PYEOF

echo "[6/8] Cleaning up unobfuscated Main/VersionInfo class files..."
# Werden durch die ProGuard-Ausgabe aus Schritt 3/8 ersetzt, damit nur
# eine Fassung ins JAR gelangt. Erst jetzt löschbar, da crypto.pro
# (Schritt 4/8) sie bis hierhin noch als Library brauchte.
rm -f "$BUILD/de/dhbw/ctf/Main.class" \
      "$BUILD/de/dhbw/ctf/Main\$EncryptedClassLoader.class" \
      "$BUILD/de/dhbw/ctf/Main\$_Cand.class" \
      "$BUILD/de/dhbw/ctf/VersionInfo.class" \
      "$BUILD/de/dhbw/ctf/RuntimeTag.class"

echo "[7/8] Packaging JAR..."
mkdir -p target
cat > target/manifest.mf <<EOF
Manifest-Version: 1.0
Main-Class: de.dhbw.ctf.Main
X-Build-Tag: $BUILD_TAG
X-Secret-Tag: $SECRET_TAG
EOF

# target/classes enthält jetzt nur noch Crypto.class.encrypted (das
# unobfuskierte Main/VersionInfo wurde oben entfernt); das obfuskierte
# Main kommt aus $OBF/main.
jar cfm target/vault.jar target/manifest.mf -C "$OBF/main" . -C "$BUILD" .

echo "[8/8] Syncing to ../Try/ (if present)..."
if [ -d "../Try" ]; then
    cp target/vault.jar ../Try/vault.jar
    echo "  Synced: ../Try/vault.jar"
fi

echo ""
echo "Build successful: target/vault.jar"
echo ""
echo "Run:    java -jar target/vault.jar --help"
echo "Sample: java -jar target/vault.jar --sample"
