# RE-Dokumentation: VaultAccess

## Ziel

Die Anwendung `vault.jar` prüft einen Token der Form `message-hex + MAC`. Ziel ist es,
einen Token zu fälschen der `user=admin` enthält und von der Anwendung als gültig
akzeptiert wird — **ohne das Secret zu kennen**.

---

## Schritt 1: JAR erkunden

```bash
java -jar vault.jar --sample
```

Keine Umgebungsvariable nötig — das Secret ist fest in der JAR eingebettet
(dazu mehr in Schritt 4). Ausgabe:
```
Sample message (hex) : 757365723d6775657374
Sample MAC           : 2c38fd78f54e6c582f5b87421920e2501405c1d11a7c77eabd537409d18ce938
```

`757365723d6775657374` ist die Hex-Kodierung von `user=guest`.

```bash
jar tf vault.jar
```

Relevante Einträge:
```
de/dhbw/ctf/Main.class
de/dhbw/ctf/Main$EncryptedClassLoader.class
de/dhbw/ctf/Crypto.class.encrypted    ← verschlüsselte Klasse
```

---

## Schritt 2: Main.class dekompilieren

```bash
jar xf vault.jar
javap -p -c de/dhbw/ctf/Main.class
```

Oder mit CFR:
```bash
java -jar cfr.jar de/dhbw/ctf/Main.class
```

**Hinweis:** `Main.class` ist mit ProGuard obfuskiert (private Felder/Methoden
heißen `a`, `b`, `c`, … statt sprechend; keine `LineNumberTable`;
Kontrollfluss teils verschachtelt). `main()` selbst ist unverändert
vorhanden (Pflicht-Einstiegspunkt), der Rest muss über die Bytecode-Struktur
erschlossen werden statt über Namen.

Im Bytecode/dekompilierten Code sichtbar (Namen hier zur Lesbarkeit wie im
Source-Code benannt, im JAR selbst sind sie umbenannt):

**`EncryptedClassLoader.findClass()`** lädt `Crypto.class.encrypted` und ruft
eine Entschlüsselungsfunktion mit einem zusammengesetzten Schlüssel auf.

**Der Schlüssel besteht aus vier getrennt liegenden Anteilen**, die über
SHA-256 zu einem Schlüssel verdichtet werden (nicht mehr per XOR verknüpft):
```java
private static final int _K1 = 0x2C;                  // in Main.class

public static int _key() {
    int k2 = _manifestTag();                           // aus MANIFEST.MF: X-Build-Tag
    int k3 = VersionInfo.BUILD_TAG;                     // aus VersionInfo.class
    int k4 = RuntimeTag.SESSION_TAG;                    // aus RuntimeTag.class
    return _deriveKey(_K1, k2, k3, k4);
}

public static int _deriveKey(int a, int b, int c, int d) {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putInt(a).putInt(b).putInt(c).putInt(d);
    byte[] hash = md.digest(buf.array());
    return ((hash[0] & 0xFF) << 24) | ((hash[1] & 0xFF) << 16)
         | ((hash[2] & 0xFF) << 8)  |  (hash[3] & 0xFF);
}
```
Alle vier Fundstellen müssen exakt korrekt kombiniert werden, um den
vollständigen Schlüssel zu erhalten (aktuell: `_K1=44`, `X-Build-Tag=81`,
`VersionInfo.BUILD_TAG=245`, `RuntimeTag.SESSION_TAG=197` →
`_deriveKey(...) & 0xFF = 145`):
- `_K1` steht im Bytecode von `Main$EncryptedClassLoader`
- `X-Build-Tag` steht im JAR-Manifest (`unzip -p vault.jar META-INF/MANIFEST.MF`)
- `VersionInfo.BUILD_TAG` steht in einer eigenen, unscheinbar benannten Klasse
- `RuntimeTag.SESSION_TAG` steht in einer weiteren, unscheinbar benannten Klasse

**Wichtig:** Der Java-Compiler faltet reine Compile-Zeit-Konstanten
(`static final int`) automatisch zusammen, wenn sie direkt verrechnet
werden — bei einem naiven XOR aus nur Literalen verschmelzen mehrere
Fragmente unbemerkt zu einer einzigen Zahl im Bytecode. Die
`_deriveKey()`-Indirektion über einen echten Methodenaufruf verhindert das:
alle vier Operanden bleiben als eigenständige `invokestatic`/Literal-Werte
im Bytecode sichtbar, keiner verschwindet durch Compiler-Optimierung.
`(byte) (x ^ key)` in `_d()`/`_secret()` verwendet nur das niedrigste Byte
von `key` — beim manuellen Nachrechnen reicht `key & 0xFF`.

**Die Entschlüsselungsfunktion selbst** (Byte-Tausch + XOR, unverändert):
```java
private static byte[] _d(byte[] data, int key) {
    byte[] r = data.clone();
    int n = r.length;
    for (int i = 0; i < n / 2; i++) {
        byte a = r[i];
        byte b = r[n - 1 - i];
        r[i]         = (byte) ((b ^ key) & 0xFF);
        r[n - 1 - i] = (byte) ((a ^ key) & 0xFF);
    }
    if (n % 2 == 1) r[n / 2] = (byte) ((r[n / 2] ^ key) & 0xFF);
    return r;
}
```

Algorithmus: Byte-Paare von außen nach innen tauschen, jeden Byte mit dem
zusammengesetzten Schlüssel XOR'n. Die Operation ist **selbstinvers** —
`_d(_d(x, k), k) == x`.

---

## Schritt 3: Crypto.class entschlüsseln

Der Schlüssel muss zuerst aus den vier Anteilen aus Schritt 2 rekonstruiert
werden (`_deriveKey(_K1, X-Build-Tag, VersionInfo.BUILD_TAG,
RuntimeTag.SESSION_TAG) & 0xFF`), dann:

```python
import hashlib, struct

def derive_key(a, b, c, d):
    buf = struct.pack(">iiii", a, b, c, d)
    h = hashlib.sha256(buf).digest()
    return struct.unpack(">i", h[:4])[0]

key = derive_key(44, 81, 245, 197) & 0xFF   # aktuell: 145

with open('de/dhbw/ctf/Crypto.class.encrypted', 'rb') as f:
    data = bytearray(f.read())

n = len(data)
for i in range(n // 2):
    a, b = data[i], data[n - 1 - i]
    data[i]         = (b ^ key) & 0xFF
    data[n - 1 - i] = (a ^ key) & 0xFF

if n % 2 == 1:
    data[n // 2] = (data[n // 2] ^ key) & 0xFF

with open('/tmp/Crypto.class', 'wb') as f:
    f.write(data)
```

Prüfen:
```bash
xxd /tmp/Crypto.class | head -1
# → cafebabe ...  ✓
```

---

## Schritt 4: Crypto.class analysieren

```bash
java -jar cfr.jar /tmp/Crypto.class
```

`Crypto.class` ist ebenfalls mit ProGuard obfuskiert (private Felder/Methoden
umbenannt, `LineNumberTable` entfernt). Die sechs öffentlichen Methoden
(`a`–`f`) sind unverändert vorhanden — sie müssen es sein, da `Main` sie per
Reflection mit Namen aufruft. Sichtbar im dekompilierten Code (Namen hier zur
Lesbarkeit wie im Source benannt):

```java
// Secret ist fest in der JAR eingebettet (nicht mehr aus VAULT_SECRET),
// XOR-kodiert mit einem aus vier Fragmenten (_deriveKey, siehe Schritt 2)
// zusammengesetzten Schlüssel:
private static final byte[] _S = { ... };

private static byte[] _secret() {
    int key = Main.EncryptedClassLoader._deriveKey(
            _S1, _secretManifestTag(), Main.EncryptedClassLoader._key(), RuntimeTag.TRACE_TAG);
    byte[] r = new byte[_S.length];
    for (int i = 0; i < _S.length; i++) r[i] = (byte) (_S[i] ^ key);
    return r;
}

// Secret-Länge verschleiert: Integer.rotateRight(Integer.rotateLeft(n, 3), 3) = n
public static int f() { return Integer.rotateRight(Integer.rotateLeft(_secret().length, 3), 3); }

// MAC-Berechnung: SHA256(secret_bytes || message_bytes)
public static String a(byte[] m) {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hash = md.digest(concat(_secret(), m));
    ...
}

// Rollen-Parsing: letztes "user="-Feld gewinnt
public static String b(byte[] m) {
    for (String p : new String(m, UTF_8).split("&")) {
        if (p.startsWith("user=")) role = p.substring(5);
    }
    ...
}

// Flag-Entschlüsselung: Keystream aus SHA256(secret || "vault-flag")
public static String c() {
    byte[] ks = _keystream(_F.length);   // wiederholtes SHA-256(block)
    ...
}
```

**Die Secret-Länge** ermitteln — `f()` per Reflection aufrufen, oder direkt
über die im nächsten Absatz beschriebene vollständige Secret-Extraktion.

**Die Schwachstelle:** `SHA256(secret || message)` statt HMAC.

Dies ist anfällig für einen **Hash-Length-Extension-Angriff**: Wer den Hash von
`secret || message` kennt, kennt den internen SHA-256-Zustand nach diesem Input und
kann `|| extra` anhängen ohne das Secret zu kennen.

Außerdem sichtbar: `extractUser()` (Methode `b`) gibt das **letzte** `user=`-Feld
zurück. D.h. `user=guest[padding]&user=admin` → Nutzer `admin`.

### Alternativer Weg: Secret direkt extrahieren

Da das Secret fest im JAR liegt (siehe oben), ist es **grundsätzlich
extrahierbar** — das ist bei einer rein lokal, offline lauffähigen JAR ohne
Servergrenze unvermeidbar (das Programm muss das Secret selbst lesen können,
also muss es irgendwo in der Datei stehen, egal wie stark verschleiert).

`_S1`, `X-Secret-Tag` (Manifest), `Main.EncryptedClassLoader._key()` und
`RuntimeTag.TRACE_TAG` liefern die vier Fragmente für den Secret-Schlüssel
(analog zu Schritt 3, `_deriveKey` statt XOR). Damit lässt sich `_S`
entschlüsseln und man erhält das Secret im Klartext — z.B.:

```python
key = derive_key(_S1, x_secret_tag, loader_key, runtime_trace_tag) & 0xFF
secret = bytes(b ^ key for b in S)
```

Mit dem Secret in der Hand kann man **ohne Length-Extension** einen eigenen,
regulär berechneten `user=admin`-MAC bauen:

```python
import hashlib
msg = b"user=admin"
mac = hashlib.sha256(secret + msg).hexdigest()
```

```bash
java -jar vault.jar 757365723d61646d696e <mac>
# → Access granted. FLAG{...}
```

Dieser Weg umgeht den eigentlichen Kryptoangriff vollständig. Die Härtung
(Hash-basierte Schlüsselableitung statt XOR, vier statt drei Fragmente,
zusätzliche Klasse `RuntimeTag`, Flag-Entschlüsselung an das Secret
gebunden statt fest kodiert) erhöht den dafür nötigen Aufwand deutlich
gegenüber einer trivialen XOR-Verschleierung, macht ihn aber nicht
unmöglich — er bleibt ein gültiger, nur aufwändigerer Lösungsweg neben dem
Hash-Length-Extension-Angriff.

---

## Schritt 5: Angriff ausführen

### Option A — mit hlextend

```bash
pip install hlextend
```

```python
import hlextend

known_mac     = "24af60bad400dee40dee5745738a122f2af594f7680d1a63002043389f8c7a6b"
known_message = bytes.fromhex("757365723d6775657374")  # user=guest
secret_length = 8          # aus f() oder Bytecode-Analyse
append_data   = b"&user=admin"

sha = hlextend.new('sha256')
new_message, new_mac = sha.extend(append_data, known_message, secret_length, known_mac)

print("Forged message (hex):", new_message.hex())
print("Forged MAC:          ", new_mac)
```

### Option B — manuell (ohne Bibliothek)

```python
import struct

def sha256_pad(n):
    p = b'\x80' + b'\x00' * ((55 - n) % 64)
    p += struct.pack('>Q', n * 8)
    return p

# ... SHA-256 compress-Funktion implementieren ...
# internen Zustand aus known_mac rekonstruieren,
# append_data mit sha256_pad(64 + len(append_data)) padden und komprimieren
```

### Übergabe an die Anwendung

Die Nachricht wird als Hex-String übergeben — Null-Bytes im Padding sind kein Problem:

```bash
java -jar vault.jar <forged_hex> <forged_mac>
```

Ausgabe:
```
Access granted.
FLAG{h4sh_l3ngth_3xt3ns10n_pwn3d}
```

---

## Warum funktioniert der Angriff?

SHA-256 verarbeitet Daten blockweise (512 Bit). Der finale Hash **ist** der interne
Zustand nach dem letzten Block. Wer den Hash von `secret || message` kennt, kennt
diesen Zustand und kann darauf aufbauend weitere Daten häshen — ohne das Secret.

Das korrekte Gegenmittel wäre **HMAC-SHA256**:
```
HMAC(key, msg) = SHA256(key XOR opad || SHA256(key XOR ipad || msg))
```
Bei HMAC ist der interne Zustand nach dem inneren Hash nicht der Output — Length-Extension
ist damit nicht möglich.

---

## Tools und Schritte auf einen Blick

| Schritt | Tool | Zweck |
|---|---|---|
| 1 | `java -jar vault.jar --sample` | Ausgangsdaten beschaffen (keine Env-Var nötig) |
| 2 | `jar xf vault.jar` + `javap -p` / CFR | Entschlüsselungslogik + vier Schlüsselfragmente aus `Main.class`, `VersionInfo`/`RuntimeTag` und `MANIFEST.MF` lesen (ProGuard-obfuskiert — Namen sind bedeutungslos, Struktur bleibt lesbar) |
| 3 | Python-Script | `Crypto.class.encrypted` entschlüsseln (Schlüssel per SHA-256 aus 4 Fragmenten ableiten, `_deriveKey` nachbauen) |
| 4 | CFR / javap -p | Schwachstelle `SHA256(secret\|\|msg)` + Secret-Länge ermitteln (auch hier: öffentliche Methoden `a`–`f` bleiben benannt, Rest ist obfuskiert). Alternativ: Secret vollständig extrahieren (siehe oben) |
| 5 | Python + `hlextend` | Hash verlängern, Flag holen |

## Build-Prozess (für Nachvollziehbarkeit)

`build.sh` läuft in 8 Schritten: Zuerst berechnet ein Python-Vorverarbeitungsschritt
das eingebettete Secret (`_S` in `Crypto.java`) und die keystream-verschlüsselte
Flag (`_F`) neu, abhängig vom aktuellen Secret-Klartext (nur im Build-Skript,
nicht ausgeliefert) und den Schlüsselfragmenten. Danach kompiliert `javac`
`Main`, `VersionInfo`, `RuntimeTag` und `Crypto` in einem Durchgang (`Crypto`
referenziert `Main.EncryptedClassLoader._key()`/`_deriveKey()` jetzt direkt).
`main.pro` obfuskiert zuerst Main/VersionInfo/RuntimeTag und schreibt ein
ProGuard-Mapping heraus, das `crypto.pro` per `-applymapping` übernimmt —
sonst würde `Crypto.class` weiterhin die unobfuskierten Klassennamen
referenzieren. Die "Verschlüsselung" von `Crypto.class` (Byte-Reverse + XOR)
läuft danach mit dem tatsächlichen, Hash-abgeleiteten Loader-Key (nicht mehr
einem festen Literal) auf dem bereits obfuskierten ProGuard-Output. Details
siehe `build.sh` und die Kommentare in `proguard/*.pro`.
