# RE-Dokumentation: VaultAccess

## Ziel

Die Anwendung `vault.jar` prüft einen Token der Form `message-hex + MAC`. Ziel ist es,
einen Token zu fälschen der `user=admin` enthält und von der Anwendung als gültig
akzeptiert wird — **ohne das Secret zu kennen**.

---

## Schritt 1: JAR erkunden

```bash
VAULT_SECRET=s3cr3t\!X java -jar vault.jar --sample
```

Ausgabe:
```
Sample message (hex) : 757365723d6775657374
Sample MAC           : 24af60bad400dee40dee5745738a122f2af594f7680d1a63002043389f8c7a6b
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

**Der Schlüssel besteht aus drei getrennt liegenden Anteilen** (nicht mehr
einer einzelnen Konstante):
```java
private static final int _K1 = 0x2C;                  // in Main.class

private static int _key() {
    int k2 = _manifestTag();                           // aus MANIFEST.MF: X-Build-Tag
    int k3 = VersionInfo.BUILD_TAG;                     // aus VersionInfo.class
    return _K1 ^ k2 ^ k3;
}
```
Alle drei Fundstellen müssen zusammengeführt werden, um den vollständigen
Schlüssel (`136 = 0x88`) zu erhalten:
- `_K1` steht im Bytecode von `Main$EncryptedClassLoader`
- `X-Build-Tag` steht im JAR-Manifest (`unzip -p vault.jar META-INF/MANIFEST.MF`)
- `VersionInfo.BUILD_TAG` steht in einer eigenen, unscheinbar benannten Klasse

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

Der Schlüssel `0x88` muss zuerst aus den drei Anteilen aus Schritt 2
rekonstruiert werden (`_K1 ^ X-Build-Tag ^ VersionInfo.BUILD_TAG`), dann:

```python
with open('de/dhbw/ctf/Crypto.class.encrypted', 'rb') as f:
    data = bytearray(f.read())

n = len(data)
for i in range(n // 2):
    a, b = data[i], data[n - 1 - i]
    data[i]         = (b ^ 0x88) & 0xFF
    data[n - 1 - i] = (a ^ 0x88) & 0xFF

if n % 2 == 1:
    data[n // 2] = (data[n // 2] ^ 0x88) & 0xFF

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
// Secret kommt aus der Umgebungsvariable VAULT_SECRET — nicht im JAR gespeichert
private static final String _ENV = System.getenv("VAULT_SECRET");

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
```

**Die Secret-Länge** ermitteln — `f()` per Reflection aufrufen:
```python
# Oder: aus dem Bytecode ablesen — Math.exp(X) wobei X die Länge ist
# Bei s3cr3t!X: Länge = 8
```

**Die Schwachstelle:** `SHA256(secret || message)` statt HMAC.

Dies ist anfällig für einen **Hash-Length-Extension-Angriff**: Wer den Hash von
`secret || message` kennt, kennt den internen SHA-256-Zustand nach diesem Input und
kann `|| extra` anhängen ohne das Secret zu kennen.

Außerdem sichtbar: `extractUser()` (Methode `b`) gibt das **letzte** `user=`-Feld
zurück. D.h. `user=guest[padding]&user=admin` → Nutzer `admin`.

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
VAULT_SECRET=s3cr3t\!X java -jar vault.jar <forged_hex> <forged_mac>
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
| 1 | `java -jar vault.jar --sample` | Ausgangsdaten beschaffen |
| 2 | `jar xf vault.jar` + `javap -p` / CFR | Entschlüsselungslogik + Schlüsselfragmente aus `Main.class` und `MANIFEST.MF` lesen (ProGuard-obfuskiert — Namen sind bedeutungslos, Struktur bleibt lesbar) |
| 3 | Python-Script | `Crypto.class.encrypted` entschlüsseln (Schlüssel aus 3 Fragmenten zusammensetzen) |
| 4 | CFR / javap -p | Schwachstelle `SHA256(secret\|\|msg)` + Secret-Länge ermitteln (auch hier: öffentliche Methoden `a`–`f` bleiben benannt, Rest ist obfuskiert) |
| 5 | Python + `hlextend` | Hash verlängern, Flag holen |

## Build-Prozess (für Nachvollziehbarkeit)

Seit der Härtung läuft `build.sh` in 7 statt 4 Schritten: Nach dem Kompilieren
von `Crypto.java` bzw. `Main.java`/`VersionInfo.java` läuft jeweils ein
ProGuard-Durchlauf (`proguard/crypto.pro`, `proguard/main.pro`), der private
Bezeichner umbenennt und Debug-Infos entfernt — die öffentliche Struktur
(Einstiegspunkt `main()`, die sechs reflektiv aufgerufenen `Crypto`-Methoden)
bleibt zwingend erhalten. Die XOR-Verschlüsselung von `Crypto.class` läuft
danach auf dem bereits obfuskierten ProGuard-Output. Details siehe
`build.sh` und die Kommentare in `proguard/*.pro`.
