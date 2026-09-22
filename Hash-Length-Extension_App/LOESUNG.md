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
javap -c de/dhbw/ctf/Main.class
```

Oder mit CFR:
```bash
java -jar cfr.jar de/dhbw/ctf/Main.class
```

Im Bytecode/dekompilierten Code sichtbar:

**`EncryptedClassLoader.findClass()`** lädt `Crypto.class.encrypted` und ruft `_d()` auf.

**`_d()` — die Entschlüsselungsfunktion:**
```java
private static final int _K = (int)(Math.pow(2, 3) * 17);  // = 136 = 0x88

private static byte[] _d(byte[] data) {
    byte[] r = data.clone();
    int n = r.length;
    for (int i = 0; i < n / 2; i++) {
        byte a = r[i];
        byte b = r[n - 1 - i];
        r[i]         = (byte) ((b ^ _K) & 0xFF);
        r[n - 1 - i] = (byte) ((a ^ _K) & 0xFF);
    }
    if (n % 2 == 1) r[n / 2] = (byte) ((r[n / 2] ^ _K) & 0xFF);
    return r;
}
```

Algorithmus: Byte-Paare von außen nach innen tauschen, jeden Byte mit `0x88` XOR'n.
Die Operation ist **selbstinvers** — `_d(_d(x)) == x`.

---

## Schritt 3: Crypto.class entschlüsseln

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

Sichtbar im dekompilierten Code:

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
| 2 | `jar xf vault.jar` + `javap` / CFR | `_d()`-Algorithmus aus `Main.class` lesen |
| 3 | Python-Script | `Crypto.class.encrypted` entschlüsseln |
| 4 | CFR / javap | Schwachstelle `SHA256(secret\|\|msg)` + Secret-Länge ermitteln |
| 5 | Python + `hlextend` | Hash verlängern, Flag holen |
