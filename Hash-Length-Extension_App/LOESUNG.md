# RE-Dokumentation: VaultAccess

## Ziel

Die Anwendung `vault.jar` prüft einen Token der Form `message + MAC`. Ziel ist es,
einen Token zu fälschen der `user=admin` enthält und von der Anwendung als gültig
akzeptiert wird — **ohne das Secret zu kennen**.

---

## Schritt 1: JAR erkunden

```bash
java -jar vault.jar --sample
```

Ausgabe:
```
Sample message : user=guest
Sample MAC     : 24af60bad400dee40dee5745738a122f2af594f7680d1a63002043389f8c7a6b
Secret length  : 8
```

Die Anwendung gibt direkt einen gültigen Ausgangspunkt und die Secret-Länge.

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
// SECRET "s3cr3t!X" XOR 0x42 — als byte-Array gespeichert
private static final byte[] _S = {0x31,0x71,0x21,...};

// SECRET_LENGTH = 8, verschleiert als Math.round(Math.log(Math.exp(8)))
private static final int _L = (int) Math.round(Math.log(Math.exp(8)));

// MAC-Berechnung:
public static String a(String m) {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] input = (_x(_S) + m).getBytes("UTF-8");   // SHA256(secret || message)
    ...
}
```

**Die Schwachstelle:** `SHA256(secret + message)` — `hash(secret || message)` statt HMAC.

Dies ist anfällig für einen **Hash-Length-Extension-Angriff**: Wer den Hash von
`secret || message` kennt, kennt den internen SHA-256-Zustand nach diesem Input und
kann `|| extra` anhängen ohne das Secret zu kennen.

Außerdem sichtbar: `extractRole()` (Methode `b`) gibt das **letzte** `user=`-Feld
zurück. D.h. `user=guest[padding]&user=admin` → Rolle `admin`.

---

## Schritt 5: Angriff ausführen

### Voraussetzung

```bash
pip install hlextend
```

### Script

```python
import hlextend, binascii

known_mac     = "24af60bad400dee40dee5745738a122f2af594f7680d1a63002043389f8c7a6b"
known_message = b"user=guest"
secret_length = 8          # aus --sample, bestätigt durch Crypto.class
append_data   = b"&user=admin"

sha = hlextend.new('sha256')
new_message, new_mac = sha.extend(append_data, known_message, secret_length, known_mac)

print("Neue Nachricht (hex):", new_message.hex())
print("Neuer MAC:           ", new_mac)
```

### Übergabe an die Anwendung

Da die Nachricht nicht-druckbare Bytes (Padding) enthält, muss sie als Byte-Literal
übergeben werden. Einfachster Weg — Python übergibt direkt:

```python
import subprocess

result = subprocess.run(
    ['java', '-jar', 'vault.jar',
     new_message.decode('latin-1'),
     new_mac],
    capture_output=True, text=True, encoding='latin-1'
)
print(result.stdout)
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
diesen Zustand und kann darauf aufbauend weitere Daten häshen.

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
| 4 | CFR / javap | Schwachstelle `SHA256(secret\|\|msg)` erkennen |
| 5 | Python + `hlextend` | Hash verlängern, Flag holen |
