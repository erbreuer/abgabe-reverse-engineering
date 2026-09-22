# Reverse Engineering – secure24v1

**Gegeben:** `secure24v1.jar`, `key`, `Message.odp.encrypted`  
**Ziel:** `Message.odp.encrypted` entschlüsseln

---

## Schritt 1: JAR erkunden

```bash
jar tf secure24v1.jar
```

Relevante Funde:
```
de/dhbw/secure24/Main.class
```

Nur eine einzige Klasse — kein Decompiler nötig, `javap` reicht.

---

## Schritt 2: Bytecode lesen

```bash
javap -c -p de/dhbw/secure24/Main.class
```

Aus dem Bytecode lässt sich der Algorithmus direkt ablesen.

**Aufruf-Signatur** (aus dem Bytecode-Kommentar):
```
secure24 <mode:enc|dec> <password> <key_file> <input_file> <output_file>
```

**Offset-Berechnung** (Zeilen 373–402):
```
// Kommentare aus javap:
invokevirtual #109   // String.hashCode()
invokestatic  #122   // Math.abs(int)
i2l                  // int → long
lrem                 // % keyFile.length()
lstore 11            // offset speichern
...
invokevirtual #131   // RandomAccessFile.seek(offset)
```

In Java:
```java
long offset = Math.abs(password.hashCode()) % keyFile.length();
keyFile.seek(offset);
```

**Verschlüsselungs-Loop** (Zeilen 492–524):
```
baload   // input[i]
baload   // key[i]
ixor     // XOR
write    // output schreiben
```

In Java:
```java
output[i] = input[i] ^ key[i];
```

**Key liest in 4096-Byte-Blöcken, mit Wrap-around** (Zeilen 419–489):
```
invokevirtual #139   // getFilePointer()
ldc2_w 4096l         // + 4096
invokevirtual #142   // length()
lcmp                 // Vergleich: noch Platz?
ifge → wrap-around   // wenn Dateiende: seek(0) und Rest lesen
```

### Gesamter Algorithmus

```python
offset = abs(password.hashCode()) % len(key_data)
output[i] = input[i] ^ key_data[(offset + i) % len(key_data)]
```

---

## Schritt 3: Schwachstelle erkennen

- Der Schlüssel (`key`) ist eine **statische Datei** (16 MB, unveränderlich)
- Das einzig Geheime ist der **Offset** (Wertebereich: `0` bis `16.777.215`)
- Der Offset hängt vom Passwort ab — aber das Passwort wird **nicht** gebraucht, wenn man den Offset direkt ermitteln kann

---

## Schritt 4: Known-Plaintext-Angriff

Der Dateiname `Message.odp.encrypted` verrät das Format.  
ODP-Dateien sind ZIP-Archive und beginnen **immer** mit demselben 4-Byte-Magic:

```
50 4B 03 04   (= "PK\x03\x04")
```

Ersten 4 verschlüsselten Bytes prüfen:
```bash
xxd Message.odp.encrypted | head -1
# d1 eb 54 8c ...
```

Benötigte Key-Bytes am Offset ableiten:
```
key[offset+i] = encrypted[i] XOR plaintext[i]

d1 XOR 50 = 81
eb XOR 4b = a0
54 XOR 03 = 57
8c XOR 04 = 88

→ gesuchte Sequenz im Key: 81 a0 57 88
```

---

## Schritt 5: Offset im Keyfile suchen

```python
with open('Message.odp.encrypted', 'rb') as f:
    enc = f.read(4)
with open('key', 'rb') as f:
    key = f.read()

zip_magic = bytes([0x50, 0x4B, 0x03, 0x04])
needed = bytes([e ^ p for e, p in zip(enc, zip_magic)])  # 81 a0 57 88

offset = key.find(needed)
print(hex(offset))  # → 0xb15ce3
```

Genau **ein Treffer** → Offset eindeutig.

---

## Schritt 6: Datei entschlüsseln

```python
with open('Message.odp.encrypted', 'rb') as f:
    enc_data = f.read()
with open('key', 'rb') as f:
    key_data = f.read()

offset = 0xb15ce3
key_len = len(key_data)

result = bytearray()
for i in range(len(enc_data)):
    result.append(enc_data[i] ^ key_data[(offset + i) % key_len])

with open('Message.odp', 'wb') as f:
    f.write(result)
```

Ergebnis prüfen:
```bash
python3 -c "
import zipfile
with zipfile.ZipFile('Message.odp') as z:
    import re
    content = z.read('content.xml').decode()
    for t in re.findall(r'<text:p[^>]*>(.*?)</text:p>', content):
        clean = re.sub(r'<[^>]+>', '', t).strip()
        if clean: print(clean)
"
```

**Ergebnis:** *„Frohe Weihnachten und einen erfolgreichen Start ins Jahr 2026 — Michael Eichberg"*

---

## Java `hashCode()` — Bonus

Falls das Passwort doch gesucht wird, lässt sich der Offset zurückrechnen:

```java
// Java String.hashCode():
// h = s[0]*31^(n-1) + s[1]*31^(n-2) + ... + s[n-1]
```

```python
def java_hashcode(s):
    h = 0
    for c in s:
        h = (h * 31 + ord(c)) & 0xFFFFFFFF
    if h >= 0x80000000:
        h -= 0x100000000
    return h

# Prüfen ob ein Passwort den gefundenen Offset liefert:
# abs(java_hashcode(password)) % 16777216 == 0xb15ce3
```

Für diese Aufgabe war das **nicht notwendig** — der Offset ließ sich direkt aus dem Known-Plaintext ableiten.

---

## Zusammenfassung der Schwachstellen

| Schwachstelle | Erklärung |
|---|---|
| Statischer Schlüssel | `key` ist eine unveränderliche Datei — wer sie hat, kann alles entschlüsseln |
| Kleiner Geheimnisraum | Offset = 24-Bit-Wert (16M Möglichkeiten) — brute-forcebar |
| Known-Plaintext | ZIP/ODP-Magic ist bekannt → Offset in O(n) aus Keyfile lesbar |
| Kein Integritätsschutz | Kein MAC, keine Prüfsumme — Manipulation unbemerkt |
