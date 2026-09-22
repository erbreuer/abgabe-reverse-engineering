# Reverse Engineering – secure24v2 (in Bearbeitung)

**Gegeben:** `secure24v2.jar`, `key` (64 MB), `Text.encrypted`  
**Ziel:** `Text.encrypted` entschlüsseln  
**Status:** Algorithmus vollständig verstanden, Entschlüsselung noch offen

---

## Schritt 1: JAR erkunden

```bash
jar tf secure24v2.jar
```

Relevante Funde:
```
de/dhbw/wi/secure24/Main.class
de/dhbw/wi/secure24/Main$EncrytedClassesClassLoader.class
de/dhbw/wi/Crypto.class.encrypted       ← verschlüsselte Klasse im JAR!
```

---

## Schritt 2: Verschlüsselte Klasse entpacken und descramble-Algorithmus lesen

```bash
jar xf secure24v2.jar
javap -c -p "de/dhbw/wi/secure24/Main\$EncrytedClassesClassLoader.class"
```

Der `ClassLoader` lädt `Crypto.class.encrypted` zur Laufzeit und entschlüsselt sie mit `descramble()`.

**descramble-Algorithmus** (aus Bytecode):
```python
# Tauscht Byte-Paare von außen nach innen und XOR'd jeden Byte mit 136
for i in range(len(data) // 2):
    a = data[i]
    b = data[len(data) - 1 - i]
    data[i]                  = (b ^ 136) & 0xFF
    data[len(data) - 1 - i]  = (a ^ 136) & 0xFF

# Mittleres Byte (bei ungerader Länge)
if len(data) % 2 == 1:
    mid = len(data) // 2
    data[mid] = (data[mid] ^ 136) & 0xFF
```

**Crypto.class entschlüsseln:**
```python
with open('de/dhbw/wi/Crypto.class.encrypted', 'rb') as f:
    data = bytearray(f.read())

n = len(data)
for i in range(n // 2):
    a, b = data[i], data[n - 1 - i]
    data[i]         = (b ^ 136) & 0xFF
    data[n - 1 - i] = (a ^ 136) & 0xFF

if n % 2 == 1:
    mid = n // 2
    data[mid] = (data[mid] ^ 136) & 0xFF

with open('/tmp/Crypto.class', 'wb') as f:
    f.write(data)
# Magic: cafebabe ✓
```

---

## Schritt 3: Crypto.class analysieren

```bash
javap -c -p /tmp/Crypto.class
```

Signatur der Hauptmethode:
```java
public static void process(String password,
                            BufferedInputStream input,
                            BufferedOutputStream output,
                            RandomAccessFile keyFile,
                            byte[] salt)
```

**Vollständiger Algorithmus** (aus Bytecode rekonstruiert):

```java
// 1. PRNG mit salt initialisieren
SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
rng.setSeed(salt);

// 2. Offset aus Passwort berechnen
long offset = Math.abs(password.hashCode()) % keyFile.length();
keyFile.seek(offset);

// 3. Encrypt/Decrypt Loop (4096-Byte-Blöcke)
while ((bytesRead = input.read(inputBlock)) != -1) {
    rng.nextBytes(prngBlock);          // PRNG-Block generieren
    keyFile.readFully(keyBlock);       // Key-Block lesen (mit wrap-around)
    for (int i = 0; i < bytesRead; i++) {
        output.write(inputBlock[i] ^ prngBlock[i] ^ keyBlock[i]);
    }
}
```

**Dateiformat (Encrypt-Modus):**
```
[ 8 Byte Salt (= longToBytes(new Date().getTime())) ]
[ verschlüsselte Nutzdaten ]
```

**Dateiformat (Decrypt-Modus):**
```
[ 8 Byte Salt lesen ]
[ Rest = Ciphertext entschlüsseln ]
```

---

## Schritt 4: Was bereits bekannt ist

```python
with open('Text.encrypted', 'rb') as f:
    data = f.read()

salt      = data[:8]   # 0000019afe85b229
ciphertext = data[8:]  # 1085 bytes
```

| Parameter | Wert | Status |
|---|---|---|
| Salt | `0000019afe85b229` | ✓ bekannt (aus Datei) |
| Timestamp | 2025-12-08 16:12:46 | ✓ (aus Salt berechnet) |
| Key-Datei | 64 MB (`key`) | ✓ vorhanden |
| PRNG-Ausgabe | deterministisch aus Salt | ✓ in Python reproduzierbar |
| Offset | `abs(password.hashCode()) % 67108864` | ✗ unbekannt |
| Passwort | unbekannt | ✗ |

**PRNG in Python reproduzieren** (verifiziert identisch zu Java):
```python
import subprocess

def get_prng(salt_hex, n_bytes=4096):
    # Ruft Java auf für exakt gleiche SHA1PRNG-Ausgabe
    result = subprocess.run(
        ['java', '-cp', '/tmp', 'GetPRNG', salt_hex],
        capture_output=True
    )
    return result.stdout[:n_bytes]

# GetPRNG.java (kompiliert in /tmp):
# SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
# rng.setSeed(HexFormat.of().parseHex(args[0]));
# byte[] out = new byte[4096];
# rng.nextBytes(out);
# System.out.write(out);
```

---

## Schritt 5: Known-Plaintext-Angriff (bisher gescheitert)

**Idee:** PRNG-Schicht entfernen, dann Offset im Keyfile suchen:
```python
partially[i] = ciphertext[i] ^ prng[i]   # = plaintext[i] ^ key[offset+i]
# Suche offset so dass partially ^ key[offset:] = valider Text
```

**Problem:** Keine der ~67 Millionen Positionen ergibt validen UTF-8- oder Latin-1-Text.

**Mögliche Ursachen (noch zu prüfen):**

1. **Reihenfolge im Loop falsch?** — Bytecode nochmal genau prüfen: wird `rng.nextBytes` wirklich *vor* `keyFile.readFully` aufgerufen? (Zeilen 69–95 in Crypto.class)

2. **Seek-Position nach dem ersten Block?** — Der `keyFile.seek(offset)` passiert *vor* der Schleife. Aber wird der PRNG *einmal vor der Schleife* oder *einmal pro Iteration* aufgerufen?

3. **Plaintext-Format?** — "Text" könnte ein proprietäres Format, komprimierter Inhalt, oder eine andere Kodierung sein.

4. **Wrap-around beim Key falsch implementiert?** — Bei v1 war es `(offset + i) % key_len`. Bei v2 liest der Code den Key mit `readFully` und setzt bei Dateiende manuell auf Position 0 zurück. Das Verhalten könnte subtil anders sein.

---

## Nächste Schritte

1. **Bytecode von Crypto.class nochmal genau durchgehen** — Zeilen 56–173, besonders die Reihenfolge von `nextBytes` vs `readFully` und den wrap-around-Mechanismus

2. **Passwort-Brute-Force** — `abs(hashCode(pw)) % 67108864 == offset`. Wenn der Offset bekannt wäre, könnte man rückwärts mögliche Passwörter suchen. Oder: bekannte Passwörter aus anderen Aufgaben testen (`Wirklich`, etc.)

3. **Plaintext-Format ermitteln** — Datei könnte mit XML-Header, JSON, oder einer ODP-ähnlichen Struktur beginnen

4. **JAR direkt ausführen** — Falls eine Linux-Umgebung verfügbar ist, kann das JAR mit einem bekannten Passwort und Plaintext getestet werden um die Implementierung zu verifizieren
