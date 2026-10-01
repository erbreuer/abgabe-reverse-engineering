# Dokumentation

Wo liegt das Sicherheitsproblem der Anwendung
`VaultAccess` und wie kann man es ausnutzen? Ziel ist ein gültiger Admin-Token,
der das Flag freischaltet, ohne das interne Secret zu kennen.

## Wo liegt das Sicherheitsproblem?

Die Anwendung berechnet den MAC einer Nachricht als

    MAC = SHA256(secret || message)

also indem sie ein geheimes Secret **vor** die Nachricht hängt und davon den
SHA-256-Hash bildet (siehe `Crypto.a()` in Crypto.java). Das ist unsicher, weil sich dieser MAC durch einen **Hash-Length-Extension-Angriff** ohne Kenntnis des Secrets erweitern lässt.

SHA-256 verarbeitet die Eingabe blockweise. Der ausgegebene Hash enthält dabei den internen Zustand nach der bisherigen Eingabe. Wer einen gültigen Hash und die
Länge der gehashten Daten kennt, kann den Hash einfach **weiterrechnen**
und beliebige Bytes anhängen, ohne das Secret zu kennen. 

**Voraussetzungen für den Angriff:**

1. `--sample` liefert eine gültige Nachricht (`user=guest`) mitsamt gültigem MAC - das dient als Ausgangspunkt beim Angriff.
2. Die Rollenprüfung (`Crypto.b()`) nimmt bei mehreren `user=`-Feldern das
   **letzte**. Hängt man `&user=admin` an, wird `user=guest` dadurch überschrieben.

Die Verschleierung (verschlüsselte Klasse, ProGuard-Umbenennung, verteilter
Schlüssel, Decoy-Klassen, mehrere XOR-Kandidaten pro Methodennamen, eine
zusätzliche "Integritätsprüfung") erschwert das Lesen des Codes, nicht aber
den Angriff selbst. Die scheinbare zweite Prüfung `Crypto.g()` läuft zwar
nach der MAC-Prüfung, vergleicht aber nur Länge/Zeichensatz des MAC gegen
sich selbst und niemals gegen das Secret. Sie kann für jede Eingabe, die
die MAC-Prüfung bereits bestanden hat, nie fehlschlagen.

## Wie kann man dies reversen?

Um die Anwendung zu reversen und das Flag zu erhalten, hängt man an die Beispielnachricht aus
`--sample`  `&user=admin` an und rechnet den MAC dafür per Length-Extension
gültig weiter.

Dafür sind drei Dinge nötig:

1. das Beispielpaar (Nachricht + MAC) aus `--sample`,
2. die Länge des Secrets, sie steckt im Bytecode der Klasse
   `Crypto.class`, die im JAR verschlüsselt vorliegt und zuerst entschlüsselt
   werden muss,
3. der Length-Extension-Angriff selbst, der aus 1. und 2. die gefälschte
   Nachricht samt gültigem MAC erzeugt.


## Verwendete Skripte / Tools

- **JDK 21+** - `jar` zum Entpacken des JAR, `javap` zum Lesen des Bytecodes
- **Python 3** - für die beiden Skripte (Entschlüsseln der
  Klasse, Length-Extension-Angriff). Standardbibliothek (`hashlib`,
  `struct`)
- Ein Decompiler für lesbareren Java-Code
  anstelle des reinen `javap`-Bytecodes
- Genaue Skripte: siehe Anleitung

## Anleitung — notwendige Schritte

### Schritt 1 — Beispielpaar holen

    $ java -jar vault.jar --sample
    Sample message (hex) : 757365723d6775657374
    Sample MAC           : 2c38fd78f54e6c582f5b87421920e2501405c1d11a7c77eabd537409d18ce938

`757365723d6775657374` ist `user=guest` in Hex. <br> Der MAC ist
`SHA256(secret || "user=guest")`.

### Schritt 2 — Secret-Länge aus dem JAR ablesen

Der Angriff braucht die Länge von `secret || message`(die Nachricht ist 10
Bytes lang), die Secret-Länge steht im Bytecode. <br>Dafür muss zuerst die
verschlüsselte Klasse entschlüsselt werden.

JAR entpacken:

    jar xf vault.jar

`Main.class` lädt die eigentliche Logik nicht per normalem Import, sondern
reflektiv über einen eigenen `ClassLoader` (`Main$a` im entpackten JAR). Der
Klassenname und alle Methodennamen, die dabei per `getMethod(...)`
aufgelöst werden, stehen nicht im Klartext im Bytecode, sondern als
XOR-kodierte Byte-Arrays mit mehreren Kandidaten-Schlüsseln pro Name
(`javap` zeigt für den Klassennamen z.B. drei Versuche mit den Schlüsseln
`0x71`, `0x27` und `0x5A`/`0x3C` auf denselben bzw. verschiedenen Rohbytes).<div>Zwei der Klassen-Kandidaten (Schlüssel `0x27`) decodieren zu echten,
ladbaren Klassen im JAR (`CacheLoader`, `ConfigStore`). Allerdings besitzen sie
nicht die Methode `a(byte[])`, mit der die Anwendung prüft, ob sie die
richtige Klasse geladen hat. Nur der Kandidat mit Schlüssel `0x5A` ergibt
`de.dhbw.ctf.Crypto` und liefert eine Klasse, auf der alle erwarteten
Methoden existieren. Diese Kandidatenliste muss man einmal durchgehen, um
zu wissen, welche Klasse tatsächlich geladen wird - am Angriff selbst
ändert das nichts.

Die Logik steckt in `de/dhbw/ctf/Crypto.class.encrypted`. Diese Datei wird zur
Laufzeit entschlüsselt: <br>Die Anwendung kehrt die Bytefolge um und XORt jedes
Byte mit einem Schlüssel. Der Schlüssel entsteht per SHA-256 aus vier Werten,
die alle im JAR stehen - einer Konstante in `Main` (`_K1 = 0x2C`), dem
Manifest-Attribut `X-Build-Tag = 81` (`cat META-INF/MANIFEST.MF`),
`VersionInfo.BUILD_TAG = 245` und `RuntimeTag.SESSION_TAG = 197` (beide per
`javap -p -c` bzw. im Decompiler ablesbar).

Dieses Python-Skript rechnet den Schlüssel nach und entschlüsselt die Klasse:

```python
import hashlib, struct

def derive_key(a, b, c, d):
    buf = struct.pack(">iiii", a, b, c, d)
    return struct.unpack(">i", hashlib.sha256(buf).digest()[:4])[0]

loader_key = derive_key(0x2C, 81, 245, 197) & 0xFF

data = bytearray(open("de/dhbw/ctf/Crypto.class.encrypted", "rb").read())
n = len(data)
for i in range(n // 2):
    a, b = data[i], data[n - 1 - i]
    data[i]         = (b ^ loader_key) & 0xFF
    data[n - 1 - i] = (a ^ loader_key) & 0xFF
if n % 2 == 1:
    data[n // 2] = (data[n // 2] ^ loader_key) & 0xFF

open("de/dhbw/ctf/Crypto.class", "wb").write(data)
print("magic:", data[:4].hex())   # cafebabe = gültige .class-Datei
```

Gibt es `cafebabe` aus, hat die Entschlüsselung funktioniert. 

<br>**Als nächstes den Bytecode
lesen:**

    javap -p -c -classpath . de.dhbw.ctf.Crypto

Im statischen Initialisierer wird das Secret-Array angelegt, direkt vor
`newarray byte` steht seine Länge:

    bipush  36
    newarray byte

Das Secret ist also **36 Bytes** lang (Es wird nur die Länge gebraucht, nicht der
Inhalt).

Das Secret selbst wird ebenfalls erst zur Laufzeit XOR-entschlüsselt, mit
einem weiteren SHA-256-abgeleiteten Schlüssel aus vier Fragmenten (Konstante
`111`, Manifest-Attribut `X-Secret-Tag = 52`, der bereits oben berechnete
Loader-Schlüssel sowie `RuntimeTag.TRACE_TAG = 88`). Für den eigentlichen
Length-Extension-Angriff ist das irrelevant: die Secret-Länge reicht,
das Secret selbst muss nie entschlüsselt werden. Möchte man es trotzdem
entschlüsseln, (siehe Weg B in `KI-EINSCHAETZUNG.md`)
dann kann man denselben Schlüssel wie beim Loader per `_deriveKey(111, 52,
loader_key, 88)` nachrechnen und auf das Byte-Array XOR-verknüpfen.

### Schritt 3 — Admin-Token fälschen

Es ist nun alles Nötige bekannt:
<br> Die Originalnachricht und ihr MAC (Schritt 1)
und die Secret-Länge 36 (Schritt 2). 
<br> 

Dieses Python-Skript interpretiert den
bekannten MAC als internen SHA-256-Zustand und rechnet den Hash über das
angehängte `&user=admin` weiter:

```python
import struct

orig_msg   = bytes.fromhex("757365723d6775657374")   # user=guest
orig_mac   = "2c38fd78f54e6c582f5b87421920e2501405c1d11a7c77eabd537409d18ce938"
secret_len = 36
append     = b"&user=admin"

def sha256_pad(msglen):
    pad  = b"\x80"
    pad += b"\x00" * ((56 - (msglen + 1) % 64) % 64)
    pad += struct.pack(">Q", msglen * 8)
    return pad

_K = [
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]

def rotr(x, n): return ((x >> n) | (x << (32 - n))) & 0xffffffff

def sha256_from_state(state, blocks):
    h = list(state)
    for off in range(0, len(blocks), 64):
        w = list(struct.unpack(">16L", blocks[off:off+64])) + [0]*48
        for i in range(16, 64):
            s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3)
            s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffff
        a,b,c,d,e,f,g,hh = h
        for i in range(64):
            S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25)
            ch = (e & f) ^ (~e & g)
            t1 = (hh + S1 + ch + _K[i] + w[i]) & 0xffffffff
            S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) & 0xffffffff
            hh=g; g=f; f=e; e=(d+t1)&0xffffffff; d=c; c=b; b=a; a=(t1+t2)&0xffffffff
        h = [(x + y) & 0xffffffff for x, y in zip(h, [a,b,c,d,e,f,g,hh])]
    return "".join(f"{x:08x}" for x in h)

glue       = sha256_pad(secret_len + len(orig_msg))
forged_msg = orig_msg + glue + append
total_len  = secret_len + len(forged_msg)
state      = struct.unpack(">8L", bytes.fromhex(orig_mac))
forged_mac = sha256_from_state(state, append + sha256_pad(total_len))

print("forged message (hex):", forged_msg.hex())
print("forged MAC          :", forged_mac)
```

Ausgabe:

    forged message (hex): 757365723d677565737480000000000000000000000000000000017026757365723d61646d696e
    forged MAC          : 096f106b8a3a2977d01be4f65ba4cab6cde45f3360d80a6073be2fdde0ea6fd8

Die gefälschte Nachricht ist `user=guest` + SHA-256-Padding + `&user=admin`.

### Schritt 4 — Flag abholen

Nachricht und MAC an die Anwendung übergeben:

    $ java -jar vault.jar \
        757365723d677565737480000000000000000000000000000000017026757365723d61646d696e \
        096f106b8a3a2977d01be4f65ba4cab6cde45f3360d80a6073be2fdde0ea6fd8
    Access granted.
    FLAG{h4sh_l3ngth_3xt3ns10n_pwn3d}

Die MAC-Prüfung akzeptiert die verlängerte Nachricht, weil der MAC korrekt
weitergerechnet wurde. Danach läuft noch `Crypto.g()` (Integritätsprüfung),
die aber nur Länge und Hex-Zeichensatz des eingereichten MAC gegen sich
selbst prüft und für jeden bereits akzeptierten MAC automatisch `true`
liefert (sie greift hier nicht ein). Erst danach nimmt die Rollenprüfung das
letzte `user=`-Feld (`admin`) und gibt das Flag frei.


### Wie man diesen Angriff verhindern könnte:
Die richtige Gegenmaßnahme wäre **HMAC-SHA256** statt
`SHA256(secret || message)`, damit wäre die Hash-Length-Extension nicht möglich.
Die zusätzliche Prüfung `Crypto.g()` ist dafür kein Ersatz: Sie prüft nur
Form (Länge, Hex-Zeichensatz) des bereits akzeptierten MAC, nie seinen Inhalt
gegen das Secret, und wäre selbst mit einer echten Prüfung gegen eine
Length-Extension wirkungslos, solange die eigentliche MAC-Berechnung
weiterhin `SHA256(secret || message)` ist.
