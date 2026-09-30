# Protokoll: VaultAccess (gehärtete Version, harden-reversing-proguard)

Ziel: aus dem frisch gebauten `vault.jar` (nach Kandidaten-Reflection +
Fake-Integritätsprüfung) blind einen gültigen Admin-Token fälschen — als ob
ich das Jar ohne jede Vorkenntnis über die gerade selbst vorgenommenen
Änderungen zum ersten Mal sehe. Umgebung: macOS, JDK 26 (SapMachine),
`jadx` via Homebrew installiert (kein cfr diesmal).

## 1. Erste Schritte / CLI erkunden

```bash
java -jar vault.jar --help
java -jar vault.jar --sample
```

Ergebnis:
- `--help` zeigt Nutzung: `java -jar vault.jar <message-hex> <mac>`.
- `--sample` liefert diesmal direkt eine gültige Beispiel-Nachricht + MAC,
  ohne Environment-Variable oder Fehlermeldung — das Secret steckt also
  komplett im JAR, nicht mehr in `VAULT_SECRET`.

```
Sample message (hex) : 757365723d6775657374
Sample MAC           : 2c38fd78f54e6c582f5b87421920e2501405c1d11a7c77eabd537409d18ce938
```

## 2. JAR entpacken

```bash
unzip -l vault.jar
```

```
META-INF/MANIFEST.MF
de/dhbw/ctf/Main$a.class
de/dhbw/ctf/Main$b.class
de/dhbw/ctf/Main.class
de/dhbw/ctf/a.class
de/dhbw/ctf/b.class
de/dhbw/ctf/Crypto.class.encrypted
```

Neu gegenüber der alten Version: eine zusätzliche innere Klasse
`Main$b.class` (bislang gab es nur `Main$a`). `Crypto.class.encrypted` ist
weiterhin ohne `.class`-Endung im JAR, also nicht direkt ladbar/dekompilierbar
— dieselbe Hürde wie vorher.

Manifest:
```
Main-Class: de.dhbw.ctf.Main
X-Build-Tag: 81
X-Secret-Tag: 52
```

## 3. Main.class, a.class, b.class dekompilieren (jadx)

```bash
jadx -d jadx-out vault.jar
```

`a.class`/`b.class` sind wie vorher schnell als Schlüssel-Fragment-Halter
identifiziert (`a`: `SESSION_TAG=197, TRACE_TAG=88`; `b`:
`NAME="VaultAccess", BUILD_TAG=245`).

`Main.class` ist deutlich dichter als beim letzten Mal. Auffällig:

- Es gibt weiterhin mehrere `byte[]`-Konstanten (`a` bis `h`), die wie
  XOR-kodierte Namen aussehen — das Muster ist noch da.
- **Neu:** zusätzlich zu diesen Rohbyte-Arrays gibt es sieben Felder vom Typ
  `Main$b[]` (z.B. `f0a`, `f1b`, ... `f6g`), die jeweils **drei** Einträge
  aus `(byte[], byte)`-Paaren enthalten — dieselben Rohbytes wie oben, aber
  mit unterschiedlichen zweiten Werten (Schlüssel-Kandidaten).
- Es gibt eine private Methode `a(Class, Main$b[], Class...)`, die über
  genau so ein Array iteriert, pro Eintrag `getMethod(decode(entry), ...)`
  probiert und beim ersten Treffer zurückgibt — mit `catch
  (NoSuchMethodException)` dazwischen. Eine zweite, fast identische Methode
  `a(ClassLoader, Main$b[])` macht dasselbe für `loadClass(...)`.
- In `main()` wird nirgends mehr direkt `crypto.getMethod("x")` aufgerufen —
  jeder Aufruf geht über diese Kandidaten-Auflösung.

**Unterschied zur alten Version:** Vorher gab es eine einzige Methode
`a(byte[])`, die mit fest `0x5A` XOR-te — ein Blick genügte, um zu wissen
"das ist der Decoder, wende ihn auf alles an". Jetzt gibt es zwar
strukturell dieselbe Idee (XOR-Decode), aber jede Aufrufstelle hat 2-3
Kandidaten mit unterschiedlichen Schlüsseln, und nur einer davon liefert
tatsächlich einen Treffer bei `getMethod`/`loadClass`. **Rein aus dem
Bytecode/Decompilat heraus ist bei den Einzelbuchstaben-Kandidaten (Methoden)
nicht mehr erkennbar, welcher Kandidat der "echte" ist** — anders als beim
Klassennamen (18 Bytes lang: dort ergibt nur ein Schlüssel ein lesbares
Ergebnis, "de.dhbw.ctf.Crypto", die anderen sind sichtbar kaputte
Zeichenfolgen). Bei den 1-Byte-Methodennamen-Kandidaten sehen dagegen alle
drei Kandidaten wie plausible einzelne ASCII-Zeichen aus ("a", "5", "]" o.ä.)
— ein rein statischer Blick auf den Quellcode lässt offen, welcher davon
tatsächlich per Reflection matcht.

Probiere das an einer Stelle konkret aus (drei Kandidaten für einen
Methodennamen, Rohbyte `59` laut Dekompilat):

```python
>>> [chr(59 ^ k) for k in (25, 90, 102)]
['"', 'a', ']']
```

Statisch nicht zu unterscheiden, welches der "richtige" Methodenname ist,
ohne die Zielklasse tatsächlich zu haben und `getMethod` wirklich
auszuführen (oder zu debuggen). Das zwingt zum nächsten Schritt: erst die
Zielklasse (`Crypto`) entschlüsseln und ihre echten Methodennamen direkt
inspizieren, statt den Aufrufer statisch zu Ende zu lesen.

## 4. Loader-Schlüssel rekonstruieren

Aus dem Dekompilat von `Main$a` (EncryptedClassLoader):

```java
public static int a() {                    // _key()
    return a(44, b(), 245, 197);            // _deriveKey(_K1, X-Build-Tag, VersionInfo.BUILD_TAG, RuntimeTag.SESSION_TAG)
}
public static int a(int a, int b, int c, int d) {   // _deriveKey
    // SHA-256(4x int big-endian), erste 4 Bytes als signed int
}
```

Alle vier Bestandteile sind bekannt/extrahierbar: `44` (Konstante im Code),
`81` (Manifest `X-Build-Tag`), `245` (`VersionInfo.BUILD_TAG`, aus `b.class`),
`197` (`RuntimeTag.SESSION_TAG`, aus `a.class`). Nachgerechnet in Python:

```python
key = derive_key(44, 81, 245, 197)   # SHA-256-basiert, wie im Code
key_byte = key & 0xFF                # = 145
```

Das ist identisch aufwendig wie beim vorherigen Build — die
Kandidaten-Härtung betrifft nur die *Namensauflösung*, nicht die
Schlüsselableitung selbst.

## 5. Crypto.class.encrypted entschlüsseln

Byte-Reverse + XOR(key), exakt wie im dekompilierten `_d()`:

```python
n = len(data)
for i in range(n // 2):
    a, b = data[i], data[n-1-i]
    data[i]       = (b ^ key) & 0xFF
    data[n-1-i]   = (a ^ key) & 0xFF
```

Ergebnis ist eine valide `.class`-Datei (`file` bestätigt: "compiled Java
class data, version 70.0"). `jadx` darauf angesetzt ergibt vollständig
lesbaren Code für `Crypto`.

## 6. Crypto.class lesen — jetzt sind alle Namen bekannt

Mit der entschlüsselten Klasse in der Hand sind die öffentlichen
Methodennamen (`a, b, c, d, e, f, g`) direkt sichtbar — kein Rätselraten
mehr nötig, welcher Kandidat "der richtige" war, weil man jetzt einfach
`Crypto.class.getMethods()` bzw. den Decompiler-Output direkt liest, statt
`Main`s Kandidatenliste weiter zu verfolgen. Das bestätigt: die
Kandidaten-Hürde bremst nur den Weg *zu* `Crypto` (bzw. das Verstehen, was
`main()` überhaupt aufruft, bevor man `Crypto` in der Hand hat) — sobald die
Zielklasse einmal entschlüsselt vorliegt, ist der Rest genauso lesbar wie
vorher.

Relevante Befunde:

- `a(byte[] m)`: `SHA256(secret || m)` als Hex — **dieselbe Kernschwäche wie
  vorher**: Secret-Prefix-MAC statt HMAC, anfällig für
  Hash-Length-Extension.
- `b(byte[] m)`: parst `key=value&key=value...`, gibt den Wert des
  **letzten** `user=`-Feldes zurück.
- **Neu: `g(byte[] m, String mac)`** — sieht auf den ersten Blick wie ein
  zweiter, unabhängiger Integritätscheck aus (heißt intern
  "verifyDigestFormat", wird zwischen MAC- und Rollenprüfung in `main()`
  aufgerufen, kann den Prozess per `System.exit` beenden). Bei genauerem
  Lesen: berechnet `SHA256(m)` **ohne** das Secret, vergleicht nur
  *Länge* des resultierenden Hex-Digests mit der Länge von `mac`, prüft
  dass `mac` nur aus Hex-Zeichen besteht, und einen `Integer.bitCount(...)
  <= 32`-Check — Letzteres ist für jeden `int` immer wahr (ein `int` hat
  exakt 32 Bits). Alle drei Bedingungen sind für jede Eingabe, die diesen
  Punkt im Kontrollfluss überhaupt erreicht, bereits strukturell erfüllt.
  **Dieser Check hat keinen Sicherheitswert und lässt sich nicht umgehen,
  weil er nie etwas verhindert.** Der Unterschied zu den alten toten
  Decoys (`_h`/`_v`/`_r`): dieser hier wird tatsächlich bei jedem Lauf
  aufgerufen — ein reiner "wird das referenziert? nein → ignorieren"-Scan
  hätte ihn nicht aussortiert. Er musste tatsächlich gelesen und
  durchdacht werden, um zu erkennen, dass er wirkungslos ist.
- `c()`: entschlüsselt die Flag mit einem aus `SHA256(secret||"vault-flag")`
  abgeleiteten Keystream.
- `d()`/`e()`: liefern die `--sample`-Nachricht/ihren MAC.
- `f()`: ungenutzte Hilfsmethode (Secret-Länge, verschleiert als
  Bit-Rotation).

## 7. Hash-Length-Extension-Angriff

Kernidee unverändert gegenüber der alten Version: `a()` ist
`SHA256(secret||message)`. SHA-256 ist Merkle-Damgård-basiert — aus dem
Hash-Output lässt sich der komplette interne Zustand rekonstruieren. Wer
`SHA256(secret||message)` und die Bytelänge von `secret||message` kennt,
kann `SHA256(secret||message||padding||beliebiges_suffix)` weiterrechnen,
ohne `secret` zu kennen. `b()`s "letztes `user=` gewinnt"-Verhalten macht
das ausnutzbar: Anhängen von `&user=admin` per Length-Extension überschreibt
die Rolle.

Eigene (unabhängig von den vorhandenen `forge.py`/`sha256_extend.py`
geschriebene) Implementierung der SHA-256-Kompressionsfunktion mit
Zustands-Resume aus einem bekannten Digest, dann Brute-Force über die
unbekannte Secret-Länge (0–64 Bytes), jeder Kandidat gegen das echte JAR
getestet:

```
[+] sample message hex: 757365723d6775657374
[+] sample mac        : 2c38fd78f54e6c582f5b87421920e2501405c1d11a7c77eabd537409d18ce938
...
[+] SUCCESS at secret_len=36
    forged message (hex): 757365723d677565737480000000000000000000000000000000017026757365723d61646d696e
    forged mac          : 096f106b8a3a2977d01be4f65ba4cab6cde45f3360d80a6073be2fdde0ea6fd8
    output:
Access granted.
FLAG{h4sh_l3ngth_3xt3ns10n_pwn3d}
```

Der neue `g()`-Check (Schritt zwischen MAC- und Rollenprüfung) hat den
gefälschten Token nicht blockiert — genau wie beim Quellcode-Review in
Schritt 6 vermutet, verhindert er nichts.

## Fazit: Aufwandseinschätzung

**Der eigentliche Angriff (Hash-Length-Extension) ist exakt so aufwendig wie
vorher** — die Kernschwachstelle wurde nicht verändert, nur der Weg dorthin.
Der Mehraufwand durch diese Härtung liegt ausschließlich in den Schritten
3 und 6:

- **Schritt 3 (Kandidaten-Reflection) kostet spürbar mehr Zeit als vorher**,
  aber nicht durch Komplexität, sondern durch Verwirrung: Anstatt eine
  einzelne `a(byte[])`-Funktion zu finden und einmal anzuwenden, muss man
  erkennen, dass es jetzt *mehrere gleich aussehende Kandidaten pro
  Aufrufstelle* gibt, von denen keiner sich rein aus dem Bytecode heraus als
  "der richtige" auszeichnet (bei 1-Byte-Namen ist jeder Kandidat für sich
  genommen plausibel). Praktisch wurde dieser Schritt hier dadurch
  umgangen, dass die Klassennamen-Kandidatenliste (18 Byte lang) sehr wohl
  statisch eindeutig ist — dort verrät die Länge sofort, welcher Kandidat
  ein echter Klassenname ist. Und sobald `Crypto` einmal entschlüsselt in
  der Hand ist, sind ihre eigenen Methodennamen ohnehin direkt sichtbar,
  ohne dass man `Main`s Kandidatenlisten für die *einzelnen Methoden*
  überhaupt vollständig auflösen müsste. Der Reflection-Umweg verzögert also
  vor allem das Verstehen von `main()`s Kontrollfluss, nicht das Erreichen
  der eigentlichen Schwachstelle. Geschätzter Mehraufwand: **niedrig bis
  mittel**, spürbar aber nicht blockierend — realistisch ein paar zusätzliche
  Minuten Verwirrung, kein grundsätzlich neuer Schritt.
- **Schritt 6 (Fake-Check `g()`) kostet die meiste zusätzliche Denkzeit.**
  Anders als die alten toten Methoden lässt er sich nicht durch einen
  Cross-Reference-Scan wegfiltern — er wird tatsächlich aufgerufen und kann
  den Prozess beenden, sieht also aus wie ein zweiter Sicherheitsmechanismus,
  den man ernst nehmen müsste. Es erfordert eine bewusste Analyse aller drei
  Bedingungen (Längenvergleich, Zeichensatz-Check, `bitCount`-Grenze), um zu
  erkennen, dass keine davon je fehlschlagen kann, sobald der Code sie
  erreicht (weil `mac` an dieser Stelle immer bereits ein valider 64-Zeichen-
  Hex-Digest ist, und `bitCount(...) <= 32` für jeden `int` tautologisch
  wahr ist). Das ist die deutlichste neue Hürde gegenüber der alten Version
  — nicht weil der Angriff dadurch schwerer wird, sondern weil man Zeit
  darauf verwendet, einen Pfad zu verifizieren, der sich am Ende als
  irrelevant herausstellt. Geschätzter Mehraufwand: **mittel** — ein
  zusätzlicher, ernstzunehmender Analyseschritt, der sich erst im
  Nachhinein als Sackgasse entpuppt.

**Gesamteinschätzung:** Der Gesamtaufwand für die vollständige Blindanalyse
ist gegenüber der alten Version um schätzungsweise **20–40 % höher**
(zusätzliche Zeit für das Verstehen der Kandidatenlisten und das Verifizieren
von `g()`), aber der Angriff selbst bleibt vollständig durchführbar und die
Kernschwachstelle unverändert leicht identifizierbar, sobald `Crypto`
entschlüsselt vorliegt. Beide Maßnahmen sind — wie von vornherein
beabsichtigt — reine Bremsen gegen rein statische Analyse ohne Codeausführung;
sobald man bereit ist, das Programm tatsächlich laufen zu lassen (wie in
diesem Protokoll ohnehin nötig, um die Kandidaten aufzulösen und den
Angriff zu verifizieren), verschwindet der Unterschied fast vollständig.
Gegen einen erfahrenen Reverser mit Debugger/Java-Agent, der die
Kandidatenauflösung einfach beobachtet statt sie zu erraten, dürfte der
Mehraufwand nahe null liegen.
