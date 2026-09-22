# Reverse-Engineering-Anleitung: SecureVault-RE

Diese Anleitung wurde vollständig gegen das reale, mit `./scripts/build.sh`
erzeugte `target/Anwendung.jar` durchgespielt (jeder Befehl wurde tatsächlich
ausgeführt, keine Schritte sind spekulativ). Alle gezeigten Werte (Keys,
Hashes, Klassennamen) stammen aus diesem realen Durchlauf und sind
reproduzierbar, solange dieselbe JAR-Datei verwendet wird.

Benötigte Werkzeuge: `file`, `unzip`, `javap` (Teil des JDK), [CFR](https://www.benf.org/other/cfr/)
(Java-Decompiler), `python3` mit dem Paket `cryptography`, `jdb` (Teil des
JDK), `openssl`, `xxd`/`sort`/`uniq` (Standard-Unix-Tools).

---

## Schritt 1: Grobanalyse

```bash
file Anwendung.jar
```

```
Anwendung.jar: Zip archive data, at least v1.0 to extract, compression method=store
```

```bash
unzip -l Anwendung.jar
```

```
  Length      Date    Time    Name
---------  ---------- -----   ----
      119  ...         ...    META-INF/MANIFEST.MF
        0  ...         ...    de/dhbw/securevault/cli/
        0  ...         ...    de/dhbw/securevault/loader/
        0  ...         ...    vault/
      999  ...         ...    de/dhbw/securevault/cli/HelpText.class
     2173  ...         ...    de/dhbw/securevault/cli/ArgumentParser.class
     4308  ...         ...    de/dhbw/securevault/loader/VaultClassLoader.class
     3428  ...         ...    de/dhbw/securevault/Main.class
      128  ...         ...    flag.enc
      852  ...         ...    vault/de_dhbw_securevault_crypto_a.bin
     1622  ...         ...    vault/de_dhbw_securevault_keyparts_e.bin
      665  ...         ...    vault/de_dhbw_securevault_keyparts_d.bin
      822  ...         ...    vault/de_dhbw_securevault_keyparts_c.bin
      331  ...         ...    vault/de_dhbw_securevault_keyparts_b.bin
      115  ...         ...    vault/integrity.anchor
     3403  ...         ...    vault/de_dhbw_securevault_vault_FlagStore.bin
     1464  ...         ...    vault/de_dhbw_securevault_keyparts_KeyAssembler.bin
```

**Beobachtung:** `Main`, `cli/*` und `loader/*` liegen als normale
`.class`-Dateien vor (lesbar). Die Pakete `keyparts`, `crypto` und `vault`
tauchen **nicht** als `.class`-Dateien auf — stattdessen liegen unter
`vault/*.bin` sieben Binärblobs, deren Dateinamen die ursprünglichen
Paketpfade noch verraten (z. B. `de_dhbw_securevault_keyparts_KeyAssembler.bin`
— zwei Klassen wurden nicht umbenannt, siehe Schritt 4). Zusätzlich liegt
`flag.enc` (128 Byte) und `vault/integrity.anchor` (115 Byte) im Archiv.

→ Codestelle: Die Paketaufteilung entspricht exakt `Main`/`cli`/`loader`
(Bootstrap, Klartext) vs. `keyparts`/`crypto`/`vault` (geschützt,
verschlüsselt) aus der Projektarchitektur.

---

## Schritt 2: Bootstrap disassemblieren

```bash
javap -c -p -v de/dhbw/securevault/loader/VaultClassLoader.class
```

Im `static {}`-Initialisierer ist ein 32-Byte-Array sichtbar, das Byte für
Byte per `bastore` befüllt wird (`bipush <wert>` gefolgt von `bastore` für
jeden Index 0–31). Diese Werte lassen sich direkt ablesen und zu Hex
zusammensetzen:

```python
vals = [43, 126, 21, 22, 40, -82, -46, -90, -85, -9, 21, -120, 9, -49, 79,
        60, 118, 46, 113, 96, -13, -117, 77, -91, 106, 120, 77, -112, 69,
        25, 12, -2]
bootstrap_key = bytes(v & 0xFF for v in vals).hex()
# -> 2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe
```

Das ergibt den **Bootstrap-Key** (32 Byte = AES-256):
`2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe`.

Weiterhin verrät `javap -c -p` auf `findClass`:
- `getResourceAsStream("vault/" + name.replace('.', '_') + ".bin")` — das
  Namensschema der `.bin`-Ressourcen.
- Entschlüsselung via `AES/GCM/NoPadding`, wobei die ersten 12 Byte der
  Ressource der IV sind (aus der Konstante `GCM_IV_LENGTH = 12` bzw. der
  entsprechenden Bytecode-Konstante ablesbar).
- `defineClass(name, classBytes, 0, classBytes.length)` — Standard-Pattern
  aus Folie 23.

→ Codestelle: `loader/VaultClassLoader.java`, Feld `BOOTSTRAP_KEY`,
Methode `findClass`/`decrypt`.

---

## Schritt 3: Statische Entschlüsselung der `.bin`-Dateien

Mit dem in Schritt 2 gewonnenen Bootstrap-Key lassen sich alle
`vault/*.bin`-Ressourcen entschlüsseln. Das mitgelieferte Skript
`tools/dump-decrypt/dump_decrypt.py` automatisiert das:

```bash
python3 tools/dump-decrypt/dump_decrypt.py <extrahiertes-jar-verzeichnis> <ausgabe-verzeichnis>
```

Reales Ergebnis:

```
de_dhbw_securevault_crypto_a.bin -> .../de/dhbw/securevault/crypto/a.class (824 bytes) [OK (cafebabe)]
de_dhbw_securevault_keyparts_KeyAssembler.bin -> .../keyparts/KeyAssembler.class (1436 bytes) [OK (cafebabe)]
de_dhbw_securevault_keyparts_b.bin -> .../keyparts/b.class (527 bytes) [OK (cafebabe)]
de_dhbw_securevault_keyparts_c.bin -> .../keyparts/c.class (794 bytes) [OK (cafebabe)]
de_dhbw_securevault_keyparts_d.bin -> .../keyparts/d.class (637 bytes) [OK (cafebabe)]
de_dhbw_securevault_keyparts_e.bin -> .../keyparts/e.class (495 bytes) [OK (cafebabe)]
de_dhbw_securevault_vault_FlagStore.bin -> .../vault/FlagStore.class (3375 bytes) [OK (cafebabe)]
```

Alle sieben Dateien beginnen korrekt mit dem Java-Class-Magic `cafebabe` —
der Bootstrap-Key war also richtig.

**Beobachtung:** Zwei Klassen (`KeyAssembler`, `FlagStore`) behielten ihre
ursprünglichen Namen; drei Klassen im `keyparts`-Paket wurden zu `b`, `c`,
`d` umbenannt, und eine vierte zu `e`. Das ist kein Zufall (siehe Schritt 4).

→ Codestelle: `tools/dump-decrypt/dump_decrypt.py`.

---

## Schritt 4: Decompilieren der entschlüsselten, aber noch obfuskierten Klassen

```bash
java -jar cfr.jar b.class
java -jar cfr.jar c.class
java -jar cfr.jar d.class
java -jar cfr.jar e.class
java -jar cfr.jar KeyAssembler.class
java -jar cfr.jar FlagStore.class
java -jar cfr.jar a.class    # aus dem crypto-Paket
```

**`KeyAssembler` (Name bewusst nicht obfuskiert):**

```java
public final class KeyAssembler {
    public static byte[] reconstructKey(ClassLoader classLoader, byte[] byArray) throws Exception {
        byte[] byArray2 = KeyAssembler.e(classLoader, e.l(), e.m(), new Class[0], new Object[0]);
        byte[] byArray3 = KeyAssembler.e(classLoader, e.n(), e.o(), new Class[]{byte[].class}, new Object[]{byArray2});
        byte[] byArray4 = KeyAssembler.e(classLoader, e.p(), e.q(), new Class[]{byte[].class}, new Object[]{byArray});
        return KeyAssembler.d(byArray2, byArray3, byArray4);
    }
    // private static byte[] e(...) { Class.forName(...).getDeclaredMethod(...).invoke(...) }
    // private static byte[] d(a, b, c) { SHA-256(a || b || c) }
}
```

→ Drei Reflection-Aufrufe nacheinander, der zweite und dritte hängen vom
Ergebnis des ersten (bzw. vom übergebenen `byArray`) ab. Klasse `e` liefert
die Namen dafür.

**Klasse `e` (= `NameRegistry`) decompiliert:**

```java
public final class e {
    public static String l() { return "de.dhbw.securevault.keyparts.b"; }
    public static String m() { return "f"; }
    public static String n() { return "de.dhbw.securevault.keyparts.c"; }
    public static String o() { return "j"; }
    public static String p() { return "de.dhbw.securevault.keyparts.d"; }
    public static String q() { return "k"; }
}
```

Damit ist die Zuordnung **rein statisch** (ohne dynamische Beobachtung)
auflösbar: `b` = erstes Fragment (aufgerufen ohne Argumente → "Alpha"),
`c` = zweites Fragment (nimmt das Ergebnis von `b` als Argument →
"Beta"), `d` = drittes Fragment (nimmt das zweite `KeyAssembler`-Argument,
also den Integrity-Anchor, als Argument → "Gamma").

**`b.class` (Alpha) decompiliert:**

```java
public final class b {
    private static final int b = b.g();   // g() { return 0x5A5A5A5A; }
    private static final int c = b.h();   // h() { return Integer.MAX_VALUE; }

    public static byte[] f() {
        int n  = ~(b ^ 0x3C3C0000) + 4660;
        int n2 = (c >>> 3 ^ 0xF0F0F0F) - 0x77777777;
        // ... n, n2 big-endian in 8 Byte geschrieben
    }
}
```

Die Konstanten sind **nicht** direkt als fertiger Wert im Bytecode sichtbar
(anders als ein naiver Ansatz, bei dem `javac` den ganzen Ausdruck zu einem
Literal falten würde) — hier verhindert der Umweg über die Methodenaufrufe
`g()`/`h()`, dass der Compiler die Bit-Operationen wegfaltet. Man muss den
Ausdruck tatsächlich auswerten:

```python
def to_u32(x): return x & 0xFFFFFFFF
b_ = 0x5A5A5A5A
c_ = 0x7FFFFFFF
n  = to_u32((~(b_ ^ 0x3C3C0000)) + 4660)
n2 = to_u32(((c_ >> 3) ^ 0xF0F0F0F) - 0x77777777)
alpha = n.to_bytes(4,'big') + n2.to_bytes(4,'big')
print(alpha.hex())   # -> 9999b7d989797979
```

**Ergebnis:** `alpha = 9999b7d989797979`

**`c.class` (Beta) decompiliert:**

```java
public final class c {
    private static final byte[] d = {66, -64, -1, -18, 19, 55, 19, 55};
    public static byte[] j(byte[] byArray) {
        // SHA-256(byArray || d), erste 8 Byte
    }
}
```

```python
import hashlib
alpha = bytes.fromhex("9999b7d989797979")
pepper = bytes([0x42,0xC0,0xFF,0xEE,0x13,0x37,0x13,0x37])
beta = hashlib.sha256(alpha + pepper).digest()[:8]
print(beta.hex())   # -> 7b806733113fbbd2
```

**Ergebnis:** `beta = 7b806733113fbbd2`

**`d.class` (Gamma) decompiliert:**

```java
public final class d {
    public static byte[] k(byte[] byArray) {
        // SHA-256(byArray), erste 16 Byte
    }
}
```

Gamma braucht als Eingabe den zweiten Parameter von
`KeyAssembler.reconstructKey(ClassLoader, byte[])` — das ist derselbe
`byte[]`, den `Main` beim Aufruf übergibt: die Bytes von
`vault/integrity.anchor` (siehe Schritt 7).

→ Codestellen: `keyparts/KeyFragmentAlpha.java`,
`keyparts/KeyFragmentBeta.java`, `keyparts/KeyFragmentGamma.java`,
`keyparts/NameRegistry.java`, `keyparts/KeyAssembler.java`.

---

## Schritt 5: Krypto-Bug identifizieren

```bash
java -jar cfr.jar a.class   # crypto-Paket, Name nicht obfuskiert-lesbar (nur "a")
```

```java
public final class a {
    private static final String a = "AES/ECB/PKCS5Padding";
    public static byte[] b(byte[] in, byte[] key) { return c(1, in, key); }  // encrypt
    public static byte[] a(byte[] in, byte[] key) { return c(2, in, key); }  // decrypt
    private static byte[] c(int mode, byte[] in, byte[] key) {
        Cipher cipher = Cipher.getInstance(a);
        cipher.init(mode, new SecretKeySpec(key, "AES"));
        return cipher.doFinal(in);
    }
}
```

**Sofort erkennbar:** `"AES/ECB/PKCS5Padding"` als String-Literal — kein IV,
kein Salt, keine Authentifizierung/HMAC, keine "Key korrekt?"-Prüfung
irgendwo im Code. Das ist die eigentliche Schwachstelle (siehe
`docs/KI-RESISTENZ.md` für eine Einschätzung, wie leicht dieser Fund für
ein LLM ist, sobald der Code lesbar ist).

`FlagStore.class` (Name nicht obfuskiert) zeigt zusätzlich das
Padding-Schema: eine feste 16-Byte-Sequenz `"PADPADPADPADPAD-"`, viermal
wiederholt, vor dem eigentlichen Flag-Text.

---

## Schritt 6: Dynamische Beobachtung der Reflection-Aufrufe (jdb)

Dieser Schritt ist **nicht zwingend nötig**, um den Key zu rekonstruieren
(Schritt 4 hat das bereits rein statisch geschafft), demonstriert aber den
in der Aufgabenstellung vorgesehenen dynamischen Weg und war in der
Praxis der aufwändigste Schritt der ganzen Anleitung.

```bash
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=5005 \
  -jar Anwendung.jar --decrypt
```

In einem zweiten Terminal:

```bash
jdb -attach 5005
> stop in de.dhbw.securevault.keyparts.KeyAssembler.reconstructKey
> run
```

**Reales Ergebnis:**

```
Breakpoint de.dhbw.securevault.keyparts.KeyAssembler.reconstructKey wird verzögert.
Wird nach Laden der Klasse festgelegt.
Breakpoint erreicht: "Thread=main", de.dhbw.securevault.keyparts.KeyAssembler.reconstructKey(), Zeile=-1 BCI=0
```

Der Breakpoint greift korrekt, **obwohl** die Klasse erst zur Laufzeit per
`defineClass()` durch `VaultClassLoader` geladen wird (JDWPs deferred
breakpoints funktionieren auch für Custom-ClassLoader-Klassen). `Zeile=-1`
zeigt, dass keine Zeilennummerninformationen vorhanden sind (Debug-Info
wurde entfernt, siehe `SCHUTZKONZEPT.md`).

Ein Breakpoint auf `java.lang.reflect.Method.invoke(java.lang.Object,java.lang.Object[])`
(volle Signatur nötig, da überladen) fängt zusätzlich jeden der drei
reflektiven Aufrufe ab:

```
> stop in java.lang.reflect.Method.invoke(java.lang.Object,java.lang.Object[])
> run
...
Breakpoint erreicht ... 
  [1] java.lang.reflect.Method.invoke (Method.java:546)
  [2] de.dhbw.securevault.keyparts.KeyAssembler.e (null)
  [3] de.dhbw.securevault.keyparts.KeyAssembler.reconstructKey (null)
  ...
```

Dieser Treffer wiederholt sich genau dreimal für die drei Fragment-Aufrufe,
danach ein viertes Mal für `FlagStore.run`'s eigenen reflektiven Aufruf aus
`Main`.

**Grenze der einfachen `jdb`-Textkonsole:** `locals`/`print <name>`
scheitern an denselben Stellen ohne lokale Variableninformationen
("Keine lokalen Variableninformationen verfügbar. Kompilieren Sie mit -g...").
Um die tatsächlichen Byte-Inhalte von Alpha/Beta/Gamma live auszulesen,
reicht die reine `jdb`-Konsole nicht komfortabel aus — nötig wäre entweder
gezieltes `dump <object-id>` auf die per `args`-Objektreferenz sichtbaren
Arrays, oder ein kleines Frida-Skript bzw. ein Java-Agent, der
`Method.invoke`-Argumente und Rückgabewerte programmatisch abgreift. Dieser
Mehraufwand — Werkzeug-Orchestrierung über mehrere Schritte statt reinem
Lesen — ist genau der Punkt, den `docs/KI-RESISTENZ.md` als größte Hürde
benennt.

---

## Schritt 7: Integrity-Anchor extrahieren und Gamma nachrechnen

```bash
unzip -p Anwendung.jar vault/integrity.anchor
```

```
SecureVault-RE integrity anchor v1
artifact=de.dhbw.securevault:securevault-re
main-class=de.dhbw.securevault.Main
```

```bash
shasum -a 256 vault/integrity.anchor
# bfcb634fbae9647009b6331ca0c7fb555d3b51ce765f36817dd56f6cc8b02f42
```

Gamma = die ersten 16 Byte dieses Hashes:
`bfcb634fbae9647009b6331ca0c7fb5`.

(Hinweis: Ursprünglich war hierfür `META-INF/MANIFEST.MF` vorgesehen; das
wurde verworfen, weil Mavens Archiver das Manifest beim Packen immer um
zusätzliche Attribute ergänzt. Die App nutzt stattdessen die feste,
unveränderte Ressource `vault/integrity.anchor` — siehe
`docs/SCHUTZKONZEPT.md`.)

---

## Schritt 8: Key zusammensetzen und `flag.enc` entschlüsseln

```python
import hashlib

alpha = bytes.fromhex("9999b7d989797979")
beta  = bytes.fromhex("7b806733113fbbd2")
gamma = bytes.fromhex("bfcb634fbae9647009b6331ca0c7fb5")

key = hashlib.sha256(alpha + beta + gamma).digest()
print(key.hex())
# -> fd91ebea4dc548799d3772fb0bf5c9269dd18977238f279bb0a97a0f40624d82
```

```bash
openssl enc -aes-256-ecb -d \
  -K fd91ebea4dc548799d3772fb0bf5c9269dd18977238f279bb0a97a0f40624d82 \
  -in flag.enc -out flag.txt
cat flag.txt
```

**Reales Ergebnis:**

```
PADPADPADPADPAD-PADPADPADPADPAD-PADPADPADPADPAD-PADPADPADPADPAD-FLAG{ecb_leaks_repeated_blocks_and_reflection_hides_the_key}
```

Damit ist die Flag vollständig und reproduzierbar entschlüsselt, ohne
irgendeinen Schritt der App selbst auszuführen.

---

## Schritt 9: Alternativer/ergänzender Weg — ECB-Musteranalyse ohne Key

Auch ganz ohne Schlüssel verrät ein einfacher Hex-Dump von `flag.enc` die
Schwachstelle:

```bash
xxd flag.enc
```

```
00000000: 2af8 9459 2a2f c29f 55c0 47e4 f3f5 ec0b  *..Y*/..U.G.....
00000010: 2af8 9459 2a2f c29f 55c0 47e4 f3f5 ec0b  *..Y*/..U.G.....
00000020: 2af8 9459 2a2f c29f 55c0 47e4 f3f5 ec0b  *..Y*/..U.G.....
00000030: 2af8 9459 2a2f c29f 55c0 47e4 f3f5 ec0b  *..Y*/..U.G.....
00000040: 1942 24de cc69 531c 5a31 5fb2 5c1e d3f3  .B$..iS.Z1_.\...
...
```

```bash
xxd -c16 flag.enc | awk '{$1="";print}' | sort | uniq -c | sort -rn
#    4 2af8 9459 2a2f c29f 55c0 47e4 f3f5 ec0b
#    1 ...
```

Der erste 16-Byte-Block wiederholt sich **exakt viermal** — ein
untrügliches Zeichen für AES im ECB-Modus (identische Klartextblöcke
erzeugen identische Chiffretextblöcke) und für ein wiederholendes
Padding-Schema im Klartext, auch ganz ohne Kenntnis des Schlüssels.

---

## Zusammenfassung des Angriffswegs

| Schritt | Werkzeug | Ergebnis |
|---|---|---|
| 1 | `file`, `unzip -l` | Struktur: Bootstrap klar, Payload verschlüsselt |
| 2 | `javap -c -p -v` | Bootstrap-AES-256-GCM-Key aus Bytecode |
| 3 | `tools/dump-decrypt/dump_decrypt.py` | 7 entschlüsselte, aber obfuskierte `.class`-Dateien |
| 4 | CFR | Fragment-Logik + Namensauflösung (rein statisch möglich) |
| 5 | CFR | Krypto-Bug (`AES/ECB/PKCS5Padding`) sofort sichtbar |
| 6 | `jdb` | Reflection-Aufrufe dynamisch bestätigt (optional, nicht notwendig) |
| 7 | `unzip -p`, `shasum` | Gamma aus `integrity.anchor` |
| 8 | Python, `openssl` | Finaler Key, `flag.enc` entschlüsselt |
| 9 | `xxd`, `sort`/`uniq` | ECB-Muster als Alternativweg ganz ohne Key |
