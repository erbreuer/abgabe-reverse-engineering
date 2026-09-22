# Key-Derivation Trace (interne Notizen -- NICHT für Studierende)

Diese Datei ist nur zur eigenen Verifikation und für den Prüfer gedacht. Sie
verrät die exakten Zwischenwerte der Schlüsselableitung und darf nicht als
Teil der RE-Anleitung an Studierende gehen.

## Fragment Alpha

Quelle: `keyparts/KeyFragmentAlpha.java`

```java
int wordA = (~(0x5A5A5A5A ^ 0x3C3C0000)) + 0x1234;
int wordB = ((0x7FFFFFFF >>> 3) ^ 0x0F0F0F0F) - 0x77777777;
```

- wordA = `0x9999b7d9`
- wordB = `0x89797979`
- alpha (8 Byte, big-endian wordA || wordB) = `9999b7d989797979`

## Fragment Beta

Quelle: `keyparts/KeyFragmentBeta.java`

```
beta = SHA-256(alpha || PEPPER)[:8]
PEPPER = 42 C0 FF EE 13 37 13 37
```

- beta = `7b806733113fbbd2`

## Fragment Gamma

Quelle: `keyparts/KeyFragmentGamma.java`

```
gamma = SHA-256(bytes of vault/integrity.anchor)[:16]
```

**Wichtig (Design-Entscheidung während der Implementierung geändert):**
Ursprünglich sollte Gamma über `META-INF/MANIFEST.MF` berechnet werden. Das
scheiterte, weil Mavens `maven-jar-plugin` beim Packen zusätzliche Attribute
(`Created-By`, `Build-Jdk-Spec`, ...) einfügt, selbst wenn man explizit ein
eigenes `manifestFile` angibt -- der zur Build-Zeit gehashte Inhalt stimmte
dadurch nicht mehr mit dem tatsächlich im JAR gepackten Manifest überein.
Lösung: Gamma hasht stattdessen eine feste, eigene Ressourcendatei
`vault/integrity.anchor` (generiert von `tools/buildutil`, unverändert von
Maven gepackt), die exakt denselben Zweck erfüllt (Kopplung an das konkrete
Artefakt), aber nicht von Mavens Archiver angefasst wird.

Inhalt von `vault/integrity.anchor` (siehe `tools/buildutil/.../BuildUtil.java`,
Methode `generateAnchor`):

```
SecureVault-RE integrity anchor v1
artifact=de.dhbw.securevault:securevault-re
main-class=de.dhbw.securevault.Main
```

- SHA-256(integrity.anchor) = `bfcb634fbae9647009b6331ca0c7fb555d3b51ce765f36817dd56f6cc8b02f42`
- gamma (erste 16 Byte) = `bfcb634fbae9647009b6331ca0c7fb5`

## Finaler Schlüssel

```
key = SHA-256(alpha || beta || gamma)   // 256 Bit AES-Key
```

- key (realer Build) = `fd91ebea4dc548799d3772fb0bf5c9269dd18977238f279bb0a97a0f40624d82`

Reproduzierbar mit: `java -jar tools/buildutil/target/buildutil.jar print-key resources/vault/integrity.anchor`

## Test-Rundlauf (Crypto + Padding), vor Build/Obfuskierung

Plaintext-Flag (Test): `FLAG{test_wert_12345}`

Padded Plaintext (4x 16-Byte-Block `PADPADPADPADPAD-` + Flag-Text):
```
5041445041445041445041445041442d
5041445041445041445041445041442d
5041445041445041445041445041442d
5041445041445041445041445041442d
464c41477b746573745f776572745f31323334357d
```

Ciphertext (AES/ECB/PKCS5Padding mit obigem Testkey):
```
587504ab74ab3f508d95131d1f8b5496
587504ab74ab3f508d95131d1f8b5496
587504ab74ab3f508d95131d1f8b5496
587504ab74ab3f508d95131d1f8b5496
018034520bdfc70ac2b78c64b830d66b19b65d43e09eff9d6d3b3c501fd5c0f9
```

Wie erwartet: die ersten vier 16-Byte-Blöcke des Chiffretexts sind
**identisch**, weil ECB gleiche Klartextblöcke auf gleiche Chiffretextblöcke
abbildet -- das ist die Kernschwachstelle, die per Hex-Dump-Analyse sichtbar
werden soll (siehe `docs/RE-ANLEITUNG.md`, Schritt 9).

Entschlüsselung liefert wieder exakt `FLAG{test_wert_12345}` -- Rundlauf
verifiziert (`ROUND TRIP OK`).

## Reale Werte nach finalem Build (`./scripts/build.sh`)

- Flag (Klartext): `FLAG{ecb_leaks_repeated_blocks_and_reflection_hides_the_key}`
  (überschreibbar über die Umgebungsvariable `SECUREVAULT_FLAG_TEXT` beim
  Build)
- `resources/vault/integrity.anchor` SHA-256:
  `bfcb634fbae9647009b6331ca0c7fb555d3b51ce765f36817dd56f6cc8b02f42`
- Finaler AES-256-Key: `fd91ebea4dc548799d3772fb0bf5c9269dd18977238f279bb0a97a0f40624d82`
- `resources/flag.enc` ist 128 Byte groß: 4x 16-Byte-Padding-Block (identisch,
  ECB-Muster sichtbar) + verschlüsselter Flag-Text (64 Byte, PKCS5-gepolstert).
- Reproduktion des Keys aus dem gebauten Artefakt:
  ```
  java -jar tools/buildutil/target/buildutil.jar print-key resources/vault/integrity.anchor
  ```
- Manuelle Entschlüsselung von `flag.enc` mit obigem Key (Verifikation
  außerhalb der Anwendung selbst), z. B. via OpenSSL:
  ```
  openssl enc -aes-256-ecb -d \
    -K fd91ebea4dc548799d3772fb0bf5c9269dd18977238f279bb0a97a0f40624d82 \
    -in resources/flag.enc -out /tmp/flag.txt
  cat /tmp/flag.txt   # -> "PADPADPADPADPAD-" x4 + FLAG{...}
  ```
- `./scripts/smoke-test.sh` grün: App selbst entschlüsselt korrekt zu
  `FLAG{ecb_leaks_repeated_blocks_and_reflection_hides_the_key}`.

Die Ableitung ist über mehrere Builds hinweg deterministisch (keine
Zeitstempel/Zufallswerte in Alpha/Beta/Gamma) -- ein erneuter
`./scripts/build.sh`-Lauf ohne Codeänderungen erzeugt exakt dieselben
Zwischenwerte und denselben finalen Key.

## Während des eigenen RE-Durchlaufs gefundene und behobene Design-Bugs

Beim Durchspielen von `docs/RE-ANLEITUNG.md` gegen das fertige JAR (Schritt
9 im Arbeitsablauf) fielen zwei echte Schwachstellen im Schutzkonzept
selbst auf (nicht im Krypto-Bug, sondern in der Umsetzung von Ebene 1/2),
die vor der finalen Abgabe behoben wurden:

1. **`name-registry.properties` wurde im Klartext ins JAR gepackt.** Ein
   simples `unzip -p Anwendung.jar name-registry.properties` hätte die
   komplette Fragment-Namenszuordnung ohne jede Decompilierung verraten.
   Behoben durch: die Zuordnung wird jetzt zur Build-Zeit direkt in
   `NameRegistry.java` einkompiliert (siehe `tools/obfuscator`s
   `NameRegistryCodegen`), diese Klasse wird wie alle anderen geschützten
   Klassen obfuskiert und verschlüsselt -- es gibt keine separate,
   unverschlüsselte Ressource mehr, die die Zuordnung verrät.
2. **`javac` faltete die "obfuskierte" Konstante in `KeyFragmentAlpha` zur
   Kompilierzeit zu einem einzelnen Bytecode-Literal zusammen**, weil beide
   Operanden compile-time-konstant waren. Die eigentlichen Bit-Operationen
   (XOR/NOT/Shift/Add) verschwanden dadurch komplett aus dem Bytecode; CFR
   dekompilierte sie als bloße Zahl zurück. Behoben durch: die
   Ausgangswerte werden jetzt über einen Methodenaufruf (`obtainSeedA()`/
   `obtainSeedB()`) bezogen, was `javac` daran hindert, den gesamten
   Ausdruck zu falten -- die Bit-Operationen bleiben nachweislich im
   Bytecode erhalten (verifiziert per `javap -c` und per CFR-Decompilat,
   siehe `docs/RE-ANLEITUNG.md` Schritt 4).

Beide Fixes ändern den tatsächlich abgeleiteten Alpha/Beta/Gamma/Key-Wert
**nicht** (identische Werte vor und nach dem Fix, siehe oben) -- sie
betreffen ausschließlich, *wie* diese Werte im Bytecode kodiert bzw. wo sie
zur Laufzeit her aufgelöst werden.
