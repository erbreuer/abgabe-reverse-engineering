# KI-Einschätzung: RE-Erschwerung

## Wie gut schützt der Schutzmechanismus gegen KI RE?

### 1: JAR-Struktur und Manifest analysieren

Eine KI mit Bash-Zugriff führt `jar tf vault.jar` und `cat MANIFEST.MF` aus.
Sie sieht sofort `Crypto.class.encrypted` und die Manifest-Attribute `X-Build-Tag`
und `X-Secret-Tag`. Die Decoy-Klassen `a.class` / `b.class` fallen auf, sind aber
bei oberflächlicher Analyse schwer von der echten Klasse zu unterscheiden.

**Einschätzung:** ~5 Minuten. Die Manifest-Attribute sind ein offensichtlicher
Hinweis — eine KI erkennt sie als Schlüsselfragmente.

### 2: Main.class dekompilieren

ProGuard hat Methodennamen obfuskiert. Eine KI nutzt CFR oder Fernflower und
rekonstruiert die Logik aus dem Kontrollfluss — `_key()`, `_deriveKey()`, `_d()`
sind inhaltlich klar, auch wenn die Namen kryptisch sind. Die Kandidatenlisten
(`_CCand`, Decoy-Klassen) kosten etwas Zeit, weil mehrere Klassen ladbar sind,
aber nur eine die richtige Methodensignatur hat.

**Einschätzung:** ~10–20 Minuten. ProGuard-Obfuskation ist das stärkste Hindernis
in diesem Schritt — ohne Decompiler kein lesbarer Code.

### 3: Loader-Schlüssel rekonstruieren

Die vier Fragmente liegen verteilt: Literal in `Main` (Bytecode), `X-Build-Tag`
im Manifest, `BUILD_TAG` in `VersionInfo`, `SESSION_TAG` in `RuntimeTag`.
Eine KI sammelt alle vier und reimplementiert `_deriveKey()` in Python. Das ist
mechanisch, aber erfordert, dass alle Fragmente korrekt identifiziert wurden.

**Einschätzung:** ~5–10 Minuten, wenn Schritt 2 vollständig war.

### 4: Crypto.class entschlüsseln und analysieren

Mit dem berechneten Loader-Key entschlüsselt die KI `Crypto.class.encrypted`
per Python-Script. Nach der Entschlüsselung sieht sie:

```java
byte[] hash = md.digest(concat(_secret(), m));  // SHA256(secret || message)
```

Jede aktuelle KI erkennt das Muster `hash(secret || message)` sofort als
**Hash-Length-Extension**-Schwachstelle. Die Secret-Länge liest sie aus
`_S.length` im Bytecode: 36 Bytes.

**Einschätzung:** Schwachstelle erkennen: < 2 Minuten. Secret-Länge: 2–5 Minuten.

### 5: Angriff ausführen

Mit Secret-Länge 36 und bekanntem Sample-MAC führt die KI den Length-Extension-
Angriff per `hlextend` oder eigenem Script aus. Die Übergabe als Hex-String
vermeidet Encoding-Probleme mit Null-Bytes im Padding.

**Einschätzung:** 5–10 Minuten inklusive Ausführung.

---

## Gesamteinschätzung

| Phase | Zeit mit KI | Haupthindernis |
|---|---|---|
| JAR + Manifest analysieren | ~5 Min | Decoy-Klassen erkennen |
| Main.class dekompilieren | ~15 Min | ProGuard-Obfuskation |
| Loader-Key rekonstruieren | ~8 Min | Alle 4 Fragmente finden |
| Crypto.class entschlüsseln | ~5 Min | Entschlüsselungs-Script |
| Schwachstelle + Secret-Länge | ~5 Min | `_S.length` im Bytecode |
| Exploit ausführen | ~8 Min | Length-Extension + Hex-Übergabe |
| **Gesamt** | **~45–60 Min** | |

Ohne KI-Unterstützung ist der Zeitaufwand deutlich höher (~120–180 Min), da:
- ProGuard-Obfuskation manuell entwirrt werden muss
- `_deriveKey()` manuell aus dem Bytecode nachgebaut werden muss
- Alle vier Schlüsselfragmente über verschiedene Klassen hinweg gefunden werden müssen
- Die Schwachstellenklasse "Hash-Length-Extension" bekannt sein muss
- Das SHA-256 Padding-Format korrekt implementiert werden muss

---

## Was eine KI braucht (Harness)

Um die Aufgabe vollständig zu lösen, benötigt eine KI:

| Tool / Fähigkeit | Zweck |
|---|---|
| Bash-Ausführung | `jar xf`, Python-Scripts, `java -jar vault.jar` ausführen |
| Datei-Lese/Schreibzugriff | Verschlüsselte Klasse lesen, entschlüsselt schreiben |
| Java-Runtime (JDK 21+) | `vault.jar` aufrufen |
| CFR oder Fernflower | ProGuard-obfuskierte `.class`-Dateien dekompilieren |
| `javap` | Rohe Bytecode-Analyse für Konstantenwerte |
| `pip install hlextend` | Length-Extension-Bibliothek (oder Eigenimplementierung) |

Ein reines Chat-Interface ohne Tool-Zugriff kann die Aufgabe **nicht** lösen —
das Entschlüsseln von `Crypto.class` und der Aufruf von `vault.jar` erfordern
zwingend Code-Ausführung.

---

## Warum schützt der Mechanismus trotzdem nicht vollständig?

Die eingebauten Schutzmechanismen (ProGuard-Obfuskation, verschlüsselter
ClassLoader, verteilte Schlüsselfragmente, Decoy-Klassen) sind **Security through
Obscurity** — sie verlangsamen die Analyse erheblich, verhindern sie aber nicht.
Eine entschlossene KI mit Tool-Zugriff und einem geeigneten Decompiler umgeht
alle Maßnahmen systematisch.

Der eigentliche Sicherheitsfehler — `SHA256(secret || message)` statt HMAC —
bleibt nach dem RE sichtbar und ausnutzbar. Die Obfuskation schützt nicht vor
dem Angriff, sie erhöht nur den Aufwand, ihn zu finden.

Gegenüber einer einfacheren Implementierung ohne ProGuard und ohne verteilte
Schlüsselfragmente steigt der KI-Zeitaufwand von ~25 Minuten auf ~45–60 Minuten —
ein spürbarer, aber kein unüberwindbarer Unterschied.
