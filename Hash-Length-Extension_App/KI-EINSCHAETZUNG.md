# KI-Einschätzung: RE-Erschwerung

## Wie gut schützt der Schutzmechanismus gegen KI-gestütztes RE?

### Stufe 1: Erste Analyse (ohne gezielten Prompt)

Eine KI (Claude, ChatGPT o.ä.) erkennt beim Dekompilieren von `Main.class` sofort:
- einen `ClassLoader` der Bytes lädt und transformiert
- eine `_d()`-Funktion mit Byte-Tausch und XOR
- `System.getenv("VAULT_SECRET")` — der ENV-Variablenname ist im Bytecode sichtbar

Mit dem Prompt *"Was macht diese Funktion?"* liefert sie sofort die korrekte Beschreibung
und Python-Implementierung von `_d()`.

**Einschätzung:** Die `EncryptedClassLoader`-Schicht verlangsamt eine KI um ca. 5-10
Minuten — sie muss `_d()` erst rekonstruieren und anwenden, bevor sie `Crypto.class`
sehen kann.

### Stufe 2: Schwachstelle erkennen

Sobald `Crypto.class` entschlüsselt ist, sieht die KI:
```java
byte[] hash = md.digest(concat(_secret(), m));  // SHA256(secret || message)
```

Jede aktuelle KI erkennt das Muster `hash(secret || message)` sofort als
**Hash-Length-Extension**-Schwachstelle und nennt `hlextend` als Tool.

Das Secret ist **nicht mehr im JAR** — es kommt aus `VAULT_SECRET`. Die KI kann es
nicht extrahieren, muss also den Angriff tatsächlich durchführen.

**Einschätzung:** Schwachstelle erkennen: < 1 Minute. Angriff aufsetzen ohne Secret: 5-15 Minuten.

### Stufe 3: Secret-Länge ermitteln

Die Länge ist nicht in `--sample` ausgegeben. Die KI muss `f()` im Bytecode finden:
```java
// Integer.rotateRight(Integer.rotateLeft(n, 3), 3) = n — verschleiert
```
Oder `f()` per Reflection aufrufen. Das ist ein kleines Hindernis, aber kein echtes.

**Einschätzung:** 2-5 Minuten.

### Stufe 4: Angriff ausführen

Die Nachricht wird als Hex-String übergeben — keine Probleme mit Null-Bytes im Padding.
`hlextend` ist in KI-Trainingsdaten gut vertreten. Die KI schreibt das Exploit-Script
korrekt auf Anhieb.

**Einschätzung:** 3-5 Minuten inklusive Ausführung.

---

## Gesamteinschätzung

| Phase | Zeit mit KI | Haupthindernis |
|---|---|---|
| JAR entpacken, `_d()` lesen | ~10 Min | Obfuscation von `Main.class` |
| `Crypto.class` entschlüsseln | ~5 Min | Entschlüsselungs-Script schreiben |
| Schwachstelle erkennen | ~2 Min | keins — Muster zu bekannt |
| Secret-Länge ermitteln | ~3 Min | `f()` im Bytecode finden |
| Exploit ausführen | ~5 Min | Hash-Extension-Script + Hex-Übergabe |
| **Gesamt** | **~25-45 Min** | |

Ohne KI-Unterstützung ist der Zeitaufwand deutlich höher (~90-150 Min), da:
- `_d()` manuell aus dem Bytecode rekonstruiert werden muss
- Die Schwachstellenklasse "Hash-Length-Extension" bekannt sein muss
- Das SHA-256 Padding-Format verstanden werden muss
- Das Secret nicht extrahiert werden kann — der Angriff muss korrekt implementiert werden

**Wichtig gegenüber der Vorgängerversion:** Das Secret ist nicht mehr im JAR gespeichert.
Eine KI kann es nicht durch Bytecode-Analyse oder Reflection extrahieren — der
Hash-Length-Extension-Angriff ist jetzt der einzig mögliche Lösungsweg.

---

## Was eine KI braucht (Harness)

Um die Aufgabe vollständig zu lösen, benötigt eine KI:

| Tool / Fähigkeit | Zweck |
|---|---|
| Bash-Ausführung | `jar xf`, `javap`, Python-Scripts ausführen |
| Datei-Lese/Schreibzugriff | Verschlüsselte Klasse lesen, entschlüsselt schreiben |
| `pip install hlextend` | Length-Extension-Bibliothek (oder Eigenimplementierung) |
| Java-Runtime mit `VAULT_SECRET` | `vault.jar` mit gesetzter Env-Variable aufrufen |
| CFR oder javap | `.class`-Dateien dekompilieren |

Ein reines Chat-Interface ohne Tool-Zugriff kann die Aufgabe **nicht** lösen —
das Entschlüsseln von `Crypto.class` und das Aufrufen von `vault.jar` erfordert
zwingend Code-Ausführung.

---

## Warum schützt der Mechanismus trotzdem nicht vollständig?

Die eingebauten Schutzmechanismen (verschlüsselter ClassLoader, Obfuscation) sind
**Security through Obscurity** — sie verlangsamen die Analyse, verhindern sie aber
nicht. Eine entschlossene KI mit Tool-Zugriff umgeht alle Schutzmaßnahmen systematisch.

Der eigentliche Sicherheitsfehler — `hash(secret || message)` statt HMAC — bleibt
nach dem RE sichtbar und ausnutzbar. Die Obfuscation schützt nicht vor dem Angriff,
sie verzögert nur das Erkennen der Schwachstelle.

Das nicht im JAR gespeicherte Secret ist der wesentliche Unterschied zur Vorgängerversion:
Es zwingt die KI dazu, den Angriff tatsächlich zu verstehen und auszuführen, statt
das Secret einfach zu extrahieren.
