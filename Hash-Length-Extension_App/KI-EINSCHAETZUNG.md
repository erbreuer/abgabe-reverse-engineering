# KI-Einschätzung: RE-Erschwerung

## Wie gut schützt der Schutzmechanismus gegen KI-gestütztes RE?

### Stufe 1: Erste Analyse (ohne gezielten Prompt)

Eine KI (Claude, ChatGPT o.ä.) erkennt beim Dekompilieren von `Main.class` sofort:
- einen `ClassLoader` der Bytes lädt und transformiert
- eine `_d()`-Funktion mit Byte-Tausch und XOR

Ohne expliziten Hinweis auf "Entschlüsselung" könnte die KI die Funktion als
Datentransformation fehldeuten. Mit dem Prompt *"Was macht diese Funktion?"* liefert
sie jedoch sofort die korrekte Beschreibung und Python-Implementierung.

**Einschätzung:** Die `EncryptedClassLoader`-Schicht verlangsamt eine KI um ca. 5-10
Minuten — sie muss `_d()` erst rekonstruieren und anwenden, bevor sie `Crypto.class`
sehen kann.

### Stufe 2: Schwachstelle erkennen

Sobald `Crypto.class` entschlüsselt ist, sieht die KI:
```java
byte[] input = (_x(_S) + m).getBytes("UTF-8");
MessageDigest.getInstance("SHA-256").digest(input);
```

Jede aktuelle KI erkennt das Muster `hash(secret || message)` sofort als
**Hash-Length-Extension**-Schwachstelle und nennt `hlextend` als Tool.

**Einschätzung:** Diese Stufe kostet eine KI weniger als 1 Minute.

### Stufe 3: Angriff ausführen

`hlextend` ist in KI-Trainingsdaten gut vertreten. Die KI schreibt das Exploit-Script
korrekt auf Anhieb.

**Einschätzung:** 2-3 Minuten inklusive Ausführung.

---

## Gesamteinschätzung

| Phase | Zeit mit KI | Haupthindernis |
|---|---|---|
| JAR entpacken, `_d()` lesen | ~10 Min | Obfuscation von `Main.class` |
| `Crypto.class` entschlüsseln | ~5 Min | Entschlüsselungs-Script schreiben |
| Schwachstelle erkennen | ~2 Min | keins — Muster zu bekannt |
| Exploit ausführen | ~5 Min | Byte-Encoding der Nachricht |
| **Gesamt** | **~25-40 Min** | |

Ohne KI-Unterstützung ist der Zeitaufwand deutlich höher (~90-120 Min), da:
- `_d()` manuell aus dem Bytecode rekonstruiert werden muss
- Die Schwachstellenklasse "Hash-Length-Extension" bekannt sein muss
- Das Padding-Format von SHA-256 verstanden werden muss

---

## Was eine KI braucht (Harness)

Um die Aufgabe vollständig zu lösen, benötigt eine KI:

| Tool / Fähigkeit | Zweck |
|---|---|
| Bash-Ausführung | `jar xf`, `javap`, Python-Scripts ausführen |
| Datei-Lese/Schreibzugriff | Verschlüsselte Klasse lesen, entschlüsselt schreiben |
| `pip install hlextend` | Length-Extension-Bibliothek |
| Java-Runtime | `vault.jar` aufrufen |
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
