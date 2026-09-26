# KI-Einschätzung: RE-Erschwerung

> **Update:** Seit Version 2 wird `build.sh` um zwei ProGuard-Durchläufe
> (`proguard/crypto.pro`, `proguard/main.pro`) sowie eine auf drei Fundstellen
> verteilte Schlüsselableitung für `EncryptedClassLoader` ergänzt. Die
> folgende Einschätzung (Stufen 1–4) beschrieb den Stand **vor** dieser
> Änderung; die Kernaussage zu Stufe 2–4 (Schwachstelle + Angriff) bleibt
> unverändert gültig, nur Stufe 1 und Stufe 3 wurden bewusst verlängert. Siehe
> "Update: Wirkung von ProGuard + verteiltem Schlüssel" am Ende dieser Datei.

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

---

## Update: Wirkung von ProGuard + verteiltem Schlüssel

Getestet, indem dieselbe Anwendung einmal **vor** und einmal **nach** der
Härtung mit KI-Unterstützung (Claude, Tool-Zugriff: Bash, `javap`, Python)
gelöst wurde.

### Was sich ändert

**Stufe 1 (Main.class lesen) — spürbar länger:**
Ohne ProGuard hießen alle Felder/Methoden sprechend (`_K`, `_d`, `_C`,
`_Ma`…`_Mf`, `_s`) — das Lesen des `javap`-Outputs war fast wie
Klartext-Lesen mit XOR-Rauschen. Mit ProGuard heißen alle privaten
Bezeichner `a`, `b`, `c`, … (teils mehrfach überladen), `LineNumberTable`
fehlt, und die innere Klasse sowie die neue dritte Klasse (`VersionInfo`)
sind ebenfalls zu `Main$a` bzw. `a` umbenannt. Der Entschlüsselungsalgorithmus
selbst (Byte-Tausch + XOR) bleibt strukturell erkennbar — Bytecode-Muster wie
`ixor`, `bastore` in einer Schleife verraten sich unabhängig vom Namen —, aber
das Zuordnen "welches Feld ist der Schlüssel, welches der verschlüsselte
Name" braucht mehr Schritte.

**Neu: Schlüssel ist nicht mehr an einer Stelle — zusätzlicher Fund nötig:**
Vorher genügte das Lesen von `Main.class`, um den kompletten
Entschlüsselungsschlüssel zu haben. Jetzt muss zusätzlich das JAR-Manifest
(`X-Build-Tag`) und eine dritte, unscheinbar benannte Klasse (`VersionInfo`
→ nach Obfuskierung `de/dhbw/ctf/a.class`) gefunden und mit XOR
zusammengeführt werden. Das ist weiterhin mit Bordmitteln lösbar
(`unzip -p vault.jar META-INF/MANIFEST.MF`, `javap` auf die dritte Klasse),
aber es ist ein bewusster zusätzlicher Schritt, der nicht übersprungen werden
kann — ohne alle drei Fragmente ist der XOR-Schlüssel falsch und die
entschlüsselte `Crypto.class` beginnt nicht mit den gültigen
`CAFEBABE`-Magic-Bytes, was ein klares, aber erst nach dem Versuch
sichtbares Fehlersignal ist.

**Stufe 2–4 (Schwachstelle + Angriff) — unverändert:**
Die sechs öffentlichen `Crypto`-Methoden (`a`–`f`) müssen aus technischen
Gründen unverändert bleiben, da `Main` sie per Reflection mit Namen aufruft
— ProGuard kann und darf sie nicht umbenennen. Sobald `Crypto.class`
entschlüsselt ist, ist das Muster `SHA256(secret||message)` in `a()` genauso
schnell erkennbar wie vorher; der Length-Extension-Angriff selbst ändert
sich nicht.

### Aktualisierte Gesamteinschätzung

| Phase | Zeit mit KI (vorher) | Zeit mit KI (nach Härtung) | Haupthindernis (neu) |
|---|---|---|---|
| JAR entpacken, Entschlüsselungslogik lesen | ~10 Min | ~20–30 Min | Umbenannte Felder/Methoden, drei statt eine Schlüsselquelle |
| `Crypto.class` entschlüsseln | ~5 Min | ~8–12 Min | Schlüssel muss aus 3 Fundstellen zusammengesetzt werden |
| Schwachstelle erkennen | ~2 Min | ~2 Min | unverändert — öffentliche Methoden bleiben lesbar |
| Secret-Länge ermitteln | ~3 Min | ~3–5 Min | unverändert, plus etwas Sucharbeit durch Umbenennung von `f()`-Umfeld |
| Exploit ausführen | ~5 Min | ~5 Min | unverändert |
| **Gesamt** | **~25–45 Min** | **~40–65 Min** | |

**Fazit:** Die Härtung verlängert vor allem die Analysephase (Stufe 1+3), in
der es um das Verstehen der Verschleierungs- und Loader-Logik geht — nicht
die Phase, in der die eigentliche kryptografische Schwachstelle erkannt und
ausgenutzt wird. Das entspricht genau der beabsichtigten Wirkung: der
Lernwert der Aufgabe (Hash-Length-Extension erkennen und durchführen) bleibt
unverändert, nur der Weg zur entschlüsselten `Crypto.class` ist aufwändiger.
