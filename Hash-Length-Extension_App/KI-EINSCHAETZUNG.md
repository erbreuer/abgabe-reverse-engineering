# KI-Einschätzung: RE-Erschwerung

> **Update (Version 3):** Das Secret kommt nicht mehr aus `VAULT_SECRET`,
> sondern ist fest in der JAR eingebettet, ebenso wie eine an das Secret
> gebundene Flag-Verschlüsselung; der Loader-Schlüssel wird jetzt über
> SHA-256 aus vier (statt drei, per XOR verknüpften) Fragmenten abgeleitet.
> Das **widerlegt die weiter unten getroffene Aussage, das Secret sei "nicht
> mehr im JAR" und daher nicht extrahierbar** — diese Aussage stimmte für
> Version 2, nicht mehr für den aktuellen Stand. Siehe "Update 2: Secret
> wieder im JAR — was das für die Einschätzung bedeutet" am Ende dieser
> Datei für die korrigierte Analyse.
>
> **Update (Version 2):** `build.sh` wurde um zwei ProGuard-Durchläufe
> (`proguard/crypto.pro`, `proguard/main.pro`) sowie eine auf drei Fundstellen
> verteilte Schlüsselableitung für `EncryptedClassLoader` ergänzt. Die
> folgende Einschätzung (Stufen 1–4) beschrieb den Stand **vor** dieser
> Änderung; die Kernaussage zu Stufe 2–4 (Schwachstelle + Angriff) bleibt
> unverändert gültig, nur Stufe 1 und Stufe 3 wurden bewusst verlängert. Siehe
> "Update: Wirkung von ProGuard + verteiltem Schlüssel" weiter unten.

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
| Java-Runtime | `vault.jar` direkt aufrufen (keine Env-Var mehr nötig, siehe Update 2 unten) |
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

---

## Update 2: Secret wieder im JAR — was das für die Einschätzung bedeutet

Grund für diese Korrektur: `VAULT_SECRET` als Voraussetzung stellte sich als
unpraktikabel heraus, wenn die JAR nur als Datei ausgeliefert wird (kein
Server, kein Zugriff auf die Umgebung der Studierenden) — das Programm
crashte ohne manuelle Vorbereitung. Als Lösung wurde das Secret fest in die
JAR eingebettet (verteiltes, Hash-kombiniertes Fragment-Muster, analog zum
Loader-Schlüssel). Das machte **eine zuvor in dieser Datei getroffene
Kernaussage falsch**: "Das Secret ist nicht mehr im JAR — eine KI kann es
nicht extrahieren." Das stimmt für den aktuellen Stand nicht mehr, und wir
haben das durch tatsächliche End-to-End-Tests verifiziert, nicht nur
theoretisch hergeleitet.

### Getesteter Shortcut: Secret extrahieren statt Length-Extension durchführen

Mit Tool-Zugriff (Bash, `javap`, Python) wurde der komplette Weg zweimal
tatsächlich durchgeführt — einmal auf einem früheren Zwischenstand (XOR-Key,
3 Fragmente) und einmal auf dem aktuellen Stand (Hash-Key, 4 Fragmente):

1. `jar xf vault.jar`, `javap -c -p -v` auf `Main.class`/`Main$a.class` →
   Loader-Schlüssel-Fragmente ablesen, `_deriveKey` (SHA-256-Kombination)
   in Python nachbauen.
2. `Crypto.class.encrypted` mit dem berechneten Schlüssel entschlüsseln
   (Byte-Reverse + XOR, Algorithmus liegt unverschlüsselt im Loader-Code).
3. `javap -c -p -v` auf das entschlüsselte `Crypto.class` → Secret-Fragmente
   ablesen (lokale Konstante, Manifest-Attribut, Loader-Key, viertes
   Fragment aus `RuntimeTag`), `_deriveKey` erneut anwenden.
4. `_S`-Array XOR-en → Secret im Klartext.
5. Mit dem Secret einen **regulären** `SHA256(secret || "user=admin")`-MAC
   berechnen — kein Length-Extension-Angriff nötig, da das Secret ja bekannt
   ist.
6. `java -jar vault.jar <hex> <mac>` → `Access granted.` + korrektes Flag.

**Ergebnis:** Dieser Weg funktioniert zuverlässig und liefert dieselbe Flag
wie der beabsichtigte Hash-Length-Extension-Angriff — er umgeht die
eigentliche kryptografische Schwachstelle vollständig.

### Warum das bei einer Offline-JAR nicht vollständig vermeidbar ist

Sobald ein Programm ohne Server/Netzwerk-Rückfrage offline lauffähig sein
muss, muss jedes Geheimnis, das es zur Laufzeit braucht, irgendwo in der
ausgelieferten Datei liegen — unabhängig davon, wie stark es verschleiert
oder verteilt ist. Ein Angreifer, der die Datei vollständig besitzt und
beliebig Zeit hat, kann jedes darin enthaltene Geheimnis grundsätzlich
extrahieren. Das ist keine KI-spezifische Schwäche, sondern eine
strukturelle Grenze von Offline-Verteilung (vgl. Kerckhoffs-Prinzip
umgekehrt angewendet). Die Härtungsmaßnahmen in diesem Projekt (Hash-Key
statt XOR, vier statt drei Fragmente, zusätzliche unscheinbare Klasse,
Flag-Verschlüsselung an das Secret statt an ein festes XOR gebunden) senken
deshalb realistisch **nicht** "Extraktion möglich vs. unmöglich", sondern
nur **wie viel Zeit die Extraktion gegenüber dem eigentlichen Angriff
kostet**.

### Aktualisierte Zeitschätzung (mit KI-Unterstützung, Tool-Zugriff)

| Weg | Geschätzte Zeit | Kommentar |
|---|---|---|
| Hash-Length-Extension (beabsichtigter Weg) | ~60–75 Min | Größtenteils Kryptoimplementierung (Padding, State-Import, Endianness) — fehleranfällig, aber gut dokumentiertes Angriffsmuster |
| Secret direkt extrahieren (Shortcut) | ~55–65 Min | Reines Bytecode-Lesen über vier Klassen + eine SHA-256-Nachimplementierung in Python, kein Kryptoverständnis über Hash-Interna nötig |

Die beiden Wege liegen nach der Härtung deutlich näher beieinander als beim
ursprünglichen, rein XOR-basierten Design (dort lag der Shortcut bei
~45 Minuten, klar unter dem Angriffsweg). Der Shortcut bleibt aber der Weg
mit dem geringeren *Fehlerrisiko*, weil er keine Kryptografie-Kenntnisse
über SHA-256-Interna erfordert, sondern nur sorgfältiges, wiederholbares
Bytecode-Lesen — eine Eigenschaft, die Sprachmodelle tendenziell gut
beherrschen.

### Lehre für zukünftige Härtungsversuche

Das eingebettete Secret lässt sich durch reine Verschleierung nicht auf
"praktisch unextrahierbar" bringen, ohne die Architektur grundlegend zu
ändern (z. B. eine echte Vertrauensgrenze — ein von den Lehrenden
betriebener Server/Prüfdienst, der das Secret nie an die Studierenden
herausgibt). Innerhalb der bestehenden Offline-JAR-Architektur ist der
sinnvollste Hebel, den Shortcut so aufwändig wie möglich zu machen (erreicht
durch diese Härtung), nicht ihn technisch auszuschließen (nicht erreichbar).
Für den didaktischen Kontext heißt das: Beide Lösungswege sollten in der
Bewertung als grundsätzlich gültig anerkannt werden, ggf. mit
unterschiedlicher Punktzahl, statt zu erwarten, dass der Shortcut
unmöglich gemacht werden kann.
