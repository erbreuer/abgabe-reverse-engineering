# KI-Einschätzung

Diese Einschätzung bewertet, wie gut der Schutzmechanismus von `VaultAccess`
eine KI (mit Werkzeugzugriff) davon abhält, die Anwendung zu reversen und das
Sicherheitsproblem — `SHA256(secret || message)` statt HMAC — zu finden und
auszunutzen. Beide beschriebenen Lösungswege wurden tatsächlich gegen die `vault.jar` durchgeführt.

## Welche Werkzeuge die KI braucht

Ein reines Chat-Interface ohne Werkzeugzugriff reicht nicht: Das Entschlüsseln
von `Crypto.class` und das Aufrufen von `vault.jar` erfordern Code-Ausführung.
Konkret braucht die KI:

- eine **Shell** mit Datei-Zugriff (`jar`, `javap`, Skripte starten,
  `vault.jar` aufrufen),
- ein **JDK 21+** zum Entpacken und Lesen des Bytecodes,
- **Python 3** zum Entschlüsseln der Klasse und Rechnen des Angriffs (Python-Standardbibliothek reicht),
- optional einen Decompiler (**CFR**, **jadx**) für lesbareren Code. 

## Was die Verschleierung bremst — und was nicht

Der Weg bis zur Schwachstelle lässt sich in zwei Phasen teilen: die
*Analysephase* (bis die verschlüsselte `Crypto.class` lesbar ist) und die
*Angriffsphase* (Schwachstelle erkennen und ausnutzen). Die Härtung wirkt fast
nur auf die erste.

**Bremst spürbar:** Die ProGuard-Umbenennung (alle Namen zu `a`, `b`, `c`), der
über vier Fundstellen verteilte und per SHA-256 kombinierte Loader-Schlüssel
sowie die Decoy-Klassen und XOR-kodierten Namen zwingen die KI, den Loader
Schritt für Schritt nachzubauen, bevor sie die Klasse überhaupt entschlüsseln
kann.

**Bremst kaum:** Sobald `Crypto.class` entschlüsselt ist, ist das Muster
`SHA256(secret || message)` sofort als Hash-Length-Extension erkennbar. Die
öffentlichen `Crypto`-Methoden müssen namensgleich bleiben (Reflection-Aufruf
aus `Main`), die „Integritätsprüfung" `g()` prüft nie den Inhalt gegen das
Secret, und der tote Code dient nur der Ablenkung — all das durchschaut eine KI,
die den Code liest, schnell.

## Der entscheidende Befund: ein Shortcut umgeht die Schwachstelle

Weil die Anwendung offline als Datei lauffähig sein muss, liegt das Secret
zwangsläufig in der JAR — verteilt und verschleiert, aber vorhanden. Dadurch
gibt es zwei Wege, die beide zum Flag führen:

- **Weg A (beabsichtigt):** Das `--sample`-Paar nehmen, die Secret-Länge aus dem
  Bytecode ablesen und den MAC per Hash-Length-Extension um `&user=admin`
  verlängern.
- **Weg B (Shortcut):** Das Secret selbst aus dem entschlüsselten Bytecode
  rekonstruieren und damit direkt einen regulären MAC für `user=admin`
  berechnen — ganz ohne Length-Extension.

Weg B umgeht also das eigentliche didaktische Ziel. Entscheidend ist aber: Er
ist **nicht wirklich schneller**. Beide Wege teilen sich den aufwändigsten Teil
— die Analysephase bis zur entschlüsselten Klasse. Weg B spart danach zwar den
Krypto-Teil, muss dafür aber das Secret aus mehreren verteilten Fragmenten
korrekt zusammensetzen. Der Umweg existiert, kostet aber ähnlich viel Zeit wie
der beabsichtigte Angriff.

## Fazit

Der Schutzmechanismus ist **Security through Obscurity**: Er verlangsamt die
Analyse, verhindert den Angriff aber nicht. Das liegt in der Offline-Architektur
selbst — jedes Geheimnis, das das Programm zur Laufzeit braucht, muss in der
ausgelieferten Datei liegen und ist damit grundsätzlich extrahierbar. Die
Härtung senkt deshalb nicht „möglich vs. unmöglich", sondern nur den Zeitaufwand.
Technisch ausschließen ließe sich der Shortcut nur mit einer echten
Vertrauensgrenze (ein von den Lehrenden betriebener Prüfdienst, der das Secret
nie herausgibt) — außerhalb der vorgegebenen Offline-Architektur.