# KI-Einschätzung

In der Einschätzung haben wir die KI gegen unsere `VaultAccess`-Anwendung laufen lassen, um die Qualität des Schutzmechanismus zu testen und inwiefern es die KI abhalten bzw. verlangsamen kann.

Die KI hat zwei Wege gefunden, um die Anwendung zu knacken. Im Folgenden haben wir zwischen der Analysephase (bis die verschlüsselte `Crypto.class` lesbar ist) und der Angriffsphase (Schwachstelle erkennen und ausnutzen) unterschieden.


## Welche Werkzeuge die KI braucht

Wird der Angriff über ein KI-Tool mit Werkzeugzugriff (z.B. Claude Code im Terminal) ausgeführt, braucht die KI folgende Werkzeuge:

- eine **Shell** mit Datei-Zugriff (`jar`, `javap`, Skripte starten,
  `vault.jar` aufrufen),
- ein **JDK 21+** zum Entpacken und Lesen des Bytecodes,
- **Python 3** zum Entschlüsseln der Klasse und Rechnen des Angriffs (Python-Standardbibliothek reicht),
- einen Decompiler (**CFR**, **jadx**) für lesbareren Code.

Das Lösen über einen reinen Browser-Chat ohne Werkzeugzugriff ist natürlich ebenfalls möglich, aber aufwändiger, da man der KI genügend Kontext liefern muss. Gibt man der KI nicht genügend Kontext, ist es fehleranfälliger bzw. dauert es länger zum Ziel.

## Analysephase: Was die Verschleierung verlangsamt und was nicht


**Verlangsamt spürbar:** Die ProGuard-Umbenennung (alle Namen zu `a`, `b`, `c`), der
über vier Fundstellen verteilte und per SHA-256 kombinierte Loader-Schlüssel
sowie die Decoy-Klassen und XOR-kodierten Namen zwingen die KI, den Loader
Schritt für Schritt nachzubauen, bevor sie die Klasse überhaupt entschlüsseln
kann. Für Methoden- und Klassennamen liegen mehrere XOR-Kandidaten vor, von
denen nur einer den echten Namen ergibt. Zwei der Klassen-Kandidaten laden
sogar erfolgreich (`CacheLoader`, `ConfigStore`), scheitern aber am
fehlenden `a(byte[])`. <br> Die KI muss also die komplette Auflösungskette
inklusive Signaturprüfung nachvollziehen, um den tatsächlich geladenen
Kandidaten zu identifizieren. Das Secret selbst ist aus vier Fragmenten
hash-abgeleitet, von denen eines (der Loader-Schlüssel) kein eigenständiges
Compile-Zeit-Literal ist, sondern selbst erst berechnet werden muss. Main
und Crypto lassen sich dadurch nicht unabhängig voneinander lösen.

**Verlangsamt kaum:** Sobald `Crypto.class` entschlüsselt ist, ist das Muster
`SHA256(secret || message)` sofort als Hash-Length-Extension erkennbar. Die
öffentlichen `Crypto`-Methoden müssen namensgleich bleiben (Reflection-Aufruf
aus `Main`), die „Integritätsprüfung" `g()` prüft nie den Inhalt gegen das
Secret, sondern nur Länge und Hex-Zeichensatz des bereits akzeptierten MAC
gegen sich selbst (ein `bitCount(...) > 32`-Check auf einem `int` ist zudem
eine Tautologie, die nie zuschlägt), und der tote Code dient nur der
Ablenkung, was alles von einer KI, die den Code durchliest, schnell durchschaut wird.

## Angriffsphase: Ein Shortcut umgeht die Schwachstelle

Weil die Anwendung offline als Datei lauffähig sein muss, liegt das Secret
zwangsläufig in der JAR, verteilt und verschleiert, aber vorhanden. Dadurch
gibt es zwei Wege, die beide zum Flag führen:

- **Weg A (beabsichtigt):** Das `--sample`-Paar nehmen, die Secret-Länge aus dem
  Bytecode ablesen und den MAC per Hash-Length-Extension um `&user=admin`
  verlängern.
- **Weg B (Shortcut):** Das Secret selbst aus dem entschlüsselten Bytecode
  rekonstruieren und damit direkt einen regulären MAC für `user=admin`
  berechnen, ganz ohne Length-Extension.

Weg B umgeht also das eigentliche gewollte Ziel. Entscheidend ist aber: Er
ist nicht wirklich schneller. 
<br> Beide Wege teilen sich den aufwändigsten Teil, die Analysephase bis zur entschlüsselten Klasse. Weg B spart danach zwar den
Krypto-Teil, muss dafür aber das Secret aus vier verteilten Fragmenten korrekt
zusammensetzen, von denen eines der bereits für den Loader berechnete
Schlüssel selbst ist. Der Umweg existiert, kostet aber ähnlich viel Zeit wie
der beabsichtigte Angriff.

## Fazit

Der Schutzmechanismus ist **Security through Obscurity**: Er verlangsamt die
Analyse, verhindert den Angriff aber nicht. Das liegt in der Offline-Architektur
selbst. Jedes Geheimnis, das das Programm zur Laufzeit braucht, muss in der
ausgelieferten Datei liegen und ist damit grundsätzlich extrahierbar. Die
Härtung senkt deshalb nicht „möglich vs. unmöglich", sondern nur den Zeitaufwand.
Technisch ausschließen ließe sich der Shortcut nur, wenn das Secret nicht in der JAR läge. Das heißt die Prüfung müsste auf einem Server stattfinden, den der Angreifer nicht einsehen kann.