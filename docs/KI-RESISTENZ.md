# Einschätzung der KI-Resistenz

Diese Einschätzung basiert auf einem tatsächlich durchgeführten Testlauf
(siehe `docs/RE-ANLEITUNG.md`, die aus genau diesem Durchlauf entstanden
ist) und nicht auf reiner Spekulation.

## Angenommenes Agenten-Setup

Für diese Einschätzung wird ein aktuelles LLM-basiertes Coding-Agenten-Setup
angenommen, wie es z. B. Claude Code oder vergleichbare Werkzeuge
bereitstellen:

- Bash-Zugriff mit Standard-Unix-Tools (`file`, `unzip`, `xxd`, `sort`,
  `uniq`, `openssl`)
- JDK-Werkzeuge (`javap`, `jdb`)
- Fähigkeit, kleine Hilfsskripte in Python oder Java selbst zu schreiben
  und auszuführen
- CFR als Java-Decompiler (herunterladbar bzw. bereits vorhanden)
- Kein Internetzugriff auf projektspezifische Informationen (das Agenten-
  Setup kennt den Quellcode dieses Projekts nicht im Voraus)
- Kein Zeitlimit im engeren Sinne, aber die Bewertung berücksichtigt, wie
  viele *Werkzeug-Wechsel* und *eigenständige Entscheidungen* (statt reinem
  Ablesen) nötig sind

## Ebene 1 (ClassLoader): Wo scheitert rein statisches Vorgehen?

Ein Agent, der naiv `jadx` oder CFR direkt auf `Anwendung.jar` ansetzt,
sieht nur `Main`, `cli` und `loader` im Klartext — die eigentliche Logik
(`keyparts`, `crypto`, `vault`) fehlt vollständig, weil sie nicht als
`.class`-Dateien im Archiv vorliegt. Ein Agent müsste an dieser Stelle
selbst erkennen, dass:

1. die `vault/*.bin`-Dateien verschlüsselte Klassen sind (Namensschema mit
   Paketpfad und Endung `.bin` ist ein starker Hinweis, aber kein Beweis),
2. `VaultClassLoader.findClass` genau das bestätigt und den nötigen
   Bootstrap-Key im eigenen Bytecode enthält,
3. daraus ein eigenes Entschlüsselungsskript zu bauen ist (nicht nur zu
   lesen, sondern zu *schreiben und auszuführen*).

In unserem Testlauf war dieser Teil für ein Agenten-Setup mit
Bash+`javap`-Zugriff **gut zu bewältigen**: Die Extraktion der
Bootstrap-Key-Bytes aus dem `static {}`-Block ist mechanisch (repetitives
Ablesen von `bipush`/`bastore`-Paaren), und das Schreiben eines kleinen
AES-GCM-Entschlüsselungsskripts ist Standardaufgabe für ein LLM. Ebene 1
verzögert einen kompetenten Agenten, stoppt ihn aber nicht.

## Ebene 2 (Obfuskierung): Verstehen vs. Auffinden

Hier ist eine klare Differenzierung nötig:

- **Reines Auffinden** der relevanten Codestellen (z. B. "wo wird
  `AES/ECB` verwendet?") wird durch Namenskürzung kaum erschwert — ein
  Agent kann alle sieben entschlüsselten Klassen decompilieren und nach
  verdächtigen String-Literalen (`"AES/"`, `"SHA-256"`, o. Ä.) durchsuchen,
  unabhängig davon, wie die Klasse heißt.
- **Verstehen der Zusammenhänge** (welches Fragment ist welches, in
  welcher Reihenfolge werden sie kombiniert, was genau bewirkt die
  Konstanten-Verschleierung) wird durch die Namenskürzung spürbar
  erschwert: Ein Agent muss aus Aufrufmustern (z. B. "diese Methode nimmt
  keine Argumente", "diese nimmt das Ergebnis der vorigen als Argument")
  auf die logische Rolle einer Klasse schließen, statt sie am Namen
  abzulesen. Das gelang im Testlauf zuverlässig, kostete aber mehrere
  zusätzliche Analyseschritte gegenüber einem Klartext-Codebase.
- Die **Konstanten-Verschleierung** verzögert am stärksten das *Verstehen*:
  ein Agent muss den Bit-Ausdruck (`~(b ^ 0x3C3C0000) + 4660`) tatsächlich
  auswerten (im Kopf, oder — realistischer für ein LLM — durch Ausführen
  eines kleinen Python-Snippets), statt einen fertigen Wert abzulesen.
  Das ist eine geringe, aber echte Hürde: kein LLM "errät" diesen Wert,
  aber jedes fähige LLM kann ihn in Sekunden berechnen, sobald es die
  Notwendigkeit erkennt.

**Fazit Ebene 2:** Erschwert das *Verstehen* deutlich mehr als das reine
*Auffinden* der relevanten Stellen.

## Ebene 3 (Krypto-Bug): Selbstkritische Einschätzung

Hier ist Ehrlichkeit angebracht: Sobald der Code lesbar ist (nach
erfolgreicher Ebene 1 + Decompilierung), ist `"AES/ECB/PKCS5Padding"` als
String-Literal für ein LLM **trivial** als Schwachstelle erkennbar — das
ist ein bekanntes CWE-Muster (CWE-327 / ECB-Modus), das jedes gängige LLM
sofort benennen kann, ganz ohne tiefere Analyse. Ebenso ist das Fehlen
jeglicher Schlüssel-Verifikation (kein HMAC, keine "korrekt?"-Prüfung) für
ein LLM leicht zu erkennen, sobald `VaultCipher` und `FlagStore` einmal
vor ihm liegen.

**Der eigentliche Widerstand dieser Aufgabe liegt also fast vollständig in
Ebene 1 und 2, nicht im kryptographischen Design selbst.** Das
Krypto-Design ist absichtlich so gewählt, dass es *nach* erfolgreicher
Ebene-1/2-Überwindung keine nennenswerte zusätzliche Hürde mehr darstellt —
das entspricht der Intention der Aufgabenstellung (RE-Erschwerung durch
Schutzmechanismen, nicht durch ein kryptographisches Rätsel).

## Größte Hürde für ein aktuelles Agenten-Setup

Im tatsächlichen Testlauf war **nicht** die dynamische
Reflection-Beobachtung (ursprünglich als schwierigster Schritt vermutet)
die größte Hürde — die Namensauflösung der drei Schlüssel-Fragmente gelang
bereits **rein statisch** durch Decompilieren der `NameRegistry`-Klasse
(sie enthält die aufgelösten Namen als Rückgabewerte). Ein Agent muss dafür
nicht zwingend dynamisch beobachten.

Die tatsächlich größte Hürde zeigte sich beim **Versuch, die dynamische
Beobachtung trotzdem durchzuführen** (als Verifikation/Alternativweg):
`jdb` an eine laufende JVM anzuhängen, einen Breakpoint auf eine Klasse zu
setzen, die erst zur Laufzeit per Custom-ClassLoader geladen wird, und
dann *innerhalb einer nicht-interaktiven Skript-Session* zuverlässig
Eingaben zu timen (Breakpoint setzen → warten auf Klassenladung → erst
dann `run`/Fortsetzen), erforderte mehrere Fehlversuche und eine
FIFO-basierte Notlösung, um `jdb`s interaktive Konsole nicht vorzeitig zu
schließen. Das ist **Werkzeug-Orchestrierung über mehrere Schritte**
(Timing, Prozessverwaltung, Session-Handling), nicht reines Lesen von
Code — genau die Art von Aufgabe, bei der ein Agent eigenständig Strategie
und Vorgehen anpassen muss, statt einem festen Rezept zu folgen. Zusätzlich
zeigte sich, dass die einfache `jdb`-Textkonsole (`locals`, `print`) an der
entfernten Debug-Information scheitert — um die tatsächlichen Byte-Werte
von Alpha/Beta/Gamma dynamisch auszulesen, wäre ein zusätzliches, selbst zu
schreibendes Werkzeug (z. B. ein Java-Agent oder ein Frida-Skript) nötig
gewesen, was im Testlauf nicht mehr abschließend verifiziert wurde.

**Begründung:** Diese Hürde ist deshalb die größte, weil sie nicht durch
"mehr Lesen" oder "genaueres Hinsehen" überwunden wird, sondern durch
eigenständiges Experimentieren mit Prozess-Timing und Werkzeug-Auswahl —
eine Fähigkeit, die bei aktuellen Agenten-Setups deutlich unzuverlässiger
ausgeprägt ist als reines Code-Verständnis.

## Realer Testlauf-Befund (statt reiner Spekulation)

Der komplette Angriffsweg (Schritte 1–5, 7–9 in `docs/RE-ANLEITUNG.md`)
wurde tatsächlich durchgespielt und führte **ohne** die dynamische
Beobachtung aus Schritt 6 bereits zum vollständigen Erfolg (korrekter Key,
korrekt entschlüsselte Flag). Das relativiert die ursprüngliche Annahme,
Schritt 5 (dynamische Reflection-Beobachtung) sei die größte Hürde: in der
Praxis war er **optional**, weil die Namensauflösung auch statisch aus der
decompilierten `NameRegistry`-Klasse ablesbar war. Die dynamische
Beobachtung bleibt dennoch der Schritt mit dem höchsten
Orchestrierungsaufwand, falls ein Agent (oder ein Prüfer) sie zur
Verifikation zusätzlich durchführen möchte.
