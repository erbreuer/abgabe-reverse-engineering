# Schutzkonzept: SecureVault-RE

Dieses Dokument beschreibt **ausschließlich** die Schutzmechanismen der
Anwendung (Ebene 1: Custom ClassLoader, Ebene 2: Obfuskierung). Es macht
bewusst **keine Aussage** darüber, ob oder wo in der eigentlichen
Anwendungslogik eine Sicherheitslücke existiert — das ist Gegenstand der
separaten `docs/RE-ANLEITUNG.md` und nicht Teil dieses Dokuments.

## Architektur

Der Quellcode ist in zwei klar getrennte Bereiche aufgeteilt:

| Bereich | Pakete | Auslieferung |
|---|---|---|
| Bootstrap (ungeschützt) | `Main`, `cli`, `loader` | normale, lesbare `.class`-Dateien im JAR |
| Geschützt | `keyparts`, `crypto`, `vault` | ausschließlich als verschlüsselte Ressourcen unter `vault/*.bin` |

Der Bootstrap-Bereich ist absichtlich klar lesbar gehalten — er ist der
Einstiegspunkt, den jeder Nutzer (und jeder Analyst) zuerst sieht, und
enthält selbst keine sicherheitsrelevante Logik.

## Ebene 1: Custom ClassLoader

`loader/VaultClassLoader` lädt die geschützten Klassen nicht aus normalen
`.class`-Dateien, sondern entschlüsselt sie zur Laufzeit aus den
`vault/*.bin`-Ressourcen und definiert sie per `defineClass(...)`. Der
dafür verwendete Bootstrap-Schlüssel (AES-256-GCM) ist absichtlich direkt
im Bytecode von `VaultClassLoader` sichtbar hinterlegt — er schützt nur vor
einfachem `unzip` + `javap`, nicht vor gezieltem Reversing. Das ist bewusst
so gestaltet: dieser Schlüssel soll lediglich verhindern, dass die
geschützten Klassen als gewöhnliche `.class`-Dateien im Archiv erscheinen;
er ist keine "echte" Zugriffskontrolle.

Ein zusätzlicher Mechanismus: die drei internen Schlüssel-Fragment-Klassen
(im Paket `keyparts`) werden von `KeyAssembler` nicht direkt aufgerufen,
sondern selbst rekursiv über denselben `VaultClassLoader` geladen und ihre
Methoden ausschließlich per Reflection (`Class.forName` +
`getDeclaredMethod(...).invoke(...)`) angesprochen. Welche Klasse welche
Methode mit welchen Argumenten liefert, ist damit nicht direkt aus einem
Methodenaufruf im Bytecode ablesbar, sondern nur über eine zur Laufzeit
generierte Namenstabelle auflösbar.

## Ebene 2: Obfuskierung

Auf die geschützten Pakete (`keyparts`, `crypto`, `vault`) wendet ein
eigenständiges Build-Tool (`tools/obfuscator`, basierend auf der
ASM-Bibliothek) vor der Verschlüsselung folgende Techniken an:

1. **Entfernen aller Debug-Informationen** — Zeilennummern und
   Local-Variable-Tables werden vollständig entfernt (Kompilierung mit
   `-g:none` bzw. `ClassReader.SKIP_DEBUG`). Ein Debugger oder Decompiler
   kann keine Quellzeilen oder lokalen Variablennamen mehr anzeigen.
2. **Kürzen aller Klassen-, Methoden- und Feldnamen** auf bedeutungslose
   Kurzformen (`a`, `b`, `c`, ...) via ASM `ClassRemapper`/`SimpleRemapper`.
   Zwei Klassen (der Einstiegspunkt in die Schlüsselableitung und der
   Einstiegspunkt in die Tresor-Logik) behalten ihre ursprünglichen Namen,
   weil der Bootstrap-Bereich sie als feste Zeichenketten referenzieren
   muss, um überhaupt in den geschützten Bereich hineinzufinden — alle
   anderen Bezeichner werden konsequent gekürzt.
3. **Verschleierung von Konstanten**: Sicherheitsrelevante numerische
   Konstanten werden nicht als direkte Literale im Bytecode abgelegt,
   sondern über Bit-Operationen (XOR, NOT, Shift, Addition) auf Werte
   berechnet, die selbst wiederum über einen nicht kompilierzeit-konstanten
   Methodenaufruf bezogen werden. Damit kann der Java-Compiler den
   Ausdruck nicht zu einem einzelnen Literal zusammenfalten — die
   eigentlichen Bit-Operationen bleiben im kompilierten Bytecode erhalten
   und müssen zur Analyse tatsächlich nachvollzogen bzw. ausgewertet
   werden.

## Selbstintegritäts-Kopplung

Ein Teil der internen Ableitungslogik bezieht eine feste, im Build
generierte Ressource innerhalb des JARs mit ein (SHA-256-Hash über deren
Bytes). Das koppelt das Ergebnis an das konkrete, gebaute Artefakt: wird
das JAR verändert oder mit anderen Build-Parametern neu erzeugt, ändert
sich auch dieser Teil der Ableitung entsprechend.

## Grenzen dieses Schutzkonzepts

Dieses Dokument macht bewusst keine Aussage über die kryptographische
Qualität der eigentlichen Verschlüsselungslogik in `crypto`/`vault` — das
wäre Gegenstand einer separaten Sicherheitsanalyse, nicht dieses
Schutzkonzepts, das sich ausschließlich mit den beiden oben beschriebenen
Ebenen (Auslieferung/Ladeverfahren und Bytecode-Verschleierung) befasst.
