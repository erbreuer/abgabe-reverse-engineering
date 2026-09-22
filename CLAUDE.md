# CLAUDE.md — Projekt "SecureVault-RE" (Reverse Engineering erschweren, Uni-Abgabe)

Dieses Dokument ist die vollständige Arbeitsanweisung für dich als Coding Agent. Du sollst das Projekt **eigenständig von Anfang bis Ende fertigstellen**: Code, Build-Skripte und alle drei geforderten Dokumentationsteile. Arbeite die Abschnitte in der angegebenen Reihenfolge ab und halte dich exakt an die Vorgaben — Abweichungen gefährden die Bewertung, weil die Doku-Pflichten (siehe unten) eine 1:1-Übereinstimmung zwischen Code-Verhalten und Beschreibung erfordern.

---

## 0. Kontext & Zielplattform

- Uni-Abgabe für eine Reverse-Engineering-Vorlesung (Dozent: Prof. Dr. Michael Eichberg, DHBW).
- Zielplattform: **Ubuntu Linux 26.04 (x86-64)**, ausführbar via `java -jar Anwendung.jar`, **Java 26**.
- Reines Java-Programm, JAR-basiert, kommandozeilenbasiert. Keine GUI, keine Netzwerkkommunikation.
- Build-Tool: **Maven** (bevorzugt) oder Gradle — wähle eines und bleib konsistent. Nutze nur Bibliotheken, die offline/aus Maven Central beziehbar sind (Netzwerkzugriff ggf. eingeschränkt — bei Problemen lokal vendored JARs verwenden).
- **QS/Tests sind laut Aufgabenstellung nicht bewertungsrelevant** — schreibe trotzdem ein minimales manuelles Testskript (`scripts/smoke-test.sh`), das Verschlüsseln + Entschlüsseln mit korrektem Schlüssel end-to-end prüft, damit du selbst verifizieren kannst, dass die App funktioniert, bevor du das Rätsel als "gelöst reproduzierbar" dokumentierst.

## 1. Bewertete Teilleistungen — was am Ende vorliegen muss

| # | Punkte | Deliverable | Ablageort |
|---|---|---|---|
| 1 | 7P | Anwendung (JAR) + vollständiger Quellcode + Build-Skripte | `src/`, `pom.xml`, `scripts/build.sh` |
| 2 | 1P | Nutzerdokumentation (kann `--help`-Ausgabe sein) | in CLI integriert + `docs/USAGE.md` |
| 3 | 5P | RE-Anleitung: exakte, reproduzierbare Schritt-für-Schritt-Anleitung mit genau benannten Tools | `docs/RE-ANLEITUNG.md` |
| 4 | 2P | Einschätzung der KI-Resistenz (begründet, mit Angabe von Tooling/Harness) | `docs/KI-RESISTENZ.md` |

**Kritische Rahmenbedingung:** Der "Schutz" (ClassLoader + Obfuskierung) muss **klar von der eigentlichen Sicherheitslücke** (Krypto-Bug) trennbar sein, weil beide getrennt dokumentiert werden. Halte dich bei der Implementierung strikt an diese gedankliche Trennung — sie bestimmt auch die Code-Struktur (siehe Abschnitt 3).

Baue am Ende zusätzlich `docs/SCHUTZKONZEPT.md`, das *nur* Ebene 1+2 (Schutz) beschreibt, ohne den Krypto-Bug zu verraten — das ist die "öffentliche" Doku-Seite, während `RE-ANLEITUNG.md` beides schrittweise aufdeckt.

---

## 2. Gesamtkonzept (bereits abgestimmt — nicht mehr verhandelbar)

Die App verwaltet eine "Flag"-Datei (`flag.enc`), die mit AES verschlüsselt im JAR liegt. Drei Ebenen:

1. **Custom ClassLoader** (Schutz-Ebene A): Die eigentliche Verschlüsselungs-/Schlüssellogik liegt nicht als normale `.class`-Dateien im JAR, sondern verschlüsselt als Ressourcen. Ein Custom `ClassLoader` entschlüsselt sie zur Laufzeit und lädt sie per `defineClass()`.
2. **Obfuskierung** (Schutz-Ebene B): Mindestens 3 Techniken aus der Vorlesungsfolie zur Bytecode-Verschleierung, angewendet auf die zu ladenden Klassen.
3. **Krypto-Bug** (die eigentliche CTF-Schwachstelle, **anspruchsvolle Variante**): AES im **ECB-Modus**, **keine Passwort-/Schlüssel-Verifikation** (passwortlose Verifikation à la Folie 32/33), und der AES-Key wird aus mehreren, über verschiedene Klassen/Reflection-Aufrufe **verteilten Teilen** zusammengesetzt.

---

## 3. Architektur & Paketstruktur

```
de.dhbw.securevault
├── Main.java                     // Bootstrap, NICHT verschlüsselt (muss startbar sein)
├── cli/
│   ├── ArgumentParser.java       // CLI-Argumente, --help, --encrypt, --decrypt
│   └── HelpText.java             // Nutzerdoku als Text (Anforderung 2)
├── loader/
│   └── VaultClassLoader.java     // Custom ClassLoader nach Folien-Pattern (Abschnitt 4)
├── keyparts/                     // NUR VOR OBFUSKIERUNG unter diesem Namen; werden verschlüsselt & umbenannt
│   ├── KeyFragmentAlpha.java      // liefert Teil 1 des Schlüssels
│   ├── KeyFragmentBeta.java       // liefert Teil 2 des Schlüssels (hängt von Alpha ab)
│   ├── KeyFragmentGamma.java      // liefert Teil 3 (abgeleitet aus JAR-Selbsthash)
│   └── KeyAssembler.java          // ruft die drei Fragmente NUR per Reflection auf und kombiniert sie
├── crypto/
│   └── VaultCipher.java           // AES/ECB/PKCS5Padding, KEINE Verifikation, KEIN Salt/IV
└── vault/
    └── FlagStore.java             // liest/schreibt flag.enc, Redundanz-Padding für ECB-Musteranalyse (Abschnitt 6)
```

**Wichtige Trennregel für den Build:** Nur die Pakete `keyparts`, `crypto` und `vault` werden verschlüsselt + obfuskiert (das ist der "geschützte Teil"). `Main`, `cli` und `loader` bleiben unverschlüsselt und leicht lesbar — sie sind der Bootstrap, den der Angreifer als Einstiegspunkt braucht (genau wie in Folie 23 vorgesehen).

---

## 4. Custom ClassLoader — exakt nach Vorlesungs-Pattern (Folie 23)

Implementiere `VaultClassLoader` **strukturell identisch** zum Folien-Beispiel, nicht funktional komplizierter als nötig:

```java
public class VaultClassLoader extends ClassLoader {
    public VaultClassLoader(ClassLoader parent) { super(parent); }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        try (InputStream in = getResourceAsStream(toResourcePath(name))) {
            byte[] encryptedBytes = in.readAllBytes();
            byte[] classBytes = decrypt(encryptedBytes, reconstructKey());
            return defineClass(name, classBytes, 0, classBytes.length);
        } catch (IOException e) {
            throw new ClassNotFoundException("failed loading " + name, e);
        }
    }
}
```

Anforderungen:
- Die verschlüsselten `.class`-Dateien liegen unter `resources/vault/<obfuskierter-name>.bin` im JAR.
- `reconstructKey()` ruft **nicht direkt** die drei `KeyFragment*`-Klassen auf, sondern lädt sie selbst **rekursiv über denselben `VaultClassLoader`** und ruft ihre Methoden per Reflection (`getDeclaredMethod(...).invoke(...)`) auf. Das ist der zentrale Erschwerungspunkt: Ein Angreifer kann nicht einfach die drei Fragment-Klassen isoliert decompilieren und den Schlüssel direkt ablesen — er muss den Bootstrap-Loader dynamisch beobachten, um zu sehen, welche Methoden mit welchen Argumenten aufgerufen werden (siehe Abschnitt 5, "anspruchsvolle Variante").
- `Main.java` instanziiert `VaultClassLoader`, lädt darüber die Klasse `de.dhbw.securevault.vault.FlagStore` und ruft deren Einstiegsmethode reflektiv auf.

---

## 5. Schlüsselableitung — ANSPRUCHSVOLLE VARIANTE (verbindlich umzusetzen)

Der AES-Key (256 Bit) entsteht aus **drei Teilen**, die NIE an einer Stelle im Code zusammenstehen:

| Fragment | Herkunft | Warum schwer zu finden |
|---|---|---|
| **Alpha** (8 Byte) | Statische, aber durch Konstanten-Verschleierung berechnete Werte (z. B. `~(((int)Math.PI) ^ Integer.MAX_VALUE >> 16)+Short.MAX_VALUE`-Stil-Ausdrücke, siehe Folie 20) | Kein direkter Literal-Wert im Bytecode sichtbar; muss berechnet/emuliert werden |
| **Beta** (8 Byte) | Abgeleitet aus dem Rückgabewert von Alpha (Beta ruft Alpha per Reflection auf und wendet eine Transformation an, z. B. HMAC-artige Mischung) | Erfordert, dass Alpha zuerst korrekt reproduziert wird — Reihenfolge ist bewusst erzwungen |
| **Gamma** (16 Byte) | SHA-256-Hash über einen **fest definierten Teil der JAR-Datei selbst** (z. B. die Bytes der `MANIFEST.MF` oder eines bestimmten Ressourcen-Eintrags), gekürzt auf 16 Byte | Selbstintegritäts-Kopplung: Der Schlüssel hängt vom konkreten Artefakt ab, das der Angreifer analysiert — das macht die RE-Anleitung anspruchsvoller, aber **immer noch exakt reproduzierbar**, weil die JAR-Datei ja vorliegt |

`KeyAssembler.reconstructKey()`:
```java
byte[] alpha = invokeReflectively("keyparts.KeyFragmentAlpha", "derive");
byte[] beta  = invokeReflectively("keyparts.KeyFragmentBeta", "derive", alpha);
byte[] gamma = invokeReflectively("keyparts.KeyFragmentGamma", "derive", getJarSelfBytes());
return concatAndHash(alpha, beta, gamma); // finaler 256-Bit-Key via SHA-256
```

**Wichtig — Determinismus sicherstellen:** Jede Methode muss bei gleichem Input **immer** denselben Output liefern (keine Zeitstempel, keine Zufallszahlen, keine Umgebungsvariablen). Sonst ist Kriterium 3 (reproduzierbare RE-Anleitung) nicht erfüllbar. Schreibe dir während der Implementierung eine private Notiz mit den tatsächlichen Zwischenwerten (Alpha/Beta/Gamma in Hex), damit du die RE-Anleitung später exakt gegenprüfen kannst.

**Grenze der Komplexität:** Die Fragmente dürfen anspruchsvoll in der *Auffindung* sein (verteilt, obfuskiert, reflection-basiert), aber die *Berechnung* selbst muss mit Standardmitteln (Java, Python, ein kleines Skript) in Sekunden nachvollziehbar sein, sobald man die Logik verstanden hat. Kein Bruteforce über einen großen Suchraum — das ist ein RE-Rätsel, kein Krypto-Bruteforce-Rätsel.

---

## 6. Der Krypto-Bug (die eigentliche Schwachstelle)

`VaultCipher`:
```java
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(reconstructedKey, "AES"));
byte[] ciphertext = cipher.doFinal(flagPlaintext);
// KEIN IV, KEIN Salt, KEINE HMAC/Prüfsumme, KEINE "Passwort korrekt?"-Rückmeldung
```

Implementiere zusätzlich in `FlagStore`:
- **Absichtliche Redundanz in der Flag-Struktur**, damit die ECB-Musteranalyse aus Folie 8 funktioniert: Baue die Flag so, dass sie ein wiederholendes 16-Byte-Präfix-Padding-Schema vor dem eigentlichen Geheimtext hat (z. B. `"FLAG{"` + Padding-Wiederholungen), sodass identische Klartextblöcke im Hex-Dump als identische Chiffretext-Blöcke sichtbar werden.
- Die App gibt **niemals** "Passwort/Key korrekt" oder "falsch" aus — nur Erfolg beim Schreiben der Datei. Verifikation, ob der Angreifer den richtigen Key gefunden hat, geschieht ausschließlich dadurch, dass die entschlüsselten Bytes wie lesbarer Text/ein gültiges Flag-Format aussehen.

Dokumentiere selbst (für dich, als Grundlage für Doku 3) den kompletten Rechenweg: JAR bauen → Gamma-Hash aus der finalen JAR-Datei berechnen → Alpha/Beta ausrechnen → finalen Key ableiten → `flag.enc` mit genau diesem Key erzeugen. Halte diese Werte in einer nicht ausgelieferten Datei `internal-notes/key-derivation-trace.md` fest (NICHT ins finale Abgabe-JAR/Repo für die Studierenden-Ansicht, sondern nur für deine eigene Verifikation und ggf. den Prüfer).

---

## 7. Obfuskierung — mindestens 3 Techniken aus Folie 20

Implementiere einen eigenen kleinen Obfuskierungs-Schritt im Build-Prozess (nutze die **ASM**-Bibliothek für Bytecode-Manipulation), der **nach dem Kompilieren, vor dem Verschlüsseln** auf die Pakete `keyparts`, `crypto`, `vault` angewendet wird. Wähle mindestens diese drei Techniken:

1. **Entfernen aller Debug-Informationen** (Zeilennummern, LocalVariableTable) — kompiliere diese Klassen mit `javac -g:none`.
2. **Kürzen aller Klassen-, Methoden- und Feldnamen** auf bedeutungslose Kurzformen (`a`, `b`, `c1`, ...) via ASM `ClassRemapper`/`SimpleRemapper`.
3. **Verschleierung von Konstanten**: Ersetze direkte Literal-Werte (v. a. in den `KeyFragment*`-Klassen) durch vermeintlich komplexe Bit-Operationen, die zur Laufzeit denselben Wert ergeben.
4. *(optional, als Bonus)* **String-Verschleierung**: Alle Log-/Fehlermeldungen in den geschützten Paketen per einfacher XOR-Kette verschlüsselt ablegen und erst zur Laufzeit entschlüsseln.

Baue das als eigenständiges Build-Modul `tools/obfuscator/` (kleines separates Java-Programm mit ASM-Dependency), das im Build-Skript **vor** dem Verschlüsselungsschritt aufgerufen wird.

---

## 8. Build-Pipeline (`scripts/build.sh`)

Reihenfolge, exakt einzuhalten (wichtig für Reproduzierbarkeit der RE-Anleitung):

1. `mvn compile` — alle Klassen normal kompilieren.
2. Obfuskierungs-Tool auf `target/classes/de/dhbw/securevault/{keyparts,crypto,vault}/*.class` anwenden → Ausgabe nach `target/obfuscated/`.
3. Für jede obfuskierte `.class`-Datei: mit AES-256-GCM (**ein separater, NUR für die Bootstrap-Verschlüsselung genutzter, im Main-Bootstrap sichtbarer Key** — nicht zu verwechseln mit dem Flag-Schlüssel!) verschlüsseln → Ablage als `resources/vault/<name>.bin`.
   *(Hinweis: Dieser Bootstrap-Verschlüsselungs-Key darf ruhig im Klartext im `Main`/Loader-Code sichtbar sein — er schützt nur vor stumpfem `unzip`+`javap`, nicht vor gezieltem Reversing. Das ist beabsichtigt und gehört zur Doku "Schutzkonzept", nicht zur eigentlichen Schwachstelle.)*
4. `flag.enc` mit dem in Abschnitt 5/6 beschriebenen Verfahren erzeugen und in die Ressourcen legen.
5. `mvn package` — finales JAR bauen, das `Main`, `cli`, `loader` im Klartext sowie `resources/vault/*.bin` und `flag.enc` enthält.
6. `scripts/smoke-test.sh` ausführen: JAR starten, End-to-End-Entschlüsselung mit dem korrekten (dir bekannten) Key testen, Ergebnis gegen erwarteten Klartext prüfen.

Alle Schritte müssen per einzelnem Aufruf `./scripts/build.sh` reproduzierbar sein (keine manuellen Zwischenschritte).

---

## 9. Nutzerdokumentation (Anforderung 2, 1P)

`--help`-Ausgabe muss enthalten:
- Verwendungszweck der App (kurz, ohne Bezug auf das Rätsel/den Schutz)
- Alle CLI-Flags (`--decrypt`, `--out <path>`, ggf. `--verify`)
- Ein Beispielaufruf

Halte das zusätzlich in `docs/USAGE.md` fest (kann fast identisch zur `--help`-Ausgabe sein).

---

## 10. RE-Anleitung (Anforderung 3, 5P) — `docs/RE-ANLEITUNG.md`

Muss **exakt reproduzierbar** sein und **jedes Tool namentlich** nennen. Verwende ausschließlich die in der Vorlesung genannten Tools (nicht Ghidra — das ist laut Folien eher für plattformübergreifende Binaries gedacht, nicht der Standardweg für `.class`-Dateien):

Struktur der Anleitung (halte dich an diese Reihenfolge, sie folgt dem tatsächlichen Angriffsweg):

1. **Grobanalyse**: `file Anwendung.jar`, `unzip -l Anwendung.jar` — Struktur erkennen (Main/cli/loader im Klartext, `resources/vault/*.bin` + `flag.enc` als Binärblobs).
2. **Bootstrap disassemblieren**: `javap -c -p -v` auf `Main.class` und `VaultClassLoader.class` — den Bootstrap-Verschlüsselungs-Key und den Ablauf `findClass → decrypt → defineClass` nachvollziehen.
3. **Statische Entschlüsselung der `.bin`-Dateien**: Mit dem aus Schritt 2 gewonnenen Bootstrap-Key ein kleines Hilfsskript (Java oder Python, im Repo unter `tools/dump-decrypt/` mitliefern!) schreiben, das alle `resources/vault/*.bin` entschlüsselt und als `.class`-Dateien ablegt.
4. **Decompilieren der entschlüsselten, aber noch obfuskierten Klassen**: CFR (`cfr KeyFragmentAlpha.class`) oder JD-GUI verwenden. Da Namen gekürzt sind, Klassen anhand ihrer Aufrufreihenfolge (Konstruktor-/Methodenaufrufe) identifizieren, nicht anhand der Namen.
5. **Dynamische Beobachtung der Reflection-Aufrufe**: `jdb` an die laufende JVM attachen (`java -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=5005 -jar Anwendung.jar` + `jdb -attach 5005`), Breakpoints auf `KeyAssembler`/`Method.invoke` setzen, tatsächliche Byte-Werte von Alpha/Beta/Gamma zur Laufzeit auslesen. Alternativ: Frida-Script zum Hooken von `Method.invoke`.
6. **Konstanten-Verschleierung auflösen**: Die verschleierten Bit-Operationen aus Abschnitt 5 manuell oder per kleinem Java-Snippet nachrechnen (exakte Ausdrücke dokumentieren!).
7. **Gamma-Berechnung nachvollziehen**: Den betroffenen Teil der JAR-Datei (z. B. `MANIFEST.MF`) extrahieren, SHA-256 berechnen (`sha256sum` oder `openssl dgst -sha256`), auf 16 Byte kürzen wie im Code.
8. **Key zusammensetzen** und `flag.enc` entschlüsseln: `openssl enc -aes-256-ecb -d -K <hex-key> -in flag.enc -out flag.txt -nopad` (oder äquivalentes Java-Snippet).
9. **(Alternativer/ergänzender Weg ohne vollständige Key-Rekonstruktion)**: ECB-Musteranalyse — Hex-Dump von `flag.enc` (`xxd flag.enc`) auf wiederholende 16-Byte-Blöcke prüfen, die auf das bekannte Padding-Schema hindeuten.

Jeder Schritt braucht: exakten Befehl, erwartete Ausgabe/Beobachtung, Verweis auf die Codestelle, die dabei sichtbar wird. Schreib die Anleitung so, dass ein Kommilitone sie ohne Rückfragen nachvollziehen kann.

---

## 11. KI-Resistenz-Einschätzung (Anforderung 4, 2P) — `docs/KI-RESISTENZ.md`

Sei ehrlich und differenziert (Kriterium verlangt "begründete Analyse", keine Marketing-Aussage):

- **Beschreibe das angenommene Agenten-Setup** konkret, z. B.: "Claude/GPT mit Bash-Zugriff, `javap`, CFR, `jdb`, `unzip`, keine Internet-Recherche, Zeitlimit X Minuten."
- **Ebene 1 (ClassLoader)**: Wo genau scheitert ein rein statisch arbeitender Agent (jadx/CFR direkt auf JAR)? Wo müsste er selbstständig erkennen, dass er dynamisch vorgehen muss (Breakpoints setzen, `defineClass` hooken)?
- **Ebene 2 (Obfuskierung)**: Erschwert Namenskürzung + Konstanten-Verschleierung eher das *Verstehen* als das *reine Auffinden* des Bugs? Differenziere hier klar.
- **Ebene 3 (Krypto-Bug)**: Sei selbstkritisch — sobald der Code lesbar ist, ist `"AES/ECB"` als String-Literal für ein LLM **trivial** als Schwachstelle erkennbar (bekanntes CWE-Muster). Der eigentliche Widerstand liegt fast vollständig in Ebene 1+2, nicht im Krypto-Design selbst. Formuliere das explizit so.
- Nenne, welcher Schritt (vermutlich Schritt 5, dynamische Reflection-Beobachtung) die größte Hürde für ein aktuell übliches Agenten-Setup darstellt, und begründe warum (Werkzeug-Orchestrierung über mehrere Schritte, Notwendigkeit eigener Skript-Erstellung statt reinem Lesen).
- Optional, falls Zeit bleibt: Führe den Agenten-Test tatsächlich einmal durch (mit dir selbst als Agent in einer separaten, kontrollierten Session) und dokumentiere das reale Ergebnis statt nur zu spekulieren.

---

## 12. Reihenfolge deiner Arbeitsschritte als Agent

1. Projektgerüst anlegen (Maven, Paketstruktur aus Abschnitt 3).
2. `crypto/VaultCipher.java`, `vault/FlagStore.java` implementieren + lokal testen (noch ohne ClassLoader/Verschlüsselung, nur Kernlogik).
3. `keyparts/*` implementieren, Determinismus manuell verifizieren, Werte in `internal-notes/key-derivation-trace.md` notieren.
4. `loader/VaultClassLoader.java` + `Main.java` + `cli/*` implementieren.
5. Obfuskierungs-Tool (`tools/obfuscator/`) mit ASM bauen.
6. Build-Pipeline (`scripts/build.sh`) zusammenstellen, End-to-End laufen lassen, `scripts/smoke-test.sh` grün bekommen.
7. Selbst die komplette RE-Anleitung **gegen das fertige, gebaute JAR** durchspielen (jeden Befehl wirklich ausführen!), dabei `docs/RE-ANLEITUNG.md` schreiben.
8. `docs/SCHUTZKONZEPT.md` (nur Ebene 1+2, ohne Krypto-Bug) und `docs/USAGE.md`/`--help` fertigstellen.
9. `docs/KI-RESISTENZ.md` auf Basis der tatsächlichen Erfahrung aus Schritt 7 schreiben.
10. Abschließende Review: Prüfen, ob alle 4 Bewertungskriterien vollständig erfüllt sind (Checkliste aus Abschnitt 1 abhaken).

Fange erst mit dem Schreiben der Dokumentation an, nachdem der Build tatsächlich funktioniert und du die Anleitung selbst einmal komplett durchgespielt hast — nur so ist Kriterium 3 ("reproduzierbar") wirklich erfüllbar.