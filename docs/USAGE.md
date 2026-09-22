# SecureVault-RE — Nutzerdokumentation

## Zweck

SecureVault-RE verwaltet einen verschlüsselt abgelegten Tresor-Eintrag und
kann dessen Inhalt bei Aufruf entschlüsseln und ausgeben.

## Voraussetzungen

- Java 21 oder neuer (getestet mit Java 26 / SapMachine)
- Kein Netzwerkzugriff notwendig, keine externen Abhängigkeiten zur
  Laufzeit

## Aufruf

```
java -jar Anwendung.jar --decrypt [--out <pfad>]
java -jar Anwendung.jar --help
```

## Optionen

| Option | Beschreibung |
|---|---|
| `--decrypt` | Entschlüsselt den im Programm hinterlegten Tresor-Eintrag. |
| `--out <pfad>` | Schreibt das Ergebnis in die angegebene Datei statt es auf stdout auszugeben. |
| `--help` | Zeigt die Hilfe an. |

## Beispiele

Entschlüsselten Inhalt auf stdout ausgeben:

```
$ java -jar Anwendung.jar --decrypt
FLAG{ecb_leaks_repeated_blocks_and_reflection_hides_the_key}
```

Entschlüsselten Inhalt in eine Datei schreiben:

```
$ java -jar Anwendung.jar --decrypt --out ergebnis.txt
$ cat ergebnis.txt
FLAG{ecb_leaks_repeated_blocks_and_reflection_hides_the_key}
```

## Exit-Codes

| Code | Bedeutung |
|---|---|
| `0` | Erfolgreich |
| `1` | Fehler bei der Verarbeitung des Tresors |
| `2` | Ungültige Kommandozeilenargumente |
