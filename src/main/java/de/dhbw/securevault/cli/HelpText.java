package de.dhbw.securevault.cli;

public final class HelpText {

    private HelpText() {
    }

    public static String text() {
        return """
                SecureVault-RE -- verschluesselter Datentresor

                Verwendung:
                  java -jar Anwendung.jar --decrypt [--out <pfad>]
                  java -jar Anwendung.jar --help

                Beschreibung:
                  SecureVault-RE verwaltet einen verschluesselt abgelegten Eintrag
                  ("Tresor") und kann dessen Inhalt bei Aufruf entschluesseln und
                  ausgeben.

                Optionen:
                  --decrypt         Entschluesselt den im Programm hinterlegten Tresor-Eintrag.
                  --out <pfad>      Schreibt das Ergebnis in die angegebene Datei
                                    statt es auf stdout auszugeben.
                  --help            Zeigt diese Hilfe an.

                Beispiel:
                  java -jar Anwendung.jar --decrypt --out ergebnis.txt
                """;
    }
}
