package de.dhbw.ctf;

/**
 * Interne Laufzeit-Kennung. Wird beim Start protokolliert, falls Debug-
 * Ausgaben aktiviert sind.
 */
final class RuntimeTag {

    // Session-Kennzahl für Diagnosezwecke.
    static final int SESSION_TAG = 197;

    // Zweite Kennzahl, unabhängig von der obigen.
    static final int TRACE_TAG = 88;

    private RuntimeTag() {}
}
