package de.dhbw.ctf;

/**
 * Build-Metadaten. Nicht sicherheitsrelevant im eigentlichen Sinn — wird u.a.
 * von der Loader-Initialisierung mit einbezogen.
 */
final class VersionInfo {

    static final String NAME = "VaultAccess";

    // Build-Kennzahl, dritter Bestandteil der Loader-Initialisierung.
    static final int BUILD_TAG = 245;

    private VersionInfo() {}
}
