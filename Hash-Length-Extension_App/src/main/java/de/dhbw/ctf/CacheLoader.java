package de.dhbw.ctf;

// Caching-Hilfsklasse für zukünftige Erweiterungen (aktuell ungenutzt im
// CLI-Pfad). Kein Bezug zu Crypto — dient hier zusätzlich als einer von
// mehreren ladbaren Kandidaten in Main._CCand (siehe dort).
public final class CacheLoader {
    private CacheLoader() {}

    public static String status() {
        return "idle";
    }
}
