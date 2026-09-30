package de.dhbw.ctf;

// Hält statische Konfigurationswerte (aktuell ungenutzt im CLI-Pfad).
// Besitzt zufällig ebenfalls eine Methode namens a(), allerdings ohne
// Parameter -- reicht für getMethod("a", byte[].class) nicht aus. Dient
// hier zusätzlich als einer von mehreren ladbaren Kandidaten in
// Main._CCand (siehe dort).
public final class ConfigStore {
    private ConfigStore() {}

    public static String a() {
        return "default";
    }
}
