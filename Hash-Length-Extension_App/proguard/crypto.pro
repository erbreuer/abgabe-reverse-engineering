# ProGuard-Konfiguration für Crypto.class.
#
# Crypto wird von Main ausschließlich reflektiv geladen und aufgerufen
# (loader.loadClass(...).getMethod("a", ...).invoke(...)) — es gibt keine
# Compile-Zeit-Referenz. Die sechs öffentlichen Methoden müssen deshalb
# exakt mit Namen und Signatur erhalten bleiben, sonst schlägt die
# Reflection in Main zur Laufzeit mit NoSuchMethodException fehl.
#
# Alles andere (private Felder/Methoden, Kontrollfluss) darf und soll
# ProGuard umbenennen bzw. verschleiern.
#
# -basedirectory macht die folgenden Pfade relativ zum Projektwurzel-
# verzeichnis, unabhängig davon, von wo aus proguard aufgerufen wird
# (ProGuard löst relative Pfade sonst relativ zur .pro-Datei selbst auf).
-basedirectory ..

# Injar ist das ganze Klassenverzeichnis mit Filter auf Crypto.class, damit
# die Paketstruktur (de/dhbw/ctf/) für ProGuard konsistent bleibt — ein
# einzelnes .class-File ohne Paketordner darüber irritiert den Reader.
-injars       target/classes(de/dhbw/ctf/Crypto.class)
-outjars      target/obfuscated/crypto
-libraryjars  <java.home>/jmods/java.base.jmod(!**.jar;!module-info.class)

-keep public class de.dhbw.ctf.Crypto {
    public static java.lang.String a(byte[]);
    public static java.lang.String b(byte[]);
    public static java.lang.String c();
    public static java.lang.String d();
    public static java.lang.String e();
    public static int f();
}

# Kein Shrinking: die Injar enthält bereits nur die eine gewünschte Klasse
# — es gibt nichts wegzulassen, nur umzubenennen und zu verschleiern.
-dontshrink
-dontoptimize
-overloadaggressively
-allowaccessmodification

# Debug-Informationen entfernen (Standardverhalten ohne -keepattributes,
# hier zur Klarheit explizit dokumentiert statt implizit gelassen).
-keepattributes !LineNumberTable,!LocalVariableTable,!LocalVariableTypeTable
