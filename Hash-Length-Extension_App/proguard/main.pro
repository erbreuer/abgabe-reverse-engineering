# ProGuard-Konfiguration für Main.class, Main$EncryptedClassLoader.class
# und VersionInfo.class — die drei gehören zusammen (VersionInfo liefert
# ein Schlüsselfragment an den Loader) und werden als ein Injar mit Filter
# eingespeist, damit ProGuard die Referenzen zwischen den Klassen auflösen
# kann.
#
# main() ist der einzige externe Einstiegspunkt (JAR-Manifest verweist
# darauf) und muss erhalten bleiben. Alles andere — insbesondere die
# Namen der Hilfsmethoden/-felder des Loaders (_d, _key, _manifestTag,
# _K1, _C, _Ma..._Mf) und der Kontrollfluss — darf umbenannt und
# verschleiert werden.
#
# -basedirectory macht die folgenden Pfade relativ zum Projektwurzel-
# verzeichnis, unabhängig davon, von wo aus proguard aufgerufen wird
# (ProGuard löst relative Pfade sonst relativ zur .pro-Datei selbst auf).
-basedirectory ..

-injars       target/classes(de/dhbw/ctf/Main.class,de/dhbw/ctf/Main$EncryptedClassLoader.class,de/dhbw/ctf/VersionInfo.class)
-outjars      target/obfuscated/main
-libraryjars  <java.home>/jmods/java.base.jmod(!**.jar;!module-info.class)

-keep public class de.dhbw.ctf.Main {
    public static void main(java.lang.String[]);
}

-dontshrink
-dontoptimize
-overloadaggressively
-allowaccessmodification

-keepattributes !LineNumberTable,!LocalVariableTable,!LocalVariableTypeTable
