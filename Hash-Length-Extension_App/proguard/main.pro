# ProGuard-Konfiguration für Main.class, Main$EncryptedClassLoader.class,
# VersionInfo.class und RuntimeTag.class — die vier gehören zusammen
# (VersionInfo und RuntimeTag liefern Schlüsselfragmente an den Loader)
# und werden als ein Injar mit Filter eingespeist, damit ProGuard die
# Referenzen zwischen den Klassen auflösen kann.
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

-injars       target/classes(de/dhbw/ctf/Main.class,de/dhbw/ctf/Main$EncryptedClassLoader.class,de/dhbw/ctf/Main$_Cand.class,de/dhbw/ctf/VersionInfo.class,de/dhbw/ctf/RuntimeTag.class,de/dhbw/ctf/CacheLoader.class,de/dhbw/ctf/ConfigStore.class)
-outjars      target/obfuscated/main
-libraryjars  <java.home>/jmods/java.base.jmod(!**.jar;!module-info.class)

-keep public class de.dhbw.ctf.Main {
    public static void main(java.lang.String[]);
}

# CacheLoader/ConfigStore sind ladbare Decoy-Klassen für Main._CCand (siehe
# dort): loadClass() muss sie unter ihrem exakten, im Quellcode als
# XOR-kodierter Kandidat fest verdrahteten Namen finden können — ProGuard
# darf ihre Klassennamen deshalb nicht umbenennen (anders als bei den
# reinen Lockvogel-Schlüsseln auf _C, die absichtlich nie eine gültige
# Klasse treffen). ConfigStore.a() muss ebenfalls exakt benannt bleiben,
# da erst der Signaturvergleich (a() vs. a(byte[])) sie als falschen
# Kandidaten entlarvt -- eine umbenannte Methode würde diesen Vergleich
# gegenstandslos machen.
-keep public class de.dhbw.ctf.CacheLoader {
    public static java.lang.String status();
}

-keep public class de.dhbw.ctf.ConfigStore {
    public static java.lang.String a();
}

# Crypto._secret() referenziert Main.EncryptedClassLoader._key() (siehe
# crypto.pro). Dieser Durchgang läuft deshalb zuerst und schreibt sein
# Umbenennungs-Mapping heraus; crypto.pro wendet es per -applymapping an,
# damit Crypto.class dieselben (verschleierten) Namen für Main und
# Main$EncryptedClassLoader verwendet wie das tatsächlich ausgelieferte,
# von main.pro erzeugte Main.class.
-printmapping target/main-mapping.txt

-dontshrink
-dontoptimize
-overloadaggressively
-allowaccessmodification

-keepattributes !LineNumberTable,!LocalVariableTable,!LocalVariableTypeTable
