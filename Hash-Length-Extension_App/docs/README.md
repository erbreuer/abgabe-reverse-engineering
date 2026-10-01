# VaultAccess — Hash-Length-Extension CTF

## Was macht die Anwendung?

VaultAccess ist ein Token-Validator. Ein Nutzer übergibt eine Nachricht und einen
MAC (Message Authentication Code). Die Anwendung prüft ob der MAC gültig ist und
gibt bei der Rolle `admin` ein Flag aus.

## Voraussetzungen

| Tool | Version |
|---|---|
| JDK | 21+ (Zielplattform: Ubuntu Linux 26.04 x86-64), getestet mit JDK 26 |
| Python 3 | 3.8+ (nur für Build-Script) |
| ProGuard | 7.9+ (Java-26-Class-Dateien werden erst ab dieser Version unterstützt) |

## Build

```bash
./build.sh
```

Erzeugt `target/vault.jar`.

## Verwendung

Die Anwendung erwartet die Nachricht als **Hex-String** (kein Klartext). Das
Secret ist fest in der JAR eingebettet (verteilt über mehrere Fragmente) — es
muss **keine** Umgebungsvariable gesetzt werden.

```
java -jar target/vault.jar <message-hex> <mac>
java -jar target/vault.jar --sample
java -jar target/vault.jar --help
```

### Argumente

| Argument | Beschreibung |
|---|---|
| `message-hex` | Die Token-Nachricht, hex-kodiert (z.B. `757365723d6775657374`) |
| `mac` | SHA-256 MAC als Hex-String |
| `--sample` | Gibt eine gültige Beispiel-Nachricht (hex) mit MAC aus |
| `--help` | Zeigt die Hilfe |

### Beispiele

```bash
# Startpunkt: gültige Werte anzeigen
java -jar target/vault.jar --sample

# Zugriff mit gültigem Token (gibt "Access denied. You are: guest")
java -jar target/vault.jar \
    757365723d6775657374 \
    2c38fd78f54e6c582f5b87421920e2501405c1d11a7c77eabd537409d18ce938

# Ungültiger MAC
java -jar target/vault.jar \
    757365723d6775657374 wrongmac
```

## Projektstruktur

```
Hash-Length-Extension_App/
├── src/main/java/de/dhbw/ctf/
│   ├── Main.java          # Einstiegspunkt + EncryptedClassLoader
│   ├── Crypto.java        # MAC-Logik + eingebettetes Secret (wird verschlüsselt ins JAR gepackt)
│   ├── VersionInfo.java   # Schlüsselfragment des Loaders
│   ├── RuntimeTag.java    # Weitere Schlüsselfragmente (Loader + Secret)
│   ├── CacheLoader.java   # Decoy-Klasse
│   └── ConfigStore.java   # Decoy-Klasse
├── proguard/
│   ├── crypto.pro         # ProGuard-Config für Crypto.class
│   └── main.pro           # ProGuard-Config für Main.class + EncryptedClassLoader
├── build.sh               # Build-Script (javac → ProGuard → Hash-Key-Verschlüsselung → jar)
├── AUFGABE.md             # Aufgabenstellung für den Löser
├── NUTZERDOKU.md          # Nutzerdokumentation (was die Anwendung tut)
├── README.md              # Diese Datei (Build + Betrieb)
├── DOKU.md                # RE-Dokumentation (Schwachstelle + Lösungsweg)
└── KI-EINSCHAETZUNG.md    # KI-Einschätzung zur RE-Erschwerung
```
