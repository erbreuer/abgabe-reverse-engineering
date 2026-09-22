# VaultAccess — Hash-Length-Extension CTF

## Was macht die Anwendung?

VaultAccess ist ein Token-Validator. Ein Nutzer übergibt eine Nachricht und einen
MAC (Message Authentication Code). Die Anwendung prüft ob der MAC gültig ist und
gibt bei der Rolle `admin` ein Flag aus.

## Voraussetzungen

| Tool | Version |
|---|---|
| JDK | 21+ (Zielplattform: Ubuntu Linux 26.04 x86-64) |
| Python 3 | 3.8+ (nur für Build-Script) |

## Build

```bash
./build.sh
```

Erzeugt `target/vault.jar`.

## Verwendung

```
java -jar target/vault.jar <message> <mac>
java -jar target/vault.jar --sample
java -jar target/vault.jar --help
```

### Argumente

| Argument | Beschreibung |
|---|---|
| `message` | Die Token-Nachricht, z.B. `user=guest` |
| `mac` | SHA-256 MAC als Hex-String |
| `--sample` | Gibt eine gültige Beispiel-Nachricht mit MAC aus |
| `--help` | Zeigt diese Hilfe |

### Beispiele

```bash
# Startpunkt: gültige Werte anzeigen
java -jar target/vault.jar --sample

# Zugriff mit gültigem Token (gibt "Access denied. You are: guest")
java -jar target/vault.jar "user=guest" 24af60bad400dee40dee5745738a122f2af594f7680d1a63002043389f8c7a6b

# Ungültiger MAC
java -jar target/vault.jar "user=guest" wrongmac
```

## Projektstruktur

```
Hash-Length-Extension_App/
├── src/main/java/de/dhbw/ctf/
│   ├── Main.java          # Einstiegspunkt + EncryptedClassLoader
│   └── Crypto.java        # MAC-Logik (wird verschlüsselt ins JAR gepackt)
├── build.sh               # Build-Script
├── README.md              # Diese Datei (Nutzerdokumentation)
├── LOESUNG.md             # RE-Dokumentation (Schwachstelle + Lösungsweg)
└── KI-EINSCHAETZUNG.md    # KI-Einschätzung zur RE-Erschwerung
```
