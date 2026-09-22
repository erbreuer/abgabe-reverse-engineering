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

Die Anwendung erwartet die Nachricht als **Hex-String** (kein Klartext).

```
VAULT_SECRET=<secret> java -jar target/vault.jar <message-hex> <mac>
VAULT_SECRET=<secret> java -jar target/vault.jar --sample
VAULT_SECRET=<secret> java -jar target/vault.jar --help
```

### Argumente

| Argument | Beschreibung |
|---|---|
| `message-hex` | Die Token-Nachricht, hex-kodiert (z.B. `757365723d6775657374`) |
| `mac` | SHA-256 MAC als Hex-String |
| `--sample` | Gibt eine gültige Beispiel-Nachricht (hex) mit MAC aus |
| `--help` | Zeigt die Hilfe |

Die Umgebungsvariable `VAULT_SECRET` muss beim Start gesetzt sein.

### Beispiele

```bash
# Startpunkt: gültige Werte anzeigen
VAULT_SECRET=s3cr3t\!X java -jar target/vault.jar --sample

# Zugriff mit gültigem Token (gibt "Access denied. You are: guest")
VAULT_SECRET=s3cr3t\!X java -jar target/vault.jar \
    757365723d6775657374 \
    24af60bad400dee40dee5745738a122f2af594f7680d1a63002043389f8c7a6b

# Ungültiger MAC
VAULT_SECRET=s3cr3t\!X java -jar target/vault.jar \
    757365723d6775657374 wrongmac
```

## Projektstruktur

```
Hash-Length-Extension_App/
├── src/main/java/de/dhbw/ctf/
│   ├── Main.java          # Einstiegspunkt + EncryptedClassLoader
│   └── Crypto.java        # MAC-Logik (wird verschlüsselt ins JAR gepackt)
├── build.sh               # Build-Script
├── AUFGABE.md             # Aufgabenstellung für Schüler
├── README.md              # Diese Datei (Nutzerdokumentation)
├── LOESUNG.md             # RE-Dokumentation (Schwachstelle + Lösungsweg)
└── KI-EINSCHAETZUNG.md    # KI-Einschätzung zur RE-Erschwerung
```
