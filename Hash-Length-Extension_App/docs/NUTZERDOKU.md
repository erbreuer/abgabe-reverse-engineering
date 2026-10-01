# Nutzerdokumentation

VaultAccess ist ein Token-Validator:
Man übergibt eine
Nachricht und einen zugehörigen MAC (Message Authentication Code). Die Anwendung
prüft, ob der MAC zur Nachricht passt. Weist die Nachricht den Nutzer `admin`
aus und ist der MAC gültig, gibt die Anwendung ein Flag aus.


## Aufruf

Folgendes wird in der
Hilfe `java -jar vault.jar --help` ausgegeben:

    VaultAccess - Token Validator

    Usage:
      java -jar vault.jar <message-hex> <mac>
      java -jar vault.jar --sample
      java -jar vault.jar --help

    Arguments:
      message-hex  The access token message, hex-encoded
      mac          SHA-256 MAC for the message (hex)

    Examples:
      java -jar vault.jar --sample
      java -jar vault.jar 757365723d6775657374 <mac>



## Verhalten

Je nach Eingabe antwortet die Anwendung mit einer von drei Meldungen:

- `Access denied. Invalid MAC.` - der MAC passt nicht zur Nachricht.
- `Access denied. You are: guest` - der MAC ist gültig, die Nachricht weist
  aber nicht den Nutzer `admin` aus.
- `Access granted.` gefolgt vom Flag - der MAC ist gültig und die Nachricht
  weist `admin` aus.

Einen `guest`-Token aus `--sample` einfach auf `admin` umzuschreiben
funktioniert nicht, da der MAC danach nicht mehr passt.
