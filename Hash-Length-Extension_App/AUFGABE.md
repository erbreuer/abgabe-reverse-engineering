# Aufgabe: VaultAccess

## Was du bekommst

- `vault.jar` — eine ausführbare Java-Anwendung

## Was die Anwendung tut

VaultAccess ist ein Token-Validator. Du übergibst eine Nachricht und einen MAC
(Message Authentication Code). Die Anwendung prüft ob der MAC gültig ist.

```bash
java -jar vault.jar --help
java -jar vault.jar --sample
java -jar vault.jar <message> <mac>
```

## Dein Ziel

Die Anwendung gibt ein Flag aus, wenn die übergebene Nachricht die Rolle `admin`
enthält **und** der MAC gültig ist.

```
Access granted.
FLAG{...}
```

Du hast keinen Admin-Token. Deine Aufgabe ist es, einen gültigen Admin-Token zu
erzeugen — **ohne das interne Secret der Anwendung zu kennen**.

Einen Token mit `--sample` zu beziehen und direkt zu modifizieren wird nicht
funktionieren, da der MAC dann ungültig ist.

## Hinweis

Analysiere die Anwendung. Der MAC-Algorithmus hat eine Schwachstelle, die es
erlaubt einen gültigen Token zu fälschen — ohne Brute-Force und ohne das Secret.
