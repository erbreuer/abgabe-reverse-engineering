# Reverse Engineering – Lösungsweg

---

## Aufgabe 1: EncryptMe (`encrypt/`)

**Gegeben:** `encryptme-x86-64`, `Image.png.encrypted`  
**Ziel:** `Image.png.encrypted` entschlüsseln

---

### Schritt 1: Binary erkunden

```bash
file encryptme-x86-64
```
→ ELF 64-bit, dynamisch gelinkt, **not stripped** (Symbole vorhanden)

```bash
strings encryptme-x86-64
```
Relevante Funde:
- `Usage: %s <password> <encrypt|decrypt>` → Programm liest von stdin, schreibt nach stdout
- Funktionsnamen: `xor_crypt`, `rng_init`, `rng_next`, `password_to_seed` → verrät den Algorithmus

---

### Schritt 2: Algorithmus rekonstruieren (objdump)

```bash
objdump -d encryptme-x86-64
```

Vier Funktionen analysieren:

#### `password_to_seed` — djb2-Hash
```
Startwert: seed = 0x1505
Schleife:  seed = seed * 33 + char   (für jeden Buchstaben)
Rückgabe:  seed
```
Wichtig: In `main` wird `seed & 0xFFFFFF` übergeben → **nur 24 Bit** des Seeds werden verwendet.

Erkennbar im Disassembly:
```asm
movq $0x1505, -0x8(%rbp)      ; Startwert
shlq $0x5, %rax               ; * 32
leaq (%rdx,%rax), %rcx        ; + seed = * 33
```
Und in main:
```asm
andl $0xffffff, %eax          ; Seed auf 24 Bit kürzen
```

#### `rng_init`
Speichert den Seed einfach als State-Pointer (8 Bytes malloc).

#### `rng_next` — Linear Congruential Generator (LCG)
```
state = (state * 0x41C64E6D + 0x3039) & 0x7FFFFFFF
return (state >> 8) & 0xFF
```
Erkennbar:
```asm
imulq $0x41c64e6d, %rax, %rax
addq  $0x3039, %rax
andl  $0x7fffffff, %eax
shrq  $0x8, %rax
```

#### `xor_crypt`
```
for i in range(length):
    output[i] = input[i] XOR rng_next()
```

---

### Schritt 3: Schwachstellen erkennen

1. **Seed nur 24 Bit** → maximal 16 Millionen mögliche Seeds
2. **RNG gibt nur Bits 8–15 zurück** (`>> 8` dann `& 0xFF`) → die oberen 8 Bits des Seeds haben keinen Einfluss auf den Keystream → effektiv nur **16-Bit-Seed** (65.536 Möglichkeiten)

---

### Schritt 4: Known-Plaintext-Angriff

Der Dateiname `Image.png.encrypted` verrät das Format. PNG-Dateien beginnen **immer** mit demselben 8-Byte-Magic:

```
89 50 4E 47 0D 0A 1A 0A
```

Ersten 8 verschlüsselten Bytes prüfen:
```bash
xxd Image.png.encrypted | head -2
```

Keystream ableiten:
```
keystream[i] = encrypted[i] XOR known_plaintext[i]
```

---

### Schritt 5: Seed finden

Alle 65.536 Seeds durchprobieren: welcher liefert denselben Keystream?

```python
for seed in range(0x10000):
    state = seed
    match = True
    for k in keystream[:8]:
        state = (state * 0x41C64E6D + 0x3039) & 0x7FFFFFFF
        if (state >> 8) & 0xFF != k:
            match = False
            break
    if match:
        print(hex(seed))  # → 0x5fce
```

---

### Schritt 6: Datei entschlüsseln

```python
with open('Image.png.encrypted', 'rb') as f:
    data = f.read()

state = 0x5fce
result = bytearray()
for b in data:
    state = (state * 0x41C64E6D + 0x3039) & 0x7FFFFFFF
    result.append(b ^ ((state >> 8) & 0xFF))

with open('Image.png', 'wb') as f:
    f.write(result)
```

Ergebnis prüfen:
```bash
file Image.png
```

---

---

## Aufgabe 2: EncryptMe2 (`Encryptme2/`)

**Gegeben:** `encryptme2-x86_64`, `poem.txt.encrypted`  
**Ziel:** `poem.txt.encrypted` entschlüsseln

---

### Schritt 1: Binary erkunden

```bash
file encryptme2-x86_64
```
→ ELF 64-bit, **stripped** (keine Funktionsnamen!)

```bash
strings encryptme2-x86_64
```
Relevante Funde:
- `Usage: %s <password> <encrypt|decrypt> <input_file> <output_file>` → liest/schreibt Dateien
- `Seed (base64): %lu` → Seed wird ausgegeben
- `[Total bytes to decrypt: %lu]` → Datei enthält die Länge gespeichert
- `Error: Invalid password or corrupted file` → Integritätsprüfung vorhanden

---

### Schritt 2: Dateistruktur verstehen (objdump)

```bash
objdump -d encryptme2-x86_64
objdump -s -j .rodata encryptme2-x86_64
```

Im Disassembly sucht man nach `fseek`-Aufrufen um die Dateistruktur zu verstehen:

```asm
movl $-0x8, %rsi
movl $0x2, %edx          ; SEEK_END
callq fseek              ; fseek(file, -8, SEEK_END)
...
callq fread              ; fread 8 bytes
xorq %rax, 0x38(%rsp)   ; XOR mit key
callq ftell              ; ftell → aktuelle Position = Dateigröße - 8
```

**Dateiformat:**
```
[ verschlüsselte Nutzdaten ] [ 8 Byte: Länge XOR Key ]
```

Die letzten 8 Bytes sind die Plaintext-Länge, XOR'd mit dem Passwort-Key.

---

### Schritt 3: Key-Berechnung verstehen

Im Disassembly (nach dem `strncpy` mit n=8):

```asm
movzbl 0x40(%rsp), %eax   ; char[0]
...
shlq $0x8, %rax            ; char[1] << 8
shlq $0x10, %r9            ; char[2] << 16
...                         ; bis char[7] << 56
orq %r9, %rax
...
```

**Key = Little-Endian-Interpretation der ersten 8 Passwort-Bytes:**
```python
key = int.from_bytes(password[:8].encode().ljust(8, b'\x00'), 'little')
```

---

### Schritt 4: Passwort aus der Länge ableiten

```bash
xxd poem.txt.encrypted | tail -1
```

Die letzten 8 Bytes des Files = `plaintext_length XOR key`.  
Die Plaintext-Länge = Dateigröße - 8 (wenn das ganze Payload verschlüsselt ist):

```bash
wc -c poem.txt.encrypted   # → 1273
# → plaintext_length = 1265
```

Damit gilt:
```python
key = stored_last_8_bytes XOR 1265
```

Key-Bytes auf Lesbarkeit prüfen:
```python
stored = int.from_bytes(data[-8:], 'little')   # 0x6863696c6b726957
key    = stored ^ 1265                          # 0x6863696c6b726957 ^ 0x4F1
key_bytes = key.to_bytes(8, 'little')           # b'Wirklich'
```
→ Passwort: **`Wirklich`**

---

### Schritt 5: Seed-Berechnung verstehen

Im Disassembly (die lange Berechnungskette nach `strncpy`):

```asm
movzbl 0x40(%rsp), %eax
addq $0x2b5a5, %rax       ; char[0] + 0x2b5a5
imulq $0x21, %rax, %rax   ; * 33
addq %rax, %rdx            ; + char[1]
imulq $0x21, %rdx, %rdx   ; * 33
...                         ; wiederholt für alle 8 Zeichen
```

**Seed-Algorithmus** (djb2-Variante, Startwert `0x2b5a5`, nur erste 8 Zeichen):
```python
seed = password[0] + 0x2b5a5
for c in password[1:8]:
    seed = seed * 33 + c
```

Unterschied zu Aufgabe 1: **kein `& 0xFFFFFF`** → voller 64-bit Seed.

---

### Schritt 6: RNG-Unterschied beachten

Beim **ersten** RNG-Schritt arbeitet der LCG mit dem vollen 64-bit Seed:

```asm
imulq $0x41c64e6d, %rcx, %rcx   ; 64-bit Multiplikation
leaq 0x3039(%rcx), %rdx          ; + 0x3039 (64-bit)
xorb %dh, (%rax)                 ; XOR mit Bits 8-15 von rdx
andl $0x7fffffff, %ecx           ; erst DANACH auf 32-bit kürzen
```

```python
# Erster Schritt:
state_full = seed * 0x41C64E6D + 0x3039        # 64-bit
xor_byte   = (state_full >> 8) & 0xFF
state      = state_full & 0x7FFFFFFF           # für alle weiteren Schritte

# Folgeschritte (normal):
state = (state * 0x41C64E6D + 0x3039) & 0x7FFFFFFF
xor_byte = (state >> 8) & 0xFF
```

---

### Schritt 7: Datei entschlüsseln

```python
password = "Wirklich"
pw = password[:8].encode().ljust(8, b'\x00')

# Seed berechnen
seed = pw[0] + 0x2b5a5
for c in pw[1:8]:
    seed = seed * 33 + c

# Länge aus Dateianhang
key = int.from_bytes(pw, 'little')
with open('poem.txt.encrypted', 'rb') as f:
    data = f.read()
plaintext_len = int.from_bytes(data[-8:], 'little') ^ key

# Entschlüsseln
state = seed
result = bytearray()
for b in data[:plaintext_len]:
    state_full = state * 0x41C64E6D + 0x3039
    result.append(b ^ ((state_full >> 8) & 0xFF))
    state = state_full & 0x7FFFFFFF

with open('poem.txt', 'wb') as f:
    f.write(result)
```

---

## Unterschiede auf einen Blick

| | EncryptMe | EncryptMe2 |
|---|---|---|
| Symbole | vorhanden (not stripped) | fehlen (stripped) |
| I/O | stdin → stdout | Dateipfade als Argumente |
| Seed-Startwert | `0x1505` | `0x2b5a5` |
| Passwort-Zeichen | alle | nur erste **8** |
| Seed-Truncation | `& 0xFFFFFF` (24 Bit) | keiner (64 Bit) |
| Erster RNG-Schritt | 32-bit | **64-bit** (erst danach kürzen) |
| Dateiformat | nur Nutzdaten | Nutzdaten + **8-Byte Länge am Ende** |
| Passwort-Angriff | Known-Plaintext auf PNG-Header | Known-Plaintext auf Längenfeld |
