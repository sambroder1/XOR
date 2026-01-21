# XOR Shellcode Encryptor

## Beskrivning
Detta verktyg är ett enkelt Python-skript som används för att XOR-kryptera rå shellcode.  
Syftet är **obfuskering**, inte stark kryptering – målet är att göra shellcode svårare att läsa och analysera direkt i binär form.

Skriptet tar in en fil med rå shellcode (t.ex. genererad med msfvenom), applicerar XOR med en valfri nyckel och skriver ut resultatet i olika format som kan användas i t.ex. Python eller C-baserade loaders.

---

## Hur man kör verktyget

Skriptet körs från kommandoraden med Python 3.

## Grundsyntax:

```bash
python xor.py --in <inputfil> --out <outputfil> --key <nyckel> --format <format>
```

## Argument

`--in`
Fil som innehåller rå shellcode (binär fil)

`--out`
Fil där den krypterade outputen sparas

`--key`
XOR-nyckel. Kan anges som:

hex-byte (`0x41`)

hex-sträng (`414243`)

vanlig text (`secret`)

`--format`
Output-format:

`raw` (standard)
`python`
`c`

## Exempelkommandon
1. XOR-kryptera shellcode till binär fil
```bash
python xor.py --in shellcode.bin --out encrypted.bin --key 0x41 --format raw
```
2. Generera Python-format
```bash
python xor.py --in shellcode.bin --out encrypted.txt --key secret --format python
```

3. Generera C-array för loader
```bash
python xor.py --in shellcode.bin --out encrypted.c --key 414243 --format c
```


## Exempel på output-format
Raw (binärt)

Output är en binär fil (.bin) som innehåller XOR-krypterade bytes.
Den är inte tänkt att läsas manuellt.

Python-format
```python
buf = b"\x90\xaf\x13\x42\xff\x01"
```


Detta format kan klistras in direkt i ett Python-skript.

C-format
```c
unsigned char buf[] = {
    0x90, 0xAF, 0x13, 0x42, 0xFF, 0x01
};
```

Detta används typiskt i en C-baserad loader där bufferten dekrypteras i minnet innan exekvering.