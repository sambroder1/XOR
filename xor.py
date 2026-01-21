import argparse
import sys
from pathlib import Path

# Nyckel delen
# Syftet är att nyckeln ska bli till bytes oavsett input.
def parse_key(key_str):
    """
    Tolkar XOR-nyckeln som användaren skickar in via CLI.

    Stödjer tre varianter:
    1) Hex-byte:   0x41
    2) Hex-sträng: 414243
    3) Text:       secret

    Returnerar alltid nyckeln som bytes.
    """
    try:
        # Hex-byte, t.ex. 0x41 -> 65 decimal
        if key_str.startswith("0x"):
            return bytes([int(key_str, 16)])
            
        # Om hela strängen består av hex-tecken tolkar vi den som hex-sträng
        # Returnerar True om alla tecken i strängen är hexadecimala, sedan konverteras till bytes
        if all(c in "0123456789abcdefABCDEF" for c in key_str):
            return bytes.fromhex(key_str)

        # Annars behandlas nyckeln som vanlig text
        else:
            return key_str.encode()

    

    except ValueError:
        raise ValueError("Ogiltigt nyckelformat")

# Encrypt delen
def xor_encrypt(data, key):
    """
    XOR-krypterar data med en upprepande nyckel.

    XOR är reversibelt, vilket betyder att samma funktion
    kan användas för både kryptering och dekryptering.
    """
    # Gör om data till mutable lista av bytes
    result = bytearray()

    for i, byte in enumerate(data):
        # i % len(key) gör att nyckeln loopar när den tar slut
        result.append(byte ^ key[i % len(key)])

        # byte = 0x90 -> 10010000
        # key  = 0x41 -> 01000001
        # --------------------
        # xor  = 11010001 -> 0xD1

    return bytes(result)

     

# Output format delen
def format_output(data, format_out):
    """
    Formaterar den krypterade shellcoden till valt output-format.
    """
    if format_out == "raw":
        # Rå bytes (binär fil)
        return data

    if format_out == "python":
        # Python byte-sträng, t.ex. b"\x90\x90\xcc"
        return "buf = b\"" + "".join(f"\\x{b:02x}" for b in data) + "\""
         
    if format_out == "c": 
        # C-array för inbäddning i loader
        values = ", ".join(f"0x{b:02X}" for b in data)
        return f"unsigned char buf[] = {{ {values} }};"
         
    raise ValueError("Okänt format")

# Huvudfunktionen
def main():
    """
    Huvudfunktion:
    - parsar argument
    - läser inputfil
    - XOR-krypterar shellcode
    - skriver output till fil
    """

    parser = argparse.ArgumentParser(
        description="XOR-krypterar shellcode för obfuskering"
    )

    parser.add_argument(
        "--in",
        dest="input_file",
        required=True,
        help="Fil med rå shellcode"
    )

    parser.add_argument(
        "--out",
        dest="output_file",
        required=True,
        help="Outputfil"
    )

    parser.add_argument(
        "--key",
        required=True,
        help="XOR-nyckel (hex eller text)"
    )

    parser.add_argument(
        "--format",
        choices=["raw", "python", "c"],
        default="raw",
        help="Output-format"
    )

    args = parser.parse_args()

    input_path = Path(args.input_file)
    output_path = Path(args.output_file)

    # Kontrollera att inputfilen finns
    if not input_path.exists():
        print("Fel: inputfilen finns inte", file=sys.stderr)
        sys.exit(1)
    
    # Tolka XOR-nyckeln
    try:
        key = parse_key(args.key)
    except ValueError as e:
        print(f"Fel: {e}", file=sys.stderr)
        sys.exit(1)
        
    if not key:
        print("Fel: nyckeln får inte vara tom", file=sys.stderr)
        sys.exit(1)

    # Läs in shellcode som rå bytes
    try:
        shellcode = input_path.read_bytes()
    except IOError:
        print("Fel: kunde inte läsa inputfilen", file=sys.stderr)
        sys.exit(1)

    # XOR-kryptera shellcoden
    encrypted = xor_encrypt(shellcode, key)

    

    # Formatera och skriv output
    try:
        formatted = format_output(encrypted, args.format)

        if args.format == "raw":
            # Binär output
            output_path.write_bytes(formatted)
        else:
            # Textbaserad output (C/Python)
            output_path.write_text(formatted)

    except IOError:
        print("Fel: kunde inte skriva outputfilen", file=sys.stderr)
        sys.exit(1)

    

    # Information efter körning
    print(f"Krypterade {len(shellcode)} byte")
    print(f"Resultat sparat i {output_path}")
    print(f"Använt format: {args.format}")


if __name__ == "__main__":
    main()


# Exempel användning:   python xor.py --in shellcode.bin --out encrypted.bin --key 0x41 --format raw
# python xor.py --help