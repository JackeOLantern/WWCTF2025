#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WWCTF - Reverse 'Stretching' (verbeux + masquage du flag)

- Déchiffre 6 blocs via TEA-like (32 cycles) avec delta custom 0xB979379E.
- Garde les 48 octets déchiffrés intacts pour la vérif memcmp(..., 0x29).
- Affiche PAR DÉFAUT le flag masqué :
    wwf{From_The_xxxxx_To_The_xxx_Pzzzzzzzz_yyyy_Be_Free}
- --reveal : affiche le vrai flag.

Remarques :
- TEA : bloc 64 bits (2x uint32), 32 cycles recommandés ; structure Feistel. (cf. TEA)  # doc
- fgets lit le '\n' s'il est présent ; ne pas l'oublier si on alimente l'exe.           # doc
"""
import argparse
from typing import List, Tuple

ROUNDS = 32
DELTA  = 0xB979379E

# Clé initiale (4 x uint32) observée dans FUN_140001836
INIT_KEY = [0xB2594E64, 0x36580AF5, 0xB41D6E56, 0x9048ACE6]

# "Cipher-text attendu" : 6 imm64 (tels que dans le code, donc bytes en mémoire LE)
CT64 = [
    0x8565D2ADB33A2D07,
    0xD4A4AC946233D52E,
    0x2412AD1C3B592793,
    0x84CA0A89B2C53C5C,
    0x0A776DE635107493,
    0xABB663DC48002375,
]

MEMCMP_LEN = 0x29  # 41 octets comparés par memcmp

MASKED_TARGET = "From_The_xxxxx_To_The_xxx_Pzzzzzzzz_yyyy_Be_Free"

# ------------------------------- utilitaires --------------------------------
def vprint(level: int, need: int, *a, **k):
    if level >= need:
        print(*a, **k)

def hexdump(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)

def rol8(v: int, n: int) -> int:
    n &= 7
    return ((v << n) | (v >> (8 - n))) & 0xFF

def mutate_key(words: List[int], verbose=0) -> List[int]:
    """
    Reproduit FUN_1400016ed :
      - découper chaque uint32 en 4 octets (ordre BE),
      - appliquer ROL8 de 1,2,3,4 bits,
      - réassembler en uint32 BE.
    """
    out = []
    vprint(verbose, 1, "[1] Mutation de la clé (ROTL byte-wise 1/2/3/4 bits)…")
    for i, w in enumerate(words):
        b0, b1, b2, b3 = (w>>24)&0xFF, (w>>16)&0xFF, (w>>8)&0xFF, w&0xFF
        before_ascii = "".join(chr(x) if 32 <= x <= 126 else "." for x in [b0,b1,b2,b3])
        vprint(verbose, 2, f"    - mot[{i}] avant : {w:08x}  ({before_ascii})")
        b0r, b1r, b2r, b3r = rol8(b0,1), rol8(b1,2), rol8(b2,3), rol8(b3,4)
        wr = (b0r<<24)|(b1r<<16)|(b2r<<8)|b3r
        out.append(wr)
        after_ascii = "".join(chr(x) if 32 <= x <= 126 else "." for x in [b0r,b1r,b2r,b3r])
        vprint(verbose, 2, f"      mot[{i}] après: {wr:08x}  ({after_ascii})")
    vprint(verbose, 1, "    → clé mutée prête.")
    return out

def tea_decrypt_block(v0: int, v1: int, K: List[int]) -> Tuple[int,int]:
    sum_ = (DELTA * ROUNDS) & 0xFFFFFFFF
    for _ in range(ROUNDS):
        v1 = (v1 - ((((v0<<4) ^ (v0>>5)) + v0) ^ (sum_ + K[(sum_>>11)&3]))) & 0xFFFFFFFF
        sum_ = (sum_ - DELTA) & 0xFFFFFFFF
        v0 = (v0 - ((((v1<<4) ^ (v1>>5)) + v1) ^ (sum_ + K[sum_&3]))) & 0xFFFFFFFF
    return v0, v1

def tea_encrypt_block(v0: int, v1: int, K: List[int]) -> Tuple[int,int]:
    sum_ = 0
    for _ in range(ROUNDS):
        v0 = (v0 + ((((v1<<4) ^ (v1>>5)) + v1) ^ (sum_ + K[sum_&3]))) & 0xFFFFFFFF
        sum_ = (sum_ + DELTA) & 0xFFFFFFFF
        v1 = (v1 + ((((v0<<4) ^ (v0>>5)) + v0) ^ (sum_ + K[(sum_>>11)&3]))) & 0xFFFFFFFF
    return v0, v1

def u64le_to_be_words(x: int) -> Tuple[int,int,bytes]:
    b = x.to_bytes(8, "little")           # représentation mémoire des imm64
    return int.from_bytes(b[0:4],"big"), int.from_bytes(b[4:8],"big"), b

def decrypt_expected_bytes(ct64: List[int], key_words: List[int], verbose=0) -> bytes:
    K = mutate_key(key_words, verbose=verbose)
    out = bytearray()
    for i, imm64 in enumerate(ct64):
        v0, v1, mem = u64le_to_be_words(imm64)
        vprint(verbose, 2, f"[2] Bloc {i}: imm64 LE = {imm64:016x}  (mem: {hexdump(mem)})")
        p0, p1 = tea_decrypt_block(v0, v1, K)
        out += p0.to_bytes(4,"big") + p1.to_bytes(4,"big")
        try:
            chunk_ascii = (p0.to_bytes(4,"big")+p1.to_bytes(4,"big")).decode("utf-8")
        except UnicodeDecodeError:
            chunk_ascii = "...."
        vprint(verbose, 2, f"    <- p0={p0:08x}, p1={p1:08x} ; ascii: {chunk_ascii}")
    return bytes(out)  # 48 octets (incluant NULs/éventuel '\n')

def encrypt_bytes(plain48: bytes, key_words: List[int]) -> bytes:
    """Ré-encryptage BE→BE par blocs, puis concat (48 octets)."""
    assert len(plain48) == 48
    K = mutate_key(key_words, verbose=0)
    out = bytearray()
    for i in range(0, 48, 8):
        v0 = int.from_bytes(plain48[i:i+4], "big")
        v1 = int.from_bytes(plain48[i+4:i+8], "big")
        c0, c1 = tea_encrypt_block(v0, v1, K)
        out += c0.to_bytes(4,"big") + c1.to_bytes(4,"big")
    return bytes(out)

def mask_phrase(s: str) -> str:
    # On masquera par "jeton" en séparant aux underscores (pas de regex \b à cause de '_').
    tokens = s.split("_")
    mapping = {"River":"xxxxx","Sea":"xxx","Palestine":"Pzzzzzzzz","Will":"yyyy"}
    return "_".join(mapping.get(t, t) for t in tokens)

# ----------------------------------- main -----------------------------------
def main():
    ap = argparse.ArgumentParser(description="Stretching solveur (verbeux + masquage)")
    ap.add_argument("-v","--verbose", action="count", default=0,
                    help="-v: étapes clés, -vv: détail par bloc")
    ap.add_argument("--reveal", action="store_true",
                    help="Afficher le vrai flag (par défaut: masqué)")
    args = ap.parse_args()

    vprint(args.verbose, 1, f"[0] Paramètres : ROUNDS={ROUNDS}, DELTA=0x{DELTA:08x}")
    vprint(args.verbose, 1, f"[0] Clé initiale : {[f'0x{x:08x}' for x in INIT_KEY]}")

    # 1) Déchiffrer les 48 octets attendus (NE PAS tronquer ici)
    plain48 = decrypt_expected_bytes(CT64, INIT_KEY, verbose=args.verbose)
    # Pour affichage humain, on peut ignorer NULs de fin :
    clear_text = plain48.rstrip(b"\x00").decode("utf-8", errors="strict")

    # 2) Vérification memcmp(..., 0x29) en ré-encryptant EXACTEMENT ces 48 octets
    reenc48 = encrypt_bytes(plain48, INIT_KEY)
    expected = b"".join(x.to_bytes(8,"little") for x in CT64)  # bytes mémoire côté binaire
    ok = (reenc48[:MEMCMP_LEN] == expected[:MEMCMP_LEN])
    vprint(args.verbose, 1, f"[3] memcmp attendu (41o) : {hexdump(expected[:MEMCMP_LEN])}")
    vprint(args.verbose, 1, f"[3] memcmp obtenu  (41o) : {hexdump(reenc48[:MEMCMP_LEN])}")
    print(f"[3] Vérification memcmp(…, 0x29) : {'OK' if ok else 'NON OK'}")

    # 3) Sortie masquée par défaut
    masked = mask_phrase(clear_text)
    print("Plaintext (masqué) :", masked)
    print(f"Flag (masqué) : wwf{{{masked}}}")
    if args.reveal:
        print(f"[!] Plaintext (réel) : {clear_text}")
        print(f"[!] Flag (réel) : wwf{{{clear_text}}}")

if __name__ == "__main__":
    main()
