#!/usr/bin/env python3
# pip install --user pwntools pycryptodome
from pwn import remote                                           # :contentReference[oaicite:0]{index=0}
from Crypto.Util.number import bytes_to_long, long_to_bytes      # :contentReference[oaicite:1]{index=1}
from hashlib import sha256                                       # :contentReference[oaicite:2]{index=2}
import secrets, re

HOST, PORT = 'chal.wwctf.com', 8001
g = 25

# p est fixe (copié de chall.py)
p = 157177458027947738464608587718505170872557537311336022386936190418737852141444802600222526305430833558655717806361264485789209743716195302937247478034883845835496282499162731072456548430299962306072692670825782721923481661135742935447793446928303177027490662275563294516442565718398572361235897805000082380599

# --------------------------------------------------------------------------
def sha_int(x: int) -> int:
    return bytes_to_long(sha256(long_to_bytes(x)).digest())

def weird_schnorr_sign(m: int, x: int) -> tuple[int, int]:
    """Recopie exacte de weird_schnorr_sign du challenge."""
    k = secrets.randbits(1024)
    r = pow(g, k, p)
    e = bytes_to_long(sha256(long_to_bytes(r) + long_to_bytes(m)).digest())
    s = (k + x * e) % ((p - 1) // 2)
    return s, e

def sign(m: int, x: int, q: int, gs: int) -> list[int]:
    """Recopie fidèle de sign() : renvoie une liste de 7 entiers."""
    ta = [secrets.randbits(100) for _ in range(4)]
    cc = [sha_int(m % q)]
    for _ in range(3):
        cc.append(sha_int(cc[-1]))

    sta = (m - sum(pow(g, b, p) * c % p for b, c in zip(ta, cc))) % q
    r   = secrets.randbits(100)
    a   = (p - 1 - x) * p - (q * r + sta) * (p - 1)

    s, e = weird_schnorr_sign(a, x)
    return [s, e, a] + ta
# --------------------------------------------------------------------------

with remote(HOST, PORT) as io:                                    # connexion TCP
    banner = ''
    while True:                                                   # lit jusqu’au prompt
        line = io.recvline().decode()
        banner += line
        if ':' in line.lower():                                   # ex. "signature for flag:"
            break

    # Extraction robuste
    q    = int(re.search(r"q=(\d+)",  banner).group(1))
    gs   = int(re.search(r"gs=(\d+)", banner).group(1))
    sm   = list(map(int, re.search(r"sm=\[([^\]]+)\]", banner)
                           .group(1).split(',')))
    leak = int(re.search(r"leak=(\d+)", banner).group(1))

    # Clé privée (relation linéaire : a = -s mod p-1)    :contentReference[oaicite:3]{index=3}
    a_demo = sm[2]
    s      = (-a_demo) % (p - 1)

    # Signature fraîche pour CE tour
    signature = sign(leak, s, q, gs)
    io.sendline(','.join(map(str, signature)).encode())

    print(io.recvline().decode().strip())          # ← le VRAI flag
