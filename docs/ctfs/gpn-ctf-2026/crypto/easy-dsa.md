---
description: SHA-256 nonces are 256 bits on a 521-bit curve; MD5 collision via fastcoll produces nonce reuse; two equations recover the private key
tags:
  - crypto
  - ecdsa
  - nonce-reuse
  - md5-collision
  - gpn-ctf-2026
---

# Easy DSA

## Overview

| | |
|---|---|
| **Event** | GPN CTF 2026 |
| **Category** | Crypto |
| **Difficulty** | Easy |
| **Author** | uxxct |

!!! info "Challenge Description"
    We don't just hand out our prized flags to everyone. Applicants must prove themselves worthy by sharing cool new recipes with us. For security reasons, these recipes of course need to be signed by us.

    I have the feeling there might be some logic error here but I just can't figure it out...

The challenge provides `main.py` as a handout and a live SSL instance to spin up. The description says there's a logic error somewhere in it.

## Recon

The first few lines of `main.py` show the crypto stack:

```python
from Crypto.PublicKey import ECC
from hashlib import sha256
from uuid import UUID, uuid3

secret_key = ECC.generate(curve="p521")
public_key = secret_key.public_key()
secure_namespace = UUID(bytes=b"kitchenexplosion")
```

`curve="p521"` is NIST P-521, a 521-bit prime-order curve.[^fips] The `sign` and `verify` functions below are standard ECDSA, which is probably where the challenge name comes from.

`secure_namespace` stands out. A real implementation would use RFC 6979 or `secrets.randbelow` for nonces; this one builds something custom on a UUID.

The rest of the file breaks down into:

- `secure_random`: a custom deterministic nonce generator; the thing supposed to produce a safe \(k\) for each signature
- `sign` / `verify`: textbook ECDSA sign and verify over P-521
- `main`: an interactive loop with four commands (`sign`, `get pkey`, `flag please`, `check please`)

I connected to the live instance and poked at the interface:

```console
$ ncat --ssl wok-tossed-pizza-wrapped-in-cured-hollandaise-gmoc.gpn24.ctf.kitctf.de 443
Welcome to the Mongolian barbecue.
Use `sign [hex recipe]` to get your recipe signed by us.
You can get the public key to verify signatures using `get pkey`.
When you are ready to taste our freshly made flag, say `flag please`.
If you would like to leave, just say `check please`.

> sign 41414141
s1: 0x169c9416090055232a700dd71b2a09ff4fb74606b22cccd18083987077cb774e0b8628897e799d250aab3f0b02e5cc3d56dae38dcc426fd014d59a3d7b1f622ea1
s2: 0x11bb2271045fdb4adee2b308371fe861a0eb923080a016a05d4a8cd5f344db2aabe3774eed260bf7115274c1914ebe8a9246c7df3571b022f9241308b70dc6356f1

> get pkey
x: 3368045842875724161243463966615440655312427116818229421784487221411467781654850078850882649724175152771820420980012980051651041181980978202281335905359364781
y: 269216404497876592656566963486518887058903535228976131781468563286111206221482700232420688427035329660645444413672354677939244716418500487600344652585597154

> flag please
To decide if you are worthy of our special flag you neeed to provide us a signed recipe we don't already know.
recipe (hex):
```

The server signs anything you send. The flag path requires a recipe with a valid signature for something it hasn't already signed, so the goal is forging a signature without the private key.

Worth noting: the server generates a fresh key pair per session.

## Finding the bugs

The only non-standard piece is `secure_random`. Instead of RFC 6979[^rfc6979] or `secrets.randbelow`, it does this:

```python
secure_namespace = UUID(bytes=b"kitchenexplosion")

def secure_random(sk: ECC.EccKey, message: bytes) -> int:
    key_id = uuid3(secure_namespace, sk.export_key(format="PEM")).bytes
    msg_id = uuid3(secure_namespace, message).bytes

    random_generator = sha256(key_id)
    random_generator.update(msg_id)

    return int.from_bytes(random_generator.digest()) % (int(sk._curve.order) - 1) + 1
```

`key_id` is constant for the session. `msg_id` changes per message but goes through `uuid3`, which RFC 4122 §4.3[^rfc4122] specifies as MD5 with a few bits overwritten. The whole function reduces to:

\[k = \text{int}(\text{SHA-256}(\text{const} \| \text{MD5}(\text{prefix} \| \text{message}))) \bmod (n - 1) + 1\]

!!! note "The masking step"
    `sign` also runs `z = e & ~(1 << n.bit_length())` before using the hash. For P-521, `n.bit_length()` is 521, clearing bit 521. SHA-256 output is at most 256 bits; bit 521 is always zero. I am almost certain the mask is a no-op. Not at all relevant to a solution but mildly interesting. 

### Bug 1: uuid3 is MD5

`uuid3(namespace, name)` computes MD5 internally (RFC 4122[^rfc4122] §4.3). If two distinct messages \(M_1 \neq M_2\) produce the same MD5 output under the `kitchenexplosion` prefix:

\[\text{MD5}(\texttt{"kitchenexplosion"} \| M_1) = \text{MD5}(\texttt{"kitchenexplosion"} \| M_2)\]

then `msg_id` is identical for both, the entire SHA-256 input is the same, and both signatures share the same nonce \(k\). Same \(k\) means same \(r\). Two signatures with the same \(r\) leak the private key directly:

\[k = (z_1 - z_2)(s_1 - s_2)^{-1} \bmod n \qquad d = (s_1 k - z_1) r^{-1} \bmod n\]

MD5 collision generation is a solved problem.[^md5] Marc Stevens' `fastcoll` generates an identical-prefix collision in seconds, and the key recovery is two modular inversions in plain Python. No lattice library needed.

### Bug 2: the nonce is only 256 bits

P-521's group order \(n\) is a 521-bit prime, just under \(2^{521}\). SHA-256 produces 256 bits, so every nonce is bounded to 256 bits. Since \(2^{256} < n\), the `% (n-1)` reduction **never fires** and the top 265 bits of every nonce are permanently zero.

This is a **Hidden Number Problem** (HNP)[^hnp] instance. With SageMath's integer LLL, four signatures recover the private key. Exploit 2 covers the full attack.

## Exploit 1: MD5 collision

### How it works

Two messages with the same MD5 share the same `msg_id`, the same SHA-256 input, and the same nonce \(k\). Same \(k\) means same \(r\). Starting from the two signature equations:

\[s_1 = k^{-1}(z_1 + r \cdot d) \bmod n \qquad s_2 = k^{-1}(z_2 + r \cdot d) \bmod n\]

Subtract and solve:

\[k = (z_1 - z_2)(s_1 - s_2)^{-1} \bmod n \qquad d = (s_1 k - z_1) r^{-1} \bmod n\]

ECDSA has a sign ambiguity: if the recovered \(d\) gives a point whose x-coordinate doesn't match the public key, negate it: \(d \leftarrow n - d\). This is the same nonce-reuse math from fail0verflow's PS3 talk[^ps3], just with a prefix-collision instead of a constant nonce.

### Building fastcoll

Marc Stevens' `fastcoll`[^md5] generates an identical-prefix MD5 collision in seconds:

```console
$ sudo apt-get install -y libboost-all-dev
$ git clone https://github.com/brimstone/fastcoll && cd fastcoll
$ g++ -O2 -DBOOST_TIMER_ENABLE_DEPRECATED -o fastcoll *.cpp \
    -lboost_filesystem -lboost_program_options
```

Generate the collision files using `kitchenexplosion` as the prefix, the bytes `uuid3` prepends internally before hashing:

```console
$ printf 'kitchenexplosion' > prefix.bin
$ ./fastcoll -p prefix.bin -o m1.bin m2.bin
MD5 collision generator v1.5
by Marc Stevens (http://www.win.tue.nl/hashclash/)

Using output filenames: 'm1.bin' and 'm2.bin'
Using prefixfile: 'prefix.bin'
Using initial value: 0d2f1c9ba85986b69e1cd13a7359534d

Generating first block: .....
Generating second block: S00.........................
Running time: 1.12571 s
```

### solve.py

Strips the 16-byte namespace prefix fastcoll includes in both files (the server's `uuid3` prepends it, so don't double-count it), signs both halves, confirms the nonces collided via matching `r` values, recovers \(d\), and forges a fresh signature:

```python title="solve.py"
#!/usr/bin/env python3
# Prerequisite: generate collision files with fastcoll:
#   printf 'kitchenexplosion' > prefix.bin
#   ./fastcoll -p prefix.bin -o m1.bin m2.bin
import re, socket, ssl, secrets, sys
from Crypto.PublicKey import ECC
from hashlib import sha256

HOST = "wok-tossed-pizza-wrapped-in-cured-hollandaise-gmoc.gpn24.ctf.kitctf.de"
PORT = 443
CURVE = 'p521'
N = int(ECC._curves[CURVE].order)
G = ECC._curves[CURVE].G

def z_of(msg):
    return int.from_bytes(sha256(msg).digest()) & ~(1 << N.bit_length())

class SSLTube:
    def __init__(self, host, port):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        self.s = ctx.wrap_socket(socket.create_connection((host, port), 20), server_hostname=host)
    def recvuntil(self, tok, timeout=20):
        self.s.settimeout(timeout); buf = b""
        while tok not in buf:
            chunk = self.s.recv(4096)
            if not chunk: break
            buf += chunk
        return buf
    def sendline(self, data): self.s.sendall(data + b"\n")

def sign_msg(io, msg):
    io.sendline(b"sign " + msg.hex().encode())
    buf = io.recvuntil(b"> ")
    r = int(re.search(rb"s1:\s*0x([0-9a-f]+)", buf).group(1), 16)
    s = int(re.search(rb"s2:\s*0x([0-9a-f]+)", buf).group(1), 16)
    return r, s

def solve(io):
    m1 = open("m1.bin", "rb").read()[16:]   # strip fastcoll's namespace prefix
    m2 = open("m2.bin", "rb").read()[16:]

    io.recvuntil(b"> ")
    io.sendline(b"get pkey")
    buf = io.recvuntil(b"> ")
    Q = ECC.EccPoint(
        int(re.search(rb"x:\s*(\d+)", buf).group(1)),
        int(re.search(rb"y:\s*(\d+)", buf).group(1)),
        curve=CURVE,
    )

    r,  s1 = sign_msg(io, m1)
    r2, s2 = sign_msg(io, m2)
    assert r == r2, "nonces did not collide -- re-run fastcoll"

    z1, z2 = z_of(m1), z_of(m2)
    k = (z1 - z2) * pow(s1 - s2, -1, N) % N
    d = (s1 * k - z1) * pow(r,  -1, N) % N
    if (d * G).x != Q.x:
        d = N - d
    assert (d * G).x == Q.x, "key recovery failed"

    kf = secrets.randbelow(N-1) + 1
    fresh = b"a new recipe the server has not seen"
    rf = int((kf * G).x) % N
    sf = pow(kf, -1, N) * (z_of(fresh) + rf * d) % N

    io.sendline(b"flag please")
    io.recvuntil(b"recipe (hex): "); io.sendline(fresh.hex().encode())
    io.recvuntil(b"s1 (hex): ");     io.sendline(format(rf, 'x').encode())
    io.recvuntil(b"s2 (hex): ");     io.sendline(format(sf, 'x').encode())
    buf = io.recvuntil(b"> ")
    if m := re.search(rb"GPNCTF\{[^}]+\}", buf):
        print(m.group(0).decode())

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    solve(SSLTube(host, port))
```

```console
$ python3 solve.py
GPNCTF{MaYbe we SHoU1d HAvE hIR3D a profeSsionAl?}
```

## Exploit 2: Lattice attack

Bug 2 is an independent solve path that needs no fastcoll. I like to think this one is probably unintended as the challenge is "easy" and only mentions a singular "logic error". Exploit 1 is the simpler path by far.

### How it works

The signing equation rearranges to \(k_i = u_i + t_i \cdot d\) where \(t_i = r_i s_i^{-1} \bmod n\) and \(u_i = z_i s_i^{-1} \bmod n\) (the `t` and `u` arrays in the Sage code). Every \(k_i < 2^{256}\), so the nonce vector is far shorter than \(n\). A lattice built from four \((t_i, u_i)\) pairs makes that shortness geometrically exploitable; LLL[^lll] finds the short vector and \(d\) falls out. This is the Nguyen-Shparlinski attack applied to biased nonces.[^hnp]

Standard float LLL fails here: Gram-Schmidt inner products hit \(n^2 \approx 2^{1042}\) and overflow 64-bit doubles silently. SageMath's `Matrix(ZZ).LLL()` uses arbitrary-precision integers and works correctly.

### Pitfall 1: key is per-connection

The server generates a fresh key pair per TCP connection. Collecting signatures in one session and submitting from another always fails. I confirmed this by running the collection step twice against the same instance and getting completely different public keys each time.

Sagecell doesn't work for the full exploit either since it can't connect to the live server. I used it to verify the lattice math on pre-collected signatures and confirm `d` was recoverable, but the TCP connection dies between collection and the Sagecell call, so the forge step always fails. Sage needs to run locally as a subprocess while the Python session keeps the connection open.

### Pitfall 2: sign ambiguity in LLL output

Both \(d\) and \(n - d\) produce a point with the same x-coordinate when multiplied by \(G\). The naive check `if (d * G).x != Qx` is always False regardless of which value LLL returned; it cannot distinguish the two.

The fix: verify against a known signature equation. If \(d\) is correct, then \(k_0 = u_0 + t_0 \cdot d\) should produce a point whose x-coordinate equals \(r_0\). If not, flip.

### solve_lattice.py

One connection: collects four signatures, calls `sage -c "..."` as a subprocess while the socket stays open, then forges and submits. Needs sage in PATH (`sudo apt install sagemath` on Kali, or `conda activate sage`):

```python title="solve_lattice.py"
#!/usr/bin/env python3
import re, socket, ssl, secrets, sys, subprocess
from Crypto.PublicKey import ECC
from hashlib import sha256

HOST = "wok-tossed-pizza-wrapped-in-cured-hollandaise-gmoc.gpn24.ctf.kitctf.de"
PORT = 443
CURVE = 'p521'
N = int(ECC._curves[CURVE].order)
G = ECC._curves[CURVE].G

def z_of(msg):
    return int.from_bytes(sha256(msg).digest(), 'big')

class SSLTube:
    def __init__(self, host, port):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        self.s = ctx.wrap_socket(socket.create_connection((host, port), 20), server_hostname=host)
    def recvuntil(self, tok, timeout=30):
        self.s.settimeout(timeout); buf = b""
        while tok not in buf:
            chunk = self.s.recv(4096)
            if not chunk: break
            buf += chunk
        return buf
    def sendline(self, data): self.s.sendall(data + b"\n")

SAGE_CODE = """
n = {n}
W = 2**256
sigs = {sigs}

m = len(sigs)
t = [(r * inverse_mod(s, n)) % n for r, s, z in sigs]
u = [(z * inverse_mod(s, n)) % n for r, s, z in sigs]

t_last_inv = inverse_mod(t[-1], n)
H = [(t[i] * t_last_inv) % n for i in range(m-1)]
U = [(u[i] - H[i] * u[-1]) % n for i in range(m-1)]

M = Matrix(ZZ, m+1, m+1)
for i in range(m-1): M[i, i] = n
for i in range(m-1): M[m-1, i] = H[i]
M[m-1, m-1] = 1
for i in range(m-1): M[m, i] = U[i]
M[m, m] = W

d = None
for row in M.LLL():
    if row[-1] in (W, -W):
        k_last = row[-2] * (1 if row[-1] == W else -1)
        d = ((k_last - u[-1]) * t_last_inv) % n
        break

p   = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151
b_c = 1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984
Gx  = int("C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", 16)
Gy  = int("11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16)
E = EllipticCurve(GF(p), [-3, b_c])
Gp = E(Gx, Gy)

k0 = (u[0] + t[0] * d) % n
if int((k0 * Gp).xy()[0]) % n != sigs[0][0]:
    d = n - d

print(d)
"""

def recover_d(sigs):
    code = SAGE_CODE.format(n=N, sigs=repr(sigs))
    result = subprocess.run(['sage', '-c', code], capture_output=True, text=True, timeout=90)
    if result.returncode != 0:
        raise RuntimeError(result.stderr[:300])
    return int(result.stdout.strip())

def solve(io):
    io.recvuntil(b"> ")
    io.sendline(b"get pkey")
    buf = io.recvuntil(b"> ")
    Q = ECC.EccPoint(
        int(re.search(rb"x:\s*(\d+)", buf).group(1)),
        int(re.search(rb"y:\s*(\d+)", buf).group(1)),
        curve=CURVE,
    )

    sigs = []
    for i in range(4):
        msg = f"recipe_{i}".encode()
        io.sendline(b"sign " + msg.hex().encode())
        buf = io.recvuntil(b"> ")
        r = int(re.search(rb"s1:\s*0x([0-9a-f]+)", buf).group(1), 16)
        s = int(re.search(rb"s2:\s*0x([0-9a-f]+)", buf).group(1), 16)
        sigs.append((r, s, z_of(msg)))

    print("[*] Running lattice recovery via sage...")
    d = recover_d(sigs)
    print("[+] d recovered")

    kf    = secrets.randbelow(N-1) + 1
    fresh = b"a new recipe the server has not seen"
    rf    = int((kf * G).x) % N
    sf    = pow(kf, -1, N) * (z_of(fresh) + rf * d) % N

    io.sendline(b"flag please")
    io.recvuntil(b"recipe (hex): "); io.sendline(fresh.hex().encode())
    io.recvuntil(b"s1 (hex): ");     io.sendline(format(rf, 'x').encode())
    io.recvuntil(b"s2 (hex): ");     io.sendline(format(sf, 'x').encode())
    buf = io.recvuntil(b"> ", timeout=60)
    if m := re.search(rb"GPNCTF\{[^}]+\}", buf):
        print(m.group(0).decode())

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    solve(SSLTube(host, port))
```

```console
$ conda activate sage && python3 solve_lattice.py wok-tossed-pizza-wrapped-in-cured-hollandaise-gmoc.gpn24.ctf.kitctf.de 443
[*] Running lattice recovery via sage...
[+] d recovered
GPNCTF{MaYbe we SHoU1d HAvE hIR3D a profeSsionAl?}
```

## Flag

!!! success "Flag"
    ```text
    GPNCTF{MaYbe we SHoU1d HAvE hIR3D a profeSsionAl?}
    ```

## Notes

- The first thing you might try is **signature malleability**: for any valid ECDSA signature \((r, s)\), the pair \((r, n - s)\) is also valid. If the server tracked (recipe, signature) pairs you could re-submit a signed recipe with its flipped \(s\). It doesn't though; it tracks recipe bytes in `already_signed`, so the same recipe bytes get rejected regardless of what signature you pair them with. Dead end.
- The two bugs are independent. Fix Bug 1 (drop uuid3) and Bug 2 still kills you via the lattice. Fix Bug 2 (use a DRBG that outputs 521 bits) and Bug 1 still kills you via fastcoll. The professional the flag is asking about would have read RFC 6979 and avoided both.[^rfc6979]
- The classic real-world example of ECDSA nonce reuse is the PS3 firmware signing key leak (2010), where Sony used a constant nonce for every signature.[^ps3] Same recovery equations as Bug 1 here: same \(r\) across signatures, key drops out from two equations. Comes up every time someone rolls their own ECDSA.
- RFC 6979 derives the nonce with HMAC-DRBG seeded from the private key and message hash. Full-width output, deterministic, no MD5 anywhere. `secure_random` is shaped similarly (deterministic, message-dependent) but uses SHA-256 on a 521-bit curve and routes the message through MD5 via `uuid3`. Two wrong primitives where one correct one closes both bugs.

## References

- NIST FIPS 186-4, *Digital Signature Standard (DSS)* - defines P-521 and ECDSA: <https://csrc.nist.gov/publications/detail/fips/186/4/final>
- RFC 6979, *Deterministic Usage of DSA and ECDSA* - the correct way to derive a signing nonce: <https://www.rfc-editor.org/rfc/rfc6979>
- RFC 4122, *A Universally Unique IDentifier (UUID) URN Namespace* - §4.3 defines uuid3 as MD5-based: <https://www.rfc-editor.org/rfc/rfc4122>
- Nguyen & Shparlinski, *The Insecurity of the Elliptic Curve Digital Signature Algorithm with Partially Known Nonces* (the canonical HNP-to-lattice reduction for ECDSA): <https://link.springer.com/article/10.1007/s10623-003-1220-2>
- Wikipedia, *Hidden number problem*: <https://en.wikipedia.org/wiki/Hidden_number_problem>
- Marc Stevens' hashclash / fastcoll: <https://github.com/cr-marcstevens/hashclash>

[^fips]: NIST FIPS 186-4, *Digital Signature Standard*, 2013: <https://csrc.nist.gov/publications/detail/fips/186/4/final>
[^rfc6979]: Pornin, T., RFC 6979, 2013: <https://www.rfc-editor.org/rfc/rfc6979>
[^rfc4122]: Leach et al., RFC 4122, 2005: <https://www.rfc-editor.org/rfc/rfc4122>
[^md5]: Wang & Yu, *How to Break MD5 and Other Hash Functions*, Eurocrypt 2005. Stevens' fast chosen-prefix variant: <https://eprint.iacr.org/2006/104>
[^hnp]: Nguyen & Shparlinski, *The Insecurity of the ECDSA with Partially Known Nonces*, Designs, Codes and Cryptography, 2003: <https://link.springer.com/article/10.1007/s10623-003-1220-2>
[^lll]: Lenstra, Lenstra, Lovász, *Factoring polynomials with rational coefficients*, Mathematische Annalen, 1982.
[^ps3]: fail0verflow, *PS3 Epic Fail*, 27th Chaos Communication Congress (27C3), 2010: <https://fail0verflow.com/blog/2010/ps3-hacking/>
