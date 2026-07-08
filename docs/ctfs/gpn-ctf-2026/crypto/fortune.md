---
description: NTRU-like encryption over the dihedral group ring Z[D_100]; ciphertext printed unreduced mod q leaks the plaintext directly via c mod p
tags:
  - crypto
  - ntru
  - group-ring
  - gpn-ctf-2026
---

# Fortune

## Overview

| | |
|---|---|
| **Event** | GPN CTF 2026 |
| **Category** | Crypto |
| **Difficulty** | Medium |
| **Author** | s1nn105 |

!!! info "Challenge Description"
    You can't eat the entire time, so why not gamble a bit?

Two files in the handout: `fortune2.py` and `fortuneUtils2.py`. A live SSL instance to spin up.

## Recon

The top of `fortune2.py` sets up the parameters:

```python
N = 100
p = 3
d = math.floor(N / 3)                               # 33
q = 2**(math.floor(math.log2((6*d+1)*p)))           # 512
```

Below that is `generatePattern`, which produces the keys:

```python
f = P(d+1, d, n)    # private key: 34 ones, 33 minus-ones
fq = f.inv(mod=q)   # f^{-1} mod q
fp = f.inv(mod=p)   # f^{-1} mod p
g = P(d, d, n)
h = (fq * g) % q    # public key
```

That structure (short ternary private key, public key \(h = f_q \cdot g \bmod q\)) is NTRU.[^ntru] `P(t1, t2, N)` generates a random ring element with exactly `t1` coefficients of `+1` and `t2` of `-1`.

Encryption is in `hideInPattern`:

```python
doubt = P(d, d, h.segments)
t = (h * doubt) % q            # h*r mod q
return t.rescale(p) + message  # 3*t + m
```

Standard NTRU encryption: blind the message with `p*h*r`, add `m`. `f`, `fq`, `fp`, and `g` stay on the server; `h` and `c` are all that get printed.

There is a `decrypt` function and it's fully implemented (the `NotImplementedError` inside it is commented out, along with a note: *"The fortunate don't need such functions to see the pattern"*). Knowing the algorithm doesn't help without `f`.

The message itself is `P(d, d, N)`, with coefficients drawn from `{-1, 0, 1}`. `msg_to_guess` converts the 200-element coefficient vector to a 200-character string via `MAPPING = {-1:"A", 0:"C", 1:"B"}`. That's the target string, with a 60-second clock running via SIGALRM.

`fortuneUtils2.py` is the ring library `fortune2.py` imports. Rather than the usual polynomial ring \(\mathbb{Z}[x]/(x^N-1)\), it implements the **dihedral group ring \(\mathbb{Z}[D_{100}]\)**.[^dihedral][^groupring] The dihedral group \(D_{100}\) has 200 elements (100 rotations and 100 reflections of a regular hectogon AKA 100-gon), so elements of the ring are vectors of 200 integers. `FortuneWheel` is a single group element with a coefficient; `FortuneForest` is a sum of wheels and represents a full ring element. `to_vector()` returns the 200 coefficients against the basis \((e, r, \ldots, r^{99}, s, sr, \ldots, sr^{99})\). Crucially, \(D_{100}\) is non-commutative, so multiplication here is order-sensitive.

Connecting to the live instance:

```console
$ ncat --ssl torched-onion-marinated-in-sliced-chimichurri-zx3e.gpn24.ctf.kitctf.de 443
got params N=100 p=3 d=33 q=512
h= [233, 146, 151, 428, 198, 143, 250, 432, ...]
c= [1128, 911, 417, 1389, 1341, 769, 1100, 1242, ...]
Give me the message: test
nope
CCBCCBBCCCCCCCCBCCCBCACBBCAACCCCBCCCCCCBACCCCCCBCCAACCCCACCCBCABCCCCCCAACACACCBCBBCCBCCBCCCCCCBCABCCCCCCCACCCCCAAACCCCACACCCCACCBCCCCCCCCCACBCCAACCCCABBCCBCBCCCACBCCCBCBAACCCCACBACACCCCCACCBCBBCCAABCC
```

Params are fixed (N=100, p=3, d=33, q=512) and `h` and `c` regenerate fresh every connection. A wrong guess prints the correct answer, though it doesn't help since the message is fresh on reconnect.

The `c` values are immediately suspicious: 1389, 1341, 1100 all exceed `q=512`, and on some connections values like `-1` show up in the vector. In proper NTRU the ciphertext is reduced mod q before transmission. These clearly are'nt and already knowing from the code that `c = 3*t + m`, those out-of-range values are a direct hint.

## The attack

The standard move for NTRU is lattice key recovery to find `f`, but the out-of-range `c` values from my recon point to something much simpler first.

From `hideInPattern`, each coefficient of the printed ciphertext satisfies:

\[c_i = 3 t_i + m_i\]

where \(t_i \in [0, 511]\) and \(m_i \in \{-1, 0, 1\}\). Take both sides mod 3:

\[c_i \bmod 3 = m_i \bmod 3\]

Since \(m_i\) is already in \(\{-1, 0, 1\}\), this recovers it directly:

| \(m_i\) | \(c_i \bmod 3\) |
|:---:|:---:|
| \(-1\) | \(2\) |
| \(0\) | \(0\) |
| \(1\) | \(1\) |

No key needed. The server prints the raw output of `t.rescale(3) + message` with no `% q` reduction before `to_vector()`, so the values aren't collapsed back into `[0, 511]`. If they were, the attack breaks: \(512 \equiv 2 \pmod 3\), so reducing mod 512 scrambles the residues for any \(c_i \geq 512\).

`msg_to_guess` maps \(\{-1, 0, 1\} \to \{\text{A, C, B}\}\). Mod 3 gives \(\{2, 0, 1\}\) for the same values, so indexing `"CBA"` by `c_i % 3` gives the right character. The `-1` values in the live ciphertext (where `t_i = 0` and `m_i = -1`) are fine too: Python's `%` returns 2 for `-1 % 3`, mapping to `"A"`.

## solve.py

```python title="solve.py"
#!/usr/bin/env python3
import socket, ssl, re

HOST = "torched-onion-marinated-in-sliced-chimichurri-zx3e.gpn24.ctf.kitctf.de"
PORT = 443

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(socket.create_connection((HOST, PORT), 30), server_hostname=HOST)

def recvuntil(tok, timeout=30):
    s.settimeout(timeout)
    buf = b""
    while tok not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf

everything = recvuntil(b"Give me the message:")
m = re.search(rb"c= \[(.*?)\]", everything, re.DOTALL)
c = [int(x.strip()) for x in m.group(1).split(b",") if x.strip()]

table = "CBA"   # 0->C, 1->B, 2->A  (-1 mod 3 == 2)
guess = "".join(table[x % 3] for x in c)
s.sendall(guess.encode() + b"\n")
print(recvuntil(b"\n").decode())
```

```console
$ python3 solve.py
You are lucky!
here is your flag GPNCTF{s0mTIMes_A11_Y0u_NE3d_I5_luCK}
```

## Flag

!!! success "Flag"
    ```text
    GPNCTF{s0mTIMes_A11_Y0u_NE3d_I5_luCK}
    ```

## Notes

- This one felt too easy for a medium crypto challenge. The full lattice key recovery over \(\mathbb{Z}[D_{100}]\) is a harder problem given the non-commutativity, and might have been the intended path, but the mod-3 shortcut skips all of that entirely.
- The fix is one line: `% q` on the return value in `hideInPattern` keeps ciphertext coefficients in \([0, q-1]\) and closes the hole.
- NTRU officially stands for *Number Theorists 'R' Us*, the name Hoffstein, Pipher, and Silverman settled on at CRYPTO 1996. The cryptosystem has long outlived the joke; a variant (NTRU-HPS / NTRU-HRSS) was standardised by NIST in 2024 as part of the post-quantum migration.[^ntru]

## References

- Hoffstein, Pipher, Silverman, *NTRU: A Ring-Based Public Key Cryptosystem*, ANTS 1998: <https://link.springer.com/chapter/10.1007/BFb0054868>
- Wikipedia, *Dihedral group*: <https://en.wikipedia.org/wiki/Dihedral_group>
- Wikipedia, *Group ring*: <https://en.wikipedia.org/wiki/Group_ring>

[^ntru]: Hoffstein, Pipher, Silverman, *NTRU: A Ring-Based Public Key Cryptosystem*, ANTS 1998: <https://link.springer.com/chapter/10.1007/BFb0054868>
[^dihedral]: Wikipedia, *Dihedral group*: <https://en.wikipedia.org/wiki/Dihedral_group>
[^groupring]: Wikipedia, *Group ring*: <https://en.wikipedia.org/wiki/Group_ring>
