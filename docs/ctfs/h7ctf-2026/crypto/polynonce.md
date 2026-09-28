---
description: Eight ECDSA signatures from a treasury signer that cut a corner on its nonces; recover the key offline and unseal the flag
tags:
  - crypto
  - ecdsa
  - polynonce
  - related-nonces
  - linearization
  - h7ctf-2026
---

# Polynonce

## Overview

| | |
|---|---|
| **Event** | H7CTF 2026 Quals |
| **Category** | Crypto |
| **Difficulty** | Hard |

!!! info "Challenge Description"
    Aurum's treasury signer rubber-stamps transfers by the batch, day in and day out. The engineer who wired it up cut a corner to keep the queue moving, then quietly left the company.

    The corner he cut is still signing every approval.

    HTTP 443: `https://$HOST`

The challenge spins up a Docker instance, which is just a tiny "Aurum treasury signer" page serving two static files:

- `signatures.json`
- `flag.enc`

`flag.enc` is the AES-256-GCM ciphertext (59 bytes). The goal is getting the key to open it.

## Recon

`signatures.json` has the curve and hash info, the signer's public key, and 8 ECDSA signatures over distinct treasury approval messages. The top of the file tells you exactly how everything is derived:

```json
{
  "curve": "secp256k1",
  "hash": "sha256",
  "z": "z = int.from_bytes(sha256(msg), 'big')  (no reduction)",
  "sealed_flag": "AES-256-GCM, key=SHA256(d_be32), iv=SHA256('Qx,Qy')[:12], flag.enc = ct||tag16",
  "pubkey": {
    "x": "82844204148873628703996834703464161140806186313179041871201342360148464197968",
    "y": "82182622956164716681646606429624519841352969485355936171064060467128106035122"
  },
```

The 8 signed messages, in file order:

```text
TRANSFER 12.5 BTC -> treasury cold wallet 0x9f2a
TRANSFER 0.4 BTC -> ops petty cash 0x51bb
APPROVE quarterly audit report Q3-2026
TRANSFER 3.0 BTC -> vendor settlement 0xc417
ROTATE signing epoch 7 -> 8
TRANSFER 88.0 BTC -> escrow 0x2d90
APPROVE firmware manifest v4.2.1
TRANSFER 1.25 BTC -> payroll batch 0x77ee
```

The AES key is `SHA256(d)` and the IV only depends on the public key, so the whole challenge is recovering the private key \(d\) from these 8 signatures. Once I had those two files, the rest was all offline.

The challenge name basically hands you the attack. Searching "polynonce" goes straight to it: PolyNonce is a real, published related nonce attack on ECDSA by Marco Macchetti at Kudelski Security ("A Novel Related Nonce Attack for ECDSA", 2023).[^polynonce] They used it to break real Bitcoin wallets, wrote it up on their blog[^blog] and gave a DEF CON 31 talk on it. There's also a public reference implementation in SageMath on their GitHub.[^repo] So this isn't a case of inventing an attack from scratch: the tooling already exists, and the real work is understanding why it applies and getting the data into the right shape.

## Background: how ECDSA signs

Before the attack makes sense it's worth being clear on what a signature actually is. On secp256k1 (the Bitcoin curve, which fits all the BTC transfers here) there's a fixed base point \(G\) and a prime group order

```text
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

The private key is a number \(d\) and the public key is the point \(Q = dG\). Getting \(d\) back from \(Q\) is the elliptic curve discrete log problem, which is hopeless at this size, so nobody attacks \(Q\) directly.

To sign a message:

1. Hash it: \(z = \text{SHA256}(msg)\) as a big-endian integer.
2. Pick a nonce \(k\) (it's supposed to be secret and fresh every time).
3. \(r = (kG)_x \bmod n\), the x-coordinate of the point \(kG\).
4. \(s = k^{-1}(z + r d) \bmod n\).

The signature is \((r, s)\). Look at step 4: it's one equation with two secrets in it, \(k\) and \(d\). The only thing keeping \(d\) safe is that \(k\) is unknown. That's why the nonce is the whole game in ECDSA, and why almost every practical ECDSA break is a nonce problem:

| Nonce mistake | What it gives you |
|---|---|
| \(k\) leaks for one signature | \(d = (s k - z) r^{-1} \bmod n\) straight away |
| same \(k\) used twice | same \(r\) twice, subtract the two equations: \(k = (z_1 - z_2)(s_1 - s_2)^{-1}\), then row 1 |
| a few bits of each \(k\) are biased | lattice attack (hidden number problem) |
| nonces tied together by a known formula with unknown coefficients | this challenge |

The repeated \(k\) case is the famous one, it's how the PS3 signing key fell.[^ps3] It's also the one you can rule out instantly here, since all 8 \(r\) values in `signatures.json` are different. Different \(r\) only means different \(k\) though, not unrelated \(k\).

## The vulnerability

The idea behind PolyNonce is that a broken signer doesn't draw a fresh random nonce \(k\) per signature. It derives each nonce from the previous one with a fixed, low degree polynomial recurrence with unknown coefficients, something like \(k_{i+1} = a k_i + b\) or \(k_{i+1} = a k_i^2 + b k_i + c \pmod n\). That fits the description's "cut a corner to keep the queue moving": it's deterministic and fast, and every individual \(r\) still comes out different, so nothing looks wrong at a glance.

### Every nonce is a line in \(d\)

Take the signing equation and solve it for \(k\) instead of \(s\):

\[s k = z + r d \quad\Rightarrow\quad k = s^{-1} z + s^{-1} r \, d \pmod n\]

So for every signature:

\[k_i = A_i + B_i d \pmod n, \qquad A_i = z_i s_i^{-1} \bmod n, \qquad B_i = r_i s_i^{-1} \bmod n\]

\(A_i\) and \(B_i\) are computed purely from public stuff (the message hash and the signature), so each nonce is a known affine function of the one number I care about. This is the `load()` step in my script:

```python title="solve.py (excerpt)"
z = int.from_bytes(hashlib.sha256(sig["msg"].encode()).digest(), "big")
r = int(sig["r"]) % N
s = int(sig["s"]) % N
sinv = modinv(s)
A.append((z * sinv) % N)
B.append((r * sinv) % N)
```

On its own that doesn't help. Each new signature brings a new equation but also a new unknown \(k_i\), so 8 signatures is 8 equations in 9 unknowns (\(d\) plus 8 nonces) and you never catch up. The flaw is what fixes the counting: if the nonces follow a recurrence, the 8 independent \(k_i\) collapse into \(d\) plus a handful of coefficients, and now there are more equations than unknowns.

### Linearization

Substituting \(k_i = A_i + B_i d\) into a recurrence gives polynomial equations, because the unknown coefficients get multiplied by \(d\). The trick is to not care: every distinct product of unknowns (like \(a d\)) just gets renamed to a fresh variable, and the system becomes linear in those variables. You lose the information that \(x\) is "really" \(a \cdot d\), but you get something plain Gaussian elimination can solve.

Gaussian elimination works mod \(n\) exactly like it does over the reals because \(n\) is prime, so every nonzero number has an inverse. There's no rounding, the answer is either exactly right or the system is singular. The inverse is just Fermat's little theorem (\(x^{n-2} \equiv x^{-1} \pmod n\)), and the solver is textbook row reduction with every operation taken mod \(q\):

```python title="solve.py (excerpt)"
def modinv(x, m=N):
    return pow(x, m - 2, m)


def solve_linear_mod(M, y, q):
    n = len(y)
    A = [row[:] + [y[i] % q] for i, row in enumerate(M)]
    for col in range(n):
        piv = None
        for r in range(col, n):
            if A[r][col] % q != 0:
                piv = r
                break
        if piv is None:
            return None
        A[col], A[piv] = A[piv], A[col]
        inv = modinv(A[col][col], q)
        A[col] = [(v * inv) % q for v in A[col]]
        for r in range(n):
            if r != col and A[r][col] % q != 0:
                f = A[r][col]
                A[r] = [(A[r][c] - f * A[col][c]) % q for c in range(n + 1)]
    return [A[i][n] for i in range(n)]
```

No Sage or lattice library needed, just Python, `hashlib` and pycryptodome for the AES at the end.

The cost of linearizing is that the number of variables grows with the degree of the recurrence, and every variable needs an equation. That's what decides which models I could even test with 8 signatures.

### The reference route: elimination and root finding

Worth knowing that linearizing isn't how the paper does it. Macchetti's version gets rid of the recurrence coefficients instead of solving for them. It works on differences between consecutive nonces (\(k_{i+1} - k_i\), which cancels the constant term), and keeps combining those equations until every unknown coefficient has been eliminated. What's left is a single polynomial in \(d\) alone with fully known coefficients, and the private key is one of its roots. Finding roots of a univariate polynomial over a finite field is fast, and that's the `roots()` call at the end of the Kudelski script.

The trade off between the two routes:

| | Elimination + roots (paper / repo) | Linearization (what I did) |
|---|---|---|
| Signatures for a degree \(D\) recurrence | \(D + 3\) consecutive | one per linearized unknown (7 for quadratic) |
| Needs | SageMath (polynomial rings, root finding) | plain Python, Gaussian elimination mod \(n\) |
| Output | a handful of candidate roots, check each against \(Q = dG\) | one exact solution, checked via the product variables |
| Degree | pick \(D\) from how many signatures you use, no need to guess the model | have to guess the model and write the equations for it |

For the quadratic case here that's \(D = 2\), so 5 consecutive signatures would already be enough for the reference attack, and 8 leaves spare windows to confirm the same \(d\) comes out of each one. The linearized version needs all 8 just to pin the system down, which is why Stage 2 ends up with nothing left over to hold out.

My solve went the linearization way instead, which is what the rest of this writeup walks through. If you just want the flag, adapting the Kudelski script to take 5 consecutive signatures from `signatures.json` is probably the shorter path (its `original-attack` script generates its own test signatures, so it needs the inputs swapped in).

## Stage 1: trying the simple models first

I went through candidate nonce models in order of increasing complexity. A square linear system will always spit out *some* answer, so a solve on its own proves nothing. For each candidate I fit on part of the data and checked against held out signatures that weren't used in the fit. A wrong model gives a \(d\) that doesn't predict the held out nonces.

Here's the counting for each model I tried:

| Model | Unknowns after linearizing | Equations available | Left over to check with |
|---|---|---|---|
| \(k_i = c_0 + c_1 i + \dots + c_D i^D\) | \(D + 2\) (\(d, c_0 \dots c_D\)) | 8 (one per signature) | \(6 - D\) |
| \(k_{i+1} = a k_i + b\) | 4 (\(d, x = a d, a, b\)) | 7 (one per consecutive pair) | 3 |
| \(k_{i+1} = a k_i^2 + b k_i + c\) | 7 (\(d, a, b, c, ad, bd, ad^2\)) | 7 | 0 |

1. **\(k_i\) as a low degree polynomial of the batch index \(i\).** This is directly linear, since \(B_i d - \sum_j c_j i^j \equiv -A_i\). I tried degrees 0 to 5 with at least one signature held out each time. None matched.
2. **Linear recurrence on the previous nonce** (\(k_{i+1} = a k_i + b\), the textbook LCG case). Substituting gives \(A_{i+1} + B_{i+1} d = a A_i + a B_i d + b\), and the \(a B_i d\) term is where \(x = a d\) comes in. I fit on 4 pairs and checked against the remaining 3. Didn't match either.
3. **Quadratic recurrence on the previous nonce** (\(k_{i+1} = a k_i^2 + b k_i + c\)). This is the one that hit.

The LCG check is a nice example of validating with the actual nonces instead of trusting the solve. Once you have a candidate \(d\) you can compute every real \(k_i\), pull \(a\) out of the first three (\(a = (k_2 - k_1)(k_1 - k_0)^{-1}\)), and see if that one \((a, b)\) produces the whole sequence:

```python title="solve.py (excerpt)"
def try_lcg(A, B):
    """k_{i+1} = a*k_i + b (mod n). Linearize with x = a*d:
       B_{i+1}*d - B_i*x - A_i*a - b == -A_{i+1}   (mod n)   [4 unknowns: d, x, a, b]
    Fit on the first 4 pairs, then independently validate the resulting d by
    checking the *actual* k_i sequence follows some single LCG for ALL pairs."""
    n_sigs = len(A)
    pairs = [(i, i + 1) for i in range(n_sigs - 1)]
    if len(pairs) < 4:
        return None
    M, y = [], []
    for (i, j) in pairs[:4]:
        M.append([B[j], (-B[i]) % N, (-A[i]) % N, -1 % N])
        y.append((-A[j]) % N)
    sol = solve_linear_mod(M, y, N)
    if sol is None:
        return None
    d = sol[0]
    k = [(A[i] + B[i] * d) % N for i in range(n_sigs)]
    # derive (a,b) from the first pair, verify against ALL remaining pairs
    if k[1] == k[0]:
        return None
    # k1 = a*k0+b, k2 = a*k1+b -> a = (k2-k1)/(k1-k0)
    a = ((k[2] - k[1]) * modinv((k[1] - k[0]) % N)) % N
    b = (k[1] - a * k[0]) % N
    for (i, j) in pairs:
        if (a * k[i] + b) % N != k[j]:
            return None
    return d, a, b
```

## Stage 2: the quadratic recurrence

Squaring the nonce is what makes this one heavier. Substitute \(k_i = A_i + B_i d\) and

\[k_i^2 = A_i^2 + 2 A_i B_i d + B_i^2 d^2\]

into \(k_{i+1} = a k_i^2 + b k_i + c\) and expand everything:

\[A_{i+1} + B_{i+1} d = a A_i^2 + 2 A_i B_i (a d) + B_i^2 (a d^2) + b A_i + B_i (b d) + c\]

Every term is a known number times one of \(d, a, b, c, ad, bd, ad^2\). Move it all to one side and you get, for each consecutive pair \((i, i+1)\):

\[B_{i+1} d - A_i^2 a - A_i b - c - (2 A_i B_i)(a d) - B_i (b d) - B_i^2 (a d^2) \equiv -A_{i+1} \pmod n\]

Renaming \(Q = a d\), \(R = b d\), \(P2 = a d^2\) gives 7 linear unknowns and one equation per pair. 8 signatures means exactly 7 consecutive pairs, which is just enough to solve the 7x7 system exactly. Each row of the matrix is just the coefficients from that equation:

```python title="solve.py (excerpt)"
    # unknown order: d, a, b, c, Q, R, P2
    M, y = [], []
    for (i, j) in pairs[:7]:
        row = [
            B[j] % N,
            (-(A[i] * A[i])) % N,
            (-A[i]) % N,
            (-1) % N,
            (-(2 * A[i] * B[i])) % N,
            (-B[i]) % N,
            (-(B[i] * B[i])) % N,
        ]
        M.append(row)
        y.append((-A[j]) % N)
    sol = solve_linear_mod(M, y, N)
    if sol is None:
        return None
    d, a, b, c, Q, R, P2 = sol
    if Q != (a * d) % N:
        return None
    if R != (b * d) % N:
        return None
    if P2 != (a * d * d) % N:
        return None
    return d, a, b, c
```

The catch is that there's no signature left over to hold out, so the held out trick from Stage 1 doesn't work. What does work is the information linearization threw away. The solver treated \(Q\), \(R\) and \(P2\) as completely independent of \(d, a, b\), so nothing forces them to come out equal to the actual products. If the model is right they will anyway, because the real system has a real solution. If the model is wrong, \(Q\) is basically a random number mod \(n\), and the chance of it landing exactly on \(a \cdot d\) is about \(1/n \approx 2^{-256}\). I checked \(Q = a d\), \(R = b d\) and \(P2 = a d^2\) (mod \(n\)) and all three held exactly.

That gives the private key directly:

```text
d = 38777567769244238539213321518098770560743901963610550632259368812131859354034
```

## Stage 3: unsealing the flag

Following the spec from `signatures.json`:

```python
key = SHA256(d.to_bytes(32, "big"))
iv  = SHA256(f"{Qx},{Qy}".encode())[:12]
ct, tag = flag_enc[:-16], flag_enc[-16:]
flag = AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)
```

GCM is authenticated encryption: the last 16 bytes of `flag.enc` are a tag computed from the key and the ciphertext, and `decrypt_and_verify` throws if it doesn't match. So a clean decrypt is one more confirmation that \(d\) is right, a wrong key can't produce a valid tag.

After working through the models one at a time, I tidied everything into a single `solve.py`: the three nonce models, the modular linear solver and the AES-GCM unseal. It checks the LCG first, then the quadratic, then the index polynomials, so the order differs from how I actually went. Running the final version:

```console
$ python solve.py
[+] found consistent quadratic-nonce solution: k_(i+1) = 11382770581900951582759572968035363583277730425120362482570037791427041762956*k_i^2 + 74312909561341734046860221848141557722553378123923901218825974791425703713279*k_i + 3983032261160503883004122585640366545788497601771474650842098371932840996005 (mod n)
    d = 38777567769244238539213321518098770560743901963610550632259368812131859354034
FLAG: H7CTF{6d746428-2c51-4644-8613-2350d24f46dd}
```

## Flag

!!! success "Flag"
    ```text
    H7CTF{6d746428-2c51-4644-8613-2350d24f46dd}
    ```

## Notes

- PolyNonce is a specific, real attack with public tooling. Search the challenge name before building anything, the paper and the Kudelski repo cover the whole attack.
- The general trick (write \(k_i\) as an affine function of \(d\), substitute into whatever relation the nonces are meant to follow, and linearize every unknown product as its own variable) scales to any polynomial degree recurrence. The cost is needing roughly \(2 \cdot \text{degree}\) unknowns and that many signatures. Still worth trying the cheap models (static, or polynomial in the index) before reaching for the quadratic one.
- Always validate against something the fit didn't see. That's either held out signatures, or when every signature is needed just to pin down the unknowns, the internal consistency of the product variables you introduced. Either check turns "the linear solve returned some answer" into "this answer is almost certainly right".

## References

[^polynonce]: Marco Macchetti, "A Novel Related Nonce Attack for ECDSA", IACR ePrint 2023/305: <https://eprint.iacr.org/2023/305>
[^blog]: Kudelski Security Research, "Polynonce: A Tale of a Novel ECDSA Attack and Bitcoin Tears" (2023): <https://research.kudelskisecurity.com/2023/03/06/polynonce-a-tale-of-a-novel-ecdsa-attack-and-bitcoin-tears/>
[^repo]: kudelskisecurity/ecdsa-polynomial-nonce-recurrence-attack: <https://github.com/kudelskisecurity/ecdsa-polynomial-nonce-recurrence-attack>
[^ps3]: fail0verflow, "Console Hacking 2010: PS3 Epic Fail", 27C3 (2010)
