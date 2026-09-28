---
description: A fleet of RSA camera certs churned out on the same assembly line, where two of the moduli quietly share a prime and one gcd cracks the whole device open
tags:
  - crypto
  - rsa
  - shared-primes
  - batch-gcd
  - pkcs1v15
  - h7ctf-2026
---

# Shared Blood

## Overview

| | |
|---|---|
| **Event** | H7CTF 2026 Quals |
| **Category** | Crypto |
| **Difficulty** | Medium |

!!! info "Challenge Description"
    VoltEye ships a whole fleet of identical cameras, cranked out on the same assembly line, in the same hurry. Somewhere in that crowd is one device whose console you'd very much like to open.

    Family resemblance runs deeper than you'd think.

    HTTP 443: `https://$HOST`

No files came with this one. Everything lived on a running service, so the first move was just to hit its endpoints and read what it told me about itself.

## Recon

The landing page is a tiny HTML stub: a "VoltEye Camera Cloud" heading, a line saying admin bootstrap is required, a paragraph listing the API, and an unlock form that POSTs a token to `/admin`. The three endpoints it documents are the whole game:

| Endpoint | What it returns |
|---|---|
| `GET /fleet` | 30 device certs, each `{serial, n}`, all sharing exponent `e = 65537` |
| `GET /captured` | one intercepted provisioning payload: a PKCS#1 v1.5 ciphertext encrypted to one specific device |
| `POST /admin {"token": ...}` | redeems the bootstrap token for the flag |

`GET /captured` tells me which device the intercept was aimed at:

```json
{
  "note": "intercepted provisioning payload (RSA/PKCS1v1.5, encrypted to the device cert)",
  "serial": "VE-92D0C45D",
  "e": 65537,
  "ciphertext": "5be2f6f924c0208db28be0dc547d87dd...1061bf"
}
```

So the goal is concrete: decrypt that ciphertext to get the admin token, then POST it to `/admin`. To decrypt it I need the private key of device `VE-92D0C45D`, and all I have is its public modulus `n` sitting in the `/fleet` list next to 29 others.

That framing, plus the flavour text, is the whole hint. "Same assembly line, in the same hurry" and "family resemblance runs deeper than you'd think" is the classic tell for **shared-prime RSA keys**. When a batch of devices generates keys with too little entropy (a weak or predictable seed, a thin entropy pool right after boot, the same RNG state across an assembly line), two independently generated moduli can end up sharing one of their two primes by pure accident. This is a real bug that was surveyed at internet scale in 2012 by Heninger et al. ("Mining Your Ps and Qs")[^heninger] and independently by Lenstra et al. ("Ron was wrong, Whit is right"),[^lenstra] both of whom factored a chunk of the live TLS/SSH keyspace exactly this way.

## Background: why one shared prime breaks everything

An RSA modulus is `n = p * q` with `p` and `q` secret primes. The security rests entirely on nobody being able to split `n` back into those two factors. The public exponent `e = 65537` and the modulus `n` are all anyone gets; the private exponent `d` is the inverse of `e` modulo `(p-1)(q-1)`, and you can only compute it if you know `p` and `q`.

Factoring a single well-generated 1024-bit modulus is infeasible. But shared primes sidestep factoring completely. Suppose two devices produced

```text
n_i = p * q_i
n_j = p * q_j
```

that happen to share the same `p`. Then `p` is a common divisor of both, and

```text
gcd(n_i, n_j) = p
```

Euclid's algorithm computes that gcd in microseconds, no factoring involved. Once I have `p`, the rest falls out immediately: `q_i = n_i / p`, and I have the full factorisation of `n_i`. From there the private key is standard RSA:

```text
d = e^(-1) mod (p-1)(q-1)
```

The catch that makes it work here: the shared prime has to actually be shared. A modulus only leaks this way if some *other* modulus in the set was unlucky in the same spot. So the attack is inherently about the fleet, not the single target. I need to gcd the target against everyone else and hope one of them is its unlucky sibling.

## The attack: pairwise gcd across the fleet

The plan is one loop. Take the target modulus `n_t` for `VE-92D0C45D`, walk every other device in the fleet, and gcd the two. A result that isn't `1` (and isn't `n_t` itself) is a shared prime.

```python
target = next(d for d in fleet if d["serial"] == captured["serial"])
n_t = int(target["n"])
for d in fleet:
    if d["serial"] == target["serial"]:
        continue
    g = math.gcd(n_t, int(d["n"]))
    if g not in (1, n_t):
        p, other = g, d["serial"]
        break
q = n_t // p
```

Checking all 29 other devices against the target found exactly one hit: `VE-92D0C45D` shares a prime with `VE-3E622BE4`. That gcd is `p`, and dividing it out of `n_t` gives `q`:

```text
p = 11352785662157276088056460671861345194465402702339490480331152885322193904386915138968280235587809346125729315234909962097916711919746890131021237899847923
q = 7604696147938340484307989343843106838073627089367115610230838143941619797864388565188452345788647827253823004774277250889334536873961818402592084947046561
```

A quick `assert p * q == n_t` confirms the split is real before spending any more effort on it.

## Recovering the key and decrypting the intercept

With `p` and `q` in hand, building the private key and decrypting is textbook. The captured payload is RSA with PKCS#1 v1.5 padding, so I hand the reconstructed key to PyCryptodome's `PKCS1_v1_5` and let it strip the padding:

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

e = captured["e"]                       # 65537
d = pow(e, -1, (p - 1) * (q - 1))
key = RSA.construct((n_t, e, d))

sentinel = object()
token = PKCS1_v1_5.new(key).decrypt(bytes.fromhex(captured["ciphertext"]), sentinel)
# -> b'vlt_7575844924112f8654e055e4'
```

The decrypted provisioning payload is the admin bootstrap token, `vlt_7575844924112f8654e055e4`. Redeeming it is the last step:

```text
POST /admin {"token": "vlt_7575844924112f8654e055e4"}
```

```json
{"authed": true, "flag": "H7CTF{033b551a-54dd-498e-a186-dcce7e26c4d8}"}
```

## Cleaning it up

The final `solve.py` is just those three pieces glued together: pull `/fleet` and `/captured`, run the pairwise-gcd search for the shared prime against the target modulus, reconstruct the private key, decrypt the PKCS#1 v1.5 ciphertext, and POST the recovered token to `/admin`. It also throws a couple of fallback token candidates at `/admin` (the raw decrypted bytes plus any token-looking substring pulled out with a regex) in case the payload had come wrapped in JSON or text, but the clean decrypt landed on the first try.

One thing worth noting for a bigger fleet: gcd-ing every pair is O(n²), which is nothing at 30 devices but does grow. The standard scale-up is Bernstein's **batch GCD**,[^batchgcd] which multiplies all the moduli into one big product and does a single product-tree pass to find every shared prime across thousands of keys in roughly O(n log² n). It's the same trick the 2012 papers used to sweep the whole internet. Here the naive double loop was already instant, so there was no reason to reach for it.

## Flag

!!! success "Flag"
    ```text
    H7CTF{033b551a-54dd-498e-a186-dcce7e26c4d8}
    ```

## Notes

- Any time a challenge hands you a *fleet* of RSA public keys instead of a single one, try pairwise gcd across all of them before anything fancier (Wiener, Fermat, common-modulus, small-`e` tricks). Each gcd is essentially free, and shared primes are the single most common real-world RSA keygen bug.
- The gcd only finds `p` if the target's unlucky sibling is also in the set you were given. That's why the challenge shipped 30 certs and pointed the intercept at one of them: the sibling is in the crowd on purpose.
- Once a modulus is factored, everything encrypted to that device is trivially decryptable. There was no clever padding attack needed on the PKCS#1 v1.5 ciphertext, just a normal RSA decrypt with the recovered key.

## References

[^heninger]: Nadia Heninger, Zakir Durumeric, Eric Wustrow, J. Alex Halderman, "Mining Your Ps and Qs: Detection of Widespread Weak Keys in Network Devices", USENIX Security 2012: <https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/heninger>
[^lenstra]: Arjen K. Lenstra, James P. Hughes, Maxime Augier, Joppe W. Bos, Thorsten Kleinjung, Christophe Wachter, "Ron was wrong, Whit is right", IACR ePrint 2012/064: <https://eprint.iacr.org/2012/064>
[^batchgcd]: Daniel J. Bernstein, "How to find smooth parts of integers" (the batch GCD algorithm): <https://cr.yp.to/factorization/smoothparts-20040510.pdf>
