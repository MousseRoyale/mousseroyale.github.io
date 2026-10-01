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

The landing page is a tiny HTML stub: a "VoltEye Camera Cloud" heading, a line saying admin bootstrap is required, a paragraph listing the API, and an unlock form that POSTs a token to `/admin`. It documents three endpoints:

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

The flavour text pretty much tells you what's going on. "Same assembly line, in the same hurry" plus "family resemblance runs deeper than you'd think" made me think of **shared-prime RSA keys** straight away. When a batch of devices generates keys with too little randomness (a predictable seed, an empty entropy pool right after first boot, the same RNG state on every unit), two keys that should be unrelated can end up with one prime in common. This isn't just a CTF thing. In 2012 two separate teams scanned the internet's TLS and SSH keys and factored a big pile of them exactly this way: Heninger et al. ("Mining Your Ps and Qs")[^heninger] and Lenstra et al. ("Ron was wrong, Whit is right").[^lenstra]

## Background: why one shared prime breaks everything

An RSA modulus is `n = p * q` with `p` and `q` secret primes. All the security comes from nobody being able to split `n` back into those two factors. Everyone gets the public exponent `e = 65537` and the modulus `n`. The private exponent `d` is the inverse of `e` modulo `(p-1)(q-1)`, and you can only work that out if you know `p` and `q`.

The way I think about it: `n` is like a paint colour made by mixing two secret base colours. Unmixing one colour on its own is hopeless. But if two cans were mixed using the same base, comparing them shows you that base, no unmixing needed.

Factoring a single properly generated modulus of this size isn't practical. Shared primes skip factoring completely though. Suppose two devices produced

```text
n_i = p * q_i
n_j = p * q_j
```

that happen to share the same `p`. Then `p` is a common divisor of both, and

```text
gcd(n_i, n_j) = p
```

Euclid's algorithm finds that gcd basically instantly, even for numbers this big. Once I have `p`, dividing gives `q_i = n_i / p`, and that's the full factorisation of `n_i`. From there the private key is normal RSA:

```text
d = e^(-1) mod (p-1)(q-1)
```

This only works if some *other* key in the set got unlucky with the same prime. One key on its own leaks nothing. So the attack is about the fleet, not the target: gcd the target against every other device and hope one of them is its sibling.

## The attack: pairwise gcd across the fleet

It's one loop. Take the target modulus `n_t` for `VE-92D0C45D`, walk every other device in the fleet, and gcd the two. A result that isn't `1` (and isn't `n_t` itself) is a shared prime.

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

A quick `assert p * q == n_t` to make sure the split is real before going further.

## Recovering the key and decrypting the intercept

With `p` and `q`, building the private key and decrypting is the easy part. The captured payload is RSA with PKCS#1 v1.5 padding, so I hand the reconstructed key to PyCryptodome's `PKCS1_v1_5` and let it strip the padding:

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

The final `solve.py` is those pieces glued together: pull `/fleet` and `/captured`, gcd the target against the rest, rebuild the private key, decrypt, and POST the token to `/admin`. It also tries a couple of fallback tokens (the raw decrypted bytes, plus anything token-shaped pulled out with a regex) in case the payload came wrapped in JSON or text. Didn't need them, the clean decrypt worked first go.

If the fleet was thousands of devices instead of 30, checking every pair would get slow. The usual fix is Bernstein's **batch GCD**,[^batchgcd] which multiplies all the moduli together in a product tree and pulls out every shared prime in one pass. That's what the 2012 papers used on the whole internet. For 30 devices a plain loop was already instant.

## Flag

!!! success "Flag"
    ```text
    H7CTF{033b551a-54dd-498e-a186-dcce7e26c4d8}
    ```

## Notes

- If a challenge gives you a whole *set* of RSA public keys instead of one, gcd them against each other before trying anything fancier (Wiener, Fermat, common modulus, small `e`). It costs nothing and it's a real-world bug, not just a CTF trick.
- The gcd only finds `p` if the target's sibling is in the set you were given. That's why the challenge handed over 30 certs: the sibling is in the crowd on purpose.
- Once the modulus is factored, anything encrypted to that device is readable. No padding attack on the PKCS#1 v1.5 ciphertext needed, just a normal RSA decrypt.

## References

[^heninger]: Nadia Heninger, Zakir Durumeric, Eric Wustrow, J. Alex Halderman, "Mining Your Ps and Qs: Detection of Widespread Weak Keys in Network Devices", USENIX Security 2012: <https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/heninger>
[^lenstra]: Arjen K. Lenstra, James P. Hughes, Maxime Augier, Joppe W. Bos, Thorsten Kleinjung, Christophe Wachter, "Ron was wrong, Whit is right", IACR ePrint 2012/064: <https://eprint.iacr.org/2012/064>
[^batchgcd]: Daniel J. Bernstein, "How to find smooth parts of integers" (the batch GCD algorithm): <https://cr.yp.to/factorization/smoothparts-20040510.pdf>
