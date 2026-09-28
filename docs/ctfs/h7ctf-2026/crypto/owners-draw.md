---
description: A payment webhook signed with SHA256(secret || body), which is a Merkle-Damgard hash begging to be length-extended into an owner-role payout
tags:
  - crypto
  - length-extension
  - sha256
  - mac-forgery
  - h7ctf-2026
---

# Owner's Draw

## Overview

| | |
|---|---|
| **Event** | H7CTF 2026 Quals |
| **Category** | Crypto |
| **Difficulty** | Medium |

!!! info "Challenge Description"
    OrionPay does exactly what it's told, provided the paperwork looks right. The owner's draw is the one payout nobody else is supposed to touch. You walked away with a single genuine slip and a lot of curiosity.

    The rest is between you and the accountant.

    HTTP 443: `https://$HOST`

No files came with this one. Everything lived on the running service, so the first job was just poking at it and reading what it told me about itself.

## Recon

`GET /` on the instance is a self-documenting API blob:

```json
{
  "service": "OrionPay webhook receiver",
  "endpoints": {
    "GET /sample": "a captured legitimate webhook (body + signature)",
    "POST /webhook": "process a webhook; body raw, header X-Signature = SHA256(secret||body); role=owner pays out",
    "POST /v2/webhook": "next-gen signing (HMAC-SHA256)"
  },
  "hint": "an owner-role payout releases the flag"
}
```

The line that jumps out is `X-Signature = SHA256(secret||body)`. That is the classic textbook-broken construction, and seeing a `SHA256(secret || ...)` "MAC" sitting next to a `/v2/webhook` that quietly upgrades to HMAC is the challenge basically pointing at the answer. This is a SHA-256 length extension setup: `SHA256(secret || body)` can be forged into `SHA256(secret || body || padding || anything_I_want)` without knowing the secret, and HMAC on `/v2` is the fix that would have killed it. The "single genuine slip" from the description is the one captured `(body, signature)` pair I need to bootstrap that.

`GET /sample` hands it over:

```json
{
  "note": "captured production webhook (as delivered to /webhook)",
  "signing": "X-Signature: SHA256(secret || body)",
  "body": "event=payment.succeeded&amount=500&currency=usd&customer=cus_9f2a&role=guest",
  "X-Signature": "762fd5939a865a0785fbcb6ed60322400b405188d406e00079a046ffc3b275f9"
}
```

So I have one valid body, its valid signature, and a goal: get the server to see `role=owner` on a webhook that still signature-checks.

This attack has well-known off-the-shelf tools. `hash_extender` (Ron Bowes) does MD4/MD5/SHA-1/SHA-256/SHA-512 and will spit out both the forged data and the forged signature for you.[^hashextender] `HashPump` (and its Python bindings `hashpumpy`) does the same job.[^hashpump] Either one would have solved this. I wrote the extension myself instead, mostly because it is about sixty lines and it let me unit-test the forge against `hashlib` before spending any live attempts. I will point out where a tool would slot in.

## Background: why this construction is broken

### SHA-256 is Merkle-Damgard

SHA-256 processes its input in 512-bit (64-byte) blocks. It carries an internal state of eight 32-bit words, starts them at a fixed IV, and folds each block into that state with a compression function. After the last block, those eight words *are* the output digest. There is no extra squeezing or truncation. The digest you get back is a complete snapshot of the machine's internal state at the moment it finished eating the (padded) message.

That is the whole problem. If I hand the digest to a compression function as its starting state, I can carry on hashing from exactly where the original computation stopped, as if more bytes had arrived.

### Padding is deterministic and public

Before hashing, SHA-256 pads the message so its length is a multiple of 64 bytes. The padding is fixed and depends only on the message length: a single `0x80` byte, then enough `0x00` bytes, then the original message length in bits as a big-endian 64-bit integer. Nothing secret goes into the padding. If I know how many bytes were hashed, I can reproduce the padding byte for byte.

### `H(secret || body)` is not a MAC

The service wants `X-Signature` to prove "this body came from someone who knows the secret". With `SHA256(secret || body)` that proof leaks. The digest is the internal state after hashing `secret || body || padding_for(len(secret)+len(body))`. Give me that state plus the length, and I can append my own bytes and keep hashing, producing a signature that verifies for a longer message, all without ever seeing `secret`. I do not learn the secret, I just get to extend the signed message with a suffix of my choosing.

The right primitive is HMAC, which nests the hash:

```text
HMAC(K, m) = H( (K XOR opad) || H( (K XOR ipad) || m ) )
```

The inner hash gets consumed by an outer hash, so an attacker never holds a raw internal state that corresponds to the message boundary. There is nothing to resume from. That is precisely what `/v2/webhook`'s "next-gen signing (HMAC-SHA256)" is doing, and it is why the flag lives on the un-hardened `/webhook`. Hashes with a different internal structure (SHA-3 / Keccak's sponge) also dodge plain length extension, since their output is not the full state.

## The plan

Putting the pieces together:

1. Take the one genuine `(body, signature)` pair from `/sample`.
2. I do not know `len(secret)`, and the glue padding depends on `len(secret) + len(body)`. So guess the secret length. A wrong guess builds the wrong padding and the server answers `{"error": "bad signature"}`, which makes the live endpoint a perfect oracle: brute-force the length and watch for the reply to change.
3. For each guessed length, resume SHA-256 from the leaked digest, append the glue padding and then my suffix `&role=owner`, and POST the forged `body + glue + suffix` with the forged signature.
4. The body is `key=value&key=value...`. If the server keeps the last value for a repeated key (the common naive behaviour), appending a second `&role=owner` after the original `&role=guest` flips the role.

## Building the forge

`hashlib` will not let me set SHA-256's starting state, so I need a small SHA-256 whose compression function I can seed from an arbitrary digest. That is just the standard algorithm with the eight state words initialised from the leaked digest instead of the fixed IV.

The padding function reproduces exactly what SHA-256 would have appended after a message of a given length:

```python
def sha256_padding(total_len):
    """The exact padding SHA-256 appends after `total_len` bytes of message."""
    pad = b"\x80"
    pad += b"\x00" * ((56 - (total_len + 1) % 64) % 64)
    pad += struct.pack(">Q", total_len * 8)
    return pad
```

The extension itself reloads the eight state words from the hex digest, computes the glue padding for the original `secret || body` length, then keeps hashing over `suffix || padding_for_the_new_total`:

```python
def length_extend(orig_digest_hex, orig_total_len, suffix):
    """Return (new_digest_hex, glue_padding_bytes) for
    H(secret||body||glue||suffix) given H(secret||body) and len(secret||body).
    """
    h = list(struct.unpack(">8L", bytes.fromhex(orig_digest_hex)))
    glue = sha256_padding(orig_total_len)
    new_total_len = orig_total_len + len(glue) + len(suffix)
    msg = suffix + sha256_padding(new_total_len)
    for i in range(0, len(msg), 64):
        h = _compress(h, msg[i : i + 64])
    return struct.pack(">8L", *h).hex(), glue
```

`_compress` is the ordinary SHA-256 round function (the `_K` constants, the message schedule, the 64 rounds) with its state passed in and out instead of hardcoded to the IV. Before touching the service I checked the whole thing against `hashlib`: for a secret and body I picked myself, the forged digest for `secret || body || glue || suffix` matched `hashlib.sha256(secret + body + glue + suffix).hexdigest()` exactly. That is the confidence I wanted before spending live attempts, and it is also what `hash_extender --table` gives you for free if you go the tool route.

## The forged message

The suffix is `&role=owner`, `len(body)` is 76 bytes, and the winning secret length turned out to be 14 (more on that next). With `secret_len = 14`, the original hashed input `secret || body` is 90 bytes, so the glue is the SHA-256 padding for 90 bytes: `0x80`, then 29 zero bytes, then the 64-bit length `0x00000000000002d0` (90 bytes is 720 bits, and `720 = 0x2d0`). The message the server actually hashes when it verifies my forgery looks like this:

| Segment | Bytes | Contents |
|---|---|---|
| `secret` | 14 | unknown to me, supplied by the server |
| `body` | 76 | `event=payment.succeeded&amount=500&currency=usd&customer=cus_9f2a&role=guest` |
| glue padding | 38 | `80` + `00`*29 + `00000000000002d0` (padding for the 90-byte prefix) |
| suffix | 11 | `&role=owner` |

I only control the last two rows on the wire (I POST `body + glue + suffix` as the raw body), but because the glue is exactly the padding SHA-256 would have inserted after `secret || body`, the server's own hashing lands on the boundary my forged state started from, and the signature checks out. The parser then walks the querystring, sees `role=guest` and later `role=owner`, and keeps the last one.

## Running it against the oracle

The attack loop guesses secret lengths from 0 upward. Each guess produces its own glue and its own forged signature, and I POST the forged body:

```python
suffix = b"&role=owner"
for secret_len in range(0, 81):
    total_len = secret_len + len(body_bytes)
    new_sig, glue = length_extend(sig, total_len, suffix)
    new_body = body_bytes + glue + suffix
    requests.post(f"{BASE}/webhook", data=new_body,
                  headers={"X-Signature": new_sig, "Content-Type": "text/plain"})
```

Wrong lengths come back as bad-signature errors. `secret_len = 14` was the hit:

```json
{"ok": true, "payout": "authorized", "flag": "H7CTF{e5858565-2388-4df5-9421-14ac975e2d82}"}
```

## Cleaning it up

Afterwards I folded the whole thing into a single `solve.py`: the pure-Python resumable SHA-256 (`_K`, `_rotr`, `_compress`), `sha256_padding`, `length_extend`, and a `main()` that pulls `/sample`, then sweeps `secret_len` from 0 to a configurable max (default 64), printing the server's JSON for each guess and stopping on the first response with `ok`, a `flag`, or `role == "owner"`. Feeding it a wider max is all it takes if 64 had not been enough.

## Flag

!!! success "Flag"
    ```text
    H7CTF{e5858565-2388-4df5-9421-14ac975e2d82}
    ```

## Notes

- Never build a MAC as `H(secret || message)`. It is length-extension-vulnerable for every Merkle-Damgard hash (MD5, SHA-1, SHA-256, SHA-512). Use HMAC, or a hash whose output is not its full internal state.
- Not knowing the secret's exact length is not a real obstacle when the verifier will tell you whether a signature is good. The endpoint is its own oracle, and a plausible secret length is a tiny search space.
- Check how the receiver parses a delimited body for duplicate keys. "Last value wins" is the naive default, and it is exactly what makes an appended `&role=owner` override work once forgery is on the table.
- Another team's writeup for the same challenge went basically the same way: their own resumable SHA-256 in Python and a brute force over the secret length against the endpoint.[^tinhatinh] Their instance had a 15 byte secret instead of my 14, and they point out a nice self-check: the length field at the end of the glue padding encodes the total bit length, so you can read the winning secret length straight back out of it.
- `hash_extender` and `HashPump`/`hashpumpy` automate this end to end. Rolling my own was quick and let me self-test against `hashlib` first, but the tools would have gotten the same forged pair.

## References

[^hashextender]: Ron Bowes, `hash_extender` (hash length extension for MD4/MD5/SHA-1/SHA-256/SHA-512, etc.): <https://github.com/iagox86/hash_extender>
[^hashpump]: bwall, `HashPump` (and the `hashpumpy` Python bindings): <https://github.com/bwall/HashPump>
[^tinhatinh]: tinhatinh, CTFWU, H7CTF 2026 Quals / owners-draw: <https://github.com/tinhatinh/CTFWU/tree/main/H7CTF%202026%20Quals/owners-draw>
