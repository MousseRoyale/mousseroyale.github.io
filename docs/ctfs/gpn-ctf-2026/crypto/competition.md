---
description: malleable SHA-256 commitment lets you pick your move after seeing the server's
tags:
  - crypto
  - commitment-scheme
  - gpn-ctf-2026
---

# COMpetition

## Overview

| | |
|---|---|
| **Event** | GPN CTF 2026 |
| **Category** | Crypto, Introduction |
| **Difficulty** | Easy |
| **Author** | uxxct |

!!! info "Challenge Description"
    This week's special: A chance to compete against our esteemed guest, the rock-paper-scissors grand master. If you manage to beat them 100 out of 100 times we will reward you with a flag specially made for you.

The challenge provides the server source as a handout and a live SSL instance to connect to via `ncat --ssl`. Rock-paper-scissors against a server, 100 rounds straight. The catch is that you have to commit to your move before seeing the server's pick, then prove the commitment was honest.

## Recon

With `main.py` in hand I can see the logic to the protocol. For each of the 100 rounds you send a commitment, the server picks and reveals its move, then you reveal your move and prove the commitment was genuine. The server calls `verify` to check:

```python
def verify(commitment: bytes, message: bytes, unveil_info: tuple[bytes, bytes]) -> bool:
    r1, r2 = unveil_info  # two is better than one, right?
    return commitment == sha256(r1 + message + r2).digest()
```

This is a **commitment scheme**: you lock in your move up front by hashing it with two nonces `r1` and `r2`, then later prove what you committed to by revealing the pre-image. For the scheme to be useful it needs to be **binding**, meaning you can only open the commitment one way. If you can open the same commitment as "rock" in one round and "paper" in another, it is no commitment at all.

There is also a replay guard that catches reusing the same hash with two different answers:

```python
elif com in already_seen and already_seen[com] != your_choice:
    print("Something fishy is going on here. What are you doing?")
    return
```

Connecting with `ncat` and sending a dummy commitment shows the full round flow:

```console
$ ncat --ssl flash-fried-risotto-marinated-in-sauced-tapenade-5uwi.gpn24.ctf.kitctf.de 443
I want to play a game...
Commitment (hex): 0000000000000000000000000000000000000000000000000000000000000000
I choose rock.
What did you choose? paper
Proof (hex): aa bb
Hey, no cheating! Do that again and I will eat all your flags
```

## The flaw

The comment in `verify` is a hint: `# two is better than one, right?`

The hash input is `r1 + message + r2`, the three fields concatenated. The verifier checks that this string hashes to the commitment, but never checks *where inside the string* `message` sits. It only checks that the bytes line up somewhere.

Since both `r1` and `r2` are supplied by the opener, the split is chosen after the fact. The same commitment opens to any of the three moves just by shifting the boundary:

Take the pre-image `rockpaperscissors_`. All three move names appear in it in sequence. Open the same hash as any move by choosing which slice you call `message`:

| `message`  | `r1`        | `r2`             | `r1 + message + r2`  |
|------------|-------------|------------------|----------------------|
| `rock`     | `""`        | `paperscissors_` | `rockpaperscissors_` |
| `paper`    | `rock`      | `scissors_`      | `rockpaperscissors_` |
| `scissors` | `rockpaper` | `_`              | `rockpaperscissors_` |

All three concatenate to the same string, so all three hash to the same commitment. One commitment opens to any move you want. The scheme is not binding.

The trailing `_` is needed because the server parses the proof as two space-separated hex values via `.split()`, which drops empty tokens. Without it, the scissors case produces an empty `r2` that cannot be sent.

## Defeating the replay check

The replay guard locks a commitment hash to whichever move it first opened to. Sending `sha256("rockpaperscissors_")` every round and claiming a different move each time would get caught on round two.

Fix: prepend a per-round nonce to the pre-image. Commit to `sha256(str(round) + "rockpaperscissors_")` for each round. Every hash is unique, each one independently opens to any move, and the guard never fires.

## Exploit

After the server reveals its pick, open the current round's commitment to the counter-move:

| Server picks | Open to    |
|--------------|------------|
| `rock`       | `paper`    |
| `paper`      | `scissors` |
| `scissors`   | `rock`     |

```python title="solve.py"
import socket
import ssl
from hashlib import sha256

HOST = "flash-fried-risotto-marinated-in-sauced-tapenade-5uwi.gpn24.ctf.kitctf.de"
PORT = 443

context = ssl.create_default_context()
with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as s:

        def recv_until(delimiter):
            buf = b""
            while delimiter not in buf:
                chunk = s.recv(1)
                if not chunk:
                    break
                buf += chunk
            return buf.decode()

        print(recv_until(b"I want to play a game...\n").strip())

        for round_num in range(100):
            salt = f"{round_num:02d}".encode()
            com = sha256(salt + b"rockpaperscissors_").hexdigest()

            recv_until(b"Commitment (hex): ")
            s.sendall(f"{com}\n".encode())

            bot_choice = recv_until(b"\n").strip().split()[-1].rstrip(".")

            wins_against = {"rock": "paper", "paper": "scissors", "scissors": "rock"}
            your_choice = wins_against[bot_choice]

            if your_choice == "rock":
                r1, r2 = salt, b"paperscissors_"
            elif your_choice == "paper":
                r1, r2 = salt + b"rock", b"scissors_"
            else:
                r1, r2 = salt + b"rockpaper", b"_"

            recv_until(b"What did you choose? ")
            s.sendall(f"{your_choice}\n".encode())

            recv_until(b"Proof (hex): ")
            s.sendall(f"{r1.hex()} {r2.hex()}\n".encode())

            print(f"Round {round_num+1:03d}/100  bot={bot_choice:<8}  you={your_choice}")

        print(s.recv(4096).decode())
```

```console
$ python3 solve.py
I want to play a game...
Round 001/100  bot=scissors  you=rock
Round 002/100  bot=rock      you=paper
Round 003/100  bot=paper     you=scissors
...
Round 100/100  bot=rock      you=paper

How can that be? Well, a deal is a deal. Here is your flag: GPNCTF{WaIT, It'S n0t JU5T LUck? N3V3r ha5 B33n.}
```

## Flag

!!! success "Flag"
    ```text
    GPNCTF{WaIT, It'S n0t JU5T LUck? N3V3r ha5 B33n.}
    ```

## Notes

- The property this scheme is missing is called **binding**: a commitment should be openable to exactly one value.[^binding] Here the opener controls both nonces, so the split is decided after the server reveals. The commitment never actually fixed anything.
- The fix is a properly structured commitment where `message` has an enforced position, for example a fixed-length `r1` or a length-prefixed encoding, so the server can verify the boundary independently.
- The replay guard is not wrong, just not enough. It stops reusing the same hash with different answers, but it cannot help when a single hash is already equivocal on its own.

## References

- Boneh & Shoup, *A Graduate Course in Applied Cryptography*, Ch. 12: <https://toc.cryptobook.us/>
- Wikipedia, *Commitment scheme*: <https://en.wikipedia.org/wiki/Commitment_scheme>

[^binding]: Boneh & Shoup, *A Graduate Course in Applied Cryptography*, Chapter 12. A commitment scheme is *binding* if no PPT adversary can produce two valid openings for the same commitment: <https://toc.cryptobook.us/>

