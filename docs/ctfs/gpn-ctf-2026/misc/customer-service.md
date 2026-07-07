---
description: three stacked bugs in a holpy theorem prover let you register false as a theorem without a real proof
tags:
  - misc
  - theorem-prover
  - logic
  - gpn-ctf-2026
---

# Customer Service

## Overview

| | |
|---|---|
| **Event** | GPN CTF 2026 |
| **Category** | Miscellaneous |
| **Difficulty** | Easy |
| **Author** | s1nn105 |

!!! info "Challenge Description"
    The customer is always right. RIGHT?
    Experienced staff will tell you that customers are always worst case users.
    Just last week one customer proclaimed that pineapple does not belong on sushi pizza.
    Yeah I know, how could he? But the customer is always right.
    My friend fears for his sanity. So please help me work out the logic details for such an argument.

The challenge provides a handout and a live instance to spin up. The handout is a Python proof-checking service built on [holpy](https://github.com/bzhan/holpy), a Higher-Order Logic theorem prover. You submit a hex-encoded JSON theory file; if the checker ends up registering `false` as an unconditional theorem, you get the flag. That should be impossible in any sound theorem prover, so the goal is finding where this one is not.

## Reading the checker

`checker.py` takes a JSON object with two keys: `imports` (theory modules to load) and `content` (a list of items to process). An **item** is holpy's word for a named piece of theory: axiom, definition, theorem, and so on.

The win condition is straightforward:

```python
def theorem_proves_false_unconditioned(thm):
    concl_str = str(thm.concl).strip().lower()
    is_false = (
        thm.concl.is_const("false") or concl_str == "false" or concl_str == "?false"
    )
    no_assumptions = len(thm.assums) == 0
    no_hypotheses  = len(thm.hyps)  == 0
    return is_false and no_assumptions and no_hypotheses
```

The conclusion must stringify to `"false"`, with no assumptions or hypotheses attached. Worth noting the three separate checks inside `is_false` (the string comparison one becomes relevant later).

The item loop splits on type. Non-`thm` items fall into an `else` path that extends the theory but never reaches the win check. Only `thm` items go through proof validation and get tested:

```python
if item.ty == "thm":
    result = monitor.check_proof(item, rewrite=False)

    if result["status"] in ["OK", "ProofOK"]:
        exts   = item.get_extension()
        report = theory.thy.checked_extend(exts)

        if (len(report.get_axioms())) > 1:
            sys.exit(1)
        elif report.get_axioms() == 1 and item.ty != "thm":
            sys.exit(1)

        thm = theory.thy.get_theorem(item.name)
        if theorem_proves_false_unconditioned(thm):
            win()
```

There are three bugs in this path.

## Bug 1: a dead guard

```python
elif report.get_axioms() == 1 and item.ty != "thm":
    sys.exit(1)
```

`report.get_axioms()` returns a **list**. Comparing a list to the integer `1` with `==` is always `False` in Python. The `> 1` check above this catches anything beyond one axiom, but exactly one axiom from a `thm` item slips through every time.

## Bug 2: proof and prop never meet

For a `thm` item, two things happen in sequence that have nothing to do with each other:

1. `monitor.check_proof(item)` validates `item.proof` as a self-contained sequence of inference steps. Each step has to follow from the previous ones by holpy's rules. It does **not** check whether the final step actually proves `item.prop`.

2. `item.get_extension()` is inherited from holpy's `Axiom` class. It builds `Theorem(name, Thm(self.prop))` using the **declared `prop`**, not whatever the proof concluded. Because it comes from `Axiom`, it attaches no proof object to the extension.

When `checked_extend` sees a theorem extension with no proof attached, it registers it as an axiom. So whatever you write in `prop` lands in the theory as fact, as long as `proof` contains any valid steps.

## Bug 3: "false" the variable vs. false the constant

Back in `theorem_proves_false_unconditioned`, the check `str(thm.concl).strip().lower() == "false"` matches any term that stringifies to the four characters f-a-l-s-e, including a free boolean **variable** named `false`. That is not the same as the built-in `false` constant, but they look identical as strings.

A holpy `thm` item accepts a `vars` field for declaring free variables in scope. Declare `{"false": "bool"}` and within that theorem, `false` is a free boolean variable. Applying the `reflexive` rule to it gives `⊢ false = false`, which is a perfectly valid proof step. `check_proof` accepts it and never looks at `prop`.

## Putting it together

Submit one `thm` item:

- `vars: {"false": "bool"}`: `false` is a free boolean variable in scope
- `prop: "false"`: claim the theorem is `false` (the variable)
- `proof: [reflexive("false")]`: prove `false = false`, which is valid

`check_proof` passes on the reflexivity step. `get_extension()` registers `Thm(false_var)` with no proof attached, so `checked_extend` adds it as an axiom (one axiom, slips past the broken guard). `get_theorem` retrieves it, `str(thm.concl)` is `"false"`, the string check matches, and `win()` runs. The customer declared `false` was provable, and the checker took their word for it.

## Exploit

```python title="solve.py"
import json
import socket
import ssl

HOST = "caramelized-risotto-wrapped-in-braised-b-arnaise-xdpe.gpn24.ctf.kitctf.de"
PORT = 443

payload = {
    "imports": [],
    "content": [
        {
            "ty": "thm",
            "name": "pwn_false",
            "vars": {"false": "bool"},
            "prop": "false",
            "proof": [
                {"id": "0", "rule": "reflexive", "args": "false", "prevs": [], "th": ""}
            ]
        }
    ]
}

hex_proof = json.dumps(payload).encode("utf-8").hex()

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

with socket.create_connection((HOST, PORT), timeout=30) as raw:
    with ctx.wrap_socket(raw, server_hostname=HOST) as s:
        try:
            print(s.recv(4096).decode(errors="replace"), end="")
        except Exception:
            pass
        s.sendall((hex_proof + "\n").encode())
        buf = b""
        while True:
            try:
                chunk = s.recv(4096)
            except Exception:
                break
            if not chunk:
                break
            buf += chunk
        print(buf.decode(errors="replace"))
```

```console
$ python3 solve.py
give me your hex proof
✓ Proof check passed
Congratulations! You've found the flag: GPNCTF{Ex-UNa-LIne4-VacUa-s3qUiTUr-QuOd1i8E7}
```

## Flag

!!! success "Flag"
    ```text
    GPNCTF{Ex-UNa-LIne4-VacUa-s3qUiTUr-QuOd1i8E7}
    ```

## Notes

- The flag decodes to *ex una linea vacua sequitur quodlibet*, "from one empty line, anything follows." It's a riff on [*ex falso quodlibet*](https://en.wikipedia.org/wiki/Principle_of_explosion) (from false, anything follows), with the "empty line" pointing at the `prf=None` slot in the theorem extension that kicks off the whole chain.
- The challenge title pays off nicely here: the checker accepts whatever you declare in `prop` without the proof ever needing to back it up. You say `false` is provable, and the checker believes you. The customer is always right.
- A sound fix would have `check_proof` compare its conclusion against `item.prop`, and `get_extension` attach the verified proof to the extension so `checked_extend` never falls back to axiom mode.

## References

- holpy source: <https://github.com/bzhan/holpy>
- Wikipedia, *Principle of explosion*: <https://en.wikipedia.org/wiki/Principle_of_explosion>
