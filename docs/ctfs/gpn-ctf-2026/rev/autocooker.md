---
tags:
  - rev
  - xor
  - nibble-swap
  - gpn-ctf-2026
---

# Autocooker

## Overview

|  |  |
|---|---|
| **Event** | GPN CTF 2026 |
| **Category** | Reversing, Introduction |
| **Difficulty** | Easy |
| **Author** | MisterPine |

> I always feel like cooking is such a chore... You have to chop up all your ingredients, cook them for hours and then make the plating look half-decent. But not with this new machine I got! You just have to put in your recipe (weirdly, the interface calls it a flag...) and it will get cooked for you. It's so easy, even someone with no experience in cooking - reverse engineering can do it.

We get a binary that runs your input through a fixed sequence of "cooking" steps and only accepts the one recipe that comes out matching a stored target. Each cooking operation is its own inverse. They each undo themselves. The goal is to "uncook" the stored target in reverse order into the original flag. Uncook the meal, get the ingredients back.

The whole thing is genuinely beginner-friendly, and it has a feature that makes it even friendlier than the author probably intended. More on that below.

## Recon
First question for any binary: what is it, and did they leave the labels on?

```console
$ file autocooker
autocooker: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
```

A normal Linux x86-64 ELF, and crucially **not stripped**. The symbol table is intact, which on a reversing challenge is roughly like handing someone the recipe card and asking them to guess the dish. We'll lean on those names heavily.

Running it gives a banner, asks for the recipe (flag) and the rejects my text input. 

```console
$ ./autocooker
[ ... AUTO COOKER banner ... ]
Welcome to the auto cooker. We'll cook any recipe for you under one condition: It must actually taste good.

Enter your recipe (flag) you want to cook and confirm with [ENTER]:
myflagguess
Your recipe is too complicated or too simple, I already know it won't taste good :(
```

Notice it didn't even pretend to cook. "Too complicated or too simple" is a length complaint: there's a gate that rejects anything the wrong size before the real logic runs. Good to know.

### `ltrace` — the library calls

`ltrace` is a cheap first move in rev CTFs. It logs library calls and now and occassionally drops an obvious `strcmp` (string compare) against the flag straight into your lap. It doesn't here (the length gate exits first), but it's not a wasted run:

```console
$ ltrace ./autocooker
...
puts("Enter your recipe (flag) you wan"...) = 68
fgets("myflagguess\n", 64, 0x7f...) = 0x4040e0
puts("Your recipe is too complicated o"...) = 84
exit(1 <no return ...>)
+++ exited (status 1) +++
```

Input comes in via `fgets`, capped at **64 bytes**, into a buffer at `0x4040e0`, and then we exit. No comparison leaks because the matching happens inside the binary's own code rather than through a single libc call.


### `strings` — the menu

Because nothing is stripped, `strings` gives away the symbols. This leaves us with the programs UI text cooking messages as well as leftover tokens and symbol names present.

```console
$ strings autocooker
Welcome to the auto cooker. We'll cook any recipe for you under one condition: It must actually taste good.
Your recipe is too complicated or too simple, I already know it won't taste good :(
We now have the following state of our kitchen:
Salting...
Frying...
Oops, it burned :(
Cutting off the burnt bits...
Mixing...
Taste testing...
YUCK!
Our taste tester thinks your recipe produces bad food, we cannot serve this...
cooking_class
Enter your recipe (flag) you want to cook and confirm with [ENTER]:
Congratulations, you "cooked" a delicious plate of food!
autocooker.c
target.c
FOOD
RECIPE
explain_current_food
TARGET_LENGTH
taste
trim
GRAIN_OF_SALT
main
check_recipe_length
DELICIOUS
```

`Note:` Strings ignores runs shorter than 4 char defaults, so some functions don't appear above. They can be read from the symbol table:

```console
$ objdump -t autocooker | grep -E ' F \.text' | awk '{print $NF}'
...
salt
fry
trim
mix
taste
check_recipe_length
explain_current_food
main
```

So the UI text maps onto real functions: `salt`, `fry`, `trim`, `mix`, then a final `taste`. There are data symbols (`GRAIN_OF_SALT`, `TARGET`, `TARGET_LENGTH`) we'll want to read. Two names stand out as not part of the cooking theme: `explain_current_food` and `cooking_class`. We'll get back to that.

??? tip "Are `strings` + `ltrace` good first moves for rev?"
    Yes. They're the triage you run *before* opening a disassembler. `strings` surfaces hardcoded text and, on a non-stripped binary, the function and variable names; `ltrace`/`strace` show library and syscall behaviour, and occasionally a flag comparison drops out for free. They rarely finish a challenge on their own, but they cost seconds and they tell you where to point the heavier tools.




## Reading the recipe

Disassemble with `objdump` (Intel syntax, because it's easier on the eyes):

```console
$ objdump -d -M intel autocooker
```

The `main` asm reads like a recipe written in C. No Ghidra needed. After the banner prints it does:

1. `fgets` user input into `RECIPE`
2. `check_recipe_length`
3. copy `RECIPE` into the `FOOD` buffer
4. `salt` → `fry` → `trim` → `mix`
5. `taste`

So the program computes `flag → salt → fry → trim → mix` and then `taste` checks the result against a stored `TARGET`. If we can describe each step, we can run it backwards.

I also noted that `explain_current_food` ran after each step in the recipe. We will discuss that next.

### The accidental tasting menu: `cooking_class`

Before grinding through assembly, look at what `main` does with its arguments:

```text
cmp    DWORD PTR [rbp-0x14],0x1          ; argc > 1 ?
...
mov    esi,0x402345                      ; "cooking_class"
call   strcmp
... sets a flag if argv[1] == "cooking_class"
```

That flag gets handed to `explain_current_food`, which `main` calls *after every single cooking step*. And `explain_current_food` does exactly what its name promises. If the flag is set, it prints:

```text
We now have the following state of our kitchen:
<hex dump of all 64 FOOD bytes>
```

In other words, the binary ships with a debug mode. Run it as `./autocooker cooking_class` and it narrates its own cooking show, dumping the buffer after salt, after fry, after trim, after mix. You can *watch* each transform happen instead of deriving it from registers. For figuring out what each stage does, this is the whole game.

The method, then: feed a **known** input, turn on `cooking_class`, and diff the rows. I'll use sixty `A`s (`0x41`), since a wall of identical bytes makes any transformation obvious:

```console
$ python3 -c "print('A'*60)" | ./autocooker cooking_class
We now have the following state of our kitchen:
41 41 41 ... 41 0A 00 00 00      <- start: sixty 0x41, newline, then padding
Salting...
EB EB EB ... EB A0 AA AA AA      <- after salt
Frying...
BE BE BE ... BE 0A AA AA AA      <- after fry
Oops, it burned :(
Cutting off the burnt bits...
BE BE BE ... BE 0A 0A 0A 0A      <- after trim
Mixing...
0A 0A 0A 0A BE BE ... BE         <- after mix
Taste testing...
YUCK!
```

Every stage is now visible. The rest is just naming what we see, with the disassembly to confirm the mechanism.

## Working out each stage

### `check_recipe_length` — why the flag is 60 characters

The gate reads two bytes of `RECIPE` relative to `TARGET_LENGTH` and is happy only if:

- `RECIPE[TARGET_LENGTH]   == 0`  (a null terminator sits exactly there → not too long)
- `RECIPE[TARGET_LENGTH-1] != 0`  (a real byte sits just before it → not too short)

`TARGET_LENGTH` is `0x3d` = **61**. `fgets` keeps the trailing newline, so a 60-character flag is stored as 60 chars + `\n` at index 60 + `\0` at index 61. This is precisely what the gate demands. So: the flag is **60 characters** long. (You can see this in the start row above: sixty `41`s, then `0A` at index 60, then padding.)

### `salt` — XOR with a constant

In the dump, `0x41` became `0xEB`, and the `0x00` padding became `0xAA`. A byte that starts at zero turning into `0xAA` is a dead giveaway for `XOR 0xAA` (`0 ^ k = k`). The disassembly agrees:

```text
movzx  edx, BYTE PTR [rax+0x404120]   ; FOOD[i]
movzx  eax, BYTE PTR [rip+...]        ; GRAIN_OF_SALT
xor    edx, eax
mov    BYTE PTR [rax+0x404120], dl    ; FOOD[i] ^= GRAIN_OF_SALT
```

XOR is the bread and butter of CTF crypto because it's its own inverse: if `A ^ K = X`, then `X ^ K = A`. Salt again with the same key and you're back where you started. Reading the key out of `.data`:

```console
$ objdump -s -j .data autocooker
 404060 3d000000 aa000000 ...      <- TARGET_LENGTH=0x3d, GRAIN_OF_SALT=0xAA
```

`GRAIN_OF_SALT = 0xAA` -> `10101010`, a tidy alternating-bit mask. And `0x41 ^ 0xAA = 0xEB`, matching the dump exactly.

### `fry` — nibble swap

Next, `0xEB` became `0xBE`, and `0xA0` became `0x0A`. The digits are swapping places. That's a **nibble swap**, where the high four bits (high nibble) and low four bits (low nibble) of each byte trade ends:

```text
1011 1110  (0xBE)
^^^^ ^^^^
high  low   ->  swap  ->  1110 1011  (0xEB)
```

The disassembly is a textbook shift-and-combine: shift the byte left 4, shift a copy right 4, OR them together which is the canonical way to swap nibbles [^nibble]:

```text
shl    eax, 0x4      ; low nibble -> high
shr    al,  0x4      ; (copy) high nibble -> low
or     edx, eax
mov    BYTE PTR [rax+0x404120], dl
```

Like XOR, doing it twice gets you the original byte, so `fry` is also self-inverse: to undo it, fry it again.

### `trim` — cutting off the burnt bits

This is where the flavour text earns its keep. The combined message *"Oops, it burned :( / Cutting off the burnt bits..."* is one string, printed by `trim`. In the dump, the only bytes that change are the last three (indices 61–63): `AA AA AA` becomes `0A 0A 0A`. The loop confirms why:

```text
mov    eax, [TARGET_LENGTH]      ; i starts at 61, not 0
...
and    eax, 0xf                  ; FOOD[i] &= 0x0F  (zero the high nibble)
```

`trim` starts at `TARGET_LENGTH` (61) and ANDs each remaining byte with `0x0F`, zeroing the high nibble, literally cutting off the "burnt" top half of the bytes that frying overflowed into. The important part for us: it only ever touches indices 61–63, which are past the 60-char flag and its newline. **`trim` never touches a byte we care about, so we skip it entirely when reversing.**

### `mix` — reverse the array

After mixing, the row is flipped end-to-end: the four `0A`s that were at the tail are now at the front. `mix` copies all 64 bytes to a scratch buffer and writes them back in reverse:

```text
FOOD[i] = scratch[63 - i]    for every i
```

Reverse a list twice and it's unchanged, so this is self-inverse too. We reverse again to undo.

### `taste` — the comparison (and where the answer lives)

`taste` walks all 64 bytes, comparing cooked `FOOD` against `TARGET` (stored at `0x404080`), accumulating any mismatch; one wrong byte prints `YUCK!` and exits. `TARGET` is hardcoded, so we lift it straight out of `.data`:

```console
$ objdump -s -j .data autocooker
 404080 0a0a0a0a 7ddf5c4c 5f9ffc2e 9fb9ec5f
 404090 ed9d99ec 8dbe2e5f 8fff5e5f 8d5ccc5f
 4040a0 3feee9fe 8f5ffc8d e95ffd5c 3f5f991e
 4040b0 3e6e5f6c fc99ce5f 3e1dceef 9e4eafde
```

## Reversing it

Forward, the kitchen runs `salt → fry → trim → mix`. So to recover the flag we apply the inverses in the opposite order: undo `mix`, undo `trim` (nothing to do), undo `fry`, undo `salt`. Every operation is its own inverse, which collapses the whole thing to: reverse the array, swap the nibbles back, XOR with `0xAA`.

```python title="solve.py"
# Constants lifted from .data
GRAIN_OF_SALT = 0xAA  # the XOR key

TARGET = list(bytearray.fromhex(
    "0a0a0a0a7ddf5c4c5f9ffc2e9fb9ec5fed9d99ec8dbe2e5f8fff5e5f8d5ccc5f"
    "3feee9fe8f5ffc8de95ffd5c3f5f991e3e6e5f6cfc99ce5f3e1dceef9e4eafde"
))

# Inverses, in reverse pipeline order: mix, fry, salt.
mixed  = TARGET[::-1]                                            # undo mix (reverse)
fried  = [((b & 0x0F) << 4) | ((b & 0xF0) >> 4) for b in mixed]  # undo fry (nibble swap)
salted = [b ^ GRAIN_OF_SALT for b in fried]                      # undo salt (XOR 0xAA)

print("Flag:", "".join(chr(b) for b in salted).strip())
```

```console
$ python3 solve.py
Flag: GPNCTF{I_F3el_LIK3_You_4re_RE4DY_for_OUR_HArd3st_d1SHeS_noW}
```

## Flag

!!! success "Flag"
    ```text
    GPNCTF{I_F3el_LIK3_You_4re_RE4DY_for_OUR_HArd3st_d1SHeS_noW}
    ```

### Verifying with the machine

The recovered string should cook back into `TARGET`, so the quickest sanity check is to feed it to the binary and let it grade itself:

```console
$ ./autocooker
...
Enter your recipe (flag) you want to cook and confirm with [ENTER]:
GPNCTF{I_F3el_LIK3_You_4re_RE4DY_for_OUR_HArd3st_d1SHeS_noW}
Salting...
Frying...
Oops, it burned :(
Cutting off the burnt bits...
Mixing...
Taste testing...
Congratulations, you "cooked" a delicious plate of food!
```

The taste tester approves.

## Notes / lessons

- **A non-stripped binary hands you the map.** The symbol names (`salt`, `fry`, `trim`, `mix`, `taste`) lined up with the cooking flavour and told us the whole pipeline before we read a single instruction.
- **Read the argument handling.** The `cooking_class` debug mode turned "derive the transform from registers" into "feed a known input and watch the bytes." Always check what a binary does with `argv` and any leftover symbols that don't fit the theme (`explain_current_food` was the tell).
- **Self-inverse operations make reversing trivial.** XOR, nibble-swap and array-reversal each undo themselves, so the "algorithm" is just running it again backwards — no solver, no constraints to crack.
- **Watch the boundaries.** `trim` looked like a step to reverse, but it only touched bytes 61–63, outside the 60-character flag. `check_recipe_length` told us that length up front and saved the wasted effort.

## References

- Challenge handout (GPN CTF 2026, *Auto Cooker* by MisterPine): <https://gpn24.ctf.kitctf.de/api/challenges/handout/autocooker>

[^nibble]: Nibble-swap reference implementation — HarshCasper, *NeoAlgo*, `Swap_two_nibbles.py`: <https://github.com/HarshCasper/NeoAlgo/blob/master/Python/other/Swap_two_nibbles.py>