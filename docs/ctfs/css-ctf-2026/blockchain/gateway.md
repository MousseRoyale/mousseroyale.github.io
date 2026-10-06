---
description: Three doors in a Solidity contract, and the third one's password is "private"
tags:
  - blockchain
  - solidity
  - storage
  - tx-origin
  - css-ctf-2026
---

# Gateway

## Overview

| | |
|---|---|
| **Event** | CSS CTF 2026: Return of Nexus |
| **Category** | Blockchain |

!!! info "Challenge Description"
    ...Its emergency gate still demands three proofs of clearance... Find your way through all three doors and claim the credentials left inside.

    Files: `Gate.sol`, `Setup.sol`

    `nc $HOST 31337`

The warm-up blockchain challenge. Two Solidity files and a launcher that spins up your own private chain with a funded account. The goal is to get `Gate.solved` set to `true`, then ask the launcher for the flag.

## Recon

`Setup.sol` just deploys the `Gate` and exposes `isSolved()`, which returns `gate.solved()`. Nothing else in there. All the interesting stuff is in `Gate.sol`:

```solidity
contract Gate {
    address public owner;      // slot 0
    bytes32 private password;  // slot 1
    bool private stepped;      // slot 2
    bool private funded;       // slot 3
    bool public solved;        // slot 4

    constructor() payable {
        owner = msg.sender;
        password = keccak256(abi.encodePacked("gateway to the flag"));
    }

    /// @notice Door 1: only a contract may pass.
    function enter() external {
        require(tx.origin != msg.sender, "Gate: must be called from a contract");
        stepped = true;
    }

    /// @notice Door 2: pay homage in plain ether.
    receive() external payable {
        require(stepped, "Gate: complete door 1 first");
        require(msg.value > 0, "Gate: send some ether");
        funded = true;
    }

    /// @notice Door 3: speak the password.
    function claim(bytes32 _password) external {
        require(stepped, "Gate: complete door 1 first");
        require(funded, "Gate: complete door 2 first");
        require(_password == password, "Gate: wrong password");
        solved = true;
    }
}
```

The "three proofs of clearance" from the description are literally the three functions, each guarded by a `require`.

## The three doors

### Door 1: be a contract

`tx.origin` is the wallet that signed the transaction. `msg.sender` is whoever called this function directly. If I call `enter()` from my wallet, they're the same address. If my wallet calls a contract that calls `enter()`, `msg.sender` is that contract and `tx.origin` is still my wallet, so they differ.

So "only a contract may pass" is enforced exactly how it says. It's the reverse of the usual pattern, where `tx.origin == msg.sender` gets used to keep contracts *out*.[^txorigin]

### Door 2: send any ether

`receive()` runs when the contract gets plain ether with no function call attached. It only checks that door 1 is done and that more than 0 wei came in. One wei is enough.

### Door 3: the "private" password

`password` is marked `private`, but that only stops *other contracts* from reading it through Solidity. It doesn't hide anything on-chain. Every node stores every contract's storage, and anyone can read a slot directly.[^private]

State variables get laid out in storage slots in the order they're declared, and the contract even comments the layout for us:

| Slot | Variable | Visibility |
|---|---|---|
| 0 | `owner` | public |
| 1 | `password` | private (not really) |
| 2 | `stepped` | private |
| 3 | `funded` | private |
| 4 | `solved` | public |

So slot 1 is the password hash. You can also just work it out, since the constructor hashes a hardcoded string, but reading it from storage confirms the guess is right instead of assuming it. Reading slot 1 on my instance gave:

```text
0x90cd83d75da724f03cbd4c1bd73dbfca4325ab5c4930082484b6f6aa9234d70b
```

which matches `keccak256("gateway to the flag")` computed locally.

## Exploit

All three doors can go in one transaction, using the constructor of an attacker contract. The constructor runs as a contract, so door 1 passes, and it can forward the ether it was deployed with for door 2:

```solidity
contract Exploit {
    constructor(address payable gateAddr, bytes32 password) payable {
        IGate gate = IGate(gateAddr);
        gate.enter();                                           // door 1
        (bool ok, ) = gateAddr.call{value: msg.value}("");      // door 2
        require(ok, "funding failed");
        gate.claim(password);                                   // door 3
    }
}
```

The steps I ran with web3.py:

1. Launch an instance from the launcher (the ticket is the team name), which gives an RPC URL and a funded key.
2. Call `Setup.gate()` to get the `Gate` address.
3. Read slot 1 with `eth_getStorageAt`.
4. Compile and deploy `Exploit` with `value=1 wei` and the address and password as arguments.
5. Check `Gate.solved()` is `true`, then pick `3 - get flag` on the launcher.

One small gotcha with the launcher: my first connection during recon had half-launched an instance without giving me the connection details, and every later launch just said "An instance is already running!". Killing it (`2`) and launching again fixed it.

## Flag

!!! success "Flag"
    ```text
    CSSCTF{CSS{B451C_BL0CKCH41N_5K1LL5}}
    ```

## Notes

- `private` in Solidity is about which code can read a variable, not about secrecy. Anything a contract stores, the whole chain can read. Real secrets need to stay off-chain, or go on-chain only as a commitment (a hash of something with enough entropy that it can't be guessed, unlike this one).
- `tx.origin` checks are worth reading carefully in either direction. Here it lets contracts in. The more common bug is using `tx.origin` for authorisation, which lets any contract you interact with act as you.
- If a CTF launcher hands back nothing useful, kill the instance and relaunch before assuming the challenge is broken.

## References

[^txorigin]: Solidity docs, "Security Considerations: tx.origin": <https://docs.soliditylang.org/en/latest/security-considerations.html#tx-origin>
[^private]: Solidity docs, "Security Considerations: Private Information and Randomness": <https://docs.soliditylang.org/en/latest/security-considerations.html#private-information-and-randomness>
