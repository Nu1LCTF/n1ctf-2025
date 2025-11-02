# Bridge

+ Solved: 2 (Emmmm2025, 0ops)

## Challenge Overview
The program implements a minimal cross-chain bridge. The admin registers supported mints with `register_mint`, and regular users can deposit those tokens into custody with the `bridge` instruction. An off-chain keeper listens for emitted events to complete the bridge process. In this challenge, when the server observes an event that satisfies specific conditions, it releases the flag.

## Vulnerability 1 – Missing Mint Consistency Check
Inside `challenge/programs/challenge/src/lib.rs` the bridge context includes both the user-supplied mint and its supposed configuration:

```rust
/* challenge/programs/challenge/src/lib.rs */
316 | pub mint: InterfaceAccount<'info, Mint>,
317 | pub mint_config: Account<'info, MintConfig>,
```

The `bridge` handler never verifies that `mint_config` is the PDA derived from the provided mint, nor does it check that `mint_config.mint` actually matches `mint`. As a result, a user can submit any arbitrary mint, even one never registered by the admin, and pair it with a valid `MintConfig` account.

## Vulnerability 2 – Anchor Client Event Parsing Bug
To turn the arbitrary mint into a practical exploit we rely on a one-day bug in Anchor, fixed by https://github.com/solana-foundation/anchor/pull/3657. The bug, originally disclosed by publicqi in April, persisted through the 0.31.1 release (the latest available when the challenge was authored) and was only fixed in 0.32.0 roughly a month before the CTF, without an explicit changelog entry.

Anchor’s client-side event parser used an overly permissive regular expression for log matching. By emitting `msg!("success");`, an attacker can prematurely exit one parsing frame, desynchronize the stack. While the pull request describes this as a potential DoS, it also enables full event forgery.

----

Combining these two vulnerabilities, we create our own Token-2022 mint and attach the Transfer Hook extension so that any transfer into the bridge invokes our malicious program. In our malicious program, we can forge malicious events based on self CPI, forged success and invoke logs.