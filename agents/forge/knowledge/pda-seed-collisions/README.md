# PDA Seed Collision Patterns — Solana/Rust

**Category:** PDA (Program Derived Address) Vulnerabilities
**Severity Range:** Medium → Critical
**Date Studied:** 2026-02-04
**Researcher:** Forge 🔧

## Overview

PDAs are deterministic, program-controlled accounts derived from seeds + program_id. They are fundamental to Solana's account model, but their derivation mechanics introduce several subtle but devastating vulnerability classes.

**Key Insight:** Rust's memory safety does NOTHING to protect against PDA logic bugs. These are entirely architectural/logic vulnerabilities.

### Core Concepts

- `find_program_address(seeds, program_id)` → returns (PDA, canonical_bump) — bump starts at 255, decrements
- `create_program_address(seeds + [bump], program_id)` → creates PDA from explicit bump
- ~50% of bump values produce valid PDAs (off the ed25519 curve)
- **Same seeds can have MULTIPLE valid bumps → MULTIPLE valid addresses**

### Patterns in This Collection

| # | Pattern | Severity | Real Impact |
|---|---------|----------|-------------|
| 01 | Bump Seed Canonicalization | High | Shadow PDAs, accounting chaos |
| 02 | Seed Prefix Collision | High | Cross-type account confusion |
| 03 | Missing PDA Derivation Verification | Critical | Account spoofing, fund theft |
| 04 | PDA Spoofing via Unvalidated Accounts | Critical | Cashio $52M, Wormhole $325M |
| 05 | Seed Encoding Ambiguity | Medium-High | Collision between logical entities |
| 06 | PDA Authority Bypass | High | Unauthorized signing/access |

### Real-World Exploits Involving PDA Issues

- **Wormhole ($325M, Feb 2022)** — Fake guardian set via deprecated function + PDA validation gap
- **Cashio ($52M, Mar 2022)** — Bypassed unverified accounts; fake token accounts accepted as PDAs
- **Crema Finance ($8.8M, Jul 2022)** — Fake "Tick" account with false price data accepted
- **Solend ($1.26M, Nov 2022)** — Oracle account substitution (wrong price feed PDA)

### Sources

- Solana Official: [Program Security Course](https://solana.com/developers/courses/program-security/bump-seed-canonicalization)
- Sec3 Blog: [Why You Should Always Validate PDA Bump Seeds](https://www.sec3.dev/blog/pda-bump-seeds)
- Helius: [Hitchhiker's Guide to Solana Program Security](https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- Trail of Bits: [Building Secure Contracts - Improper PDA Validation](https://secure-contracts.com/not-so-smart-contracts/solana/improper_pda_validation/)
- ThreeSigma: [Rust Memory Safety on Solana](https://threesigma.xyz/blog/rust-and-solana/rust-memory-safety-on-solana)
- Stepan Chekhovskoi: [Solana PDA and PDA Seeds](https://medium.com/@SteMak/solana-pda-and-pda-seeds-380e3bf550ec)
- dev.to: [Solana Vulnerabilities Every Developer Should Know](https://dev.to/4k_mira/solana-vulnerabilities-every-developer-should-know-389l)
