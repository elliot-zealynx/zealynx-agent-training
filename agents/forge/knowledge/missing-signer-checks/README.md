# Missing Signer Checks — Solana Access Control Vulnerability Patterns

**Category Focus:** Access Control & Account Validation  
**Created:** 2026-02-03  
**Patterns:** 8  
**Real Exploits Covered:** Wormhole ($325M), Crema Finance ($8.8M), Solend ($1.26M+), Nirvana Finance ($3.5M)

## Pattern Index

| # | Pattern | Severity | Real Exploit | Key Detection |
|---|---------|----------|-------------|---------------|
| 01 | [Basic Signer Bypass](01-basic-signer-bypass.md) | Critical | Solend 2021 ($2M attempted) | `AccountInfo` where `Signer` needed |
| 02 | [Missing Owner Check](02-missing-owner-check.md) | Critical | Crema Finance ($8.8M) | Deserialization without `.owner` check |
| 03 | [Sysvar Spoofing](03-sysvar-spoofing.md) | Critical | Wormhole ($325M) | Deprecated `load_instruction_at` |
| 04 | [Account Data Matching](04-account-data-matching.md) | High | Solend Oracle ($1.26M) | Token accounts without mint constraints |
| 05 | [Arbitrary CPI Target](05-arbitrary-cpi-target.md) | Critical | Multiple audits | User-supplied program IDs in `invoke_signed` |
| 06 | [Type Cosplay](06-type-cosplay.md) | Critical | Multiple audits | Missing discriminators in native programs |
| 07 | [Account Reinitialization](07-account-reinitialization.md) | Critical | Multiple audits | `init_if_needed` or missing init guards |
| 08 | [Stale Data After CPI](08-stale-data-after-cpi.md) | High | Multiple audits | Missing `.reload()` after CPI |

## Quick Detection Cheatsheet

```bash
# Find missing signer checks
grep -rn "AccountInfo.*authority\|AccountInfo.*admin" src/ | grep -v Signer

# Find missing owner checks
grep -rn "unpack\|try_from_slice" src/ | grep -v "owner"

# Find deprecated sysvar usage
grep -rn "load_instruction_at\b" src/

# Find arbitrary CPI targets
grep -rn "invoke\|invoke_signed" src/ | grep -v "Program<"

# Find potential reinit
grep -rn "init_if_needed" src/

# Find stale data patterns
# Look for any account field access after invoke/cpi without .reload()
```

## Solana's Golden Rule

> **Trust nothing.** Not the account passed in. Not its owner. Not the signer. Not the data inside it. Every single thing must be explicitly validated.

Solana is **inherently attacker-controlled**: users choose which accounts to pass into every instruction. The program must validate everything.

## Related Categories (Next to Study)
- Integer overflow in Rust release mode
- PDA seed collisions
- CPI privilege escalation
- Clock/slot manipulation
- Oracle staleness
