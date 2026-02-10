# CPI Privilege Escalation Patterns

Cross-Program Invocation (CPI) is fundamental to Solana's composability. However, improper CPI handling creates serious security vulnerabilities.

## Category Overview

CPI privilege escalation occurs when:
1. Attacker controls the target program of a CPI call
2. Signer privileges are forwarded to malicious programs
3. Account state changes aren't reflected after CPI returns
4. PDA signing authority is abused across programs

## Key Insight from Asymmetric Research

> "Once a user account or a PDA signs an instruction, that signer privilege is retained for the duration of the transaction and can be reused in subsequent CPIs."

This single property is the root cause of most CPI exploits.

## Patterns in This Category

| # | Pattern | Severity | Real Exploits |
|---|---------|----------|---------------|
| 01 | Arbitrary CPI Target | Critical | Token spoofing attacks |
| 02 | Signer Privilege Forwarding | Critical | Wormhole ($325M), multiple bridges |
| 03 | Missing Account Reload | High | State desync exploits |
| 04 | Ownership Transfer via CPI | High | Account hijacking |
| 05 | Lamport Drain via Signer | High | SOL theft patterns |
| 06 | Account Passthrough Abuse | Medium | LayerZero, bridge exploits |
| 07 | PDA Authority Confusion | High | Orderly Network ($56K contest) |

## Detection Checklist

- [ ] Are all CPI target programs validated against known IDs?
- [ ] After CPIs, are accounts reloaded with `.reload()`?
- [ ] Are signer privileges stripped before arbitrary callbacks?
- [ ] Is account ownership verified post-CPI?
- [ ] Are lamport balances checked before/after CPIs?
- [ ] Are PDAs scoped to specific users (account isolation)?

## Sources

- Asymmetric Research: "Invocation Security: Navigating Vulnerabilities in Solana CPIs" (May 2025)
- Helius: "Hitchhiker's Guide to Solana Program Security" (Feb 2025)
- ThreeSigma: "Rust Memory Safety on Solana" (2025)
- Sherlock: Orderly Solana Vault Contest (Sep 2024, $56.5K)
- zfedoran: Solana Program Vulnerabilities Guide (GitHub Gist)
