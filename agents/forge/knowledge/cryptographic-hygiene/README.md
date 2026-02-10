# Cryptographic Hygiene Patterns

Patterns for auditing Rust programs that handle encryption keys, ZK proofs, confidential data, and cryptographic primitives. These go beyond arithmetic and account validation into crypto-specific implementation security.

## When to Apply
- Programs using ElGamal, AES, Pedersen commitments, or any encryption
- ZK proof generation/verification (range proofs, sigma proofs)
- Programs handling private keys, secret scalars, or nonces
- Confidential transfer/balance implementations
- Any code importing `zeroize`, `curve25519-dalek`, `aes-gcm-siv`, etc.

## Patterns
1. [Memory Zeroization of Secrets](01-memory-zeroization-of-secrets.md) — Ensuring decrypted data and ephemeral secrets are wiped from memory
2. [Key Material Debug/Display Protection](02-key-material-debug-display.md) — Preventing accidental logging of secret key bytes
3. [Ephemeral Secret Lifecycle](03-ephemeral-secret-lifecycle.md) — Proper creation, use, and destruction of one-time secrets

## Source
Derived from Solana Foundation Token22 C4 contest (Aug-Sep 2025, $203.5K). All 3 zk-sdk Low findings were in this category, none covered by our existing patterns.

## Category Stats
- **Created:** 2026-02-05
- **Patterns:** 3
- **Total knowledge base:** 28 patterns across 6 categories
