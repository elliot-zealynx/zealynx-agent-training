# Forge Shadow Audit — 2026-02-05

## Target: Solana Foundation Token22 Confidential Transfer (Code4rena)
- **Pool:** $203,500 USDC
- **Duration:** Aug 21 - Sep 23, 2025
- **Scope:** Token22 confidential transfers, ZK ElGamal Proof program, zk-sdk
- **Result:** 0 High, 0 Medium, 7 Low/QA, 1 Informational
- **Language:** Rust (Solana native program, not Anchor)

## Contest Characteristics
This is a high-profile, heavily-audited codebase from Solana Foundation itself. The fact that NO High or Medium findings were discovered across a $203K contest speaks to the maturity of this code. It had multiple prior audits (Anza security audits repo) and two prior security advisories (May 2025, June 2025 post-mortems).

The scope was deeply cryptographic: ElGamal encryption, Pedersen commitments, zero-knowledge range proofs, and confidential transfer state management. This is NOT a typical DeFi protocol - it's infrastructure-level cryptographic code.

## Actual Findings (8 Low/QA + Info)

### Token-2022 Program Findings
1. **L-01: assert!() on native accounts can panic** — Uses `assert!(!token_account.base.is_native())` in deposit/withdraw/mint-burn paths. Panics instead of returning structured error. DoS vector (transaction aborts).
2. **L-02: Missing check_program_account before unpack/mutate** — In confidential_transfer_fee processor, destination account and mint in harvest-to-mint are unpacked without first calling `check_program_account(owner)?`. Fails late with unclear errors.
3. **L-03: On-chain unwrap may panic in decryptable balance update** — `checked_add(...).unwrap()` in `new_decryptable_available_balance`. If inputs overflow, panics and aborts transaction.
4. **L-04: Re-derive and check registry PDA before update** — `process_update_registry_account` mutates ElGamal registry without re-deriving PDA with `get_elgamal_registry_address_and_bump_seed`. Accepts wrong but program-owned accounts.
5. **L-info: Centralized fee authority** — `ConfidentialTransferFee` authority can enable/disable harvest-to-mint immediately without timelock or multisig.

### zk-sdk Findings
6. **L-05: Plaintext not zeroized after AEAD decryption** — `AuthenticatedEncryption::decrypt` returns u64 without zeroizing the decrypted `Vec<u8>` plaintext buffer. Key material lingers on heap.
7. **L-06: Ephemeral scalars not zeroized in RangeProof::new** — Secret scalars (`a_blinding`, `s_L`, `s_R`, `s_blinding`) used for range proof construction are not zeroized after use.
8. **L-07: Sensitive key material derives Debug** — `AeKey` derives `Debug`, allowing `format!("{:?}", key)` to print raw AES key bytes to logs.

### ZK ElGamal Proof Program
No findings. Verifier logic was clean.

## Shadow Audit — What Our Patterns Caught

### ✅ Caught (4/8)

| Finding | Pattern Used | Confidence |
|---------|-------------|------------|
| L-01 (assert! panic) | Integer Overflow #05 (panic detection) + Logic Bugs #01 | High — `assert!()` is a known DoS vector in on-chain code. Our overflow pattern teaches scanning for panicking operations. |
| L-02 (missing check_program_account) | Missing Signer Checks #04 (Account Data Matching) | High — Pattern explicitly looks for "processing accounts without verifying they belong to the correct program." Direct match. |
| L-03 (checked_add().unwrap()) | Integer Overflow #01 (Silent Wrapping) | High — Pattern teaches searching for raw arithmetic AND `.unwrap()` on checked operations. `checked_add().unwrap()` is a variant where developer half-fixed it. |
| L-04 (missing PDA re-derivation) | PDA Seed Collisions #03 (Missing PDA Derivation Verification) | Very High — This is the EXACT pattern. Our #03 literally says "program accepts a PDA account but never re-derives it to verify seeds and program_id." |

### ❌ Missed (4/8)

| Finding | Why Missed | Gap Category |
|---------|-----------|--------------|
| L-05 (plaintext not zeroized) | No crypto memory hygiene patterns | **Cryptographic Hygiene** |
| L-06 (ephemeral scalars not zeroized) | No crypto memory hygiene patterns | **Cryptographic Hygiene** |
| L-07 (Debug derive on key material) | No key material protection patterns | **Cryptographic Hygiene** |
| L-info (centralized authority) | Could partially flag as access control, but our patterns focus on technical bypass not governance design | **Governance/Trust** |

## Performance Metrics

- **Precision:** 100% (4/4 findings raised were correct, 0 false positives)
- **Recall:** 50% (caught 4 of 8 low findings)
- **Adjusted Recall (excluding info):** 57% (4/7)
- **Critical miss rate:** 0% (no H/M findings existed to miss)

## Key Lessons

### 1. New Pattern Category Needed: Cryptographic Hygiene
ALL 3 missed technical findings (L-05, L-06, L-07) fall into a single category we don't cover: cryptographic implementation hygiene. This includes:
- **Memory zeroization** of secrets after use (plaintexts, ephemeral scalars, nonces)
- **Key material protection** (no Debug derive, no Display, redacted logging)
- **Side-channel resistance** (constant-time comparisons, timing-safe operations)
- **Scope:** Applies to any program handling encryption keys, ZK proofs, signatures, or confidential data

### 2. Our Classic Patterns Are Strong
For the "bread and butter" Solana vulnerabilities (account validation, arithmetic, PDA verification), our patterns performed perfectly. Every finding in those categories was caught. The pattern descriptions directly mapped to the actual findings.

### 3. Contest Context Matters
A $203K contest with 0 High/Medium findings means:
- The code was already well-audited (multiple prior audits)
- The Solana Foundation likely has strong internal review
- Remaining findings are "polish" issues, not structural flaws
- This is a good benchmark for our LOW-severity detection capability

### 4. Crypto Code Requires Domain-Specific Patterns
Auditing ZK proofs and ElGamal encryption requires fundamentally different knowledge than auditing DeFi protocols. The "Areas of concern" section of the contest repo explicitly mentioned:
- Merlin transcript management
- Proof context creation/deletion
- Proof consistency checks
- Extension interaction security

These are all crypto-domain-specific and not covered by our current patterns.

## Action Items
1. **Create new pattern category:** `/root/clawd/knowledge/rust/cryptographic-hygiene/`
   - Pattern 01: Memory Zeroization of Secrets
   - Pattern 02: Key Material Debug/Display Protection
   - Pattern 03: Ephemeral Secret Lifecycle
2. **Priority:** Medium — this gap only affects crypto-heavy audits (ZK, encryption), not typical DeFi
3. **Source material:** This contest's findings + `zeroize` crate documentation + Solana's own zeroization practices

## Observations for Team
This was a unique audit target. Most Zealynx clients build DeFi/GameFi protocols, not infrastructure-level cryptographic programs. However, as confidential transfers become more common (Token22 adoption growing), understanding these patterns becomes important. The cryptographic hygiene patterns would also apply to any protocol handling private keys, encrypted data, or ZK proofs.
