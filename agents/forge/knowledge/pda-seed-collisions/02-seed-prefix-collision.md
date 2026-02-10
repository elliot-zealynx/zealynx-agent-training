# Pattern 02: Seed Prefix Collision

**Severity:** High
**Category:** PDA Seed Collisions
**Prevalence:** Medium — more subtle than bump canonicalization

## Description

When a program uses multiple PDA types with string prefixes (e.g., `b"VAULT"`, `b"VAULT_SPECIAL"`), there's a risk that the variable portion of one seed set accidentally matches the suffix of another prefix, causing two logically different accounts to resolve to the same address.

**Key Rule:** No seed prefix should start with another full prefix.

This is because seeds are concatenated as raw bytes. If `VAULT` is a prefix and the variable seed starts with `_SPECIAL`, then `[b"VAULT", b"_SPECIAL_data"]` and `[b"VAULT_SPECIAL", b"_data"]` may produce the same hash input.

## Vulnerable Code Example

```rust
// VULNERABLE: Prefix overlap
// Vault PDA: seeds = [b"VAULT", user_key]
// Special Vault PDA: seeds = [b"VAULT_SPECIAL", user_key]

// If user_key bytes happen to start with "_SPECIAL" prefix bytes,
// the concatenated seed bytes become identical:
// "VAULT" + "_SPECIAL..." == "VAULT_SPECIAL" + "..."

pub fn init_vault(ctx: Context<InitVault>) -> Result<()> {
    let seeds = &[b"VAULT" as &[u8], ctx.accounts.user.key().as_ref()];
    // ...
}

pub fn init_special_vault(ctx: Context<InitSpecialVault>) -> Result<()> {
    let seeds = &[b"VAULT_SPECIAL" as &[u8], ctx.accounts.user.key().as_ref()];
    // ...
}
```

## Attack Scenario

```
Prefix A: "ORDER" (5 bytes)
Prefix B: "ORDER_LIMIT" (11 bytes)

Variable seed for A: some_nonce where first 6 bytes = "_LIMIT" + remaining
Variable seed for B: remaining bytes only

Concatenation A: "ORDER" + "_LIMIT" + remaining = "ORDER_LIMIT" + remaining
Concatenation B: "ORDER_LIMIT" + remaining

Same byte sequence → same PDA address → collision!

Impact:
- DoS: Can't create both accounts (address taken)
- Data corruption: One type interpreted as another
- Privilege escalation: Order account read as Order_Limit with different permission model
```

## Detection Strategy

1. **Enumerate all seed prefixes** in the program
2. **Check prefix containment:** Does any prefix start with another complete prefix?
   - `VAULT` and `VAULT_SPECIAL` → ⚠️ DANGEROUS
   - `VAULT` and `POOL` → ✅ Safe
   - `USER_PROFILE` and `USER` → ⚠️ DANGEROUS
3. **Check for delimiter usage:** Are seeds separated by a non-ambiguous delimiter?
4. **Verify discriminator bytes** are used in addition to seed prefixes
5. **Anchor:** Check that account discriminators (8-byte hash) prevent cross-type confusion even if addresses collide

## Fix Pattern

### Approach 1: Use unique, non-overlapping prefixes
```rust
// SAFE: No prefix is a prefix of another
const VAULT_SEED: &[u8] = b"v1_vault";
const SPECIAL_VAULT_SEED: &[u8] = b"v1_special";
const ORDER_SEED: &[u8] = b"v1_order";
const LIMIT_ORDER_SEED: &[u8] = b"v1_limit";
```

### Approach 2: Use length-prefixed or delimited seeds
```rust
// SAFE: Fixed-length prefix + separator
let seeds = &[
    b"VAULT" as &[u8],
    b":" as &[u8],  // delimiter
    user_key.as_ref(),
];
```

### Approach 3: Hash-based prefixes
```rust
// SAFE: Use hash of type name as prefix (like Anchor discriminator)
use anchor_lang::solana_program::hash::hash;
let vault_prefix = &hash(b"account:Vault").to_bytes()[..8];
let special_prefix = &hash(b"account:SpecialVault").to_bytes()[..8];
```

## Real Examples

- Identified in security reviews by Stepan Chekhovskoi (Oct 2024)
- Common in protocols with many account types (lending protocols, DEXes)
- Particularly dangerous in upgradeable programs where new account types are added over time

## Key Insight

> "Seeds are just bytes. The computer doesn't know where your 'prefix' ends and your 'data' begins. If you don't make that boundary unambiguous, neither will an attacker."

The safest approach: use fixed-length prefixes (e.g., 8-byte hashes) that can never be a prefix of each other.
