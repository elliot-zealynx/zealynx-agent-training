# Pattern: Type Cosplay (Account Type Confusion)

**Category:** Missing Signer Checks / Account Validation  
**Severity:** Critical  
**Chains:** Solana (Native especially; Anchor auto-mitigates)  
**Last Updated:** 2026-02-03  

## Root Cause

Multiple account types in the same program share similar byte layouts. Without a **discriminator** (type identifier), an attacker can pass one account type where another is expected. Fields at identical byte offsets get misinterpreted — a `User.points` field reads as a `Vault.balance`, or a `Config.fee_rate` reads as a `Pool.authority`.

## Real-World Context

Found in multiple security audits, particularly in native Solana programs that don't use Anchor's automatic discriminators. Any program with >1 account type that uses raw `try_from_slice` deserialization is at risk.

## Vulnerable Code Pattern

### Native Solana (No Discriminator)
```rust
// ❌ VULNERABLE: No discriminator — types are interchangeable

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Vault {
    pub authority: Pubkey,   // 32 bytes at offset 0
    pub balance: u64,        // 8 bytes at offset 32
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct User {
    pub user_key: Pubkey,    // 32 bytes at offset 0  ← SAME LAYOUT
    pub points: u64,         // 8 bytes at offset 32  ← SAME OFFSET AS balance!
}

pub fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let vault_info = next_account_info(account_iter)?;
    
    // Deserializes bytes — doesn't know if it's actually a Vault!
    let vault = Vault::try_from_slice(&vault_info.data.borrow())?;
    
    // If attacker passes a User account with 1,000,000 points...
    // vault.balance reads as 1,000,000!
    if amount <= vault.balance {
        // Allows withdrawal based on fake balance
    }
    Ok(())
}
```

### The Layout Overlap
```
Vault: [authority: 32 bytes][balance: 8 bytes]  = 40 bytes total
User:  [user_key:  32 bytes][points:  8 bytes]  = 40 bytes total

Same size, same field offsets → perfectly interchangeable at byte level
```

## Attack Pattern

1. Attacker creates a `User` account with 1,000,000 `points`
2. Passes the `User` account to instruction expecting a `Vault`
3. Program deserializes bytes → reads offset 32 as `balance`
4. Gets 1,000,000 (actually the `points` field)
5. Allows withdrawal based on fake balance

## Detection Strategy

1. **Check for discriminator usage:**
   ```bash
   # Look for raw deserialization without discriminator check
   grep -rn "try_from_slice\|unpack\|deserialize" src/
   # Verify each has a preceding discriminator check
   ```

2. **In Anchor programs:** This is auto-mitigated via 8-byte SHA-256 discriminators. Focus on:
   - `UncheckedAccount` usage
   - Manual deserialization bypassing Anchor's type system
   - `remaining_accounts` iteration with raw deserialization

3. **In Native programs:** HIGH RISK if:
   - Multiple account types exist
   - No enum/discriminator at byte offset 0
   - `BorshDeserialize` used directly

4. **Layout analysis:** Map all account types' byte layouts. Any overlapping field positions = risk.

## Secure Fix

### Native Solana (Manual Discriminator)
```rust
// ✅ SECURE: Every type has a unique discriminator

#[derive(BorshSerialize, BorshDeserialize)]
pub enum AccountType {
    Vault,
    User,
    Config,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Vault {
    pub account_type: AccountType,  // First field = discriminator
    pub authority: Pubkey,
    pub balance: u64,
}

pub fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let vault_info = next_account_info(account_iter)?;
    let vault = Vault::try_from_slice(&vault_info.data.borrow())?;
    
    // Verify discriminator FIRST
    match vault.account_type {
        AccountType::Vault => {},  // OK
        _ => return Err(ProgramError::InvalidAccountData),
    }
    
    // Now safe to use vault.balance
    Ok(())
}
```

### Hash-Based Discriminator (Anchor-style)
```rust
// ✅ SECURE: SHA-256 hash discriminator
const VAULT_DISCRIMINATOR: [u8; 8] = /* first 8 bytes of sha256("account:Vault") */;

pub fn deserialize_vault(data: &[u8]) -> Result<Vault, ProgramError> {
    let disc = &data[0..8];
    if disc != VAULT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    Vault::try_from_slice(&data[8..])
}
```

### Anchor (Automatic)
```rust
// ✅ SECURE: Anchor handles discriminators automatically
#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

// Account<'info, Vault> checks:
// 1. Owner == program_id
// 2. Discriminator matches sha256("account:Vault")[0..8]
// 3. Data deserializes correctly
```

## Audit Checklist

- [ ] Every account type has a unique discriminator (first bytes)
- [ ] Discriminator is checked BEFORE any field access
- [ ] Native programs use enum-based or hash-based discriminators
- [ ] No raw `try_from_slice` without preceding type verification
- [ ] Account types with overlapping layouts are identified and documented
- [ ] `remaining_accounts` deserialization validates discriminators
