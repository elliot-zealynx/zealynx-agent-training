# Pattern: Sysvar Account Spoofing

**Category:** Missing Signer Checks / Account Validation  
**Severity:** Critical  
**Chains:** Solana (Anchor & Native)  
**Last Updated:** 2026-02-03  

## Root Cause

Solana has system accounts called "sysvars" (Clock, Rent, Instructions, etc.) that contain cluster state. If a program reads sysvar data without verifying the account is **actually** the real sysvar (by checking its address), an attacker can pass a fake account with manipulated system data.

## Real-World Exploit

### Wormhole Bridge (February 2022 — $325M stolen)
**One of the largest DeFi hacks in history.**

- Wormhole used `load_instruction_at()` to verify signature verification had occurred
- This deprecated function reads instruction data but **doesn't verify** the account is the real Instructions sysvar
- Attacker created a fake Instructions sysvar with fabricated signature verification data
- Bridge believed signatures were verified when they weren't
- Attacker minted 120,000 wETH (~$325M) on Solana and bridged to Ethereum

### Key Insight
The deprecated `solana_program::sysvar::instructions::load_instruction_at()` takes an `AccountInfo` but never checks if it's actually `sysvar::instructions::ID`. The safe replacement `load_instruction_at_checked()` validates the account address.

## Vulnerable Code Pattern

### Native Solana (Wormhole-style)
```rust
// ❌ VULNERABLE: Uses deprecated function that doesn't validate sysvar
use solana_program::sysvar::instructions::load_instruction_at;

pub fn verify_signatures(
    accounts: &[AccountInfo],
) -> ProgramResult {
    let instruction_sysvar = next_account_info(account_iter)?;
    
    // DANGEROUS: Doesn't verify this is the REAL Instructions sysvar
    let instruction = load_instruction_at(0, instruction_sysvar)?;
    
    // Checks if secp256k1 verification was called...
    // But attacker's fake sysvar says it was!
    if instruction.program_id == secp256k1_program::ID {
        // "Verified" — but it's all fake
    }
    
    Ok(())
}
```

### Clock Sysvar Manipulation
```rust
// ❌ VULNERABLE: Accepts any account as Clock
pub fn check_timelock(
    accounts: &[AccountInfo],
    unlock_time: i64,
) -> ProgramResult {
    let clock_account = next_account_info(account_iter)?;
    
    // Never verifies this is the real Clock sysvar
    let clock = Clock::from_account_info(clock_account)?;
    
    // Attacker passes fake clock with future timestamp
    if clock.unix_timestamp >= unlock_time {
        // Timelock "bypassed"
        release_funds()?;
    }
    
    Ok(())
}
```

## Attack Pattern

1. Program expects `Sysvar::Instructions` account
2. Attacker creates fake account with same data layout
3. Program uses deprecated `load_instruction_at()` without address check
4. Fake data is read as authentic system data
5. Critical signature/time/rent validation bypassed

## Detection Strategy

1. **Search for deprecated sysvar functions:**
   ```bash
   grep -rn "load_instruction_at\b" src/  # Note: no _checked suffix
   grep -rn "from_account_info" src/ | grep -i "clock\|rent\|epoch"
   ```

2. **Check sysvar account validation:**
   - Is the sysvar address compared against the known ID?
   - Is `_checked` variant used where available?

3. **Anchor:** Look for sysvar accounts passed as `AccountInfo` instead of typed sysvar types

4. **Red flags:**
   - Any use of `load_instruction_at` (deprecated, unsafe)
   - `Clock::from_account_info()` without address constraint
   - Sysvar deserialization from unchecked accounts

## Secure Fix

### Native Solana
```rust
// ✅ SECURE: Use _checked variant
use solana_program::sysvar::instructions::load_instruction_at_checked;

pub fn verify_signatures(accounts: &[AccountInfo]) -> ProgramResult {
    let instruction_sysvar = next_account_info(account_iter)?;
    
    // Validates account IS the real Instructions sysvar
    let instruction = load_instruction_at_checked(0, instruction_sysvar)?;
    // ...
}

// ✅ SECURE: Manual address verification
pub fn check_timelock(accounts: &[AccountInfo]) -> ProgramResult {
    let clock_account = next_account_info(account_iter)?;
    
    // Verify it's the real Clock sysvar
    if clock_account.key != &solana_program::sysvar::clock::ID {
        return Err(ProgramError::InvalidArgument);
    }
    
    let clock = Clock::from_account_info(clock_account)?;
    // Now safe to use...
}
```

### Anchor
```rust
// ✅ SECURE: Address constraint on sysvar
#[derive(Accounts)]
pub struct VerifyInstruction<'info> {
    /// CHECK: Verified via constraint
    #[account(address = sysvar::instructions::ID)]
    pub instruction_sysvar: AccountInfo<'info>,
}

// ✅ EVEN BETTER: Use Anchor's typed sysvar
pub struct TimelockedAction<'info> {
    pub clock: Sysvar<'info, Clock>,  // Automatically validated
}
```

## Audit Checklist

- [ ] No use of deprecated `load_instruction_at` (must be `_checked`)
- [ ] All sysvar accounts have address constraints or use typed sysvar types
- [ ] Clock, Rent, EpochSchedule accounts are validated before reading
- [ ] Instructions sysvar verified before reading instruction introspection data
- [ ] No `AccountInfo` used for sysvars without explicit address check
