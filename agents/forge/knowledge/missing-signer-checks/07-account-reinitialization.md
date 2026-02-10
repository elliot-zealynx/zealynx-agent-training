# Pattern: Account Reinitialization

**Category:** Missing Signer Checks / State Management  
**Severity:** Critical  
**Chains:** Solana (Anchor & Native)  
**Last Updated:** 2026-02-03  

## Root Cause

An `initialize` instruction can be called on an already-initialized account, **overwriting** its data. The attacker calls initialize on someone else's vault, replaces the `authority` field with their own key, and takes control of existing funds.

## Real-World Context

Core vulnerability in early Solana programs before best practices solidified. Found in numerous audit reports. Particularly dangerous in:
- Vault/treasury initialization
- Config/admin setup
- Pool creation
- Any account that controls funds or permissions

## Vulnerable Code Pattern

### Native Solana
```rust
// ❌ VULNERABLE: No check if already initialized
pub fn process_initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let vault_info = next_account_info(account_iter)?;
    let authority = next_account_info(account_iter)?;
    
    // Blindly overwrites — doesn't check if vault already has data
    let mut vault = Vault::default();
    vault.authority = *authority.key;
    vault.balance = 0;
    vault.is_initialized = true;
    
    vault.serialize(&mut *vault_info.data.borrow_mut())?;
    Ok(())
}
```

### Anchor (Missing init guard)
```rust
// ❌ VULNERABLE: init_if_needed allows reinitialization
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init_if_needed,  // DANGEROUS: allows re-calling
        payer = user,
        space = 8 + 32 + 8,
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

## Attack Pattern

1. User creates vault: `authority = User's key`, balance accumulates
2. Vault holds substantial funds
3. Attacker calls `initialize` on the **same** vault account
4. Program overwrites: `authority = Attacker's key`
5. Attacker now controls user's funds via the new authority

### Variant: Account Revival Reinitialization
1. User closes their vault (lamports drained, data not zeroed)
2. Attacker re-funds the account with lamports in the same transaction
3. Account "revives" with stale data
4. Attacker calls initialize to take control

## Detection Strategy

1. **Search for initialization without guards:**
   ```bash
   grep -rn "initialize\|init" src/ | grep -v "is_initialized\|init,"
   ```

2. **Anchor specific:**
   - `init_if_needed` is a red flag — requires `#[cfg(feature = "init-if-needed")]`
   - Check if `init` (which correctly fails if account exists) is used instead

3. **Native specific:**
   - Any `serialize()` / `pack()` call without preceding `is_initialized` check
   - Functions named `initialize` / `create` / `setup` without guards

4. **Account closure:**
   - Check if `close` operations zero out data (not just drain lamports)
   - Can closed accounts be revived and reinitialized?

## Secure Fix

### Native Solana
```rust
// ✅ SECURE: Check initialization status first
pub fn process_initialize(accounts: &[AccountInfo]) -> ProgramResult {
    let vault_info = next_account_info(account_iter)?;
    
    // Check if already initialized
    let existing_data = vault_info.data.borrow();
    if existing_data[0..8] != [0u8; 8] {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    drop(existing_data);
    
    // Or check a flag
    let vault = Vault::unpack_unchecked(&vault_info.data.borrow())?;
    if vault.is_initialized {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    
    // Now safe to initialize
    let mut vault = Vault::default();
    vault.is_initialized = true;
    vault.authority = *authority.key;
    vault.serialize(&mut *vault_info.data.borrow_mut())?;
    Ok(())
}
```

### Anchor
```rust
// ✅ SECURE: `init` fails if account already has data/lamports
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,  // NOT init_if_needed — fails if account exists
        payer = user,
        space = 8 + 32 + 8,
        seeds = [b"vault", user.key().as_ref()],
        bump,
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

### Proper Account Closure (Prevents Revival)
```rust
// ✅ SECURE: Zero data AND drain lamports on close
// Anchor
#[account(
    mut,
    close = destination  // Zeros data + transfers lamports
)]
pub vault: Account<'info, Vault>,

// Native
let mut data = account.try_borrow_mut_data()?;
for byte in data.iter_mut() {
    *byte = 0;  // Zero ALL data
}
**destination.lamports.borrow_mut() += **account.lamports.borrow();
**account.lamports.borrow_mut() = 0;
```

## Audit Checklist

- [ ] Every initialize function checks if account is already initialized
- [ ] `init` is used instead of `init_if_needed` in Anchor
- [ ] If `init_if_needed` is used, there's a strong justification and additional guards
- [ ] Account closure zeros ALL data, not just drains lamports
- [ ] Closed accounts can't be revived in the same transaction
- [ ] Discriminator/is_initialized flag is the FIRST thing checked on every instruction
