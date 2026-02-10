# Pattern: Basic Signer Bypass

**Category:** Missing Signer Checks  
**Severity:** Critical  
**Chains:** Solana (Anchor & Native)  
**Last Updated:** 2026-02-03  

## Root Cause

Program checks that the correct public key is present in the instruction accounts but never verifies that the key's owner actually **signed** the transaction. Public keys are public — anyone can pass them as an account reference without holding the private key.

## Real-World Exploit

**Solend (August 2021)** — Attacker attempted to steal $2M by passing the admin's public key without signing. The protocol checked `vault.authority == passed_authority.key` but never checked `passed_authority.is_signer`. Caught before funds were lost, but exposed a critical flaw.

## Vulnerable Code Pattern

### Native Solana
```rust
// ❌ VULNERABLE: Only checks key match, not signature
pub fn process_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault = next_account_info(account_iter)?;
    let authority = next_account_info(account_iter)?;
    
    let vault_data = Vault::unpack(&vault.data.borrow())?;
    
    // Only checks key equality — NOT signature!
    if vault_data.authority != *authority.key {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Proceeds to transfer... attacker drains vault
    transfer_lamports(vault, authority, amount)?;
    Ok(())
}
```

### Anchor (Insecure)
```rust
// ❌ VULNERABLE: AccountInfo doesn't enforce signing
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: This should be Signer, not AccountInfo
    pub authority: AccountInfo<'info>,
}
```

## Attack Pattern

1. Vault stores `authority = "AuthPubkey123"`
2. Attacker sends instruction with authority account = `"AuthPubkey123"` (public info)
3. Program checks: `vault.authority == passed_authority.key` ✓
4. Program **never** checks: `passed_authority.is_signer`
5. Withdrawal executes — funds gone

The attacker never needed the private key. They just needed the public key.

## Detection Strategy

1. **Grep for authority/admin checks without `is_signer`:**
   ```bash
   grep -n "authority\|admin\|owner" src/lib.rs | grep -v "is_signer\|Signer"
   ```
2. **In Anchor:** Look for `AccountInfo<'info>` where `Signer<'info>` should be used
3. **In Native:** Search for key comparisons (`== *account.key`) without accompanying `is_signer` check
4. **Check ALL privileged operations:** withdraw, update_config, change_authority, pause, unpause, set_fee

## Secure Fix

### Native Solana
```rust
// ✅ SECURE: Checks both key match AND signature
if vault_data.authority != *authority.key {
    return Err(ProgramError::InvalidAccountData);
}
if !authority.is_signer {
    return Err(ProgramError::MissingRequiredSignature);
}
```

### Anchor
```rust
// ✅ SECURE: Signer<'info> enforces signature at deserialization
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,  // Enforces signature check
}
```

## Audit Checklist

- [ ] Every privileged instruction requires `Signer<'info>` (Anchor) or `is_signer` check (Native)
- [ ] Admin operations can't be called by passing admin pubkey without signing
- [ ] Multi-sig scenarios properly validate all required signers
- [ ] `AccountInfo<'info>` is never used where `Signer<'info>` is appropriate
