# Pattern: Missing Owner Check (Account Spoofing)

**Category:** Missing Signer Checks / Access Control  
**Severity:** Critical  
**Chains:** Solana (Anchor & Native)  
**Last Updated:** 2026-02-03  

## Root Cause

Every Solana account has an `owner` field indicating which program controls it. If a program reads/writes account data without verifying that the account is owned by the expected program, an attacker can craft a **fake account** with identical data layout but owned by a different program (e.g., SystemProgram). The program trusts the fake data and gets exploited.

## Real-World Exploits

### Crema Finance (July 2022 — $8.8M stolen)
- Attacker created a fake "Tick" account with false price data
- The fake account wasn't owned by Crema's program
- Because ownership wasn't validated, the fake account was accepted as real
- Attacker used fake price data to claim inflated LP fees through flash loans

### Solend (August 2021)
- Attacker created fake lending markets with manipulated parameters
- Fake accounts had liquidation thresholds set to 1%, bonuses to 90%
- Program treated them as legitimate because it never checked `account.owner`

## Vulnerable Code Pattern

### Native Solana
```rust
// ❌ VULNERABLE: Never checks who owns the account
pub fn process_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let vault_info = next_account_info(account_iter)?;
    
    // Deserializes data without checking owner
    let vault = Vault::unpack(&vault_info.data.borrow())?;
    
    // Attacker's fake vault has attacker's key as authority
    if vault.authority != *authority.key {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Transfers from real vault using fake authority...
    Ok(())
}
```

### Anchor (Insecure)
```rust
// ❌ VULNERABLE: UncheckedAccount doesn't verify owner
#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// CHECK: Missing owner validation
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}
```

## Attack Pattern

1. Real vault owned by `YourProgram` with legitimate authority + balance
2. Attacker creates fake vault owned by `SystemProgram`
3. Fake vault has same data layout, attacker's key as authority
4. Program accepts fake vault, reads attacker's authority
5. Program allows withdrawal — funds stolen from real accounts

## Detection Strategy

1. **Anchor:** Look for `UncheckedAccount<'info>` or `AccountInfo<'info>` used for program-owned data
2. **Native:** Search for `unpack()` / `try_from_slice()` without preceding owner check
3. **Check pattern:** Any deserialization of account data MUST be preceded by `account.owner == program_id`
4. **CPI targets:** Accounts passed to CPIs need owner validation too

```bash
# Find potential owner check gaps
grep -n "unpack\|try_from_slice\|deserialize" src/ -r | grep -v "owner"
```

## Secure Fix

### Native Solana
```rust
// ✅ SECURE: Check owner before deserializing
if vault_info.owner != program_id {
    return Err(ProgramError::IllegalOwner);
}
let vault = Vault::unpack(&vault_info.data.borrow())?;
```

### Anchor
```rust
// ✅ SECURE: Account<'info, T> auto-verifies owner == program_id
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,  // Owner check automatic
    pub authority: Signer<'info>,
}
```

### For External Program Accounts
```rust
// ✅ Verify token accounts are owned by Token Program
#[account(
    mut,
    token::mint = expected_mint,
    token::authority = expected_authority,
)]
pub token_account: Account<'info, TokenAccount>,
```

## Audit Checklist

- [ ] Every account deserialization is preceded by an owner check
- [ ] No `UncheckedAccount` used for program-owned data without explicit owner validation
- [ ] Token accounts verified against Token Program ownership
- [ ] Cross-program account references validate expected owners
- [ ] PDA accounts verify derivation from expected program
