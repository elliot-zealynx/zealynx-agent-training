# Pattern: Account Data Matching Failure

**Category:** Missing Signer Checks / Account Validation  
**Severity:** High  
**Chains:** Solana (Anchor & Native)  
**Last Updated:** 2026-02-03  

## Root Cause

An account passes type and owner checks but isn't the **specific** account required. For example, accepting any valid token account when the program specifically needs the pool's token account. The attacker substitutes their own account that passes generic validation but doesn't match required relationships.

## Real-World Exploit

### Solend Oracle Manipulation (November 2022 — $1.26M stolen)
- Protocol accepted USDH as collateral, checking price from a single Saber pool
- Attacker traded between Saber and Orca, manipulating the Saber pool price
- Deposited USDH valued at the inflated price ($8.80 instead of $1.00)
- Borrowed against it and defaulted on the loan
- **Root cause:** Oracle validated it was reading *a* price feed, not *the correct* price feed

## Vulnerable Code Pattern

### Anchor (Insecure)
```rust
// ❌ VULNERABLE: Accepts ANY token account, not the specific one needed
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,  // Any token account passes
    pub user: Signer<'info>,
}

pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    // user_token could be for a DIFFERENT mint than the pool expects
    // Attacker can pass their own mint's token account
    transfer_tokens(
        &ctx.accounts.user_token,
        &ctx.accounts.pool_token,
        amount,
    )?;
    Ok(())
}
```

### Native Solana
```rust
// ❌ VULNERABLE: Checks owner but not mint/relationship
pub fn process_deposit(accounts: &[AccountInfo]) -> ProgramResult {
    let pool_info = next_account_info(account_iter)?;
    let token_account_info = next_account_info(account_iter)?;
    
    // Checks it's a valid token account (owner = Token Program) ✓
    if token_account_info.owner != &spl_token::ID {
        return Err(ProgramError::IllegalOwner);
    }
    
    let token_account = TokenAccount::unpack(&token_account_info.data.borrow())?;
    // Never checks: token_account.mint == pool.expected_mint ✗
    // Never checks: token_account.owner == user.key ✗
    
    Ok(())
}
```

## Attack Pattern

1. Pool expects token account for `MintA`
2. Attacker passes token account for `MintB` (which they control)
3. Both are valid token accounts, both owned by Token Program
4. Program accepts it because **type** matches
5. Attacker manipulates their own mint, drains pool

## Detection Strategy

1. **Look for missing relationship constraints:**
   ```bash
   grep -n "Account<'info, TokenAccount>" src/ -r
   # Check if each has mint/owner constraints
   ```

2. **Anchor red flags:**
   - `Account<'info, TokenAccount>` without `token::mint` constraint
   - `Account<'info, T>` without `has_one` or `constraint` linking to parent
   - PDAs without seed verification linking accounts together

3. **Native red flags:**
   - Token account deserialization without `.mint` comparison
   - Account relationship assumptions not enforced in code

4. **Question for each account:** "Could an attacker substitute a different but valid account here?"

## Secure Fix

### Anchor
```rust
// ✅ SECURE: Constraints validate ALL relationships
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    
    #[account(
        mut,
        constraint = user_token.mint == pool.mint @ ErrorCode::MintMismatch,
        constraint = user_token.owner == user.key() @ ErrorCode::OwnerMismatch,
    )]
    pub user_token: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        constraint = pool_token.mint == pool.mint,
        constraint = pool_token.owner == pool.key(),
    )]
    pub pool_token: Account<'info, TokenAccount>,
    
    pub user: Signer<'info>,
}
```

### Native Solana
```rust
// ✅ SECURE: Explicit relationship checks
let token_account = TokenAccount::unpack(&token_account_info.data.borrow())?;

if token_account.mint != pool.expected_mint {
    return Err(ProgramError::InvalidAccountData);
}
if token_account.owner != *user.key {
    return Err(ProgramError::InvalidAccountData);
}
```

## Audit Checklist

- [ ] Every token account has mint and owner/authority constraints
- [ ] Pool/vault accounts are linked to their parent via seeds or has_one
- [ ] Oracle price feeds validate they're reading the CORRECT feed, not just ANY feed
- [ ] Account relationships form a validated chain (pool → mint → token_account → user)
- [ ] No account can be substituted with a "valid but wrong" account
