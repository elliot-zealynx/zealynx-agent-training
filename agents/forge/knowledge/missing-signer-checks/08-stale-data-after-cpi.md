# Pattern: Stale Data After CPI (Account Reload Failure)

**Category:** Missing Signer Checks / Cross-Program Security  
**Severity:** High  
**Chains:** Solana (Anchor & Native)  
**Last Updated:** 2026-02-03  

## Root Cause

After a CPI (Cross-Program Invocation), the called program modifies account data on-chain. However, Anchor's deserialized in-memory copy is **NOT automatically updated**. If the program continues using the stale in-memory data for balance checks, spending limits, or state decisions, it operates on outdated information — enabling double-spends, limit bypasses, and accounting manipulation.

## Real-World Context

Found in numerous audit reports. Particularly dangerous when:
- Program transfers tokens via CPI then checks balances
- Program updates state via CPI then makes decisions on that state
- Multi-step operations where CPI results affect subsequent logic

## Vulnerable Code Pattern

### Anchor
```rust
// ❌ VULNERABLE: Uses stale balance after CPI transfer
pub fn transfer_and_check(ctx: Context<TransferAndCheck>, amount: u64) -> Result<()> {
    let balance_before = ctx.accounts.token_account.amount;
    
    // CPI: Transfer tokens out
    let cpi_accounts = Transfer {
        from: ctx.accounts.token_account.to_account_info(),
        to: ctx.accounts.destination.to_account_info(),
        authority: ctx.accounts.authority.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        cpi_accounts,
    );
    token::transfer(cpi_ctx, amount)?;
    
    // ⚠️ STALE: token_account.amount still shows pre-transfer value!
    // In-memory struct was NOT updated by the CPI
    require!(
        ctx.accounts.token_account.amount >= MIN_BALANCE,
        ErrorCode::BalanceTooLow
    );
    // This check passes even if actual balance is below MIN_BALANCE
    
    Ok(())
}
```

### Native Solana
```rust
// ❌ VULNERABLE: Reading cached data after CPI
pub fn process(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let token_info = next_account_info(account_iter)?;
    let token_data = TokenAccount::unpack(&token_info.data.borrow())?;
    
    // CPI transfer
    invoke(&transfer_ix, &[/* ... */])?;
    
    // token_data is stale — it was deserialized BEFORE the CPI
    if token_data.amount >= MIN_BALANCE {
        // Wrong! This uses the old balance
    }
    Ok(())
}
```

## Attack Pattern

1. Program loads account balance: 100 tokens (deserialized to memory)
2. Program makes CPI that transfers 95 tokens
3. In-memory struct still thinks balance is 100 (stale)
4. Program checks `balance >= MIN_BALANCE (10)`: passes (100 >= 10) 
5. Program allows another operation based on wrong balance
6. **Actual on-chain balance**: 5 tokens, but program thinks 100

### Compounding Attack
```
Loop:
  1. CPI transfer 50 tokens out
  2. Check balance (stale: still shows 100)
  3. CPI transfer 50 more tokens out  
  4. Check balance (stale: still shows 100)
Result: 100 tokens transferred, but program never saw balance drop
```

## Detection Strategy

1. **Search for CPI followed by account reads WITHOUT reload:**
   ```bash
   # Find CPI calls
   grep -n "invoke\|cpi::" src/ -r
   # Check if .reload() appears within ~10 lines after each CPI
   ```

2. **Anchor specific:**
   - Any account field access after a CPI without `.reload()?` between them
   - Pattern: `cpi::some_call(...)? → ctx.accounts.X.field` (missing reload)

3. **Native specific:**
   - Data deserialized before CPI, then used after CPI
   - Must re-borrow and re-unpack `data.borrow()` after CPI

4. **Key question:** "Is any account data read AFTER a CPI without re-deserialization?"

## Secure Fix

### Anchor
```rust
// ✅ SECURE: Reload after CPI
pub fn transfer_and_check(ctx: Context<TransferAndCheck>, amount: u64) -> Result<()> {
    // CPI transfer
    token::transfer(cpi_ctx, amount)?;
    
    // CRITICAL: Reload to get fresh on-chain data
    ctx.accounts.token_account.reload()?;
    
    // NOW this check uses the actual post-transfer balance
    require!(
        ctx.accounts.token_account.amount >= MIN_BALANCE,
        ErrorCode::BalanceTooLow
    );
    
    Ok(())
}
```

### Native Solana
```rust
// ✅ SECURE: Re-deserialize after CPI
invoke(&transfer_ix, &[/* ... */])?;

// Re-borrow and re-unpack AFTER the CPI
let fresh_data = TokenAccount::unpack(&token_info.data.borrow())?;

if fresh_data.amount < MIN_BALANCE {
    return Err(ProgramError::InsufficientFunds);
}
```

## Audit Checklist

- [ ] Every CPI call is followed by `.reload()?` on affected accounts (Anchor)
- [ ] Every CPI call is followed by re-deserialization of affected accounts (Native)
- [ ] No business logic decisions are made using pre-CPI account state
- [ ] Multi-CPI sequences reload between each CPI if account data is checked
- [ ] Balance checks, limit checks, and state assertions use post-CPI data
