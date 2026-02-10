# Missing Account Reload After CPI

## Severity: High

## Description

Anchor deserializes account data into memory at instruction start. When a CPI modifies account data, **the in-memory copy is NOT automatically updated**. Subsequent operations using the stale data lead to incorrect calculations or security bypasses.

From Asymmetric Research:
> "If a CPI is made to a program that modifies an account being read in the current instruction, the in-memory copy of the data is not updated automatically."

## Root Cause

Anchor's `Account<'info, T>` takes a snapshot at deserialization. The underlying `AccountInfo` fields (lamports, data, owner) are updated via `Rc<RefCell<...>>`, but the deserialized struct is not.

## Vulnerable Code Pattern

```rust
// VULNERABLE: Operating on stale data after CPI
pub fn update_rewards(ctx: Context<UpdateStakingRewards>, amount: u64) -> Result<()> {
    let staking_seeds = &[b"stake", ctx.accounts.staker.key().as_ref(), &[bump]];

    let cpi_ctx = CpiContext::new_with_signer(
        ctx.accounts.rewards_program.to_account_info(),
        UpdateRewards { staking_account: ctx.accounts.staking_account.to_account_info() },
        staking_seeds
    );

    // CPI modifies staking_account.rewards
    rewards_distribution::cpi::update_rewards(cpi_ctx, amount)?;

    // ⚠️ BUG: ctx.accounts.staking_account.rewards is STALE
    msg!("Rewards: {}", ctx.accounts.staking_account.rewards);
    
    // Any logic using staking_account.rewards here is wrong
    calculate_something_based_on(ctx.accounts.staking_account.rewards);
    
    Ok(())
}
```

## Attack Scenario

1. User has 100 tokens in token account
2. Program reads token account balance (100)
3. CPI transfers 50 tokens out
4. Program still sees 100 tokens (stale)
5. Program calculates rewards/ratios based on 100
6. User benefits from incorrect calculation

**Real-world impact:**
- Lending protocols: Incorrect collateral ratios
- Staking: Double rewards calculation
- DEXs: Incorrect swap amounts

## Detection Strategy

1. Find all CPI calls that modify accounts used in current instruction
2. Check if `.reload()` is called after CPI
3. Flag any arithmetic/logic using account data after CPI without reload
4. Special attention to token transfers and balance checks

## Fix Pattern

```rust
pub fn update_rewards(ctx: Context<UpdateStakingRewards>, amount: u64) -> Result<()> {
    // ... CPI call ...
    rewards_distribution::cpi::update_rewards(cpi_ctx, amount)?;

    // ✅ Reload account to get fresh data
    ctx.accounts.staking_account.reload()?;

    // Now staking_account.rewards reflects the updated value
    msg!("Rewards: {}", ctx.accounts.staking_account.rewards);
    
    Ok(())
}
```

## What Gets Updated vs. What Doesn't

**Automatically updated (via Rc<RefCell>):**
- `account_info.lamports()`
- `account_info.data` (raw bytes)
- `account_info.owner`

**NOT automatically updated:**
- Deserialized struct fields (`Account<'info, T>`)
- Any cached copies of data

## Related Vulnerabilities

- **State desync attacks**: Exploiting gap between actual and cached state
- **Double-spend patterns**: CPI transfers but program sees old balance
- **Collateral manipulation**: Borrow against stale collateral values

## References

- Asymmetric Research: "Anchor's Missing Reload Pitfall"
- Anchor documentation: `reload()` method
- ThreeSigma: "State Desync Across Instructions"
