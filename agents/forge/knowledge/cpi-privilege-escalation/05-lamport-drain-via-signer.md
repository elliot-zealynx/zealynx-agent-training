# Lamport Drain via Signer

## Severity: High

## Description

When a signer is forwarded through CPI, the callee program can use `system_instruction::transfer` to drain all SOL (lamports) from the signer's account. Unlike Ethereum's `msg.value`, Solana doesn't have a built-in mechanism to limit how much SOL a callee can spend.

From Asymmetric Research:
> "Unlike Ethereum, Solana doesn't have a msg.value to control how much SOL is spent. Instead, the callee can access all lamports held by the signing account."

## Root Cause

`system_instruction::transfer` only requires the sender to be a signer. Once signer privilege is forwarded via CPI, there's no limit on transfer amount.

## Vulnerable Code Pattern

```rust
// VULNERABLE: No limit on signer's lamport exposure
pub fn protocol_with_callback(ctx: Context<Callback>, external_program: Pubkey) -> Result<()> {
    // User signs transaction
    let user = &ctx.accounts.user;
    
    // CPI to external program with user as signer
    // ⚠️ External program can drain ALL user's SOL
    invoke(
        &custom_instruction,
        &[user.to_account_info(), external_program_info],
    )?;
    
    Ok(())
}
```

## Attack Scenario

1. Attacker deploys malicious program
2. User calls legitimate protocol that makes CPI with user signer
3. Malicious program receives user's signer privileges
4. Malicious program executes:
   ```rust
   invoke(
       &system_instruction::transfer(
           user.key,
           attacker_wallet.key,
           user.lamports(),  // ALL SOL
       ),
       &[user, attacker_wallet, system_program],
   )
   ```
5. User's entire SOL balance is stolen

## Detection Strategy

1. Identify all CPIs where signer accounts are included
2. Check if there's lamport balance verification before/after CPI
3. Flag patterns where arbitrary programs receive signers
4. Look for missing `spendable_amount` limits

## Fix Pattern

```rust
pub fn protocol_with_callback(ctx: Context<Callback>, max_spend: u64) -> Result<()> {
    let balance_before = ctx.accounts.user.lamports();
    
    // CPI with signer...
    invoke(&instruction, &[ctx.accounts.user.to_account_info()])?;
    
    // ✅ Verify spending limit
    let balance_after = ctx.accounts.user.lamports();
    require!(
        balance_before <= balance_after + max_spend,
        Error::ExcessiveSpend
    );
    
    Ok(())
}
```

## Better: Account Isolation

```rust
// Best practice: Never forward user signer to arbitrary programs
// Instead, use PDAs scoped to user

pub fn safe_callback(ctx: Context<SafeCallback>) -> Result<()> {
    // PDA is derived from user's key - isolated authority
    let pda_seeds = &[
        b"user_vault",
        ctx.accounts.user.key().as_ref(),
        &[bump]
    ];
    
    // Only the PDA has funds, not user's wallet
    // CPI uses PDA signer, not user signer
    invoke_signed(
        &instruction,
        &[ctx.accounts.user_vault.to_account_info()],
        pda_seeds,
    )?;
    
    Ok(())
}
```

## Related Checks

When arbitrary callbacks are required:
1. Check lamport balance before/after
2. Check account ownership before/after
3. Strip signer privilege if possible
4. Use allow-listed programs only

## References

- Asymmetric Research: "Prevent Stealing Funds on Signer"
- Solana System Program documentation
- Cross-program invocation security patterns
