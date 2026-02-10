# Ownership Transfer via CPI

## Severity: High

## Description

On Solana, all accounts have an owner. Using the `assign` instruction, an account's owner can be changed. If a program passes a signer to an untrusted CPI, the callee can use `assign` to take ownership of the account, effectively stealing it.

From Asymmetric Research:
> "While the previous section suggests checking account balances before and after a CPI to detect unexpected transfers, that alone isn't sufficient. An attacker can still steal funds by changing the account's owner instead of transferring SOL directly."

## Root Cause

The `system_instruction::assign` only requires the account to be a signer. Once ownership is transferred, the original private key holder loses all control.

## Attack Flow

1. User's wallet is passed as signer to untrusted program via CPI
2. Malicious program calls `system_instruction::assign` with user's wallet
3. Ownership transfers from SystemProgram to attacker's program
4. Attacker-controlled program can now:
   - Drain all SOL
   - Modify account data
   - Close the account

```rust
// Attacker's malicious program
pub fn steal_ownership(ctx: Context<Steal>) -> Result<()> {
    // User's wallet was passed with signer privilege
    let user_wallet = &ctx.accounts.user_wallet;
    
    // Change owner to attacker's program
    invoke(
        &system_instruction::assign(
            user_wallet.key,
            &attacker_program::ID,
        ),
        &[user_wallet.to_account_info()],
    )?;
    
    // Later: drain funds using program authority
    Ok(())
}
```

## Vulnerable Code Pattern

```rust
// VULNERABLE: Only checks balance, not ownership
pub fn callback_with_signer(ctx: Context<Callback>) -> Result<()> {
    let balance_before = ctx.accounts.user.lamports();
    
    // Arbitrary CPI with signer
    invoke(
        &arbitrary_instruction,
        &[ctx.accounts.user.to_account_info(), ctx.accounts.arbitrary_program.clone()],
    )?;
    
    // ⚠️ Balance check passes but ownership was stolen
    let balance_after = ctx.accounts.user.lamports();
    require!(balance_after >= balance_before, Error::FundsStolen);
    
    // Attacker now owns the account, will drain later
    Ok(())
}
```

## Detection Strategy

1. Find all CPIs where signer accounts are passed to external programs
2. Check if ownership is verified post-CPI
3. Look for balance-only checks without ownership verification
4. Flag any patterns allowing arbitrary callbacks with signers

## Fix Pattern

```rust
pub fn callback_with_signer(ctx: Context<Callback>) -> Result<()> {
    let balance_before = ctx.accounts.user.lamports();
    let owner_before = ctx.accounts.user.owner;
    
    invoke(&arbitrary_instruction, &[ctx.accounts.user.to_account_info()])?;
    
    let balance_after = ctx.accounts.user.lamports();
    let owner_after = ctx.accounts.user.owner;
    
    // ✅ Check BOTH balance AND ownership
    require!(balance_after >= balance_before, Error::FundsStolen);
    require!(owner_after == owner_before, Error::OwnershipChanged);
    require!(owner_after == &system_program::ID, Error::InvalidOwner);
    
    Ok(())
}
```

## Why This Works on Solana

- Private keys on Solana don't own accounts; programs do
- By default, wallets are owned by SystemProgram
- SystemProgram allows `assign` when account is signer
- Once reassigned, even the private key holder can't reverse it

## Real Examples

- Combined with arbitrary CPI in bridge protocols
- Callback mechanisms in composable protocols
- Any pattern where user signer is forwarded to external program

## References

- Asymmetric Research: "Verify Ownership—or Lose It"
- Solana documentation: Account ownership model
- System Program: `assign` instruction
