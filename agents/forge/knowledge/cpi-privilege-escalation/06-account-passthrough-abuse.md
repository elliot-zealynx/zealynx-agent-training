# Account Passthrough Abuse

## Severity: Medium-High

## Description

When a program allows arbitrary CPIs with user-provided accounts, those accounts may carry unexpected signer privileges from earlier in the transaction. This creates a "confused deputy" scenario where the caller program facilitates attacks by passing through accounts with elevated privileges.

From Asymmetric Research:
> "When making an arbitrary CPI, the program, accounts, and instruction data must be provided for the call to succeed. Without verification, these accounts can contain anything. In particular, they can have signers from a previous call."

## Root Cause

Solana's transaction model allows accounts to be reused across instructions. If an account was signed earlier in the transaction, it retains that status for subsequent instructions.

## Vulnerable Code Pattern

```rust
// VULNERABLE: No verification of account signers in passthrough
pub fn execute_callback(
    ctx: Context<ExecuteCallback>,
    account_params: Vec<AccountMeta>,
    instruction_data: Vec<u8>,
) -> Result<()> {
    // Build CPI accounts from user input
    let accounts: Vec<AccountInfo> = account_params
        .iter()
        .map(|meta| /* get account info */)
        .collect();
    
    // ⚠️ Accounts may include signers from earlier instructions
    invoke(
        &Instruction {
            program_id: ctx.accounts.target_program.key(),
            accounts: account_params,
            data: instruction_data,
        },
        &accounts,
    )?;
    
    Ok(())
}
```

## Attack Scenario (LayerZero Pattern)

1. Transaction Instruction 1: User signs for legitimate action
2. Transaction Instruction 2: Calls vulnerable callback mechanism
3. Attacker includes user's account (still marked as signer) in callback
4. Callback program uses the passthrough signer maliciously

**Real-world example from Orderly Network:**
```
User wallet signs deposit → Bridge callback → 
  Attacker intercepts, substitutes their wallet as recipient
```

## Detection Strategy

1. Find functions accepting dynamic account lists (`Vec<AccountMeta>`)
2. Check if signer status is verified before CPI
3. Look for `ctx.remaining_accounts` without validation
4. Flag any pattern where account metas are user-controlled

## Fix Pattern

```rust
pub fn execute_callback(
    ctx: Context<ExecuteCallback>,
    account_params: Vec<AccountMeta>,
    instruction_data: Vec<u8>,
) -> Result<()> {
    // ✅ Strip all signer privileges before arbitrary CPI
    for account in &account_params {
        require!(!account.is_signer, Error::FoundSigner);
    }
    
    // Now safe to proceed
    invoke(&instruction, &accounts)?;
    
    Ok(())
}
```

## Validating Remaining Accounts

```rust
pub fn process_batch(ctx: Context<ProcessBatch>) -> Result<()> {
    for account in ctx.remaining_accounts.iter() {
        // ✅ Validate each remaining account
        require!(
            account.owner == &expected_program_id,
            Error::InvalidAccountOwner
        );
        require!(
            !account.is_signer || account.key() == &expected_signer,
            Error::UnexpectedSigner
        );
        
        // Now safe to use
    }
    
    Ok(())
}
```

## Real Examples

- **Orderly Solana Vault (H-2)**: Shared vault authority allowed cross-user withdrawal
- **LayerZero implementations**: PDA signer isolation required for OApp endpoints
- **Bridge protocols**: Message handlers passing through accounts

## Best Practice: Account Isolation

From Asymmetric Research:
> "By requiring a specific user account as part of a PDA's derivation, a program can limit the blast radius of a potential downstream bug to only a single user account."

```rust
// Good: User-scoped PDA prevents cross-user attacks
let signer_seeds = &[
    b"user_authority",
    user.key().as_ref(),  // Unique per user
    &[bump]
];
```

## References

- Asymmetric Research: "Account Signer PassThroughs"
- Sherlock: Orderly Solana Vault H-2
- LayerZero Solana implementation
