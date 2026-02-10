# PDA Authority Confusion

## Severity: High

## Description

Program Derived Addresses (PDAs) often serve as signing authorities for program-owned accounts. When PDA derivation seeds are shared across functionalities or users, or when authority validation is missing, attackers can abuse the shared authority to perform unauthorized actions.

This combines PDA misuse with CPI escalation: the same PDA signs for multiple users/operations, breaking isolation.

## Root Cause

PDAs derived with generic seeds (e.g., just `["vault"]`) create a single authority for all users. When that authority signs a CPI, any user can exploit it.

## Vulnerable Code Pattern

```rust
// VULNERABLE: Same PDA for ALL users
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(
        seeds = [b"vault_authority"],  // ⚠️ Same for everyone
        bump
    )]
    pub vault_authority: AccountInfo<'info>,
    
    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let signer_seeds = &[b"vault_authority", &[ctx.bumps.vault_authority]];
    
    // ⚠️ Anyone can trigger withdrawal to any token account
    // using the shared vault_authority
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.vault_token_account.to_account_info(),
                to: ctx.accounts.user_token_account.to_account_info(),
                authority: ctx.accounts.vault_authority.to_account_info(),
            },
            &[signer_seeds],
        ),
        amount,
    )?;
    
    Ok(())
}
```

## Attack Scenario (Orderly Network H-2)

From the Sherlock contest finding:
> "A shared vault authority signing mechanism will cause unauthorized withdrawals for users, as User A can withdraw funds belonging to User B."

1. User B initiates withdrawal on Ethereum
2. Cross-chain message arrives on Solana
3. User A front-runs, calling withdraw with:
   - User B's withdrawal parameters
   - User A's token account as recipient
4. Shared vault authority signs the transfer
5. User A receives User B's funds

## Detection Strategy

1. Check PDA derivation seeds for user uniqueness
2. Look for PDAs without user-specific components
3. Verify that PDA-signed CPIs validate recipient matches the authorized user
4. Flag patterns where one PDA signs for multiple user operations

## Fix Pattern

**Option 1: User-scoped PDAs**
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(
        seeds = [b"user_vault", user.key().as_ref()],  // ✅ Unique per user
        bump
    )]
    pub user_vault_authority: AccountInfo<'info>,
}
```

**Option 2: Recipient validation**
```rust
pub fn process_withdrawal(ctx: Context<ProcessWithdrawal>, payload: WithdrawPayload) -> Result<()> {
    // ✅ Verify recipient matches the authorized receiver
    require_keys_eq!(
        ctx.accounts.recipient.key(),
        payload.authorized_receiver,
        Error::UnauthorizedRecipient
    );
    
    // Now safe to use shared authority
    // ...
}
```

## Real Examples

- **Orderly Solana Vault (Sherlock $56.5K)**: Missing recipient validation on withdrawal
- **Cross-chain bridges**: Shared relayer authorities
- **Staking protocols**: Shared pool authorities

## Best Practice: Account Isolation

From Asymmetric Research:
> "One account, one permission. An example of this is the Solana LayerZero implementation. It has PDA signer isolation for authentication checks by the Endpoint using a unique signer seed for each SendLibrary."

```rust
// LayerZero pattern: Unique signer per library
let signer_seeds = &[
    b"oapp",
    oapp_config.key().as_ref(),
    send_library.key().as_ref(),  // Isolation
    &[bump]
];
```

## References

- Sherlock: Orderly Solana Vault Contest (2024-09)
- Asymmetric Research: "Use Account Isolation to Contain Risk"
- LayerZero Solana: PDA signer isolation pattern
