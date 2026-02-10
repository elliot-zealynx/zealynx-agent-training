# Token Account Owner Not Validated

**Severity:** High to Critical
**Impact:** Token theft, unauthorized token operations, cross-user fund access
**CVSS:** 7.5-9.5 depending on token value and operations

## Description

Programs accept token accounts as parameters but fail to validate that the token account is owned by the expected user or authority. This allows attackers to substitute token accounts they control or that belong to other users, leading to token theft or unauthorized operations.

## Root Cause

SPL Token accounts have an `owner` field that determines who can authorize transfers and operations. Programs that don't validate this field can be tricked into operating on the wrong token accounts, potentially transferring tokens to/from accounts the user doesn't control.

## Vulnerable Code Pattern

```rust
// VULNERABLE: No token account owner validation
#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(mut)]
    pub source_token: Account<'info, TokenAccount>, // ⚠️ No owner validation!
    
    #[account(mut)]
    pub destination_token: Account<'info, TokenAccount>, // ⚠️ No owner validation!
    
    #[account(signer)]
    pub user: Signer<'info>,
    
    pub token_program: Program<'info, Token>,
}

pub fn transfer_tokens(ctx: Context<TransferTokens>, amount: u64) -> Result<()> {
    // ⚠️ No check that source_token.owner == user.key()
    // ⚠️ User could provide any token account as source!
    
    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        Transfer {
            from: ctx.accounts.source_token.to_account_info(),
            to: ctx.accounts.destination_token.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        },
    );
    
    token::transfer(cpi_ctx, amount)?;
    Ok(())
}
```

## Attack Scenario

1. **Token Account Discovery:** Attacker finds token accounts with valuable tokens
2. **Owner Bypass:** Provides victim's token account as source in their transaction
3. **Authority Substitution:** Uses their own key as signing authority
4. **Token Theft:** Program transfers tokens from victim to attacker without proper validation

## Real Examples

### Orderly Solana Vault (Sherlock Contest 524)

**Finding:** H-1 - Missing deposit token validation (arbitrary token deposit)
**Issue:** The vault accepted any token account for deposits without validating ownership or mint
**Impact:** Users could deposit tokens they didn't own or wrong token types

```rust
// Simplified vulnerable pattern from audit
pub fn deposit_tokens(ctx: Context<DepositTokens>, amount: u64) -> Result<()> {
    // Missing validation:
    // 1. token_account.owner == user.key()
    // 2. token_account.mint == expected_mint
    
    // Direct token transfer without ownership checks
    token::transfer(/* CPI without validation */)?;
    Ok(())
}
```

### Generic DeFi Token Theft Pattern

Common in DeFi protocols where users provide token accounts without proper validation:

- **Vault deposits:** Users can deposit others' tokens
- **Staking operations:** Stake tokens from any account  
- **Yield farming:** Claim rewards to wrong accounts
- **Token swaps:** Use others' tokens as swap source

## Detection Strategy

1. **Token Account Analysis:** Find `Account<TokenAccount>` without owner constraints
2. **CPI Validation:** Check token CPIs for proper authority validation
3. **Associated Token Patterns:** Verify use of associated token accounts vs arbitrary accounts
4. **Cross-Reference Authority:** Ensure token account owner matches expected signer

```rust
// Detection patterns:
pub token_account: Account<'info, TokenAccount>, // ⚠️ No owner constraint

// vs secure patterns:
#[account(token::authority = user)] // ✅ Owner validation
#[account(associated_token::authority = user)] // ✅ Associated token account
```

## Fix Pattern

### Using Token Constraint (Preferred)

```rust
// SECURE: Token account owner validation
#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(
        mut,
        token::authority = user, // ✅ Must be owned by user
        token::mint = expected_mint, // ✅ Optional: validate mint too
    )]
    pub source_token: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub destination_token: Account<'info, TokenAccount>,
    
    #[account(signer)]
    pub user: Signer<'info>,
    
    pub token_program: Program<'info, Token>,
}
```

### Associated Token Account (Most Secure)

```rust
// MOST SECURE: Use associated token accounts
#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(
        mut,
        associated_token::authority = user,
        associated_token::mint = mint,
    )]
    pub source_token: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        associated_token::authority = recipient,
        associated_token::mint = mint,
    )]
    pub destination_token: Account<'info, TokenAccount>,
    
    #[account(signer)]
    pub user: Signer<'info>,
    
    pub recipient: AccountInfo<'info>,
    pub mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}
```

### Manual Token Account Validation

```rust
pub fn transfer_tokens_manual(ctx: Context<TransferTokensManual>, amount: u64) -> Result<()> {
    let source_token = &ctx.accounts.source_token;
    let user = &ctx.accounts.user;
    
    // Manual owner validation
    require!(
        source_token.owner == user.key(),
        ErrorCode::InvalidTokenAccountOwner
    );
    
    // Optional: validate mint
    require!(
        source_token.mint == ctx.accounts.expected_mint.key(),
        ErrorCode::InvalidTokenMint
    );
    
    // Now safe to transfer
    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        Transfer {
            from: source_token.to_account_info(),
            to: ctx.accounts.destination_token.to_account_info(),
            authority: user.to_account_info(),
        },
    );
    
    token::transfer(cpi_ctx, amount)?;
    Ok(())
}
```

## Advanced Patterns

### Multi-Token Validation

```rust
#[derive(Accounts)]
pub struct MultiTokenOperation<'info> {
    // User's token A account
    #[account(
        mut,
        token::authority = user,
        token::mint = mint_a,
    )]
    pub user_token_a: Account<'info, TokenAccount>,
    
    // User's token B account  
    #[account(
        mut,
        token::authority = user,
        token::mint = mint_b,
    )]
    pub user_token_b: Account<'info, TokenAccount>,
    
    #[account(signer)]
    pub user: Signer<'info>,
    
    pub mint_a: Account<'info, Mint>,
    pub mint_b: Account<'info, Mint>,
}
```

### Delegated Authority Pattern

```rust
#[derive(Accounts)]
pub struct DelegatedTransfer<'info> {
    #[account(
        mut,
        // Token account can be owned by user OR delegate
        constraint = token_account.owner == user.key() || 
                    token_account.delegate.unwrap_or_default() == user.key(),
        constraint = if token_account.delegate.is_some() {
            token_account.delegated_amount >= amount
        } else { true },
    )]
    pub token_account: Account<'info, TokenAccount>,
    
    #[account(signer)]
    pub user: Signer<'info>,
}
```

### Vault Token Account Pattern

```rust
#[derive(Accounts)]
pub struct VaultDeposit<'info> {
    // User's source token account
    #[account(
        mut,
        token::authority = user,
        token::mint = vault.token_mint,
    )]
    pub user_token: Account<'info, TokenAccount>,
    
    // Vault's token account (owned by vault PDA)
    #[account(
        mut,
        token::authority = vault_authority,
        token::mint = vault.token_mint,
    )]
    pub vault_token: Account<'info, TokenAccount>,
    
    #[account(
        seeds = [b"vault", vault.id.to_le_bytes().as_ref()],
        bump = vault.authority_bump,
    )]
    pub vault_authority: AccountInfo<'info>,
    
    #[account(signer)]
    pub user: Signer<'info>,
    
    pub vault: Account<'info, Vault>,
}
```

## Testing Strategy

```rust
#[test]
fn test_wrong_token_owner_rejected() {
    let user = Keypair::new();
    let victim = Keypair::new();
    
    // Create token account owned by victim
    let victim_token = create_token_account(&victim.pubkey(), &mint);
    
    // User tries to transfer from victim's account
    let result = transfer_tokens(&victim_token, &user, 1000);
    
    // Should fail with token account owner validation
    assert_eq!(result.unwrap_err(), ErrorCode::ConstraintTokenOwner);
}

#[test]
fn test_wrong_mint_rejected() {
    let user = Keypair::new();
    let correct_mint = create_mint();
    let wrong_mint = create_mint();
    
    let token_account = create_token_account_with_mint(&user.pubkey(), &wrong_mint);
    
    let result = transfer_tokens_with_mint(&token_account, &user, &correct_mint, 1000);
    
    // Should fail with mint validation  
    assert_eq!(result.unwrap_err(), ErrorCode::ConstraintTokenMint);
}

#[test]
fn test_associated_token_account_works() {
    let user = Keypair::new();
    let mint = create_mint();
    
    // Create proper associated token account
    let ata = get_associated_token_address(&user.pubkey(), &mint);
    create_associated_token_account(&user.pubkey(), &mint);
    
    let result = transfer_tokens(&ata, &user, 1000);
    assert!(result.is_ok());
}
```

## Common Mistakes

1. **Any Token Account:** Accepting any `TokenAccount` without owner validation
2. **Missing Mint Check:** Not validating token account has the expected mint
3. **Authority Confusion:** Mixing up token account owner vs transfer authority
4. **Delegate Bypass:** Not checking delegate fields for proper authorization
5. **Associated Token Assumptions:** Assuming accounts are ATAs without validation

## Best Practices

1. **Use Associated Token Accounts:** Prefer ATAs over arbitrary token accounts when possible
2. **Always Validate Owner:** Use `token::authority` constraint for ownership validation
3. **Validate Mint:** Include `token::mint` constraint to ensure correct token type
4. **Check Delegate Status:** Validate delegate fields for delegated transfer scenarios  
5. **Clear Error Messages:** Provide clear errors for token account validation failures

## Token Extensions Considerations

With Token-2022 and token extensions, additional validation may be needed:

```rust
#[derive(Accounts)]
pub struct Token22Operation<'info> {
    #[account(
        mut,
        token::authority = user,
        token::mint = mint,
        token::token_program = token_program, // Support both token programs
    )]
    pub token_account: Account<'info, TokenAccount>,
    
    #[account(signer)]
    pub user: Signer<'info>,
    
    pub mint: Account<'info, Mint>,
    
    // Could be Token or Token22 program
    pub token_program: Interface<'info, TokenInterface>,
}
```

## References

- Sherlock Orderly Solana Vault Contest Report (Contest 524, Oct 2024)
- SPL Token Program documentation and source code
- Anchor Token constraint documentation
- Token-2022 program and extension patterns
- Multiple DeFi exploits involving token account owner validation bypass