# Missing Authority Signer Requirement

**Severity:** Critical
**Impact:** Complete authority bypass, unauthorized administrative actions
**CVSS:** 9.0-10.0 for administrative operations

## Description

Programs allow modification of authority fields or execution of privileged operations without requiring the current authority to sign the transaction. This enables complete authority bypass where any user can grant themselves administrative privileges.

## Root Cause

The program accepts an authority account as a parameter but doesn't enforce that the current authority must sign the transaction to authorize changes. This violates the principle that authority transfers or privileged operations require explicit approval from the current authority.

## Vulnerable Code Pattern

```rust
// VULNERABLE: Authority change without signer requirement
#[derive(Accounts)]
pub struct ChangeAuthority<'info> {
    #[account(
        mut,
        has_one = authority, // ✅ Validates current authority
    )]
    pub account: Account<'info, MyAccount>,
    
    pub authority: AccountInfo<'info>, // ⚠️ Not required to sign!
    pub new_authority: AccountInfo<'info>,
}

pub fn change_authority(ctx: Context<ChangeAuthority>) -> Result<()> {
    let account = &mut ctx.accounts.account;
    // ⚠️ No verification that authority signed this transaction
    account.authority = ctx.accounts.new_authority.key();
    Ok(())
}
```

## Attack Scenario

1. **Authority Discovery:** Attacker finds an account with known authority
2. **Transaction Crafting:** Creates transaction changing authority to their key
3. **Bypass Success:** Provides current authority as non-signer parameter
4. **Privilege Escalation:** Now controls the account without original authority's consent

## Real Examples

### Generic Authority Transfer Pattern (Multiple Audits)

This vulnerability appears frequently in programs that implement authority transfer mechanisms without proper signer validation.

**Common Vulnerable Operations:**
- Authority transfer functions
- Administrative privilege changes
- Ownership transfer in tokenized assets
- Vault management authority updates

### DeFi Vault Authority Bypass (Hypothetical)

```rust
// VULNERABLE: Vault authority can be changed without current authority signing
#[derive(Accounts)]
pub struct TransferVaultAuthority<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    
    pub authority: AccountInfo<'info>, // ⚠️ Should be Signer<'info>
    pub new_authority: AccountInfo<'info>,
}

// Attacker can call this to steal vault control
pub fn transfer_vault_authority(ctx: Context<TransferVaultAuthority>) -> Result<()> {
    ctx.accounts.vault.authority = ctx.accounts.new_authority.key();
    Ok(())
}
```

## Detection Strategy

1. **Authority Change Analysis:** Find functions that modify authority/owner fields
2. **Signer Requirements:** Check if authority accounts have `signer` constraint
3. **Privileged Operations:** Identify admin functions that don't require authority signature
4. **Parameter Validation:** Look for authority accounts passed as `AccountInfo` vs `Signer`

```rust
// Detection patterns to look for:
pub authority: AccountInfo<'info>, // ⚠️ Red flag for authority operations

// vs the secure pattern:
pub authority: Signer<'info>, // ✅ Required to sign
```

## Fix Pattern

### Authority Change with Signer Requirement

```rust
// SECURE: Authority must sign to transfer
#[derive(Accounts)]
pub struct ChangeAuthority<'info> {
    #[account(
        mut,
        has_one = authority, // ✅ Current authority validation
    )]
    pub account: Account<'info, MyAccount>,
    
    #[account(signer)] // ✅ Must sign the transaction
    pub authority: Signer<'info>,
    
    pub new_authority: AccountInfo<'info>,
}

pub fn change_authority(ctx: Context<ChangeAuthority>) -> Result<()> {
    let account = &mut ctx.accounts.account;
    account.authority = ctx.accounts.new_authority.key();
    emit!(AuthorityChanged {
        old_authority: ctx.accounts.authority.key(),
        new_authority: ctx.accounts.new_authority.key(),
    });
    Ok(())
}
```

### Administrative Operation Protection

```rust
#[derive(Accounts)]
pub struct AdminOperation<'info> {
    #[account(
        mut,
        has_one = admin,
        constraint = config.admin_enabled @ ErrorCode::AdminDisabled,
    )]
    pub config: Account<'info, Config>,
    
    #[account(signer)] // ✅ Admin must sign
    pub admin: Signer<'info>,
}

pub fn emergency_pause(ctx: Context<AdminOperation>) -> Result<()> {
    ctx.accounts.config.paused = true;
    emit!(EmergencyPause {
        admin: ctx.accounts.admin.key(),
        timestamp: Clock::get()?.unix_timestamp,
    });
    Ok(())
}
```

## Advanced Patterns

### Multi-Signature Authority

```rust
#[derive(Accounts)]
pub struct MultiSigOperation<'info> {
    #[account(
        mut,
        has_one = authority_1,
        has_one = authority_2,
    )]
    pub multisig_account: Account<'info, MultiSigAccount>,
    
    #[account(signer)] // ✅ Both must sign
    pub authority_1: Signer<'info>,
    
    #[account(signer)] // ✅ Both must sign  
    pub authority_2: Signer<'info>,
}
```

### Conditional Authority Requirements

```rust
#[derive(Accounts)]
pub struct ConditionalAdmin<'info> {
    #[account(
        mut,
        constraint = if config.emergency_mode {
            // Emergency mode: any admin can act
            config.admin_1 == authority.key() || 
            config.admin_2 == authority.key()
        } else {
            // Normal mode: primary admin only
            config.primary_admin == authority.key()
        }
    )]
    pub config: Account<'info, Config>,
    
    #[account(signer)]
    pub authority: Signer<'info>,
}
```

### Time-Delayed Authority Transfer

```rust
#[derive(Accounts)]  
pub struct ProposeAuthorityChange<'info> {
    #[account(
        mut,
        has_one = authority,
    )]
    pub account: Account<'info, MyAccount>,
    
    #[account(signer)] // ✅ Current authority must sign proposal
    pub authority: Signer<'info>,
    
    pub proposed_authority: AccountInfo<'info>,
}

pub fn propose_authority_change(ctx: Context<ProposeAuthorityChange>) -> Result<()> {
    let account = &mut ctx.accounts.account;
    account.proposed_authority = Some(ctx.accounts.proposed_authority.key());
    account.proposal_timestamp = Clock::get()?.unix_timestamp;
    Ok(())
}

#[derive(Accounts)]
pub struct AcceptAuthorityChange<'info> {
    #[account(
        mut,
        constraint = account.proposed_authority == Some(new_authority.key()),
        constraint = Clock::get()?.unix_timestamp >= 
                    account.proposal_timestamp + DELAY_SECONDS,
    )]
    pub account: Account<'info, MyAccount>,
    
    #[account(signer)] // ✅ New authority must accept
    pub new_authority: Signer<'info>,
}
```

## Testing Strategy

```rust
#[test]
fn test_authority_change_requires_signer() {
    let authority = Keypair::new();
    let new_authority = Keypair::new();
    let account = create_account_with_authority(&authority.pubkey());
    
    // Attempt authority change without signing
    let mut ctx = create_context(&account, &authority, &new_authority);
    ctx.accounts.authority.is_signer = false; // Simulate non-signer
    
    let result = change_authority(ctx);
    
    // Should fail with missing signer error
    assert_eq!(result.unwrap_err(), ErrorCode::AccountNotSigner);
}

#[test]  
fn test_authority_change_with_wrong_signer() {
    let real_authority = Keypair::new();
    let fake_authority = Keypair::new();
    let new_authority = Keypair::new();
    let account = create_account_with_authority(&real_authority.pubkey());
    
    // Attempt with wrong signer
    let result = change_authority(&account, &fake_authority, &new_authority);
    
    // Should fail with has_one constraint violation
    assert_eq!(result.unwrap_err(), ErrorCode::ConstraintHasOne);
}

#[test]
fn test_valid_authority_change() {
    let authority = Keypair::new();
    let new_authority = Keypair::new();
    let account = create_account_with_authority(&authority.pubkey());
    
    let result = change_authority(&account, &authority, &new_authority);
    
    assert!(result.is_ok());
    assert_eq!(account.authority, new_authority.pubkey());
}
```

## Common Mistakes

1. **AccountInfo for Authority:** Using `AccountInfo<'info>` instead of `Signer<'info>` for authority parameters
2. **Optional Signer:** Making authority signing optional for convenience
3. **Proxy Authority:** Allowing other accounts to act on behalf of authority without delegation
4. **Batch Operations:** Not requiring authority signature for each privileged operation in a batch
5. **Emergency Bypass:** Creating emergency functions that bypass signer requirements

## Best Practices

1. **Always Require Signers:** Use `Signer<'info>` for all authority accounts in privileged operations
2. **Audit Authority Flows:** Trace all paths that can modify authority fields
3. **Event Emission:** Log authority changes with old and new authority values
4. **Time Delays:** Consider time-delayed authority transfers for high-value operations
5. **Multi-Signature:** Require multiple signatures for critical authority changes

## References

- Multiple DeFi authority bypass incidents
- Anchor Signer constraint documentation
- Solana Program Authority Best Practices
- SPL Token Program authority transfer implementation