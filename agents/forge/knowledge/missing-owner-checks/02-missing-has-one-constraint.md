# Missing has_one Constraint in Anchor

**Severity:** High to Critical
**Impact:** Authority bypass, unauthorized access to user funds
**CVSS:** 7.0-9.0 depending on privileges controlled

## Description

Anchor programs fail to use the `has_one` constraint to verify that an account's stored authority field matches the provided authority account. This allows attackers to bypass authority checks by providing valid but wrong accounts.

## Root Cause

The program assumes that if an account exists and has the correct type, its authority field will match the intended signer. Without the `has_one` constraint, there's no validation that `account.authority == provided_authority.key()`.

## Vulnerable Code Pattern

```rust
// VULNERABLE: Missing has_one constraint
#[derive(Accounts)]
pub struct WithdrawFunds<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    
    #[account(signer)]  
    pub authority: Signer<'info>, // ⚠️ No has_one validation!
    
    #[account(mut)]
    pub destination: SystemAccount<'info>,
}

// In the instruction handler:
pub fn withdraw_funds(ctx: Context<WithdrawFunds>, amount: u64) -> Result<()> {
    let user_account = &mut ctx.accounts.user_account;
    // ⚠️ No verification that user_account.authority == authority.key()
    user_account.balance -= amount;
    // Transfer funds...
    Ok(())
}
```

## Attack Scenario

1. **Authority Mismatch:** Attacker finds a valid `UserAccount` belonging to victim
2. **Signer Substitution:** Provides their own keypair as `authority` signer
3. **Bypass Success:** Program processes withdrawal without verifying authority field
4. **Fund Theft:** Attacker drains victim's account using their own signature

## Real Examples

### Generic Authority Bypass Pattern (Multiple Audits)

This pattern appears frequently in DeFi protocols where user accounts have stored authority fields but the program doesn't validate the authority matches the signer.

**Common Vulnerable Contexts:**
- Vault withdrawal functions
- Token account operations  
- Staking/unstaking operations
- Administrative functions

### Orderly Solana Vault (Sherlock Contest 524)

**Finding:** H-2 - Shared vault authority allowing cross-user withdrawal theft
**Root Cause:** Missing validation that vault authority field matched the provided signer
**Impact:** Users could withdraw from other users' vaults

## Detection Strategy

1. **Constraint Audit:** Check all `Account<T>` fields that have authority/owner fields in their data structure
2. **Cross-Reference Analysis:** Verify authority fields are checked against signer accounts
3. **Pattern Search:** Look for `signer` constraints without corresponding `has_one` constraints
4. **Data Structure Review:** Examine account types for authority/owner fields that need validation

```rust
// Detection: Find account types with authority fields
#[account]
pub struct UserAccount {
    pub authority: Pubkey,  // ⚠️ This needs has_one validation
    pub balance: u64,
}
```

## Fix Pattern

```rust
// SECURE: Using has_one constraint
#[derive(Accounts)]
pub struct WithdrawFunds<'info> {
    #[account(
        mut,
        has_one = authority,  // ✅ Validates user_account.authority == authority.key()
    )]
    pub user_account: Account<'info, UserAccount>,
    
    #[account(signer)]
    pub authority: Signer<'info>,
    
    #[account(mut)]
    pub destination: SystemAccount<'info>,
}

// Alternative: Manual validation
pub fn withdraw_funds(ctx: Context<WithdrawFunds>, amount: u64) -> Result<()> {
    let user_account = &mut ctx.accounts.user_account;
    
    // Manual check (prefer has_one constraint above)
    require!(
        user_account.authority == ctx.accounts.authority.key(),
        ErrorCode::UnauthorizedAuthority
    );
    
    user_account.balance -= amount;
    Ok(())
}
```

## Advanced Patterns

### Multiple Authority Validation

```rust
#[derive(Accounts)]
pub struct ComplexOperation<'info> {
    #[account(
        mut,
        has_one = owner,
        has_one = manager,  // Multiple authority checks
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(signer)]
    pub owner: Signer<'info>,
    
    #[account(signer)]  
    pub manager: Signer<'info>,
}
```

### Conditional Authority

```rust
#[derive(Accounts)]
pub struct FlexibleAccess<'info> {
    #[account(
        mut,
        constraint = account.authority == authority.key() || 
                    account.admin == authority.key()  // Either authority or admin
    )]
    pub account: Account<'info, FlexibleAccount>,
    
    #[account(signer)]
    pub authority: Signer<'info>,
}
```

## Testing Strategy

```rust
#[test]
fn test_authority_bypass_prevented() {
    let victim_account = create_user_account(&victim_authority);
    let attacker_authority = Keypair::new();
    
    // Attempt to withdraw from victim's account using attacker's signature
    let result = withdraw_funds(
        &victim_account,
        &attacker_authority,  // Wrong authority
        1000
    );
    
    // Should fail with authority mismatch error
    assert_eq!(result.unwrap_err(), ErrorCode::ConstraintHasOne);
}

#[test]
fn test_correct_authority_succeeds() {
    let authority = Keypair::new();
    let user_account = create_user_account(&authority.pubkey());
    
    // Should succeed with correct authority
    let result = withdraw_funds(&user_account, &authority, 1000);
    assert!(result.is_ok());
}
```

## Common Mistakes

1. **Trust by Type:** Assuming `Account<UserAccount>` guarantees correct authority
2. **Signer-Only Validation:** Only checking `signer` constraint without authority field validation
3. **Manual Check Gaps:** Forgetting manual authority validation when not using constraints
4. **Multi-Authority Confusion:** Missing validation when accounts have multiple authority fields

## References

- Anchor Account Constraints Documentation
- Sherlock Orderly Solana Vault Contest Report (Contest 524, Oct 2024)  
- Multiple DeFi exploit analyses showing authority bypass patterns
- Anchor Framework has_one constraint source code