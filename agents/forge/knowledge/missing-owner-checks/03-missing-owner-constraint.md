# Missing owner Constraint Validation

**Severity:** High to Critical  
**Impact:** Program ownership bypass, unauthorized account access
**CVSS:** 7.5-9.0 depending on program privileges

## Description

Programs fail to validate that accounts are owned by the expected program using the `owner = expr` constraint or manual ownership checks. This allows attackers to substitute accounts owned by different programs that may have compatible data layouts.

## Root Cause

Solana programs must explicitly verify account ownership since any program can read any account. Without ownership validation, attackers can substitute accounts owned by malicious programs or system accounts that happen to have compatible data structures.

## Vulnerable Code Pattern

```rust
// VULNERABLE: No owner constraint
#[derive(Accounts)]
pub struct ProcessData<'info> {
    #[account(mut)]
    pub target_account: AccountInfo<'info>, // ⚠️ Any program can own this!
    
    #[account(signer)]
    pub authority: Signer<'info>,
}

// Manual processing without owner check
pub fn process_data(ctx: Context<ProcessData>) -> Result<()> {
    let account_info = &ctx.accounts.target_account;
    
    // ⚠️ No check that account_info.owner == expected_program_id
    let mut data = MyAccountType::unpack_mut(&mut account_info.data.borrow_mut())?;
    data.value = 1000;
    
    Ok(())
}
```

## Attack Scenario

1. **Malicious Program Creation:** Attacker deploys a program with compatible data layout
2. **Account Substitution:** Creates accounts owned by their malicious program
3. **Data Manipulation:** The malicious program can modify account data arbitrarily
4. **Bypass Success:** Target program processes the malicious account without ownership validation

## Real Examples

### Wormhole Bridge Exploit ($325M, February 2022)

**Attack Vector:** Sysvar account spoofing through missing ownership validation
- Attacker created fake sysvar accounts owned by their program
- Bridge contract didn't validate sysvar account ownership  
- Malicious sysvar contained fabricated signature verification data
- Led to unauthorized bridge message processing

### Cashio Protocol Exploit ($52M, March 2022)

**Attack Vector:** Mint account ownership bypass
- Missing validation that mint account was owned by SPL Token program
- Attacker substituted mint owned by their malicious program
- Could arbitrarily modify mint supply and authority data
- Led to infinite token printing

## Detection Strategy

1. **Account Type Audit:** Find all `AccountInfo<'info>` usages without `owner` constraints
2. **Program ID Validation:** Check for missing manual ownership validation
3. **Cross-Program Calls:** Verify accounts passed to CPIs have correct ownership
4. **Sysvar Usage:** Ensure sysvar accounts are validated against known addresses

```rust
// Detection pattern: AccountInfo without constraints
pub struct VulnerableStruct<'info> {
    pub unchecked_account: AccountInfo<'info>, // ⚠️ Red flag
}
```

## Fix Pattern

### Using Anchor Constraints (Preferred)

```rust
// SECURE: owner constraint validation
#[derive(Accounts)]  
pub struct ProcessData<'info> {
    #[account(
        mut,
        owner = my_program::id(), // ✅ Must be owned by our program
    )]
    pub target_account: Account<'info, MyAccountType>,
    
    #[account(signer)]
    pub authority: Signer<'info>,
}
```

### Manual Ownership Validation

```rust
pub fn process_data(ctx: Context<ProcessData>) -> Result<()> {
    let account_info = &ctx.accounts.target_account;
    
    // Manual ownership check
    if account_info.owner != &my_program::id() {
        return Err(ErrorCode::IncorrectProgramId.into());
    }
    
    let mut data = MyAccountType::unpack_mut(&mut account_info.data.borrow_mut())?;
    data.value = 1000;
    
    Ok(())
}
```

### System Account Validation

```rust
#[derive(Accounts)]
pub struct CreateAccount<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + 32,
        owner = system_program::id(), // ✅ Must be owned by system program initially
    )]
    pub new_account: SystemAccount<'info>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}
```

## Advanced Patterns

### SPL Token Account Validation

```rust
#[derive(Accounts)]
pub struct TokenOperation<'info> {
    #[account(
        mut,
        owner = token::id(), // ✅ Must be SPL Token program
        constraint = token_account.mint == expected_mint,
    )]
    pub token_account: Account<'info, TokenAccount>,
}
```

### Sysvar Account Validation

```rust
#[derive(Accounts)]
pub struct UseClock<'info> {
    #[account(
        address = solana_program::sysvar::clock::id(), // ✅ Exact address check
    )]
    pub clock: Sysvar<'info, Clock>,
}
```

### Cross-Program Account Validation

```rust
#[derive(Accounts)]
pub struct CrossProgramCall<'info> {
    #[account(
        owner = other_program::id(), // ✅ Must be owned by specific program
    )]
    pub other_program_account: AccountInfo<'info>,
    
    /// CHECK: This account is validated in the CPI call
    #[account(
        executable,
        address = other_program::id(),
    )]
    pub other_program: AccountInfo<'info>,
}
```

## Testing Strategy

```rust
#[test]
fn test_wrong_owner_rejected() {
    let malicious_program_id = Pubkey::new_unique();
    let fake_account = create_account_with_owner(&malicious_program_id);
    
    let result = process_data(&fake_account);
    
    // Should fail with ownership error
    assert_eq!(result.unwrap_err(), ErrorCode::ConstraintOwner);
}

#[test] 
fn test_system_account_spoofing() {
    // Attacker creates account that looks like a sysvar
    let fake_clock = create_fake_sysvar_account();
    
    let result = use_clock_sysvar(&fake_clock);
    
    // Should fail with address constraint violation
    assert_eq!(result.unwrap_err(), ErrorCode::ConstraintAddress);
}

#[test]
fn test_correct_ownership_succeeds() {
    let correct_account = create_account_with_owner(&my_program::id());
    
    let result = process_data(&correct_account);
    assert!(result.is_ok());
}
```

## Common Mistakes

1. **AccountInfo Overuse:** Using `AccountInfo<'info>` instead of `Account<'info, T>`
2. **Trust by Parameter:** Assuming caller provides correctly-owned accounts
3. **Late Validation:** Checking ownership after data manipulation
4. **Sysvar Trust:** Not validating sysvar account addresses
5. **Cross-Program Assumptions:** Trusting accounts from other programs without validation

## Best Practices

1. **Use Account<T>:** Prefer `Account<'info, MyType>` over `AccountInfo<'info>`
2. **Explicit owner Constraints:** Always specify `owner = program::id()` when needed
3. **Sysvar Address Validation:** Use `address = sysvar::id()` for sysvar accounts
4. **Early Validation:** Check ownership before any data access
5. **Test Negative Cases:** Always test with wrong owners and malicious accounts

## References

- Wormhole Bridge Exploit Analysis (Feb 2022, $325M)
- Cashio Protocol Exploit Analysis (Mar 2022, $52M)
- Anchor Account Constraints Documentation
- Solana Program Security Best Practices
- SPL Token Program source code for ownership validation examples