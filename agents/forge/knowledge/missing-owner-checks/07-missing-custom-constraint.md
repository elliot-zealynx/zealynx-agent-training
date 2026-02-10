# Missing Constraint in Custom Instructions

**Severity:** Medium to Critical
**Impact:** Business logic bypass, unauthorized access, data manipulation
**CVSS:** 5.0-9.0 depending on operation criticality

## Description

Programs implement custom validation logic but fail to include proper constraint checks for account relationships, state validation, or business rules. This creates gaps where attackers can bypass intended restrictions through carefully crafted transactions.

## Root Cause

When programs move beyond standard Anchor constraints and implement custom validation logic, they may miss edge cases or fail to enforce all necessary checks. Complex business logic often requires custom constraints that aren't covered by standard Anchor patterns.

## Vulnerable Code Pattern

```rust
// VULNERABLE: Missing custom constraint validation
#[derive(Accounts)]
pub struct ComplexOperation<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    
    #[account(mut)]  
    pub target_account: Account<'info, TargetAccount>,
    
    #[account(signer)]
    pub user: Signer<'info>,
    // ⚠️ Missing constraint to validate relationship between accounts!
}

pub fn complex_operation(ctx: Context<ComplexOperation>, amount: u64) -> Result<()> {
    let user_account = &mut ctx.accounts.user_account;
    let target_account = &mut ctx.accounts.target_account;
    
    // ⚠️ No validation that user_account and target_account are properly related
    // ⚠️ No validation of account state requirements
    // ⚠️ No validation of amount limits based on account data
    
    user_account.balance -= amount;
    target_account.balance += amount;
    
    Ok(())
}
```

## Attack Scenarios

### 1. Account Relationship Bypass

```rust
// Attacker provides unrelated accounts that pass individual validation
// but shouldn't be used together in the same operation
```

### 2. State Requirement Bypass

```rust
// Account is in wrong state (e.g., locked, paused, expired) 
// but no constraint validates the state
```

### 3. Business Rule Violation

```rust
// Operation violates business rules (limits, permissions, timing)
// that aren't enforced by constraints
```

## Real Examples

### Solana Foundation Token22 Audit (Code4rena 2025)

**Finding:** Centralized Power / Trust Assumption
**Issue:** The configured ConfidentialTransferFee authority can enable/disable harvest-to-mint immediately without time-bound safeguards or multisig
**Missing Constraint:** Time-delay or multisig requirements for critical authority actions

### Generic DeFi Protocol Patterns

**Common Missing Constraints:**
- Vault state validation (active/paused/emergency)
- Time-based restrictions (cooldowns, lock periods)
- Cross-account relationship validation
- Amount limits based on account data
- Permission level checks beyond basic ownership

## Detection Strategy

1. **Business Logic Analysis:** Identify complex operations beyond standard CRUD
2. **State Machine Review:** Check if account state transitions are properly validated
3. **Relationship Mapping:** Verify accounts used together have proper relationship validation
4. **Edge Case Testing:** Look for missing validation in error conditions
5. **Custom Logic Audit:** Review all custom validation beyond standard Anchor constraints

## Fix Patterns

### Custom Constraint Implementation

```rust
// SECURE: Comprehensive custom constraint validation
#[derive(Accounts)]
pub struct ComplexOperation<'info> {
    #[account(
        mut,
        has_one = owner,
        constraint = user_account.status == AccountStatus::Active @ ErrorCode::AccountInactive,
        constraint = user_account.balance >= amount @ ErrorCode::InsufficientBalance,
    )]
    pub user_account: Account<'info, UserAccount>,
    
    #[account(
        mut,
        constraint = target_account.accepts_transfers @ ErrorCode::TransfersDisabled,
        constraint = user_account.allowed_targets.contains(&target_account.key()) 
                    @ ErrorCode::UnauthorizedTarget,
    )]
    pub target_account: Account<'info, TargetAccount>,
    
    #[account(
        signer,
        constraint = !user.blacklisted @ ErrorCode::UserBlacklisted,
    )]
    pub user: Signer<'info>,
}

#[instruction(amount: u64)]
#[derive(Accounts)]
pub struct ComplexOperationWithInstruction<'info> {
    // Access instruction parameters in constraints
    #[account(
        constraint = user_account.daily_limit >= user_account.daily_used + amount 
                    @ ErrorCode::DailyLimitExceeded,
    )]
    pub user_account: Account<'info, UserAccount>,
}
```

### State Validation Pattern

```rust
#[derive(Accounts)]
pub struct StateValidatedOperation<'info> {
    #[account(
        mut,
        constraint = config.status == ProtocolStatus::Active @ ErrorCode::ProtocolPaused,
        constraint = Clock::get()?.unix_timestamp <= config.expiry @ ErrorCode::ProtocolExpired,
    )]
    pub config: Account<'info, ProtocolConfig>,
    
    #[account(
        mut,
        constraint = user_account.lock_expiry < Clock::get()?.unix_timestamp 
                    @ ErrorCode::AccountLocked,
    )]
    pub user_account: Account<'info, UserAccount>,
}
```

### Relationship Validation Pattern

```rust
#[derive(Accounts)]
pub struct RelationshipValidated<'info> {
    #[account(
        mut,
        has_one = vault, // Basic relationship
        constraint = user_position.vault == vault.key() @ ErrorCode::InvalidVault,
        constraint = user_position.user == user.key() @ ErrorCode::InvalidUser,
    )]
    pub user_position: Account<'info, UserPosition>,
    
    #[account(
        mut,
        constraint = vault.active @ ErrorCode::VaultInactive,
        constraint = vault.strategy == strategy.key() @ ErrorCode::InvalidStrategy,
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(
        constraint = strategy.approved @ ErrorCode::StrategyNotApproved,
    )]
    pub strategy: Account<'info, Strategy>,
    
    #[account(signer)]
    pub user: Signer<'info>,
}
```

## Advanced Custom Constraints

### Time-Based Constraints

```rust
#[derive(Accounts)]
pub struct TimeBoundedOperation<'info> {
    #[account(
        mut,
        constraint = user_account.last_action + COOLDOWN_SECONDS 
                    <= Clock::get()?.unix_timestamp @ ErrorCode::CooldownActive,
        constraint = Clock::get()?.unix_timestamp >= user_account.unlock_time 
                    @ ErrorCode::StillLocked,
    )]
    pub user_account: Account<'info, UserAccount>,
}
```

### Mathematical Constraints

```rust
#[instruction(amount: u64)]
#[derive(Accounts)]  
pub struct MathematicalValidation<'info> {
    #[account(
        mut,
        constraint = amount.checked_mul(price).is_some() @ ErrorCode::Overflow,
        constraint = amount <= user_account.max_single_transaction 
                    @ ErrorCode::AmountTooLarge,
        constraint = user_account.balance
                    .checked_sub(amount)
                    .is_some() @ ErrorCode::InsufficientBalance,
    )]
    pub user_account: Account<'info, UserAccount>,
}
```

### Multi-Account State Consistency

```rust
#[derive(Accounts)]
pub struct ConsistencyValidated<'info> {
    #[account(
        mut,
        constraint = vault.total_shares == user_positions.iter().map(|p| p.shares).sum::<u64>() 
                    @ ErrorCode::SharesMismatch,
    )]
    pub vault: Account<'info, Vault>,
    
    // Validate multiple user positions
    #[account(
        constraint = user_positions.iter().all(|p| p.vault == vault.key()) 
                    @ ErrorCode::InvalidPositionVault,
    )]
    pub user_positions: Vec<Account<'info, UserPosition>>,
}
```

## Complex Validation with Custom Functions

```rust
#[derive(Accounts)]
pub struct AdvancedValidation<'info> {
    #[account(
        mut,
        constraint = validate_complex_business_rules(&user_account, &market_data, amount)? 
                    @ ErrorCode::BusinessRuleViolation,
    )]
    pub user_account: Account<'info, UserAccount>,
    
    pub market_data: Account<'info, MarketData>,
}

// Custom validation function
fn validate_complex_business_rules(
    user_account: &Account<UserAccount>,
    market_data: &Account<MarketData>, 
    amount: u64
) -> Result<bool> {
    // Complex multi-factor validation
    let risk_score = calculate_risk_score(user_account, market_data)?;
    let max_allowed = user_account.base_limit.checked_mul(risk_score)?;
    
    Ok(amount <= max_allowed && 
       user_account.reputation >= MINIMUM_REPUTATION &&
       market_data.volatility <= MAX_VOLATILITY)
}
```

## Testing Strategy

```rust
#[test]
fn test_account_relationship_constraint() {
    let user = Keypair::new();
    let wrong_vault = create_vault(); // Not user's vault
    let user_position = create_position_for_different_vault();
    
    let result = complex_operation(&user_position, &wrong_vault, &user);
    
    // Should fail constraint validation
    assert_eq!(result.unwrap_err(), ErrorCode::InvalidVault);
}

#[test]
fn test_state_constraint() {
    let user = Keypair::new();
    let locked_account = create_locked_user_account(&user);
    
    let result = perform_operation(&locked_account);
    
    // Should fail state validation
    assert_eq!(result.unwrap_err(), ErrorCode::AccountLocked);
}

#[test]
fn test_amount_limit_constraint() {
    let user = Keypair::new();
    let user_account = create_user_account(&user);
    let excessive_amount = user_account.daily_limit + 1;
    
    let result = transfer(&user_account, excessive_amount);
    
    // Should fail amount validation
    assert_eq!(result.unwrap_err(), ErrorCode::DailyLimitExceeded);
}

#[test]
fn test_time_constraint() {
    let user = Keypair::new();
    let user_account = create_user_account(&user);
    
    // Perform operation
    perform_operation(&user_account);
    
    // Try again immediately (should fail cooldown)
    let result = perform_operation(&user_account);
    assert_eq!(result.unwrap_err(), ErrorCode::CooldownActive);
    
    // Warp time and try again (should succeed)
    warp_time(COOLDOWN_SECONDS + 1);
    let result = perform_operation(&user_account);
    assert!(result.is_ok());
}
```

## Common Constraint Gaps

1. **State Validation:** Account status, protocol state, time constraints
2. **Relationship Validation:** Cross-account relationships and dependencies
3. **Business Rules:** Domain-specific logic not covered by standard constraints
4. **Mathematical Invariants:** Overflow protection, balance conservation
5. **Permission Hierarchies:** Complex authorization beyond simple ownership
6. **Temporal Constraints:** Time-based restrictions and cooldowns

## Best Practices

1. **Comprehensive Constraint Design:** Map out all validation requirements before implementation
2. **Early Validation:** Use constraints over manual checks in instruction handler
3. **Clear Error Messages:** Provide specific error codes for each constraint type
4. **Test Negative Cases:** Thoroughly test constraint violations
5. **Document Constraints:** Clearly document business rules and validation logic
6. **Constraint Composition:** Build complex validation from simpler constraint primitives

## References

- Solana Foundation Token22 Code4rena Audit Report (Aug-Sep 2025)
- Anchor Framework constraint documentation
- Multiple DeFi audit findings related to business logic bypass
- Solana Program validation patterns and best practices