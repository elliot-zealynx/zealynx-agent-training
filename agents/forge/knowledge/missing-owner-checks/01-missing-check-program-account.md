# Missing check_program_account Before Unpack/Mutation

**Severity:** Medium to High
**Impact:** Late failure with confusing errors, potential security bypass if combined with other issues
**CVSS:** 5.0-7.5 depending on context

## Description

Programs fail to call `check_program_account()` before unpacking or mutating account data. This leads to late failure with less clear errors when non-Token-2022 accounts are supplied, and in some contexts can contribute to authority bypass vulnerabilities.

## Root Cause

The program attempts to unpack/mutate account data without first verifying the account is owned by the expected program. While the unpack may eventually fail, the error comes later in the execution and may be less clear.

## Vulnerable Code Pattern

```rust
// VULNERABLE: Missing check_program_account() before unpack
let account_info = next_account_info(account_info_iter)?;
let mut account_data = MyAccountType::unpack_mut(&mut account_info.data.borrow_mut())?;
account_data.balance = new_balance; // Mutating without ownership verification

// Another vulnerable pattern
let destination_account = Account::<DestinationAccount>::try_from_unchecked(account_info)?;
destination_account.amount += fee; // Mutation without program ownership check
```

## Attack Scenario

1. **Confused Account Substitution:** Attacker provides an account owned by a different program that happens to have compatible data layout
2. **Late Error Discovery:** The program processes the account and fails later with cryptic error messages  
3. **Potential Bypass:** If the wrong account has compatible data, operations might proceed unexpectedly

## Real Examples

### Solana Foundation Token22 Audit (Code4rena 2025)

**Locations:**
- `program/src/extension/confidential_transfer_fee/processor.rs:#L182-L221` (destination account)
- `program/src/extension/confidential_transfer_fee/processor.rs:#L326-L341` (mint in harvest-to-mint)

**Finding:** Unpack/mutate without first calling `check_program_account(..)` led to late failures with unclear errors when non-Token-2022 accounts were supplied.

**Impact:** Fails late with less clear errors, adds unnecessary compute usage, reduces observability.

## Detection Strategy

1. **Static Analysis:** Look for `unpack()`, `unpack_mut()`, or `try_from_unchecked()` calls not preceded by ownership verification
2. **Pattern Search:** Find account mutations without prior `check_program_account()` or similar validation  
3. **Code Review:** Check that every account access validates ownership first
4. **Testing:** Supply accounts owned by different programs and verify clear, early error messages

## Fix Pattern

```rust
// SECURE: Check program ownership before unpacking
let account_info = next_account_info(account_info_iter)?;

// Option 1: Explicit check_program_account
check_program_account(account_info.owner)?;

// Option 2: Using Anchor (preferred)
#[account(mut, owner = token_2022::id())]
pub destination_account: Account<'info, DestinationAccount>,

// Option 3: Manual ownership verification
if account_info.owner != &expected_program_id {
    return Err(TokenError::IncorrectProgramId.into());
}

// Now safe to unpack/mutate
let mut account_data = MyAccountType::unpack_mut(&mut account_info.data.borrow_mut())?;
account_data.balance = new_balance;
```

## Anchor Prevention

```rust
// Anchor automatically enforces ownership with Account<T>
#[derive(Accounts)]
pub struct ProcessAccount<'info> {
    #[account(
        mut,
        // Anchor ensures this account is owned by the current program
        // and has the correct discriminator for MyAccountType
    )]
    pub my_account: Account<'info, MyAccountType>,
}
```

## Testing Strategy

```rust
#[test]
fn test_wrong_program_owner() {
    // Create an account owned by system program instead of token program
    let wrong_account = create_account_with_owner(&system_program::id());
    
    // Should fail early with clear error, not late with cryptic message
    let result = process_instruction(&wrong_account);
    assert_eq!(result.unwrap_err(), TokenError::IncorrectProgramId);
}
```

## References

- Solana Foundation Token22 Code4rena Audit Report (Aug-Sep 2025)
- SPL Token Program source code examples
- Anchor Account<T> type implementation for automatic ownership checking