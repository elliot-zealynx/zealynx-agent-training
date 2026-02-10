# Account Type/Discriminator Confusion

**Severity:** HIGH  
**CVSS Score:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
**Real Exploits:** Multiple DeFi protocols on Solana

## Description

Account type confusion occurs when a program accepts an account of one type where another is expected. In Solana, account types are typically distinguished by discriminators (8-byte prefixes that identify the data structure). Attackers can substitute accounts of different types to bypass validation or access unintended functionality.

## Vulnerable Code Pattern

```rust
// VULNERABLE: Manual deserialization without discriminator check
use bytemuck::{Pod, Zeroable};

#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable)]
pub struct UserAccount {
    pub discriminator: [u8; 8],
    pub owner: Pubkey,
    pub balance: u64,
    pub is_admin: bool,
}

#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable)]
pub struct AdminAccount {
    pub discriminator: [u8; 8],
    pub admin_key: Pubkey,
    pub permissions: u64,
    pub can_withdraw: bool,
}

pub fn withdraw_funds(accounts: &[AccountInfo]) -> Result<(), ProgramError> {
    let account_iter = &mut accounts.iter();
    let user_account_info = next_account_info(account_iter)?;
    
    // VULNERABLE: No discriminator validation
    let user_account = UserAccount::try_from_slice(&user_account_info.data.borrow())?;
    
    // Attacker could pass AdminAccount here - layout is similar enough
    if !user_account.is_admin {
        return Err(ProgramError::InsufficientPrivileges);
    }
    
    // Proceed with withdrawal...
    Ok(())
}
```

## Attack Vector

1. **Identify Similar Layouts:** Find account types with similar memory layouts
2. **Craft Substitute Account:** Create account of wrong type with favorable values
3. **Exploit Type Confusion:** Pass wrong account type to bypass checks
4. **Privilege Escalation:** Gain unintended permissions or access

## Memory Layout Attack Example

```rust
// Both accounts have similar layouts - confusion possible
// UserAccount:  [8 bytes discriminator][32 bytes owner][8 bytes balance][1 byte is_admin]
// AdminAccount: [8 bytes discriminator][32 bytes admin][8 bytes perms][1 byte can_withdraw]

// Attacker creates AdminAccount with can_withdraw=true
let fake_admin = AdminAccount {
    discriminator: ADMIN_DISCRIMINATOR,
    admin_key: attacker_pubkey,
    permissions: u64::MAX,
    can_withdraw: true,  // This maps to user_account.is_admin position
};

// When cast to UserAccount, can_withdraw becomes is_admin=true
```

## Real-World Example: Token Account Confusion

```rust
// VULNERABLE: Accepting any token account without mint validation
pub fn deposit_tokens(
    accounts: &[AccountInfo],
    amount: u64,
) -> Result<(), ProgramError> {
    let account_iter = &mut accounts.iter();
    let token_account_info = next_account_info(account_iter)?;
    
    // VULNERABLE: No validation of token account mint
    let token_account = TokenAccount::unpack(&token_account_info.data.borrow())?;
    
    // Attacker could pass account for worthless token here
    if token_account.amount < amount {
        return Err(ProgramError::InsufficientFunds);
    }
    
    // Protocol treats any token as valuable...
    Ok(())
}
```

## Secure Implementation

```rust
// SECURE: Proper discriminator and type validation
const USER_ACCOUNT_DISCRIMINATOR: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const ADMIN_ACCOUNT_DISCRIMINATOR: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];

pub fn withdraw_funds_secure(accounts: &[AccountInfo]) -> Result<(), ProgramError> {
    let account_iter = &mut accounts.iter();
    let user_account_info = next_account_info(account_iter)?;
    
    // SECURE: Validate account is owned by our program
    if user_account_info.owner != &crate::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    
    // SECURE: Explicit discriminator check
    let data = user_account_info.data.borrow();
    if data.len() < 8 {
        return Err(ProgramError::InvalidAccountData);
    }
    
    let discriminator: [u8; 8] = data[0..8].try_into().unwrap();
    if discriminator != USER_ACCOUNT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // SECURE: Safe deserialization after validation
    let user_account = UserAccount::try_from_slice(&data)?;
    
    if !user_account.is_admin {
        return Err(ProgramError::InsufficientPrivileges);
    }
    
    // Proceed with withdrawal...
    Ok(())
}

// SECURE: Anchor-style account validation
#[account]
pub struct SecureUserAccount {
    pub owner: Pubkey,
    pub balance: u64,
    pub is_admin: bool,
}

// Anchor automatically adds 8-byte discriminator and validates it
#[derive(Accounts)]
pub struct WithdrawFunds<'info> {
    #[account(
        mut,
        has_one = owner,
        constraint = user_account.is_admin @ ErrorCode::InsufficientPrivileges
    )]
    pub user_account: Account<'info, SecureUserAccount>,
    pub owner: Signer<'info>,
}
```

## Detection Strategy

### Static Analysis
- Look for manual deserialization without discriminator checks
- Search for `try_from_slice` calls without prior validation
- Check if account ownership is verified before deserialization
- Identify accounts with similar memory layouts

### Dynamic Testing
```rust
#[test]
fn test_account_type_confusion() {
    // Create AdminAccount with can_withdraw=true
    let mut admin_data = vec![0u8; std::mem::size_of::<AdminAccount>()];
    let admin_account = AdminAccount {
        discriminator: ADMIN_ACCOUNT_DISCRIMINATOR,
        admin_key: Pubkey::new_unique(),
        permissions: u64::MAX,
        can_withdraw: true,
    };
    
    // Serialize AdminAccount data
    admin_data.copy_from_slice(bytemuck::bytes_of(&admin_account));
    
    let fake_account = AccountInfo::new(
        &Pubkey::new_unique(),
        false,
        false,
        &mut 0,
        &mut admin_data,
        &crate::id(),
        false,
        0,
    );
    
    // Try to use AdminAccount as UserAccount - should fail
    let result = withdraw_funds(&[fake_account]);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), ProgramError::InvalidAccountData);
}
```

## Anchor Framework Protection

Anchor automatically handles discriminator validation:

```rust
// Anchor adds discriminator validation automatically
#[account]
pub struct MyAccount {
    pub data: u64,
}

// This will fail if wrong account type is passed
let my_account: Account<MyAccount> = Account::try_from(&account_info)?;
```

## Fix Pattern

1. **Always validate discriminators:** Check 8-byte prefix matches expected type
2. **Verify program ownership:** Ensure account is owned by expected program  
3. **Use strong typing:** Leverage Anchor's automatic validation when possible
4. **Validate account size:** Ensure account data is expected size for type
5. **Add constraint checks:** Implement business logic validation after type check

## Prevention Checklist

- [ ] All account deserialization includes discriminator validation
- [ ] Account ownership verified before type casting
- [ ] Account data size matches expected struct size
- [ ] Similar account types have distinct discriminators
- [ ] Tests include wrong account type attack scenarios
- [ ] Business logic constraints validated after type check

## Common Mistakes

1. **Trusting Anchor validation alone:** Still need business logic checks
2. **Similar discriminators:** Using sequential or predictable discriminators
3. **Bypassing with remaining_accounts:** Anchor doesn't validate these automatically
4. **Reusing discriminators:** Same discriminator for different account versions

## Related Patterns

- [Authority Account Substitution](03-authority-account-substitution.md)  
- [Cross-Program Account Injection](06-cross-program-account-injection.md)
- [Token Account Mint Confusion](05-token-account-mint-confusion.md)

## References

- [Anchor Account Validation](https://book.anchor-lang.com/anchor_bts/account_validation.html)
- [Solana Account Data Layout Best Practices](https://docs.solana.com/developing/programming-model/accounts#account-data-layout)
- [Bytemuck Safety Documentation](https://docs.rs/bytemuck/latest/bytemuck/)