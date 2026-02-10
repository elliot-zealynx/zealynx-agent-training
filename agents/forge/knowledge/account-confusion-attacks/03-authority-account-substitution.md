# Authority Account Substitution

**Severity:** CRITICAL  
**CVSS Score:** 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)  
**Real Exploits:** Multiple DeFi protocols, missing signer checks

## Description

Authority account substitution occurs when a program accepts the wrong authority or signer account, allowing unauthorized users to perform privileged operations. This is one of the most common and dangerous vulnerability patterns in Solana programs, often resulting in complete protocol compromise.

## Vulnerable Code Pattern

```rust
// VULNERABLE: Missing signer validation
pub fn update_admin_settings(
    accounts: &[AccountInfo],
    new_fee_rate: u64,
) -> Result<(), ProgramError> {
    let account_iter = &mut accounts.iter();
    let admin_account = next_account_info(account_iter)?;
    let protocol_config = next_account_info(account_iter)?;
    
    // VULNERABLE: Admin key is checked but not required as signer
    let config_data = ProtocolConfig::unpack(&protocol_config.data.borrow())?;
    if *admin_account.key != config_data.admin_key {
        return Err(ProgramError::InvalidAdminKey);
    }
    
    // CRITICAL VULNERABILITY: Anyone can pass admin's pubkey without signature
    // Missing: if !admin_account.is_signer
    
    // Update protocol settings with unauthorized access
    config_data.fee_rate = new_fee_rate;
    ProtocolConfig::pack(&config_data, &mut protocol_config.data.borrow_mut())?;
    
    Ok(())
}
```

## Attack Vector

1. **Identify Authority Check:** Find functions that check admin/authority pubkeys
2. **Check for Missing is_signer:** Verify if signer validation is missing
3. **Craft Transaction:** Create transaction with admin pubkey but no signature
4. **Execute Privileged Operation:** Perform admin actions without authorization

## Real-World Example: Admin Bypass

```rust
// VULNERABLE: Protocol configuration update
pub fn set_protocol_fee(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_fee: u64,
) -> Result<(), ProgramError> {
    let account_iter = &mut accounts.iter();
    let payer = next_account_info(account_iter)?;          // Could be anyone
    let admin = next_account_info(account_iter)?;          // Admin pubkey
    let config = next_account_info(account_iter)?;         // Protocol config
    
    let config_data = ConfigAccount::unpack(&config.data.borrow())?;
    
    // VULNERABLE: Validates admin key but not signature
    if *admin.key != config_data.admin {
        return Err(ProgramError::Unauthorized);
    }
    
    // MISSING: if !admin.is_signer { return Err(...); }
    
    // Attacker can now modify protocol parameters
    config_data.fee_rate = new_fee;
    ConfigAccount::pack(&config_data, &mut config.data.borrow_mut())?;
    
    Ok(())
}
```

## Subtle Vulnerability: Wrong Signer Check

```rust
// SUBTLE VULNERABILITY: Checking wrong account for signature
pub fn withdraw_treasury(
    accounts: &[AccountInfo],
    amount: u64,
) -> Result<(), ProgramError> {
    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let treasury = next_account_info(account_iter)?;
    let recipient = next_account_info(account_iter)?;
    
    // VULNERABLE: Checking recipient signature instead of authority
    if !recipient.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Authority check without signer validation
    let treasury_data = Treasury::unpack(&treasury.data.borrow())?;
    if *authority.key != treasury_data.authority {
        return Err(ProgramError::Unauthorized);
    }
    
    // Proceed with withdrawal - authority never signed!
    transfer_lamports(treasury, recipient, amount)?;
    
    Ok(())
}
```

## Secure Implementation

```rust
// SECURE: Proper authority and signer validation
pub fn update_admin_settings_secure(
    accounts: &[AccountInfo],
    new_fee_rate: u64,
) -> Result<(), ProgramError> {
    let account_iter = &mut accounts.iter();
    let admin_account = next_account_info(account_iter)?;
    let protocol_config = next_account_info(account_iter)?;
    
    // SECURE: Validate admin is signer first
    if !admin_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // SECURE: Validate program ownership
    if protocol_config.owner != &crate::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    
    // SECURE: Validate admin key matches after signer check
    let mut config_data = ProtocolConfig::unpack(&protocol_config.data.borrow())?;
    if *admin_account.key != config_data.admin_key {
        return Err(ProgramError::Unauthorized);
    }
    
    // Now safe to perform admin operation
    config_data.fee_rate = new_fee_rate;
    ProtocolConfig::pack(&config_data, &mut protocol_config.data.borrow_mut())?;
    
    Ok(())
}

// SECURE: Using Anchor framework
#[derive(Accounts)]
pub struct UpdateAdminSettings<'info> {
    #[account(
        mut,
        has_one = admin_key @ ErrorCode::Unauthorized,
        constraint = admin.is_signer @ ErrorCode::MissingRequiredSignature
    )]
    pub protocol_config: Account<'info, ProtocolConfig>,
    
    #[account(signer)]  // Anchor ensures this account is signer
    pub admin: AccountInfo<'info>,
}

pub fn update_admin_settings_anchor(
    ctx: Context<UpdateAdminSettings>,
    new_fee_rate: u64,
) -> Result<()> {
    // Anchor already validated admin is signer and matches config
    ctx.accounts.protocol_config.fee_rate = new_fee_rate;
    Ok(())
}
```

## Detection Strategy

### Static Analysis
- Search for authority/admin key comparisons
- Look for missing `is_signer` checks after key validation
- Check for incorrect signer validation (wrong account)
- Identify privileged functions without signer requirements

### Code Patterns to Flag
```rust
// RED FLAGS:
if *account.key == expected_authority {  // Missing is_signer check
if authority_key == config.admin {       // No signer validation
if admin_account.key != &ADMIN_PUBKEY {  // Hardcoded key without signature
```

### Dynamic Testing
```rust
#[test]
fn test_missing_signer_attack() {
    let admin_pubkey = Pubkey::new_unique();
    let attacker_pubkey = Pubkey::new_unique();
    
    // Create transaction with admin pubkey but attacker signature
    let mut transaction = Transaction::new_with_payer(
        &[update_admin_instruction(admin_pubkey, 5000)],  // Admin pubkey
        Some(&attacker_pubkey),                           // Attacker pays + signs
    );
    
    // Sign with attacker key (not admin)
    transaction.sign(&[&attacker_keypair], recent_blockhash);
    
    // This should fail but might succeed if vulnerability exists
    let result = process_transaction(&mut banks_client, transaction);
    assert!(result.is_err());
}

#[test]
fn test_authority_substitution() {
    let real_admin = Keypair::new();
    let fake_admin = Keypair::new();
    
    // Attacker tries to use their key as admin
    let instruction = update_settings_instruction(
        fake_admin.pubkey(),  // Wrong admin
        1000,
    );
    
    let result = process_instruction_as_transaction(
        &mut banks_client,
        instruction,
        &fake_admin,  // Fake admin signs
    );
    
    assert_eq!(result.unwrap_err().unwrap(), ProgramError::Unauthorized);
}
```

## Fix Pattern

1. **Check signer first:** Always validate `is_signer` before authority checks
2. **Order matters:** `is_signer` validation should come before key comparison
3. **Use constraints:** Leverage Anchor's `#[account(signer)]` when possible
4. **Test negative cases:** Write tests for unauthorized access attempts
5. **Audit all privileged functions:** Ensure every admin function has proper validation

## Prevention Checklist

- [ ] All authority checks include `is_signer` validation
- [ ] Signer check comes before key comparison
- [ ] No hardcoded admin keys without signature validation
- [ ] Tests cover unauthorized access scenarios
- [ ] Anchor constraints used for signer validation where possible
- [ ] Code review focuses on privileged function entry points

## Common Mistakes

1. **Checking key without signature:** Validating pubkey but not `is_signer`
2. **Wrong order:** Checking authority before signer status
3. **Wrong account:** Checking signature on wrong account
4. **Anchor over-reliance:** Assuming Anchor prevents all signer issues
5. **Missing in upgrades:** Adding admin functions without proper validation

## Anchor Framework Considerations

```rust
// GOOD: Proper Anchor signer constraint
#[account(signer, constraint = admin.key() == config.admin_key)]
pub admin: AccountInfo<'info>,

// BAD: Missing signer constraint
#[account(constraint = admin.key() == config.admin_key)]
pub admin: AccountInfo<'info>,  // Not required to be signer!

// GOOD: Using Signer type
pub admin: Signer<'info>,  // Automatically enforces is_signer
```

## Related Patterns

- [Sysvar Account Spoofing](01-sysvar-account-spoofing.md)
- [PDA Account Spoofing](04-pda-account-spoofing.md)
- [Missing Signer Checks](../missing-signer-checks/) (previous category)

## References

- [Solana Program Security: Authority Checks](https://docs.solana.com/developing/programming-model/calling-between-programs#program-signed-accounts)
- [Anchor Account Constraints](https://book.anchor-lang.com/anchor_bts/account_constraints.html)
- [Common Solana Security Pitfalls](https://github.com/crytic/building-secure-contracts/blob/master/not-so-smart-contracts/solana/)