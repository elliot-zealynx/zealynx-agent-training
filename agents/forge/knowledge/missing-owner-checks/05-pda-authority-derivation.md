# PDA Authority Derivation Not Verified

**Severity:** High
**Impact:** PDA authority bypass, unauthorized access to program-controlled accounts
**CVSS:** 7.0-8.5 depending on PDA privileges

## Description

Programs derive Program Derived Addresses (PDAs) for authority validation but fail to verify that the provided account matches the derived address. Attackers can substitute their own accounts that appear valid but aren't actually derived from the expected seeds and program.

## Root Cause

The program derives a PDA address using seeds but doesn't compare the derived address with the provided account address. This allows attackers to provide accounts they control that happen to have compatible data but aren't actually the canonical PDA.

## Vulnerable Code Pattern

```rust
// VULNERABLE: Derives PDA but doesn't verify address matches
#[derive(Accounts)]
pub struct UsePDA<'info> {
    #[account(mut)]
    pub pda_account: AccountInfo<'info>, // ⚠️ No seeds constraint!
    
    #[account(signer)]
    pub user: Signer<'info>,
}

pub fn update_pda(ctx: Context<UsePDA>, new_value: u64) -> Result<()> {
    let user_key = ctx.accounts.user.key();
    
    // Derives the expected PDA address
    let (expected_pda, _bump) = Pubkey::find_program_address(
        &[b"pda", user_key.as_ref()],
        ctx.program_id,
    );
    
    // ⚠️ But never checks if pda_account.key() == expected_pda!
    
    let mut data = PDAAccount::unpack_mut(&mut ctx.accounts.pda_account.data.borrow_mut())?;
    data.value = new_value;
    
    Ok(())
}
```

## Attack Scenario

1. **PDA Understanding:** Attacker analyzes how program derives PDAs
2. **Fake Account Creation:** Creates account with compatible data structure but different address
3. **Substitution Attack:** Provides fake account instead of real PDA
4. **Bypass Success:** Program processes fake account without verifying derivation

## Real Examples

### Solana Foundation Token22 Audit (Code4rena 2025)

**Finding:** Re-derive and check registry PDA before update (robustness, not security)

**Location:** `confidential-transfer/elgamal-registry/src/processor.rs:#L76-L100`

**Issue:** `process_update_registry_account` updated the registry without re-deriving the PDA for wallet + program_id and comparing to `elgamal_registry_account_info.key`.

```rust
// VULNERABLE: No PDA re-derivation check
let elgamal_registry_account_info = next_account_info(account_info_iter)?;
// ... no PDA check here ...
let proof_context = verify_and_extract_context(/*...*/)?;
// ... mutate registry fields without PDA validation ...
```

**Impact:** Passing a program-owned but non-canonical account yielded fail-late behavior; PDA mismatch wasn't surfaced early.

### Generic PDA Authority Bypass Pattern

Common in programs that use PDAs for user-specific data or permissions but don't enforce the derivation relationship.

## Detection Strategy

1. **PDA Derivation Analysis:** Find calls to `find_program_address()` or `create_program_address()`
2. **Address Comparison Audit:** Check if derived addresses are compared with provided accounts
3. **Seeds Constraint Missing:** Look for PDA accounts without `seeds` and `bump` constraints
4. **Manual Derivation:** Identify manual PDA derivation without validation

```rust
// Detection patterns:
let (pda, bump) = Pubkey::find_program_address(/*...*/); // PDA derived
// ... but no comparison with provided account

// vs secure pattern:
#[account(seeds = [...], bump)] // Automatic validation
```

## Fix Pattern

### Using Anchor seeds Constraint (Preferred)

```rust
// SECURE: Automatic PDA verification with seeds constraint  
#[derive(Accounts)]
pub struct UsePDA<'info> {
    #[account(
        mut,
        seeds = [b"pda", user.key().as_ref()],
        bump, // ✅ Validates address matches derivation
    )]
    pub pda_account: Account<'info, PDAAccount>,
    
    #[account(signer)]
    pub user: Signer<'info>,
}

// No manual derivation needed - Anchor handles it
pub fn update_pda(ctx: Context<UsePDA>, new_value: u64) -> Result<()> {
    ctx.accounts.pda_account.value = new_value;
    Ok(())
}
```

### Manual PDA Verification

```rust
pub fn update_pda_manual(ctx: Context<UsePDAManual>, new_value: u64) -> Result<()> {
    let user_key = ctx.accounts.user.key();
    
    // Derive expected PDA
    let (expected_pda, expected_bump) = Pubkey::find_program_address(
        &[b"pda", user_key.as_ref()],
        ctx.program_id,
    );
    
    // ✅ Verify provided account matches derived address
    if ctx.accounts.pda_account.key() != expected_pda {
        return Err(ErrorCode::InvalidPDA.into());
    }
    
    let mut data = PDAAccount::unpack_mut(&mut ctx.accounts.pda_account.data.borrow_mut())?;
    data.value = new_value;
    
    Ok(())
}
```

### PDA Creation with Verification

```rust
#[derive(Accounts)]
pub struct CreatePDA<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + PDAAccount::INIT_SPACE,
        seeds = [b"pda", user.key().as_ref()],
        bump, // ✅ Ensures canonical bump is used
    )]
    pub pda_account: Account<'info, PDAAccount>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    
    #[account(signer)]
    pub user: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}
```

## Advanced Patterns

### Multiple Seed PDA

```rust
#[derive(Accounts)]
pub struct ComplexPDA<'info> {
    #[account(
        mut,
        seeds = [
            b"vault",
            user.key().as_ref(),
            &vault_id.to_le_bytes(),
        ],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(signer)]
    pub user: Signer<'info>,
}
```

### Cross-Program PDA Validation

```rust
#[derive(Accounts)]
pub struct CrossProgramPDA<'info> {
    #[account(
        seeds = [b"registry", user.key().as_ref()],
        bump,
        seeds::program = external_program.key(), // ✅ PDA from different program
    )]
    pub external_pda: AccountInfo<'info>,
    
    #[account(signer)]
    pub user: Signer<'info>,
    
    /// CHECK: Program ID validated in CPI
    pub external_program: AccountInfo<'info>,
}
```

### Dynamic Seed Validation

```rust
#[derive(Accounts)]
#[instruction(seed_data: Vec<u8>)]
pub struct DynamicPDA<'info> {
    #[account(
        mut,
        seeds = [b"dynamic", seed_data.as_ref()],
        bump,
    )]
    pub dynamic_pda: Account<'info, DynamicAccount>,
}
```

## Testing Strategy

```rust
#[test]
fn test_wrong_pda_rejected() {
    let user = Keypair::new();
    let wrong_pda = Keypair::new(); // Not a PDA
    
    let result = update_pda(&wrong_pda.pubkey(), &user, 100);
    
    // Should fail with invalid seeds/bump error
    assert_eq!(result.unwrap_err(), ErrorCode::ConstraintSeeds);
}

#[test]
fn test_pda_from_different_seeds() {
    let user1 = Keypair::new();
    let user2 = Keypair::new();
    
    // Create PDA for user1 but try to use with user2
    let (pda_user1, _) = Pubkey::find_program_address(
        &[b"pda", user1.pubkey().as_ref()],
        &program_id,
    );
    
    let result = update_pda(&pda_user1, &user2, 100);
    
    // Should fail because PDA wasn't derived from user2
    assert_eq!(result.unwrap_err(), ErrorCode::ConstraintSeeds);
}

#[test]
fn test_correct_pda_succeeds() {
    let user = Keypair::new();
    
    // Properly derived PDA
    let (pda, _) = Pubkey::find_program_address(
        &[b"pda", user.pubkey().as_ref()],
        &program_id,
    );
    
    let result = update_pda(&pda, &user, 100);
    assert!(result.is_ok());
}
```

## Common Mistakes

1. **Manual Derivation Without Check:** Deriving PDA address but not validating provided account matches
2. **Bump Seed Issues:** Using non-canonical bump seeds that allow multiple valid addresses
3. **Seed Order Errors:** Incorrect seed ordering in derivation vs validation
4. **Missing seeds Constraint:** Not using Anchor's automatic PDA validation
5. **Cross-Program Confusion:** Wrong program ID in PDA derivation

## Best Practices

1. **Use Anchor Constraints:** Prefer `seeds` and `bump` constraints over manual validation
2. **Canonical Bump:** Always use canonical bump (255, 254, etc.) from `find_program_address()`
3. **Consistent Seed Order:** Maintain consistent seed ordering across all operations
4. **Document Seed Schema:** Clearly document PDA seed construction for each account type
5. **Test Edge Cases:** Test with wrong seeds, wrong program IDs, and non-canonical bumps

## Security Considerations

- **Bump Grinding:** Attackers might try to find alternative bump values for same seeds
- **Seed Collision:** Different logical entities might derive to same PDA if seeds overlap
- **Program Upgrade:** PDA derivation must remain consistent across program upgrades
- **Cross-Chain:** PDA addresses change if program is deployed to different program ID

## References

- Solana Foundation Token22 Code4rena Audit Report (Aug-Sep 2025) 
- Anchor Framework seeds constraint documentation
- Solana PDA and Program Derived Address security guide
- Multiple audit findings related to PDA validation bypass