# Sysvar Account Spoofing

**Severity:** CRITICAL  
**CVSS Score:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**Real Exploit:** Wormhole Bridge ($325M loss, Feb 2022)

## Description

Sysvar account spoofing occurs when a program accepts a fake system variable account instead of the legitimate sysvar. System variables (sysvars) like `Instructions`, `Clock`, `Rent`, etc. are special accounts that provide blockchain state information. Attackers can create fake accounts that mimic sysvars to bypass critical security checks.

## Vulnerable Code Pattern

```rust
// VULNERABLE: Uses deprecated load_instruction_at without validation
use solana_program::{
    instruction::{get_stack_height, load_instruction_at},
    pubkey::Pubkey,
    account_info::{AccountInfo, next_account_info},
    program_error::ProgramError,
};

pub fn verify_signatures(
    accounts: &[AccountInfo],
    vaa: &[u8],
) -> Result<(), ProgramError> {
    let account_iter = &mut accounts.iter();
    let instruction_sysvar = next_account_info(account_iter)?;
    
    // VULNERABLE: No validation that this is the real Instructions sysvar
    let current_ix = load_instruction_at(
        get_stack_height(),
        instruction_sysvar
    )?;
    
    // Attacker can bypass this check with fake sysvar
    if current_ix.program_id != secp256k1_program::id() {
        return Err(ProgramError::InvalidInstruction);
    }
    
    // Signature validation logic continues...
    Ok(())
}
```

## Attack Vector

1. **Create Fake Account:** Attacker creates an account that mimics the Instructions sysvar
2. **Populate with Fake Data:** Fill the fake account with crafted instruction data
3. **Pass to Program:** Submit the fake account instead of the real sysvar
4. **Bypass Validation:** Program accepts fake data and skips security checks

## Real-World Example: Wormhole Bridge Exploit

```rust
// Wormhole's vulnerable signature verification
let instruction_acc = &accounts[accounts.len() - 1];

// VULNERABLE: load_instruction_at doesn't verify account is real sysvar
let current_instruction = load_instruction_at(
    get_stack_height(),
    instruction_acc
)?;

// Attacker bypassed this check with fake Instructions account
if current_instruction.program_id != secp256k1_program::id() {
    return Err(ProgramError::InvalidInstructionData);
}
```

**Exploit Transaction:** [2zCz2GgSoSS68eNJENWrYB48dMM1zmH8SZkgYneVDv2G4gRsVfwu5rNXtK5BKF8K4mYSxnAXkNMZTXNzX5iQsdy2](https://solscan.io/tx/2zCz2GgSoSS68eNJENWrYB48dMM1zmH8SZkgYneVDv2G4gRsVfwu5rNXtK5BKF8K4mYSxnAXkNMZTXNzX5iQsdy2)

## Secure Implementation

```rust
// SECURE: Proper sysvar validation
use solana_program::{
    instruction::{get_stack_height, load_current_index_checked},
    sysvar::{instructions::Instructions, Sysvar},
    pubkey::Pubkey,
    account_info::{AccountInfo, next_account_info},
    program_error::ProgramError,
};

pub fn verify_signatures_secure(
    accounts: &[AccountInfo],
    vaa: &[u8],
) -> Result<(), ProgramError> {
    let account_iter = &mut accounts.iter();
    let instruction_sysvar = next_account_info(account_iter)?;
    
    // SECURE: Explicitly validate sysvar account
    if *instruction_sysvar.key != Instructions::id() {
        return Err(ProgramError::IncorrectSysvarAccount);
    }
    
    // SECURE: Use checked variant that validates sysvar
    let current_ix = load_current_index_checked(instruction_sysvar)?;
    
    // Additional validation: ensure it's the expected instruction
    if current_ix.program_id != secp256k1_program::id() {
        return Err(ProgramError::InvalidInstruction);
    }
    
    // SECURE: Actually validate guardian signatures (missing in original)
    validate_guardian_signatures(&current_ix, vaa)?;
    
    Ok(())
}

fn validate_guardian_signatures(ix: &Instruction, vaa: &[u8]) -> Result<(), ProgramError> {
    // Parse VAA to extract signatures and guardian set
    let (signatures, guardian_set_index) = parse_vaa(vaa)?;
    
    // Verify we have enough signatures (2/3+ of guardian set)
    if signatures.len() < (guardian_set.len() * 2 / 3) + 1 {
        return Err(ProgramError::InsufficientSignatures);
    }
    
    // Validate each signature against guardian set
    for (i, signature) in signatures.iter().enumerate() {
        verify_signature(&guardian_set[i].pubkey, &vaa[..], signature)?;
    }
    
    Ok(())
}
```

## Detection Strategy

### Static Analysis
- Search for `load_instruction_at` usage (deprecated, unsafe function)
- Look for sysvar usage without explicit address validation
- Check if programs validate sysvar ownership/address

### Dynamic Testing
```rust
#[test]
fn test_sysvar_spoofing_attack() {
    // Create fake Instructions sysvar account
    let mut fake_sysvar = Account::new(1000000, 1024, &system_program::id());
    
    // Populate with malicious instruction data
    let fake_instruction_data = create_fake_secp_instruction();
    fake_sysvar.data.copy_from_slice(&fake_instruction_data);
    
    // Test program with fake sysvar - should fail
    let result = process_instruction(
        &program_id,
        &[fake_sysvar.clone()],
        &instruction_data,
    );
    
    // Program should reject fake sysvar
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), ProgramError::IncorrectSysvarAccount);
}
```

## Fix Pattern

1. **Always validate sysvar addresses:** Check `account.key == Sysvar::id()`
2. **Use checked variants:** Prefer `load_current_index_checked` over deprecated functions
3. **Verify account ownership:** Ensure sysvar is owned by system program
4. **Don't trust sysvar data blindly:** Validate the contents make sense

## Prevention Checklist

- [ ] All sysvar accounts have explicit address validation
- [ ] No usage of deprecated `load_instruction_at` function
- [ ] Sysvar data is validated for reasonableness (e.g., Clock timestamp)
- [ ] Error handling for sysvar validation failures
- [ ] Tests include fake sysvar attack scenarios

## Related Patterns

- [Account Type/Discriminator Confusion](02-account-type-discriminator-confusion.md)
- [Cross-Program Account Injection](06-cross-program-account-injection.md)

## References

- [Wormhole Bridge Exploit Analysis](https://immunebytes.com/blog/wormhole-bridge-hack-feb-2-2022-detailed-hack-analysis)
- [Solana Documentation: Sysvars](https://docs.solana.com/developing/runtime-facilities/sysvars)
- [CertiK Wormhole Analysis](https://www.certik.com/resources/blog/1kDYgyBcisoD2EqiBpHE5l-wormhole-bridge-exploit-incident-analysis)