# Pattern: Arbitrary CPI Target

**Category:** Missing Signer Checks / Cross-Program Security  
**Severity:** Critical  
**Chains:** Solana (Anchor & Native)  
**Last Updated:** 2026-02-03  

## Root Cause

Cross-Program Invocations (CPI) allow programs to call other programs. If the target program ID comes from **user input** without validation, an attacker substitutes their malicious program. The victim program invokes the attacker's code with its own PDA signatures, effectively handing over its authority.

## Real-World Context

Found regularly in security audits. Particularly dangerous when programs invoke:
- Token transfers (attacker intercepts PDA-signed transfers)
- Oracle reads (attacker returns fake price data)
- Any privileged operation via CPI

The danger is acute because `invoke_signed()` passes the caller's PDA authority to the callee. If the callee is malicious, it receives valid PDA signatures it can abuse.

## Vulnerable Code Pattern

### Native Solana
```rust
// ❌ VULNERABLE: Token program comes from user input
pub fn process_transfer(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let source = next_account_info(account_iter)?;
    let destination = next_account_info(account_iter)?;
    let authority = next_account_info(account_iter)?;
    let token_program = next_account_info(account_iter)?;  // USER-CONTROLLED
    
    let seeds = &[b"vault", &[bump]];
    
    // CPI to whatever program the user passed!
    invoke_signed(
        &spl_token::instruction::transfer(
            token_program.key,  // Could be attacker's program
            source.key,
            destination.key,
            authority.key,
            &[],
            amount,
        )?,
        &[source.clone(), destination.clone(), authority.clone(), token_program.clone()],
        &[seeds],  // Passes PDA signature to potentially malicious program!
    )
}
```

### Anchor (Insecure)
```rust
// ❌ VULNERABLE: Program not typed, accepts any program ID
#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub source: AccountInfo<'info>,
    #[account(mut)]
    pub destination: AccountInfo<'info>,
    pub authority: AccountInfo<'info>,
    /// CHECK: This should be Program<'info, Token>
    pub token_program: AccountInfo<'info>,  // Any program accepted!
}
```

## Attack Pattern

1. Program intends to CPI to Token Program for a transfer
2. Program accepts `token_program` account from user input
3. Attacker passes their **malicious program** instead of Token Program
4. CPI executes to malicious program WITH the victim's PDA signature
5. Malicious program now has the victim's authority, drains funds

### Why This Is Devastating
`invoke_signed()` passes signer seeds. The malicious program receives a valid PDA signature from the victim program. It can use this to:
- Call the REAL Token Program with the victim's authority
- Drain all PDA-controlled token accounts
- Modify any PDA-controlled state

## Detection Strategy

1. **Search for unchecked program IDs in CPI:**
   ```bash
   grep -rn "invoke\|invoke_signed" src/ 
   # Check if program_id is hardcoded or validated
   ```

2. **Anchor red flags:**
   - `AccountInfo<'info>` used for program accounts
   - Missing `Program<'info, T>` type annotations
   - `/// CHECK:` comments on program accounts

3. **Native red flags:**
   - Program ID from `next_account_info()` without address comparison
   - `invoke_signed` where target program is user-supplied

4. **Key question:** "Is the CPI target hardcoded or validated, or does it come from user input?"

## Secure Fix

### Anchor
```rust
// ✅ SECURE: Program<'info, Token> locks CPI target at compile time
#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub source: Account<'info, TokenAccount>,
    #[account(mut)]
    pub destination: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,  // MUST be Token Program
}
```

### Native Solana
```rust
// ✅ SECURE: Hardcode and verify program IDs
const TOKEN_PROGRAM_ID: Pubkey = spl_token::ID;

pub fn process_transfer(accounts: &[AccountInfo]) -> ProgramResult {
    let token_program = next_account_info(account_iter)?;
    
    // Verify before CPI
    if token_program.key != &TOKEN_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    
    invoke_signed(/* ... now safe ... */)?;
    Ok(())
}
```

## Edge Cases

### Multiple Valid Programs
Some operations might legitimately target Token Program OR Token-2022:
```rust
// ✅ Validate against known set
if token_program.key != &spl_token::ID 
    && token_program.key != &spl_token_2022::ID {
    return Err(ProgramError::IncorrectProgramId);
}
```

### Configurable CPI Targets
If a program MUST support configurable CPI targets (e.g., oracle addresses), store them in admin-controlled state and validate:
```rust
// ✅ Read from trusted state, not user input
let config = Config::unpack(&config_account.data.borrow())?;
if oracle_program.key != &config.oracle_program_id {
    return Err(ProgramError::IncorrectProgramId);
}
```

## Audit Checklist

- [ ] Every CPI target program ID is hardcoded or validated against known values
- [ ] No `invoke` / `invoke_signed` calls use user-supplied program IDs
- [ ] Anchor uses `Program<'info, T>` for all CPI targets
- [ ] `invoke_signed` calls are especially scrutinized (PDA authority leak)
- [ ] Configurable program IDs stored in admin-controlled state, not instruction args
