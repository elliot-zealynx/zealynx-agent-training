# Arbitrary CPI Target

## Severity: Critical

## Description

In Solana, all accounts (including the target program) must be passed as inputs to an instruction. If a program doesn't validate the target program ID before making a CPI, an attacker can substitute a malicious program.

Unlike Ethereum where contract addresses can be hardcoded, Solana requires explicit verification of program IDs passed at runtime.

## Root Cause

The Solana runtime allows any program to call any other program. Validation is the caller's responsibility.

## Vulnerable Code Pattern

```rust
// VULNERABLE: No validation of ledger_program
#[derive(Accounts)]
pub struct DistributeAndRecord<'info> {
    reward_account: AccountInfo<'info>,
    ledger_program: AccountInfo<'info>,  // ⚠️ Not validated
}

pub fn distribute_and_record_rewards(ctx: Context<DistributeAndRecord>, amount: u64) -> ProgramResult {
    let instruction = custom_ledger_program::instruction::record_transaction(
        &ctx.accounts.ledger_program.key(),
        &ctx.accounts.reward_account.key(),
        amount,
    )?;

    // Attacker can pass ANY program as ledger_program
    invoke(&instruction, &[
        ctx.accounts.reward_account.clone(),
        ctx.accounts.ledger_program.clone(),
    ])
}
```

## Attack Scenario

From Asymmetric Research:
> "An attacker could specify a program that they control as the token program. Their program would simply return successfully without any value transfer, while still incrementing their account balance in the bank program."

1. Attacker deploys malicious program that mimics expected interface
2. Attacker passes malicious program ID instead of legitimate program
3. Malicious program executes but doesn't perform expected action (e.g., token transfer)
4. Caller program continues as if legitimate action occurred

## Detection Strategy

1. Search for `invoke(` or `invoke_signed(` calls
2. Check if target program account has validation
3. Look for missing `Program<'info, T>` type in Anchor
4. Flag `AccountInfo<'info>` for program accounts

## Fix Pattern

**Option 1: Explicit program ID check**
```rust
pub fn distribute_and_record_rewards(ctx: Context<DistributeAndRecord>, amount: u64) -> ProgramResult {
    // Verify program identity BEFORE CPI
    if ctx.accounts.ledger_program.key() != &custom_ledger_program::ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    // ... rest of function
}
```

**Option 2: Anchor's Program type (preferred)**
```rust
#[derive(Accounts)]
pub struct DistributeAndRecord<'info> {
    reward_account: AccountInfo<'info>,
    // Anchor automatically validates program ID
    ledger_program: Program<'info, CustomLedgerProgram>,
}
```

## Real Examples

- **Token spoofing attacks**: Attacker passes fake token program that returns success without transferring tokens
- **Oracle manipulation**: Attacker substitutes fake oracle program returning manipulated prices
- **Bridge exploits**: Attacker substitutes verification program to bypass signature checks

## References

- Asymmetric Research: "The Arbitrary CPI Problem" (May 2025)
- Solana Cookbook: Arbitrary CPI section
- Helius Security Guide: Arbitrary CPI
