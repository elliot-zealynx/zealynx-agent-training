# Pattern 03: Missing PDA Derivation Verification

**Severity:** Critical
**Category:** PDA Seed Collisions
**CVSS-like:** 9.0-10.0
**Prevalence:** Common in native programs, rare in Anchor (if constraints used correctly)

## Description

A program accepts a PDA account from the transaction but **never re-derives it** to verify it was created with the expected seeds and program_id. The program trusts the account's address without verification, allowing an attacker to substitute any account (even one from a different program or with different seeds).

This is the most basic and most dangerous PDA vulnerability. It breaks the fundamental trust model of Solana's account architecture.

## Vulnerable Code Example

```rust
// VULNERABLE: PDA accepted without any derivation check
pub fn withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let vault = next_account_info(accounts_iter)?;  // ⚠️ No derivation check!
    let authority = next_account_info(accounts_iter)?;
    let destination = next_account_info(accounts_iter)?;
    
    // Deserializes data from whatever account was passed
    let vault_data = Vault::unpack(&vault.data.borrow())?;
    
    if vault_data.authority != *authority.key {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Transfers from potentially fake vault
    **vault.lamports.borrow_mut() -= amount;
    **destination.lamports.borrow_mut() += amount;
    
    Ok(())
}
```

## Attack Scenario

```
Expected: vault PDA derived from [b"vault", user_key] owned by program
Actual attack:

1. Attacker creates their own program that generates a "vault" account
2. Attacker's vault has: authority = attacker's key, balance = 0
3. Attacker passes this fake vault to the withdraw instruction
4. Program reads authority from fake vault → matches attacker's key
5. Program attempts transfer (or worse, mints tokens, updates state)
6. Real user's vault is never touched, but protocol state is corrupted
```

More dangerous variant:
```
1. Program stores vault PDA address in a config account
2. Attacker substitutes the config account itself (if also not verified)
3. Fake config points to fake vault
4. Entire chain of trust is broken
```

## Detection Strategy

1. **Search for `next_account_info` usage** without subsequent `find_program_address` / `create_program_address` verification
2. **Check all PDA accounts** — is the address verified against expected seeds?
3. **Verify owner check** — even if PDA is derived, is `account.owner == program_id` checked?
4. **Anchor-specific:** Ensure `seeds = [...]` constraint exists on every PDA account in every instruction
5. **Cross-reference:** If a PDA is used in multiple instructions, verify derivation in ALL of them, not just `init`

## Fix Pattern

### Native Solana
```rust
// SAFE: Re-derive and verify PDA address
pub fn withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let vault = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;
    let destination = next_account_info(accounts_iter)?;
    
    // 1. Verify PDA derivation
    let (expected_vault, bump) = Pubkey::find_program_address(
        &[b"vault", authority.key.as_ref()],
        program_id,
    );
    if *vault.key != expected_vault {
        return Err(ProgramError::InvalidSeeds);
    }
    
    // 2. Verify owner
    if vault.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    
    // 3. Verify signer
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Now safe to proceed
    let vault_data = Vault::unpack(&vault.data.borrow())?;
    // ...
}
```

### Anchor
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump,  // Verify stored canonical bump
    )]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    /// CHECK: destination for lamports
    #[account(mut)]
    pub destination: SystemAccount<'info>,
}
```

## Real Examples

- **Cashio ($52M, March 2022)** — Bypassed unverified accounts validation. The attacker created fake collateral accounts that the program accepted without verifying they were derived from the expected seeds. The program trusted the data in these fake accounts, allowing the attacker to mint unlimited CASH tokens.

- **Crema Finance ($8.8M, July 2022)** — Fake "Tick" account with manipulated price data was passed to the program. The program didn't verify the Tick account was derived from the expected pool seeds, so it accepted the attacker's fabricated price data for fee calculations.

- **Multiple audit findings** across Code4rena, Sherlock, and private audits consistently find this pattern in native Solana programs.

## Key Insight

> "A PDA is only as trustworthy as its verification. If you don't re-derive it, you're trusting a stranger's word that they are who they say they are."

**Defense in depth for PDAs:**
1. Verify derivation (seeds + bump)
2. Verify owner (program_id)
3. Verify discriminator (account type)
4. Verify data integrity (authority, relationships)
