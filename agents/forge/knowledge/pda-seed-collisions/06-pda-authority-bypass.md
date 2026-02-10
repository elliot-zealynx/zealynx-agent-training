# Pattern 06: PDA Authority Bypass

**Severity:** High-Critical
**Category:** PDA Seed Collisions / Authority
**CVSS-like:** 8.0-9.5
**Prevalence:** Medium — emerges in complex programs with PDA signing

## Description

PDAs can act as signers in CPIs — the runtime verifies the PDA was correctly derived from the calling program's ID. An attacker exploits this by:

1. **Finding alternate seeds** that produce a valid PDA the program will sign for
2. **Using a PDA signer for unintended operations** (the program signs for a PDA used in the wrong context)
3. **Exploiting reusable PDA signers** across different instructions

The core issue: the program signs for a PDA, but the signing context doesn't match the intended use case.

## Vulnerable Code Example

```rust
// VULNERABLE: PDA signer used across multiple instructions without context separation
pub fn transfer_from_pool(ctx: Context<PoolTransfer>, amount: u64) -> Result<()> {
    let pool_seeds = &[
        b"pool",
        ctx.accounts.pool.token_mint.as_ref(),
        &[ctx.accounts.pool.bump],
    ];
    let signer_seeds = &[&pool_seeds[..]];
    
    // PDA signs for token transfer
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.pool_vault.to_account_info(),
                to: ctx.accounts.destination.to_account_info(),
                authority: ctx.accounts.pool.to_account_info(), // PDA signer
            },
            signer_seeds,
        ),
        amount,  // ⚠️ Amount not validated against pool logic
    )?;
    
    Ok(())
}

// This instruction is meant for admin withdrawals, but the pool PDA
// signs for ANY transfer. If an attacker can call this instruction
// directly (missing access control), they drain the pool.
```

## Attack Scenario

### Scenario 1: Cross-Instruction PDA Reuse
```
Pool PDA signs for:
  - Instruction A: swap (user-facing, amount bounded by pool math)
  - Instruction B: admin_withdraw (should be admin-only)
  - Instruction C: rebalance (internal use only)

If Instruction B lacks admin check:
  Attacker calls admin_withdraw → Pool PDA signs → funds drained

If Instruction C is externally callable:
  Attacker calls rebalance with crafted params → Pool PDA signs → funds redirected
```

### Scenario 2: PDA Seed Manipulation
```
Pool PDA seeds: [b"pool", mint_key]

1. Attacker deploys their own token mint (mint_key_attacker)
2. Creates a pool for the attacker's mint
3. This pool PDA can sign for its own vault
4. If program logic conflates pools or doesn't verify mint correctness,
   attacker's pool PDA might be used to authorize operations on other pools
```

### Scenario 3: Wormhole-style Guardian Set Bypass
```
The Wormhole exploit (Feb 2022, $325M) involved:
1. Program had a deprecated function `verify_signatures`
2. This function accepted a guardian set PDA
3. Attacker used the deprecated function to create a fake guardian set
4. The fake guardian set PDA was valid (correctly derived by the program)
5. Program signed VAA verifications using the fake guardian set
6. Attacker minted 120,000 wETH on Solana
```

## Detection Strategy

1. **Map all PDA signers:** Which PDAs sign in CPIs? List every instruction that uses `CpiContext::new_with_signer`
2. **Verify access control on EVERY instruction that triggers PDA signing**
3. **Check for deprecated/unused instructions** — they may still have PDA signing capability
4. **Verify amount/parameter bounds:** PDA signing transfers should have logic-enforced limits
5. **Cross-reference PDA seeds with signing context:** Is the PDA signing for the correct operation?
6. **Look for instruction_data parsing** in native programs — are all instruction variants properly access-controlled?

## Fix Pattern

### Approach 1: Strict access control per instruction
```rust
#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    #[account(
        mut,
        seeds = [b"pool", pool.token_mint.as_ref()],
        bump = pool.bump,
        has_one = admin,  // ✅ Only stored admin can call
    )]
    pub pool: Account<'info, Pool>,
    pub admin: Signer<'info>,  // ✅ Must sign
    // ...
}
```

### Approach 2: Context-specific PDA signers
```rust
// Instead of one pool PDA signing everything, derive context-specific PDAs

// For swaps:
let swap_authority_seeds = &[b"swap_auth", pool.key().as_ref(), &[swap_bump]];

// For admin operations:
let admin_authority_seeds = &[b"admin_auth", pool.key().as_ref(), &[admin_bump]];

// Different PDAs for different operations → can't cross-use
```

### Approach 3: Remove deprecated instructions
```rust
// If an instruction is no longer needed, REMOVE IT from the program.
// Deprecated but accessible instructions are a major attack surface.
// Don't just add a comment "// deprecated" — delete the code.
```

## Real Examples

- **Wormhole ($325M, February 2022)** — Most devastating Solana exploit. The `complete_wrapped` instruction relied on a guardian set PDA. The attacker used a deprecated `verify_signatures` function to create a fake guardian set with a single attacker-controlled guardian. This fake guardian set PDA was validly derived by the Wormhole program, so the runtime accepted the PDA as a signer. The attacker then used this to forge VAA approvals and mint 120,000 wETH ($325M).

- **Multiple audit findings** where PDA-signed operations lack proper access control, allowing unauthorized users to trigger privileged transfers.

## Key Insight

> "A PDA signer is a loaded gun. The runtime only checks that the program pulled the trigger — it doesn't check whether the program should have. Every instruction that uses PDA signing needs its own safety catch."

**Critical checklist for PDA signers:**
1. ✅ Is this instruction access-controlled?
2. ✅ Are the parameters (amount, destination) bounded by program logic?
3. ✅ Can this instruction be called externally?
4. ✅ Is this instruction still needed? (Remove deprecated code!)
5. ✅ Is the PDA signer scoped to this specific operation?
