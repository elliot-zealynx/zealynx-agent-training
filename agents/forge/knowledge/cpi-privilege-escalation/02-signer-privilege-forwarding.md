# Signer Privilege Forwarding

## Severity: Critical

## Description

When a program makes a CPI and includes a signed account, **that signer status is retained and forwarded to the callee program**. This is by design but creates critical vulnerabilities when combined with arbitrary CPI.

From Asymmetric Research:
> "Once a user account or a PDA signs an instruction, that signer privilege is retained for the duration of the transaction and can be reused in subsequent CPIs."

## Root Cause

Solana's runtime preserves signer privileges across the entire transaction call chain. A signed account at depth 0 remains signed at depths 1, 2, 3, 4 (max CPI depth).

## Vulnerable Code Pattern

```rust
// VULNERABLE: Arbitrary CPI with signer forwarding
pub fn perform_action(ctx: Context<PerformAction>) -> Result<()> {
    // User has signed this transaction
    let user = &ctx.accounts.user;  // is_signer = true
    
    // External program passed by user (not validated)
    let external_program = &ctx.accounts.external_program;
    
    // ⚠️ User's signer privilege is forwarded to untrusted program
    invoke(
        &some_instruction,
        &[user.to_account_info(), external_program.clone()],
    )?;
    
    Ok(())
}
```

## Attack Scenario

**Combined with Arbitrary CPI:**

1. Attacker calls legitimate program with their wallet as signer
2. Legitimate program makes CPI to "external_program" (attacker-controlled)
3. Attacker's malicious program receives user's signer privileges
4. Malicious program uses signer privileges to:
   - Transfer all SOL from user's account
   - Sign for other programs (perpetuals, lending)
   - Perform unauthorized actions

**The Wormhole Pattern:**
```
User signs TX → Legitimate Bridge → Attacker Program
                                   ↓
                    Uses signer privilege to drain funds
```

## What Attackers Can Do With Forwarded Signer

1. **Transfer SOL**: `system_instruction::transfer()` from signer's account
2. **Close accounts**: Close accounts owned by signer
3. **Sign for other protocols**: Use signer in nested CPIs to DeFi protocols
4. **Reassign account ownership**: Transfer control of signer's accounts

## Detection Strategy

1. Identify all CPIs with user-controlled program targets
2. Check if signer accounts are included in CPI account lists
3. Flag any arbitrary callback patterns where signers are passed through
4. Look for `is_signer` being passed without stripping

## Fix Pattern

**Option 1: Strip signer before arbitrary CPI**
```rust
// Check that no accounts have signer privilege before arbitrary call
for account in account_params {
    require!(!account.is_signer, Error::FoundSigner);
}
```

**Option 2: Use account isolation (PDA per user)**
```rust
// PDA derived from user ensures isolation
let signer_seeds = &[
    b"vault",
    user.key().as_ref(),  // Unique per user
    &[bump]
];

// Even if CPI abuses signer, damage limited to this user
invoke_signed(&instruction, accounts, signer_seeds)?;
```

**Option 3: Validate CPI targets strictly**
```rust
// Only allow calls to known, audited programs
const ALLOWED_PROGRAMS: &[Pubkey] = &[
    TOKEN_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID,
    SYSTEM_PROGRAM_ID,
];

require!(
    ALLOWED_PROGRAMS.contains(ctx.accounts.target_program.key()),
    Error::UnauthorizedProgram
);
```

## Real Examples

- **Wormhole ($325M)**: Signer verification bypass via CPI
- **Bridge protocols**: Cross-chain message handlers forwarding signers
- **Callback patterns**: Protocols allowing arbitrary callbacks with signer

## References

- Asymmetric Research: "Signer Privileges Can Be Abused"
- Helius: "Cross-Program Invocation Issues"
- Solana Security Best Practices
