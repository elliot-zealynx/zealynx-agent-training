# Account Confusion Attacks

**Category:** Account Validation Vulnerabilities  
**Severity:** HIGH to CRITICAL  
**Prevalence:** Very High - Account validation is fundamental to Solana security

## Overview

Account confusion attacks occur when a Solana program accepts the wrong account type or fails to properly validate account relationships. Unlike traditional smart contracts, Solana programs operate on an account-based model where each account must be explicitly validated for:

- Correct program ownership
- Expected account type/discriminator  
- Proper relationships between accounts
- Authority and permission checks
- PDA derivation validation

**Key Insight:** Rust's type system cannot verify that you're passing the correct accounts or that account relationships are valid. These checks must be implemented manually in program logic.

## Common Attack Vectors

1. **Sysvar Spoofing** - Passing fake system accounts (Clock, Instructions, etc.)
2. **Account Type Substitution** - Using wrong account discriminator/type
3. **Authority Confusion** - Wrong owner/authority accounts
4. **PDA Spoofing** - Fake program-derived addresses
5. **Token Account Confusion** - Wrong mint or associated token accounts
6. **Cross-Program Account Poisoning** - Malicious accounts from other programs

## Real-World Impact

- **Wormhole Bridge ($325M)** - Sysvar spoofing via fake Instructions account
- **Cashio ($52M)** - Fake bank account with wrong token mint
- **Solend ($1.26M)** - Oracle manipulation via account substitution
- **Multiple DeFi protocols** - Token account confusion attacks

## Patterns in This Category

1. [Sysvar Account Spoofing](01-sysvar-account-spoofing.md)
2. [Account Type/Discriminator Confusion](02-account-type-discriminator-confusion.md) 
3. [Authority Account Substitution](03-authority-account-substitution.md)
4. [PDA Account Spoofing](04-pda-account-spoofing.md)
5. [Token Account Mint Confusion](05-token-account-mint-confusion.md)
6. [Cross-Program Account Injection](06-cross-program-account-injection.md)
7. [Associated Token Account Validation](07-associated-token-account-validation.md)

## Prevention Strategy

- **Explicit Account Validation:** Never assume accounts are correct
- **Program ID Checks:** Verify account ownership before use
- **Discriminator Validation:** Check account type/discriminator
- **Authority Verification:** Validate signer relationships
- **PDA Re-derivation:** Always re-derive and compare PDAs
- **Constraint-Based Validation:** Use Anchor constraints or manual equivalents

## Detection During Audit

- Look for missing `account.owner` checks
- Search for hardcoded addresses without validation
- Check if PDAs are re-derived vs. trusted
- Verify sysvar accounts use proper loading functions
- Ensure token accounts validate mint/authority
- Test with malicious account substitutions

---

**Total Patterns:** 7  
**Last Updated:** 2026-02-07  
**Sources:** ThreeSigma, Wormhole exploit, Cashio hack, Solend exploit