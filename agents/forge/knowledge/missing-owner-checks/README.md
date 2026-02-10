# Missing Owner Checks

**Risk Level:** High to Critical
**Impact:** Complete authority bypass, unauthorized access, fund theft
**Detection:** Static analysis for constraint validation, authority field checks, program ownership verification

## Overview

Missing owner checks are one of the most critical vulnerability classes in Solana programs. They occur when a program fails to properly validate that:
- An account is owned by the expected program
- A signer has the required authority for an operation  
- Account data fields match expected authority/owner values
- PDAs are properly derived and validated

Unlike traditional smart contracts, Solana's account model requires explicit validation that accounts are owned by the correct programs and authorities. Missing these checks can lead to complete bypasses of access controls.

## Root Causes

1. **Missing Program Ownership Check:** Not validating account.owner == expected_program_id
2. **Missing Authority Field Validation:** Not checking data.authority == expected_authority  
3. **Missing Constraint Enforcement:** Anchor constraints omitted or bypassed
4. **Incomplete PDA Validation:** Deriving but not comparing derived vs provided address
5. **Token Account Owner Skip:** Not validating token_account.owner == expected_user
6. **Missing Signer Requirements:** Operations that modify authority without requiring signer

## Impact Examples

- **Wormhole Bridge ($325M):** Sysvar account spoofing bypassed signature verification
- **Cashio Protocol ($52M):** Missing mint validation allowed arbitrary token printing
- **Solend Protocol ($1.26M+):** Oracle account substitution manipulated price feeds
- **Multiple DeFi protocols:** Authority bypass through missing owner checks

## Detection Strategies

1. **Static Analysis:** Check for missing `check_program_account()` calls
2. **Constraint Validation:** Verify Anchor `has_one`, `owner`, `address` constraints  
3. **Authority Flow Analysis:** Trace authority changes without signer requirements
4. **Account Ownership Audit:** Verify all accounts have proper ownership validation
5. **PDA Derivation Check:** Ensure derived addresses match provided addresses

## Patterns Covered

1. [Missing check_program_account Before Unpack/Mutation](01-missing-check-program-account.md)
2. [Missing has_one Constraint in Anchor](02-missing-has-one-constraint.md) 
3. [Missing owner Constraint Validation](03-missing-owner-constraint.md)
4. [Missing Authority Signer Requirement](04-missing-authority-signer.md)
5. [PDA Authority Derivation Not Verified](05-pda-authority-derivation.md)
6. [Token Account Owner Not Validated](06-token-account-owner.md)
7. [Missing Constraint in Custom Instructions](07-missing-custom-constraint.md)

## Mitigation Strategies

1. **Use Anchor Constraints:** Prefer `has_one`, `owner`, `address` over manual checks
2. **Always Check Program Ownership:** Call `check_program_account()` before unpack
3. **Require Signers for Authority Ops:** Use `signer` constraint for authority changes
4. **Validate PDA Derivations:** Always compare derived vs provided addresses  
5. **Comprehensive Testing:** Test with malicious accounts and wrong owners
6. **Security Reviews:** Focus extra attention on authority and ownership logic

## References

- Solana Foundation Token22 Audit Report (Code4rena, Aug-Sep 2025)
- Anchor Framework Account Constraints Documentation  
- ThreeSigma: "Rust Memory Safety on Solana: What Smart Contract Audits Reveal"
- Helius: "Hitchhiker's Guide to Solana Program Security" (Feb 2025)
- Real exploit analyses: Wormhole, Cashio, Solend incidents