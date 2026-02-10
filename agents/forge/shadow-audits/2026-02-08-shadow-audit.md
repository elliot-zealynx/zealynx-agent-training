# Rust Security Research - Shadow Audit February 8, 2026

## Contest: Orderly Solana Vault (Sherlock Contest 524)
**Date**: February 8, 2026  
**Target**: Sherlock Contest 524 - Orderly Solana Vault  
**Scope**: Solana-side vault implementation  
**Duration**: ~60 minutes  

## My Shadow Audit Findings

### 🔧 FINDING #1: HIGH - Missing Deposit Token Validation
**Severity**: High  
**Category**: Missing Owner/Constraint Validation  
**Pattern**: Missing constraint validation (Pattern 7 from knowledge base)  

**Issue**: In `deposit.rs`, there's no validation that the provided `deposit_token` matches the `allowed_token.mint_account`. Users can deposit arbitrary tokens while claiming they're depositing allowed tokens.

**Location**: `solana-vault/src/instructions/vault_instr/deposit.rs`

**Root Cause**: 
```rust
#[account()]
pub deposit_token: Box<Account<'info, Mint>>, // No constraint!

#[account(
    seeds = [TOKEN_SEED, deposit_params.token_hash.as_ref()],
    bump = allowed_token.bump,
    constraint = allowed_token.allowed == true @ VaultError::TokenNotAllowed
)]
pub allowed_token: Box<Account<'info, AllowedToken>>, // Missing: deposit_token == allowed_token.mint_account
```

**Impact**: Users can deposit worthless tokens and get credited with USDC on the destination chain.

**Fix**: Add constraint `constraint = deposit_token.key() == allowed_token.mint_account`

### 🔧 FINDING #2: LOW - Cross-User Deposit Access (False Positive)
**Severity**: Low  
**Category**: Missing Authority Validation  
**Pattern**: Missing authority signer requirement (Pattern 4)

**Issue**: Initially flagged that anyone can deposit to any vault since there's no validation that the signer has authority over the vault.

**Assessment**: Upon reflection, this might be intentional design - a public vault where anyone can deposit. Without knowing business requirements, this could be either valid design or vulnerability.

## Actual Contest Results Comparison

### ✅ FINDING H-1: CAUGHT! 
**Match**: Perfect match on missing deposit token validation
**Precision**: 100% - identified exact same constraint issue
**Impact**: Correctly assessed as High severity

### ❌ FINDING H-2: MISSED!  
**Miss**: Cross-user withdrawal theft via shared vault authority
**Issue**: In `oapp_lz_receive.rs`, the `user` account has no validation against the `receiver` field in withdrawal payload
**Root Cause**: 
```rust
/// CHECK  // <-- No validation!
#[account()]
pub user: AccountInfo<'info>,
```
**Impact**: User A can steal User B's withdrawals by providing B's withdrawal message but A's user account

### ❌ FINDING M-1: MISSED!
**Miss**: Missing LayerZero ordered execution option  
**Issue**: In `SolConnector.sol`, withdrawal messages lack ordered execution option
**Impact**: Message ordering issues causing state inconsistencies

## Performance Analysis

| Metric | Score |
|--------|--------|
| **Found** | 1/3 |
| **Missed** | 2/3 |  
| **False Positives** | 1 |
| **Precision** | 50% (1 true positive / 2 total findings) |
| **Recall** | 33% (1 caught / 3 actual findings) |

## Key Lessons Learned

### 🎯 **Strengths**
1. **Pattern Recognition**: Successfully applied missing constraint validation pattern to identify H-1
2. **Anchor Knowledge**: Good understanding of Anchor constraint system and validation gaps
3. **Impact Assessment**: Correctly assessed severity of token substitution attack

### ⚠️ **Critical Gaps**

1. **Missed Withdrawal Flow**: Focused only on deposit flow, completely missed withdrawal vulnerability
   - **Lesson**: Always audit both inbound AND outbound flows
   - **Pattern**: Cross-user authority issues can occur in any user-specific operation

2. **Incomplete User Validation**: Didn't recognize that `/// CHECK` accounts need explicit validation
   - **Lesson**: `/// CHECK` accounts are red flags - always verify they have proper validation logic
   - **Pattern**: User identity validation must match message payload expectations

3. **Cross-Chain Context**: Missed LayerZero ordering requirements for cross-chain messaging
   - **Lesson**: Cross-chain protocols have additional ordering/consistency requirements
   - **Pattern**: Message ordering is critical for state synchronization

### 🔧 **Detection Strategy Improvements**

1. **Complete Flow Analysis**: Map all user flows (deposit, withdraw, admin) before deep diving
2. **Account Validation Checklist**: For each `/// CHECK` account, verify explicit validation exists
3. **Cross-Chain Patterns**: Study LayerZero and other bridge-specific vulnerability patterns
4. **User Authority Matrix**: For each user operation, verify proper authorization mechanisms

## Updated Knowledge Base Actions

### New Patterns to Add:
1. **Cross-Chain Message Ordering**: LayerZero ordered execution requirements
2. **User Identity Validation**: Explicit validation of `/// CHECK` accounts in user operations  
3. **Withdrawal Flow Authority**: User authorization in fund withdrawal operations

### Pattern Updates:
- **Pattern 7 (Missing Custom Constraint)**: Add token substitution example from this audit
- **Pattern 4 (Missing Authority Signer)**: Add withdrawal authority bypass example

## Next Steps
1. Add missed patterns to knowledge base
2. Create checklist for cross-chain protocol audits
3. Practice on more withdrawal/outbound flow contracts
4. Study LayerZero security documentation

---

**Overall Assessment**: Good pattern recognition on known vulnerability types, but missed critical flows and cross-chain specific issues. Need broader coverage of protocol functionality before focusing on specific vulnerability classes.