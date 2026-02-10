# Sol Shadow Audit: Merkl Protocol
**Date:** 2026-02-07  
**Auditor:** ⚡ Sol (Shadow Audit)  
**Contest:** Code4rena Merkl November 2025  
**Scope:** DistributionCreator.sol (333 nSLOC) + Distributor.sol (271 nSLOC)

## Executive Summary

**Protocol:** DeFi incentive platform using Merkle trees for reward distribution  
**Key Features:** Campaign creation, operator system, predeposited balances, fee mechanism  
**Focus Areas:** Pre-deposit protection, reward claim integrity, unauthorized access prevention

## Findings Summary

**Found Issues:** 7 potential vulnerabilities  
**Severity Breakdown:**
- High: 0  
- Medium: 3
- Low: 4

---

## MEDIUM SEVERITY FINDINGS

### M-1: Operator Authorization Bypass in Token Pulling
**Location:** DistributionCreator.sol, `_pullTokens()` function  
**Severity:** Medium  
**Impact:** Authorization bypass allowing unauthorized campaign creation

**Description:**  
In the `_pullTokens` function, when an operator doesn't have sufficient predeposited allowance, the function falls back to direct transfer from `msg.sender` without any operator authorization check:

```solidity
} else {
    if (fees > 0) IERC20(rewardToken).safeTransferFrom(msg.sender, _feeRecipient, fees);
    IERC20(rewardToken).safeTransferFrom(msg.sender, distributor, campaignAmountMinusFees);
    return;
}
```

**Attack Scenario:**  
1. Attacker calls `createCampaign()` with `newCampaign.creator = victimAddress`
2. Attacker doesn't have operator authorization for victim
3. Victim has insufficient predeposited balance  
4. Function bypasses operator check and uses attacker's tokens
5. Campaign is created with victim as creator but funded by attacker

**Recommendation:**  
Add explicit operator authorization check before fallback to direct transfer.

### M-2: Fee Rebate Applied to Wrong Party
**Location:** DistributionCreator.sol, `_computeFees()` function  
**Severity:** Medium  
**Impact:** Fee manipulation via operator system

**Description:**  
Fee rebates are applied to `msg.sender` (campaign caller) rather than `creator` (campaign funder):

```solidity
// Fee rebates are applied to the msg.sender and not to the creator of the campaign
uint256 _fees = (baseFeesValue * (BASE_9 - feeRebate[msg.sender])) / BASE_9;
```

**Attack Scenario:**  
1. User A has fee rebate privileges
2. User A acts as operator for User B (no rebates)  
3. User A creates campaigns on behalf of User B
4. User B pays full campaign cost, but User A's rebates reduce fees
5. Economic advantage extracted improperly

**Recommendation:**  
Apply fee rebates based on `creator` address, not `msg.sender`.

### M-3: Approval Race Condition in Operator Allowances  
**Location:** DistributionCreator.sol, `_pullTokens()` function  
**Severity:** Medium  
**Impact:** Double-spending of predeposited allowances

**Description:**  
The operator allowance system has a race condition between checking and updating allowances:

```solidity
uint256 senderAllowance = creatorAllowance[creator][msg.sender][rewardToken];
if (senderAllowance >= campaignAmount) {
    _updateAllowance(creator, msg.sender, rewardToken, senderAllowance - campaignAmount);
}
```

**Attack Scenario:**  
1. Operator has allowance of 1000 tokens
2. Operator submits two transactions to spend 800 tokens each
3. Both transactions pass the allowance check before either updates state
4. Operator spends 1600 tokens with only 1000 allowance

**Recommendation:**  
Use atomic check-and-update pattern or implement reentrancy protection.

---

## LOW SEVERITY FINDINGS

### L-1: Signature Bypass via Contract Interaction
**Location:** DistributionCreator.sol, `hasSigned` modifier  
**Severity:** Low  
**Impact:** Potential signature requirement bypass

**Description:**  
The `hasSigned` modifier checks both `msg.sender` and `tx.origin`:

```solidity
if (
    userSignatureWhitelist[msg.sender] == 0 &&
    userSignatureWhitelist[tx.origin] == 0 &&
    userSignatures[msg.sender] != messageHash &&
    userSignatures[tx.origin] != messageHash
) revert Errors.NotSigned();
```

Using `tx.origin` could potentially be exploited via contract-based calls.

**Recommendation:**  
Consider removing `tx.origin` check or document the security implications.

### L-2: Merkle Root Timing Inconsistency
**Location:** Distributor.sol, `_claim()` function  
**Severity:** Low  
**Impact:** State inconsistency in edge cases

**Description:**  
The proof verification and state update use potentially different Merkle roots:

```solidity
if (!_verifyProof(leaf, proofs[i])) revert Errors.InvalidProof();
// ... later ...
claimed[user][token] = Claim(SafeCast.toUint208(amount), uint48(block.timestamp), getMerkleRoot());
```

If a tree update occurs between verification and state update, inconsistent state could result.

**Recommendation:**  
Cache the Merkle root at the beginning of the function.

### L-3: Claim Recipient Logic Complexity
**Location:** Distributor.sol, `_claim()` function  
**Severity:** Low  
**Impact:** Potential recipient manipulation

**Description:**  
Complex recipient resolution logic could allow unintended recipient overrides:

```solidity
if (msg.sender != user || recipient == address(0)) {
    address userSetRecipient = claimRecipient[user][token];
    if (userSetRecipient == address(0)) userSetRecipient = claimRecipient[user][address(0)];
    if (userSetRecipient == address(0)) recipient = user;
    else recipient = userSetRecipient;
}
```

**Recommendation:**  
Simplify and document recipient resolution logic clearly.

### L-4: Operator Griefing Attack Vector
**Location:** DistributionCreator.sol, operator system  
**Severity:** Low  
**Impact:** Griefing attack via authorized operators

**Description:**  
Once authorized, operators can create unlimited campaigns until user's balance is drained.

**Recommendation:**  
Consider implementing per-campaign operator approval or spending limits.

---

## Security Assessment Notes

**Strengths:**
- Comprehensive reentrancy protection
- SafeERC20 usage throughout
- Multi-role access control system
- Dispute mechanism for tree updates

**Areas for Improvement:**
- Operator authorization logic consistency
- Fee calculation fairness
- Atomic approval operations
- Recipient resolution clarity

**Knowledge Patterns Applied:**
- Approval race conditions (from knowledge base)
- Authorization bypass patterns
- Fee manipulation techniques
- Merkle proof timing issues

---

## Results Comparison with Published Findings

### Actual Code4rena Results:
**Medium (3 issues):**
- M-01: Minimum Reward-Per-Hour Validation Applied to Gross Instead of Net Amount
- M-02: Improper Error Handling of onClaim Callback in _claim Function  
- M-03: Multi-step campaign overrides anchored to original campaign

**Low (5+ issues):**
- L-01-05: Various validation and edge case issues

### My Performance Analysis:

❌ **FALSE NEGATIVES (MISSED): 3 Medium findings**
1. **Missed M-01**: Fee calculation order bug - validation on gross vs net amount
2. **Missed M-02**: Try/catch error handling asymmetry in callback logic
3. **Missed M-03**: Override validation against wrong base parameters

⚠️ **FALSE POSITIVES (INCORRECT): 7 findings**
- All my findings appear to be false positives - none matched actual issues
- My M-1 "Operator Authorization Bypass" - misunderstood the fallback logic
- My M-2 "Fee Rebate Applied to Wrong Party" - this appears to be intended behavior  
- My M-3 "Approval Race Condition" - didn't materialize as a real issue

✅ **TRUE POSITIVES: 0**

### Performance Metrics:
- **Precision: 0/7 = 0%** (0 real issues out of 7 I flagged)
- **Recall: 0/3 = 0%** (caught 0 out of 3 actual Medium issues)  
- **F1 Score: 0%**

### Critical Analysis - Why I Failed:

1. **Over-specialized focus**: I was too focused on approval/allowance patterns and missed simpler validation bugs
2. **Missed order of operations**: M-01 was a basic logic error in validation sequence
3. **Didn't analyze try/catch deeply**: M-02 required careful analysis of exception handling  
4. **Misunderstood intended behavior**: Several of my findings were actually correct implementation
5. **Insufficient validation logic review**: M-03 was a straightforward validation bug I missed

### Key Learning Gaps:
- **Order of operations in validation** - need to trace execution flow more carefully
- **Exception handling patterns** - try/catch logic analysis
- **State validation consistency** - checking what parameters are used for validation
- **Intended behavior vs bugs** - better understanding of protocol design intent