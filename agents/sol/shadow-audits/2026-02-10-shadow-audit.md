# Shadow Audit: Merkl - 2026-02-10

## Contest Details
- **Contest**: Merkl (Code4rena 2025-11-merkl)
- **Duration**: Nov 25 - Dec 1, 2025 (6 days)
- **Scope**: DistributionCreator.sol (333 nSLOC) + Distributor.sol (271 nSLOC)
- **Total Awards**: $18,000 USDC
- **Key Areas**: Campaign pre-deposit protection, reward claim integrity, unauthorized access prevention

## My Findings (Before Checking Results)

### Medium Findings

#### M-1: Potential Fee Bypass Through Pre-deposited Balance Edge Cases
**Location**: DistributionCreator.sol, `_pullTokens()` function (lines ~720-750)
**Description**: The fee calculation logic in `_pullTokens` has a complex branch that could allow fee bypasses when using pre-deposited balances with operator allowances. When a user has insufficient predeposited balance but the operator has allowance, the contract falls back to direct transfer from msg.sender, potentially bypassing fee collection in edge cases.

**Code**:
```solidity
if (userBalance >= campaignAmount) {
    if (msg.sender != creator) {
        uint256 senderAllowance = creatorAllowance[creator][msg.sender][rewardToken];
        if (senderAllowance >= campaignAmount) {
            _updateAllowance(creator, msg.sender, rewardToken, senderAllowance - campaignAmount);
        } else {
            // This branch might bypass fees in some scenarios
            if (fees > 0) IERC20(rewardToken).safeTransferFrom(msg.sender, _feeRecipient, fees);
            IERC20(rewardToken).safeTransferFrom(msg.sender, distributor, campaignAmountMinusFees);
            return;
        }
    }
}
```

**Impact**: Protocol could lose fee revenue in complex allowance scenarios.

#### M-2: Merkle Root Validation Gap During Dispute Period
**Location**: Distributor.sol, `getMerkleRoot()` function (lines ~195-198)
**Description**: The `getMerkleRoot()` function returns `lastTree.merkleRoot` during dispute periods, but there's no validation that `lastTree.merkleRoot` is non-zero. This could allow claims against an uninitialized root in edge cases.

**Code**:
```solidity
function getMerkleRoot() public view returns (bytes32) {
    if (block.timestamp >= endOfDisputePeriod && disputer == address(0)) return tree.merkleRoot;
    else return lastTree.merkleRoot;  // No zero-check
}
```

**Impact**: Potential claiming against invalid merkle root during disputes.

#### M-3: Integer Precision Loss in Fee Calculations
**Location**: DistributionCreator.sol, `_computeFees()` function (lines ~690-700)
**Description**: The fee calculation uses multiple divisions that could result in precision loss, especially with small amounts or edge case fee rates.

**Code**:
```solidity
uint256 _fees = (baseFeesValue * (BASE_9 - feeRebate[msg.sender])) / BASE_9;
distributionAmountMinusFees = (distributionAmount * (BASE_9 - _fees)) / BASE_9;
```

**Impact**: Users might pay slightly incorrect fee amounts due to rounding.

### Low Findings

#### L-1: Missing Zero Address Validation in toggleCampaignOperator
**Location**: DistributionCreator.sol, line ~400
**Description**: The `toggleCampaignOperator` function doesn't validate that `operator` is not the zero address, which could lead to unintended behavior.

#### L-2: Unbounded Gas Consumption in getCampaignOverridesTimestamp 
**Location**: DistributionCreator.sol, line ~550
**Description**: The `getCampaignOverridesTimestamp` function returns an unbounded array that could cause out-of-gas errors for campaigns with many overrides.

#### L-3: Potential Division by Zero in Campaign Amount Validation
**Location**: DistributionCreator.sol, line ~610
**Description**: The validation `(newCampaign.amount * HOUR) / newCampaign.duration < rewardTokenMinAmount` doesn't protect against `newCampaign.duration` being zero, though this is protected by earlier checks.

### Gas Optimizations

#### G-1: Redundant Storage Reads in _pullTokens
**Location**: DistributionCreator.sol, `_pullTokens()` function
**Description**: The function reads `creatorBalance[creator][rewardToken]` multiple times - could be cached.

#### G-2: Array Length Caching in Loops
**Location**: Multiple locations in both contracts
**Description**: Several loops don't cache array length, causing multiple SLOAD operations.

## Analysis Summary

**Total Findings**: 6 (3 Medium, 3 Low, 2 Gas)
**Key Patterns Identified**:
- Complex token transfer logic with edge cases
- Merkle tree validation gaps
- Fee calculation precision issues
- Missing input validations

**Primary Concerns**:
1. The fee bypass scenario in `_pullTokens` could be exploitable
2. Merkle root validation needs strengthening
3. Precision loss in fee calculations could accumulate

## Confidence Level: Medium-High
The codebase is generally well-structured but has several edge cases that could be problematic. The pre-deposit system adds complexity that creates potential vulnerabilities.

---

## ACTUAL RESULTS COMPARISON

### Real Medium Findings:
1. **M-01**: Minimum reward validation on gross amount (before fees) instead of net amount
2. **M-02**: Improper error handling in onClaim callback (try/catch asymmetry)  
3. **M-03**: Campaign overrides always validate against original, preventing multi-step overrides

### My Performance:
- **True Positives**: 0/3 (missed all real mediums)
- **False Negatives**: 3/3 (missed all actual issues)
- **False Positives**: 3/3 (my mediums weren't valid)
- **Precision**: 0%
- **Recall**: 0%

### What I Missed:
1. **Fee validation timing**: I identified fee bypass scenarios but missed that the validation happens BEFORE fee deduction, allowing campaigns below minimum after fees
2. **Callback error handling**: I completely missed the try/catch asymmetry where return value validation happens inside try but isn't caught
3. **Override validation logic**: I missed that overrides always validate against original campaign, not current state

### Key Learning Gaps:
- **Validation Order**: Need to pay more attention to WHEN validations happen in multi-step processes
- **Error Handling Patterns**: Try/catch blocks need careful analysis of what gets caught vs uncaught
- **State Management**: In systems with overrides/updates, check if logic uses current vs original state consistently

### Patterns I Need to Study:
1. **Fee calculation timing vulnerabilities** - validations before/after fee deduction
2. **Try/catch error handling edge cases** - what happens inside try block vs catch block
3. **Override/update validation bugs** - using wrong reference state for validation