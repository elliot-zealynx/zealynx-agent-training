# Pattern: Admin Address Change Without State Migration

**Severity:** Medium
**Source:** Morpheus Capital Protocol (C4, Aug 2025) — M-03
**Category:** Access Control / State Management

## Description
When an admin changes an external dependency address (e.g., Aave Pool, Oracle, Router, DEX), associated state like token approvals, cached values, or configuration tied to the old address is not updated. This creates a broken state where the new address cannot function.

## Vulnerable Pattern
```solidity
// During setup: approvals granted to initial address
function addDepositPool(address token_, Strategy strategy_) external onlyOwner {
    if (strategy_ == Strategy.AAVE) {
        IERC20(token_).safeApprove(aavePool, type(uint256).max); // ✅ Approved for current pool
    }
    isTokenAdded[token_] = true; // Prevents re-adding
}

// Later: admin changes address, but approvals aren't migrated
function setAavePool(address value_) public onlyOwner {
    aavePool = value_; // ❌ New pool has zero allowance
    // Old pool still has max allowance (security risk)
    // isTokenAdded prevents re-adding tokens to fix approvals
}
```

## Detection Strategy
1. Find ALL `setX()` functions that change external contract addresses
2. For each, identify what state was configured with the OLD address:
   - Token approvals (`approve()`)
   - Cached return values
   - Registered callbacks
   - Whitelisted addresses
3. Verify the setter function migrates or invalidates old state
4. Check for guards (like `isTokenAdded`) that prevent re-initialization

## Fix Pattern
```solidity
function setAavePool(address value_) public onlyOwner {
    address oldPool = aavePool;
    
    // Revoke old approvals
    for (uint i = 0; i < depositPoolTokens.length; i++) {
        if (depositPools[tokens[i]].strategy == Strategy.AAVE) {
            IERC20(tokens[i]).safeApprove(oldPool, 0);
            IERC20(tokens[i]).safeApprove(value_, type(uint256).max);
        }
    }
    
    aavePool = value_;
}
```

Or better: use Aave's `PoolAddressProvider` pattern — query dynamically instead of storing.

## Audit Checklist
- [ ] For each admin setter: what approvals reference the old address?
- [ ] For each admin setter: are old approvals revoked? (security risk if not)
- [ ] For each admin setter: are new approvals granted?
- [ ] Are there guards preventing re-initialization after address change?
- [ ] Does the protocol use dynamic address resolution instead of stored addresses?
