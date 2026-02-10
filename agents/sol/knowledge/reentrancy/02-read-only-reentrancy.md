# Read-Only Reentrancy

**Category:** Reentrancy  
**Severity:** Critical/High  
**Last Updated:** 2026-02-03  
**Tags:** reentrancy, read-only, view-function, oracle, price-manipulation, cross-protocol

---

## Pattern Summary

A `view` function returns stale/inconsistent data during an active external call from the same contract. Other protocols that depend on this view function as a price oracle or data source make decisions based on manipulated values.

This is the **most overlooked** reentrancy variant because the re-entered function doesn't modify state — it just reads it incorrectly.

## Root Cause

A state-modifying function partially updates state, makes an external call, then completes state updates. During the external call window, `view` functions return values calculated from the **inconsistent intermediate state**. Cross-protocol dependencies amplify this into a critical exploit.

## Historical Exploits

| Protocol | Date | Loss | Chain | Vector |
|----------|------|------|-------|--------|
| dForce | Feb 2023 | $3.7M | Arbitrum/Optimism | Curve `get_virtual_price()` read-only reentrancy |
| Sentiment | Apr 2023 | $1M | Arbitrum | Balancer read-only reentrancy |
| QuickSwap Lend | Oct 2022 | $220K | Polygon | Curve pool read-only reentrancy |
| Midas Capital | Jan 2023 | $660K | Polygon | Curve read-only reentrancy |
| Beanstalk Wells | Jun 2023 (audit) | N/A (caught) | — | LP share price inconsistency |

## Vulnerable Code Pattern

```solidity
contract Vault is ReentrancyGuard {
    uint256 public totalShares;
    uint256 public totalBalance;

    function withdraw(uint256 shareAmount) external nonReentrant {
        uint256 ethAmount = (shareAmount * totalBalance) / totalShares;
        
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;  // Updated BEFORE external call
        
        // External call — re-entry window opens
        (bool success, ) = msg.sender.call{value: ethAmount}("");
        require(success);
        
        totalBalance -= ethAmount;   // Updated AFTER — inconsistent state!
    }
    
    // View function reads inconsistent state during reentrancy window
    function getSharePrice() public view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (totalBalance * 1e18) / totalShares;
        // During reentrancy: totalShares reduced but totalBalance not yet
        // Result: INFLATED share price
    }
}

// Victim lending protocol trusts getSharePrice()
contract LendingProtocol {
    function borrow() external {
        uint256 sharePrice = vault.getSharePrice(); // Returns inflated price
        uint256 collateralValue = collateral[msg.sender] * sharePrice;
        // Attacker borrows more than collateral is worth
    }
}
```

## Attack Flow (dForce/Curve Pattern)

1. Attacker flash-loans large amount of assets
2. Deposits into Curve pool to get LP tokens
3. Initiates `remove_liquidity()` on Curve pool
4. During Curve's external ETH transfer (before all state is updated), `get_virtual_price()` returns **stale inflated value**
5. In the callback, attacker calls dForce lending which reads `get_virtual_price()` as collateral oracle
6. Borrows against inflated collateral value
7. Transaction completes — Curve state normalizes, but attacker keeps the over-borrowed funds

## Detection Strategy

### Identification Checklist
- [ ] Does the protocol use external `view` functions as price oracles?
- [ ] Does the source contract (Curve, Balancer, etc.) have functions that partially update state before external calls?
- [ ] Is there a window where `totalSupply`, `totalAssets`, `get_virtual_price`, or similar can return inconsistent values?
- [ ] Are there cross-protocol dependencies where Protocol A reads from Protocol B during B's state transition?

### Static Analysis
- Slither: `reentrancy-benign` may flag, but read-only reentrancy often requires manual review
- Map all `view` function dependencies — trace what state they read and when that state is updated

### Key Signals
- `nonReentrant` on state-mutating functions but NOT on view functions
- View functions computing ratios from multiple state variables updated at different points
- External protocols using `getSharePrice()`, `get_virtual_price()`, `totalAssets()` as oracles

## Fix / Remediation

### 1. Fix the Source: CEI Pattern (Primary)
```solidity
function withdraw(uint256 shareAmount) external nonReentrant {
    uint256 ethAmount = (shareAmount * totalBalance) / totalShares;
    
    // Update ALL state before external call
    shares[msg.sender] -= shareAmount;
    totalShares -= shareAmount;
    totalBalance -= ethAmount;  // Moved BEFORE external call
    
    (bool success, ) = msg.sender.call{value: ethAmount}("");
    require(success);
}
```

### 2. Guard View Functions Against Reentrancy
```solidity
function getSharePrice() public view returns (uint256) {
    // Revert if called during reentrancy window
    if (_reentrancyGuardEntered()) {
        revert ReentrancyGuardReentrantCall();
    }
    if (totalShares == 0) return 1e18;
    return (totalBalance * 1e18) / totalShares;
}
```

### 3. Consumer-Side Protection
```solidity
// In the lending protocol that READS the price:
function borrow() external {
    // Check if source contract is mid-execution
    // Balancer: vault.ensureNotPaused() + manualReentrancyCheck
    // Curve: verify reentrancy lock status
    uint256 price = vault.getSharePrice();
    // Additional: compare with TWAP or secondary oracle
}
```

## Key Takeaways

- **Read-only reentrancy is the #1 missed reentrancy variant in modern audits**
- `nonReentrant` on write functions is NOT sufficient — view functions can still return stale data
- Cross-protocol composability makes this critical: one protocol's view function = another's oracle
- **Always apply CEI to ALL state variables**, not just the obvious ones
- Auditors must map the full dependency graph: who reads from whom?
