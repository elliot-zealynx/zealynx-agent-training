# Vault Share Price Manipulation via Reentrancy

**Category:** Reentrancy  
**Severity:** High/Critical  
**Last Updated:** 2026-02-03  
**Tags:** reentrancy, ERC4626, vault, share-price, inflation, oracle

---

## Pattern Summary

ERC4626 vaults and similar share-based protocols calculate share prices from `totalAssets / totalSupply`. During withdrawals, if these values are updated at different times around an external call, the share price can be temporarily inflated or deflated — enabling over-borrowing, unfair liquidations, or theft via dependent protocols.

## Root Cause

Share price is a ratio of two independently-updated state variables (`totalAssets` and `totalSupply`). Partial updates around external calls create windows where the ratio is inconsistent.

## Relationship to Other Patterns

This is essentially **read-only reentrancy applied to vault share pricing** — the most common real-world manifestation:

```
Vault.withdraw() → updates totalSupply → external call → updates totalAssets
                                          ↓ (reentrancy window)
                                    getSharePrice() = totalAssets / totalSupply
                                    = (unchanged large number) / (reduced number)
                                    = INFLATED PRICE
```

## Vulnerable ERC4626 Pattern

```solidity
contract VulnerableVault is ERC4626 {
    function withdraw(uint256 assets, address receiver, address owner) 
        public override returns (uint256 shares) 
    {
        shares = previewWithdraw(assets);
        
        // Burn shares FIRST (reduces totalSupply)
        _burn(owner, shares);
        
        // Transfer assets (external call — reentrancy window)
        // totalAssets() still returns old value
        SafeERC20.safeTransfer(asset, receiver, assets);
        
        // If asset is ETH or ERC-777, receiver gets callback
        // During callback: totalSupply reduced, totalAssets unchanged
        // → convertToAssets(shares) returns inflated value
    }
    
    // This is what dependent protocols call
    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply();
        return supply == 0 ? shares : shares.mulDiv(totalAssets(), supply);
        // During reentrancy: totalAssets() is stale-high, supply is already reduced
        // Result: INFLATED conversion rate
    }
}
```

## Concrete Scenario: Beanstalk Wells (Caught in Audit)

From the Cyfrin audit of Beanstalk Wells:

**Invariant:** `totalSupply() == calcLpTokenSupply(reserves)`

**Problem:** After `removeLiquidityOneToken`:
- `totalSupply` was updated (LP burned)
- But reserves weren't proportionally updated due to rounding
- Over time, this discrepancy compounded
- Result: valid transactions could REVERT, and share prices were incorrect

**Key insight:** Even without malicious reentrancy, mathematical inconsistency between related state variables causes the same class of bugs.

## Detection Strategy

### For ERC4626 Vaults Specifically
1. Check `withdraw()` and `redeem()` — when are shares burned vs assets transferred?
2. Check `deposit()` and `mint()` — when are shares minted vs assets received?
3. Trace `totalAssets()` — does it use `balanceOf(address(this))` or an internal tracker?
4. If internal tracker: when is it updated relative to external calls?
5. If `balanceOf`: it auto-updates after transfers, which is safer but has other issues

### Cross-Protocol Integration
```
If Protocol B uses Protocol A's vault for pricing:
  1. Can Protocol A's vault be in an inconsistent state?
  2. Does Protocol B read vault state during A's state transitions?
  3. Is there any way to trigger B's read during A's external call?
```

### Invariant Tests
```solidity
// Fuzzing invariant: share price should be monotonic (or near-monotonic)
function invariant_sharePriceConsistent() external {
    uint256 price = vault.convertToAssets(1e18);
    // Price should not deviate more than X% from expected
    assert(price >= minExpectedPrice && price <= maxExpectedPrice);
}
```

## Fix / Remediation

### 1. Update All State Before External Calls
```solidity
function withdraw(uint256 assets, address receiver, address owner) 
    public override nonReentrant returns (uint256 shares) 
{
    shares = previewWithdraw(assets);
    
    // Update ALL state atomically before any external interaction
    _burn(owner, shares);
    _totalAssets -= assets;  // Internal tracker updated HERE
    
    // External call LAST
    SafeERC20.safeTransfer(asset, receiver, assets);
}
```

### 2. Guard View Functions
```solidity
function convertToAssets(uint256 shares) public view returns (uint256) {
    if (_reentrancyGuardEntered()) revert ReentrancyGuardReentrantCall();
    uint256 supply = totalSupply();
    return supply == 0 ? shares : shares.mulDiv(totalAssets(), supply);
}
```

### 3. Use Internal Asset Tracking
```solidity
// Instead of relying on balanceOf (which changes with every transfer):
uint256 private _internalAssets;

function totalAssets() public view returns (uint256) {
    return _internalAssets;  // Only updated explicitly
}

function deposit(uint256 assets) external {
    _internalAssets += assets;  // Before transfer
    asset.safeTransferFrom(msg.sender, address(this), assets);
    _mint(msg.sender, shares);
}
```

## Key Takeaways

- **ERC4626 vaults are the #1 target for read-only reentrancy in 2024-2025**
- Share price = ratio of two state variables → inconsistency between updates = manipulation
- `convertToAssets()` and `convertToShares()` are price oracles used by other protocols
- Internal asset tracking is safer than `balanceOf(address(this))` for preventing manipulation
- Rounding errors in share calculations can compound into exploitable inconsistencies
- **Always audit the vault AND its integration points together**
