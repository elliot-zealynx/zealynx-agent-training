# Pattern: Cross-Contract Rounding Propagation

**Severity:** Medium-High
**Source:** Morpheus Capital Protocol (C4, Aug 2025) — M-02
**Category:** Arithmetic / Token Integration

## Description
When tokens with non-standard transfer behavior (stETH 1-2 wei rounding, fee-on-transfer) are transferred through a chain of contracts, each contract must independently account for the actual transferred amount — not the requested amount.

## Vulnerable Pattern
```solidity
// Contract A: Correctly handles rounding
uint256 balanceBefore = token.balanceOf(address(this));
token.safeTransferFrom(msg.sender, address(this), amount);
uint256 balanceAfter = token.balanceOf(address(this));
amount = balanceAfter - balanceBefore; // ✅ Adjusted for rounding

// Contract A then passes `amount` to Contract B
contractB.supply(amount); // ❌ `amount` was adjusted, but Contract B doesn't know

// Contract B: Doesn't re-measure
function supply(uint256 amount_) external {
    token.safeTransferFrom(msg.sender, address(this), amount_);
    deposited += amount_;  // ❌ Could be > actual received due to rounding
    lastBalance += amount_; // ❌ lastBalance > actual balance → underflow later
}
```

## Detection Strategy
1. Identify ALL token transfers in the codebase
2. For rebasing/rounding tokens (stETH, fee-on-transfer tokens): trace the `amount` variable through every function that receives it
3. Verify that at each boundary where a `safeTransferFrom` occurs, the code measures actual balance change
4. Check if `deposited` or `lastBalance` state variables could exceed actual balances

## Fix Pattern
```solidity
function supply(uint256 amount_) external {
    uint256 before = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amount_);
    uint256 actual = token.balanceOf(address(this)) - before;
    deposited += actual;  // ✅ Uses actual received amount
    lastBalance += actual; // ✅ Matches reality
}
```

## Affected Tokens
- Lido stETH (share-based rounding, 1-2 wei)
- Fee-on-transfer tokens
- Rebasing tokens (aTokens when transferred, though typically accounted for differently)

## Related Patterns
- Read-only reentrancy on stale balances
- Donation attack on balance-based accounting
