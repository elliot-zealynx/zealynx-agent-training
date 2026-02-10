# Zero Value Transfer Compatibility Patterns

## Pattern: Tokens That Revert on Zero Transfers
*Successfully applied in Krystal DeFi shadow audit (2026-02-09)*

### Vulnerable Code Pattern
```solidity
// ALWAYS CHECK: Can feeAmount be zero?
function _deductFees(DeductFeesParams memory params, bool emitEvent) internal returns(...) {
    if (params.amount0 > 0) {
        feeAmount0 = FullMath.mulDiv(params.amount0, params.feeX64, Q64);
        amount0Left = params.amount0 - feeAmount0;
        // 🚨 VULNERABILITY: Can transfer 0 if feeAmount0 = 0
        SafeERC20.safeTransfer(IERC20(params.token0), FEE_TAKER, feeAmount0);
    }
}
```

### When Zero Amounts Occur
```solidity
// If params.feeX64 * params.amount0 < Q64, then feeAmount0 = 0
uint256 Q64 = 2**64;
uint256 feeAmount = FullMath.mulDiv(amount, feeX64, Q64);
// Example: amount=1, feeX64=1000 → feeAmount = 1*1000/2^64 = 0
```

### Tokens That Fail
- **BNB** (Binance Coin) - explicitly reverts on zero transfers
- **LEND** - similar behavior
- Other tokens with explicit zero-value checks

### Detection Checklist
- [ ] Look for direct `transfer()` or `safeTransfer()` calls
- [ ] Check if amount can be calculated as zero via division
- [ ] Verify if protocol claims to support "revert on zero transfer" tokens  
- [ ] Look for fee calculations using `mulDiv` with small amounts
- [ ] Check README/docs for supported token types

### Secure Pattern
```solidity
if (feeAmount0 > 0) {
    SafeERC20.safeTransfer(IERC20(params.token0), FEE_TAKER, feeAmount0);
}
```

### Audit Questions
1. **Can the transfer amount be zero?** (fee calculations, rounding down)
2. **Does protocol support zero-revert tokens?** (check documentation)
3. **Are all transfer locations protected?** (fee deductions, swaps, etc.)

## Pattern Success Rate
- **Applied in:** Krystal DeFi (M-03)
- **Detection Rate:** 1/1 (100%)
- **False Positives:** 0/1 (0%)

This pattern is a reliable vulnerability class for DeFi protocols claiming broad token compatibility.