# Pattern: DEX Spot Price Used as Oracle (Flash Loan Vulnerable)

**Severity:** Critical
**Category:** Oracle Manipulation / Price Manipulation
**Prevalence:** Very common, especially with newer tokens not on Chainlink

## Description

Protocols that fetch asset prices directly from DEX spot prices (e.g., Uniswap `slot0`, SushiSwap reserves) are vulnerable to flash loan manipulation. An attacker can take a large flash loan, execute a massive swap to skew the pool's price, exploit the manipulated price in the victim protocol, then swap back and repay the flash loan, all within a single transaction.

Unlike the balance-based pattern (which reads `balanceOf`), this pattern reads from external DEX pools. But the result is the same: spot prices are instantaneous and manipulable.

## Vulnerable Code Example

```solidity
// VULNERABLE: Using Uniswap V3 slot0 for pricing
function getTokenPrice() external view returns (uint256) {
    (uint160 sqrtPriceX96, , , , , , ) = IUniswapV3Pool(pool).slot0();
    // slot0 returns the CURRENT tick/price, which is flash-loan manipulable
    uint256 price = (uint256(sqrtPriceX96) ** 2 * 1e18) >> 192;
    return price;
}

// ALSO VULNERABLE: Using Uniswap V2 reserves
function getTokenPrice() external view returns (uint256) {
    (uint112 reserve0, uint112 reserve1, ) = IUniswapV2Pair(pair).getReserves();
    return uint256(reserve1) * 1e18 / uint256(reserve0);
}
```

## Detection Strategy

1. Search for calls to `IUniswapV3Pool.slot0()` used in pricing
2. Search for `IUniswapV2Pair.getReserves()` used in pricing
3. Look for any DEX pool `balanceOf` or reserve reading in price calculations
4. Check if TWAP is used instead (safe pattern)
5. Verify the TWAP window length (too short = still manipulable)

## Fix Pattern

```solidity
// SAFE: Use Uniswap V3 TWAP instead of slot0
function getTokenPriceTWAP(uint32 twapInterval) external view returns (uint256) {
    require(twapInterval > 0, "TWAP interval must be > 0");

    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = twapInterval; // e.g., 1800 for 30-minute TWAP
    secondsAgos[1] = 0;

    (int56[] memory tickCumulatives, ) = IUniswapV3Pool(pool).observe(secondsAgos);

    int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
    int24 arithmeticMeanTick = int24(tickCumulativesDelta / int56(int32(twapInterval)));

    // Handle negative tick with rounding
    if (tickCumulativesDelta < 0 && (tickCumulativesDelta % int56(int32(twapInterval)) != 0)) {
        arithmeticMeanTick--;
    }

    uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(arithmeticMeanTick);
    return (uint256(sqrtPriceX96) ** 2 * 1e18) >> 192;
}
```

## TWAP Window Guidelines

| Scenario | Recommended Window | Notes |
|----------|-------------------|-------|
| High-liquidity tokens | 30 minutes | Standard for major pairs |
| Low-liquidity tokens | 1-2 hours | Longer window for stability |
| Governance/voting | 24 hours+ | Prevent vote manipulation |
| High-frequency trading | 5-10 minutes | Accepts some risk for freshness |

## Real Examples

- [Cream Finance - $130M: Used Uniswap spot price as oracle](https://rekt.news/cream-rekt-2/)
- [Warp Finance - $7.7M: LP token price from spot reserves](https://rekt.news/warp-finance-rekt/)
- [Harvest Finance - $34M: Curve pool spot price manipulation](https://rekt.news/harvest-finance-rekt/)
- [Value DeFi - $6M: spot price manipulation via flash loan](https://rekt.news/value-defi-rekt/)
- [$52M+ in 2024 alone from price manipulation via DEX spots](https://threesigma.xyz/blog/exploit/2024-defi-exploits-top-vulnerabilities)

## Key Insight

`slot0()` is the "current price" and is the single most dangerous function to use for pricing in DeFi. If you see `slot0()` in any pricing context, it's almost certainly a vulnerability unless the protocol explicitly handles flash loan scenarios. TWAP is the antidote: to manipulate a 30-minute TWAP, an attacker must hold a skewed position for the entire 30 minutes, which is prohibitively expensive in liquid pools. However, TWAP is lagging, so it's a tradeoff between manipulation resistance and price freshness.
