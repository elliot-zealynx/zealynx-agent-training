# Pattern: Price Derived from Token Balance Ratios (Flash Loan Vulnerable)

**Severity:** Critical
**Category:** Oracle Manipulation / Price Manipulation
**Prevalence:** Common in custom DEXes, lending protocols with internal pricing

## Description

When a smart contract calculates the price of an asset using the ratio of token balances it holds (e.g., `balanceOf(tokenA) / balanceOf(tokenB)`), an attacker can temporarily skew these balances using flash loans or direct token donations. The manipulated price then cascades into any dependent logic: liquidations, swaps, collateral valuations, or share price calculations.

This is the most fundamental oracle manipulation pattern. It's essentially "don't use your own contract's state as a price oracle."

## Vulnerable Code Example

```solidity
// CRITICAL VULNERABILITY: Price from balance ratio
function getPrice(IERC20 tokenIn, IERC20 tokenOut) public view returns (uint256) {
    uint256 balIn = tokenIn.balanceOf(address(this));
    uint256 balOut = tokenOut.balanceOf(address(this));
    return balOut * 1e18 / balIn; // Flash-loan manipulable
}

// Also vulnerable: share price from total supply ratio
function sharePrice() public view returns (uint256) {
    return totalAssets() * 1e18 / totalSupply(); // Donation-attackable
}
```

## Attack Flow

1. Attacker takes flash loan of Token A from Pool (or another source)
2. Pool's Token A balance drops, artificially inflating Token A's "price" (less A = A appears scarce)
3. Attacker swaps a small amount of Token A for Token B at the inflated price
4. Attacker repays flash loan
5. Net profit: excess Token B received due to manipulated exchange rate

## Detection Strategy

1. Search for `balanceOf(address(this))` used in price/rate calculations
2. Look for `totalAssets() / totalSupply()` patterns in vault contracts
3. Check if any pricing function reads on-chain reserves directly
4. Identify if the pool offers flash loans (self-manipulation vector)
5. Check for ERC-4626 vaults using `convertToShares`/`convertToAssets` without protections

## Fix Pattern

```solidity
// Option 1: Use external oracle (Chainlink, TWAP)
function getPrice() external view returns (uint256) {
    (, int256 price, , , ) = chainlinkFeed.latestRoundData();
    return uint256(price);
}

// Option 2: Use TWAP (time-weighted average price)
function getTWAPPrice() external view returns (uint256) {
    // Uniswap V3 TWAP over 30-minute window
    (int24 arithmeticMeanTick, ) = OracleLibrary.consult(pool, 1800);
    return OracleLibrary.getQuoteAtTick(arithmeticMeanTick, 1e18, token0, token1);
}

// Option 3: Virtual price tracking (for vaults)
// Track deposits/withdrawals explicitly rather than reading balances
uint256 private _totalDeposited;
function sharePrice() public view returns (uint256) {
    return _totalDeposited * 1e18 / totalSupply();
}
```

## Real Examples

- [Cream Finance - $130M flash loan oracle manipulation](https://rekt.news/cream-rekt-2/)
- [Beanstalk Wells - Balance-based pricing exploitation](https://solodit.cyfrin.io)
- [C4 Solodit Checklist - SOL-AM-PMA-1](https://solodit.cyfrin.io/checklist)
- [Mango Markets - $117M oracle manipulation via self-referencing price](https://rekt.news/mango-markets-rekt/)
- [Warp Finance - $7.7M flash loan price manipulation](https://rekt.news/warp-finance-rekt/)

## Key Insight

Any time `balanceOf(address(this))` appears in a pricing function, it's a red flag. The contract's token balances are ephemeral state that can be manipulated within a single transaction. Reliable pricing must come from either (a) external oracles, (b) time-weighted averages, or (c) internal accounting that tracks deposits/withdrawals rather than reading spot balances.
