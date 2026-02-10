# Pattern: Oracle Price Feed Decimal Precision Mismatch

**Severity:** High
**Category:** Oracle Manipulation / Arithmetic
**Prevalence:** Common when mixing ETH-pair and USD-pair feeds

## Description

Different Chainlink price feeds return prices with different decimal precision. The general rule is:
- Non-ETH pairs (e.g., ETH/USD, BTC/USD): 8 decimals
- ETH pairs (e.g., LINK/ETH, AAVE/ETH): 18 decimals

But there are exceptions (e.g., AMPL/USD uses 18 decimals despite being a USD pair). If a protocol assumes all feeds use the same precision, price calculations will be off by orders of magnitude (10^10 in the 8 vs 18 case), leading to catastrophic over/under-valuation.

## Vulnerable Code Example

```solidity
// VULNERABLE: Assumes all feeds use 8 decimals
function getValueInUSD(address token, uint256 amount) external view returns (uint256) {
    (, int256 price, , , ) = feeds[token].latestRoundData();

    // Assumes price has 8 decimals -- wrong for ETH-pair feeds!
    return amount * uint256(price) / 1e8;
}
```

## Detection Strategy

1. Check how the protocol handles `decimals()` from different oracle feeds
2. Look for hardcoded decimal assumptions (e.g., `/ 1e8` or `* 1e10`)
3. Verify that `AggregatorV3Interface.decimals()` is called and used dynamically
4. When two feed prices are combined (e.g., TOKEN/ETH * ETH/USD), verify decimal normalization
5. Check edge cases: AMPL/USD (18 decimals), tokens with non-standard decimals

## Fix Pattern

```solidity
function getValueInUSD(address token, uint256 amount) external view returns (uint256) {
    AggregatorV3Interface feed = feeds[token];
    (, int256 price, , , ) = feed.latestRoundData();

    uint8 feedDecimals = feed.decimals();
    uint8 tokenDecimals = IERC20Metadata(token).decimals();

    // Normalize to 18 decimals
    uint256 normalizedPrice = uint256(price) * 10**(18 - feedDecimals);
    return amount * normalizedPrice / 10**tokenDecimals;
}
```

## Real Examples

- [C4 Y2K Finance - Incorrect handling of priceFeedDecimals](https://code4rena.com/reports/2022-09-y2k-finance#h-01-incorrect-handling-of-pricefeeddecimals)
- [C4 Tracer - Wrong price scale for GasOracle](https://code4rena.com/reports/2021-06-tracer#h-06-wrong-price-scale-for-gasoracle)
- [C4 Vader - Oracle returns improperly scaled price](https://code4rena.com/reports/2021-12-vader#h-05-oracle-returns-an-improperly-scaled-usdvvader-price)
- [Sherlock Sentiment - Decimal mismatch](https://github.com/sherlock-audit/2022-08-sentiment-judging/blob/main/019-H/019-h.md)
- [Solodit - Chainlink oracle crashes with decimals > 18](https://solodit.xyz/issues/chainlink-oracle-can-crash-with-decimals-longer-than-18-halborn-savvy-defi-pdf)
- [Sherlock USSD - Multiple decimal issues](https://github.com/sherlock-audit/2023-05-USSD-judging/issues/236)

## Key Insight

Never assume decimals. Always call `feed.decimals()` and `token.decimals()` dynamically. The most dangerous scenario is when two feeds are combined (e.g., TOKEN/ETH * ETH/USD = TOKEN/USD) because you need to normalize BOTH feeds plus the token's own decimals. A mismatch here can mean the protocol values a $1 token at $10,000,000,000 or vice versa.
