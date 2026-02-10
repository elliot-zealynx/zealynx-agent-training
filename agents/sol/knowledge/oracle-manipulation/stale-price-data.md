# Pattern: Stale Price Data from Chainlink Oracle

**Severity:** Medium-High
**Category:** Oracle Manipulation
**Prevalence:** Extremely common (most frequently reported oracle issue in competitive audits)

## Description

Smart contracts that call Chainlink's `latestRoundData()` but fail to check the `updatedAt` timestamp will consume stale pricing data. If the oracle hasn't updated recently (due to network congestion, oracle outage, or the price not deviating beyond the heartbeat threshold), the returned price may be significantly different from the actual market price, leading to incorrect liquidations, mis-priced swaps, or under-collateralized borrowing.

## Vulnerable Code Example

```solidity
// VULNERABLE: No staleness check
function getPrice() external view returns (uint256) {
    (, int256 price, , , ) = priceFeed.latestRoundData();
    return uint256(price);
}
```

## Detection Strategy

1. Search for all calls to `latestRoundData()` in the codebase
2. Verify that the `updatedAt` return value is captured and checked against a staleness threshold
3. Verify the staleness threshold matches the feed's actual heartbeat (check Chainlink's feed page)
4. Check that `answeredInRound >= roundId` (ensures the answer is from the current round)
5. Check that `price > 0` (negative or zero prices are invalid)

## Fix Pattern

```solidity
function getPrice() external view returns (uint256) {
    (
        uint80 roundId,
        int256 price,
        ,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = priceFeed.latestRoundData();

    require(price > 0, "Invalid price");
    require(updatedAt > 0, "Round not complete");
    require(answeredInRound >= roundId, "Stale price");
    require(block.timestamp - updatedAt <= STALENESS_THRESHOLD, "Price too old");

    return uint256(price);
}
```

## Real Examples

- [Sherlock USSD Audit - Stale price data](https://github.com/sherlock-audit/2023-05-USSD-judging/issues/31)
- [C4 Juicebox - Oracle data feed outdated](https://code4rena.com/reports/2022-07-juicebox#h-01-oracle-data-feed-can-be-outdated-yet-used-anyways-which-will-impact-payment-logic)
- [C4 Wise Lending - Chainlink stale prices when roundId < 50](https://code4rena.com/reports/2024-02-wise-lending)
- [Sherlock Midas - Hardcoded 3-day staleness threshold](https://github.com/sherlock-audit/2024-05-midas-judging/issues/158)
- [C4 Yield - Insufficient oracle validation](https://code4rena.com/reports/2022-01-yield#m-01-oracle-data-feed-is-insufficiently-validated)
- [Solodit - Spearbit LooksRare stale prices](https://solodit.xyz/issues/strategyfloorfromchainlink-will-often-revert-due-to-stale-prices-spearbit-looksrare-pdf)

## Key Insight

The staleness threshold MUST match the specific feed's heartbeat. ETH/USD on Ethereum mainnet has a 1-hour heartbeat, but BTC/USD might differ. Cross-check with Chainlink's documentation for the target chain and asset pair. Using a uniform threshold across all feeds is itself a separate bug pattern (see: same-heartbeat-multi-feed.md).
