# Pattern: Same Heartbeat Used for Multiple Price Feeds

**Severity:** Medium
**Category:** Oracle Manipulation
**Prevalence:** Common in protocols using multiple Chainlink feeds

## Description

Different Chainlink price feeds have different heartbeat intervals. For example, ETH/USD on Ethereum mainnet has a 1-hour heartbeat, while USDC/USD might have a 24-hour heartbeat. When a protocol uses a single `heartbeatInterval` variable to check staleness across multiple feeds, feeds with a longer heartbeat will be incorrectly flagged as stale, while feeds with shorter heartbeats may accept prices that are actually stale for their specific feed.

## Vulnerable Code Example

```solidity
// VULNERABLE: Same heartbeatInterval for different feeds
uint256 constant heartbeatInterval = 3600; // 1 hour

function getMarkPrice() external view returns (uint256) {
    (, int256 rawPrice, , uint256 updatedAt, ) = IChainlink(chainlink).latestRoundData();
    (, int256 USDCPrice, , uint256 USDCUpdatedAt, ) = IChainlink(USDCSource).latestRoundData();

    // Feed #1 (ETH/USD): 1-hour heartbeat - this check is correct
    require(block.timestamp - updatedAt <= heartbeatInterval, "ORACLE_HEARTBEAT_FAILED");

    // Feed #2 (USDC/USD): 24-hour heartbeat - using 1-hour check will cause false reverts
    require(block.timestamp - USDCUpdatedAt <= heartbeatInterval, "USDC_ORACLE_HEARTBEAT_FAILED");

    return (SafeCast.toUint256(rawPrice) * 1e8) / SafeCast.toUint256(USDCPrice);
}
```

## Detection Strategy

1. Identify all Chainlink feed integrations in the codebase
2. Check if a single staleness threshold is applied to multiple feeds
3. Cross-reference each feed's actual heartbeat on Chainlink's price feed page
4. Look for hardcoded staleness values that don't match the feed's heartbeat

## Fix Pattern

```solidity
mapping(address => uint256) public feedHeartbeats;

function setFeedHeartbeat(address feed, uint256 heartbeat) external onlyOwner {
    feedHeartbeats[feed] = heartbeat;
}

function getPriceFromFeed(address feed) internal view returns (int256) {
    (, int256 price, , uint256 updatedAt, ) = AggregatorV3Interface(feed).latestRoundData();
    require(price > 0, "Invalid price");
    require(
        block.timestamp - updatedAt <= feedHeartbeats[feed],
        "Stale price"
    );
    return price;
}
```

## Real Examples

- [Sherlock JOJO - Same heartbeat for different feeds](https://github.com/sherlock-audit/2023-04-jojo-judging/issues/449)
- [Sherlock Olympus - Similar feeds with different heartbeat/deviation](https://github.com/sherlock-audit/2023-03-olympus-judging/issues/2)
- [Sherlock Isomorph - Different heartbeat thresholds needed](https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/256)
- [TrailOfBits CAP Labs - Incorrect staleness period for multiple assets](https://solodit.cyfrin.io/issues/incorrect-oracle-staleness-period-leads-to-price-feed-dos-trailofbits-none-cap-labs-covered-agent-protocol-pdf)

## Key Insight

Common heartbeat values on Ethereum mainnet:
- ETH/USD: 3600s (1 hour)
- BTC/USD: 3600s (1 hour)
- USDC/USD: 86400s (24 hours)
- DAI/USD: 3600s (1 hour)

These values differ across chains. Always check the specific chain's Chainlink feed page. The 1% deviation threshold for ETH/USD means the oracle updates whenever price moves 1% OR the heartbeat elapses, whichever comes first.
