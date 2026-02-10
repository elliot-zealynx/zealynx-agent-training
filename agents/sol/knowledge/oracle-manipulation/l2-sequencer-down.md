# Pattern: Missing L2 Sequencer Uptime Check

**Severity:** High
**Category:** Oracle Manipulation
**Prevalence:** Common in L2 deployments (Arbitrum, Optimism, Base, etc.)

## Description

On L2 chains with a centralized sequencer (Arbitrum, Optimism, etc.), when the sequencer goes down, the Chainlink oracle price feeds stop updating but still return the last known price. When the sequencer comes back online, there's a grace period during which prices may be stale. If the contract doesn't check whether the L2 sequencer is operational, it will use prices that don't reflect the current market, enabling arbitrage or liquidation exploits.

## Vulnerable Code Example

```solidity
// VULNERABLE: No L2 sequencer check on Arbitrum/Optimism
contract PriceOracle {
    AggregatorV3Interface public priceFeed;

    function getPrice() external view returns (uint256) {
        (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
        require(block.timestamp - updatedAt <= 3600, "Stale price");
        return uint256(price);
    }
}
```

The staleness check above will pass because `updatedAt` reflects the last update BEFORE the sequencer went down. Meanwhile the actual market price may have moved significantly.

## Detection Strategy

1. Check if the protocol targets L2 deployment (Arbitrum, Optimism, Base, Scroll, etc.)
2. Search for `latestRoundData()` calls without an accompanying sequencer uptime feed check
3. Look for missing imports/references to the sequencer uptime feed address
4. Verify that a grace period is enforced after the sequencer restarts

## Fix Pattern

```solidity
AggregatorV3Interface internal sequencerUptimeFeed;
uint256 private constant GRACE_PERIOD_TIME = 3600; // 1 hour

function getPrice() external view returns (uint256) {
    // Check sequencer uptime
    (, int256 answer, uint256 startedAt, , ) = sequencerUptimeFeed.latestRoundData();

    // answer == 0: sequencer is up
    // answer == 1: sequencer is down
    bool isSequencerUp = answer == 0;
    require(isSequencerUp, "Sequencer is down");

    // Grace period: don't trust prices immediately after restart
    uint256 timeSinceUp = block.timestamp - startedAt;
    require(timeSinceUp > GRACE_PERIOD_TIME, "Grace period not over");

    // Now fetch the actual price
    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt <= STALENESS_THRESHOLD, "Stale price");
    return uint256(price);
}
```

## Real Examples

- [Sherlock Sentiment - L2 sequencer down check missing](https://github.com/sherlock-audit/2023-01-sentiment-judging/issues/16)
- [Sherlock Bond - Missing sequencer check](https://github.com/sherlock-audit/2023-02-bond-judging/issues/1)
- [Sherlock Blueberry - L2 sequencer activity check](https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/142)
- [Sherlock GMX - Missing sequencer check](https://github.com/sherlock-audit/2023-02-gmx-judging/issues/151)
- [Sherlock Perennial - No sequencer check](https://github.com/sherlock-audit/2023-05-perennial-judging/issues/37)
- [Chainlink Official Docs - L2 Sequencer Feeds](https://docs.chain.link/data-feeds/l2-sequencer-feeds)

## Key Insight

Sequencer uptime feed addresses differ per L2 network. Chainlink provides specific addresses for Arbitrum, Optimism, and other L2s. The grace period after sequencer restart is critical because the oracle needs time to re-sync with actual market prices. A 1-hour grace period is common but should be tuned per protocol risk tolerance.
