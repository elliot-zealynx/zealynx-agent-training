# Pattern: Oracle minAnswer/maxAnswer Circuit Breaker Not Checked

**Severity:** High-Critical
**Category:** Oracle Manipulation
**Prevalence:** Common in lending/borrowing protocols

## Description

Chainlink price feeds have built-in minimum and maximum price thresholds (`minAnswer` and `maxAnswer`). During extreme market events like flash crashes, bridge compromises, or depegging events, if an asset's actual price falls below `minAnswer`, the oracle will continue reporting `minAnswer` instead of the real (lower) price. Similarly, if price exceeds `maxAnswer`, the oracle caps at that value.

An attacker can exploit this by buying the crashed asset cheaply on a DEX and depositing it into a lending protocol that still values it at the oracle's `minAnswer` (which is higher than the real price), then borrowing against it to drain the protocol.

## Vulnerable Code Example

```solidity
// VULNERABLE: No min/max answer check
function getPrice(address feed) external view returns (uint256) {
    (, int256 price, , uint256 updatedAt, ) = AggregatorV3Interface(feed).latestRoundData();
    require(block.timestamp - updatedAt <= 3600, "Stale");
    require(price > 0, "Invalid");
    return uint256(price);
    // If LUNA crashes to $0.001 but minAnswer is $0.10,
    // this returns $0.10 -- 100x the real price!
}
```

## Detection Strategy

1. Search for `latestRoundData()` calls
2. Check if the returned `answer` is compared against `minAnswer` and `maxAnswer` from the aggregator
3. Look for missing calls to `AggregatorV3Interface.minAnswer()` / `AggregatorV3Interface.maxAnswer()`
4. Note: In newer Chainlink aggregators, these values may be accessed differently (check aggregator implementation)
5. Consider whether the protocol handles assets that could depeg (stablecoins, wrapped tokens, LSTs)

## Fix Pattern

```solidity
function getPrice(address feed) external view returns (uint256) {
    AggregatorV3Interface oracle = AggregatorV3Interface(feed);
    (, int256 price, , uint256 updatedAt, ) = oracle.latestRoundData();

    require(block.timestamp - updatedAt <= STALENESS_THRESHOLD, "Stale");
    require(price > 0, "Invalid price");

    // Check circuit breaker bounds
    int192 minAnswer = IAccessControlledOffchainAggregator(oracle.aggregator()).minAnswer();
    int192 maxAnswer = IAccessControlledOffchainAggregator(oracle.aggregator()).maxAnswer();

    require(price > int256(minAnswer), "Price at min circuit breaker");
    require(price < int256(maxAnswer), "Price at max circuit breaker");

    return uint256(price);
}
```

## Real Examples

- [Sherlock Blueberry - Oracle returns incorrect price during flash crashes](https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/18)
- [Venus/Blizz - LUNA crash exploit using oracle floor price](https://rekt.news/venus-blizz-rekt/)
- [CodeHawks Beanstalk - LibEthUsdOracle returning wrong price on minAnswer](https://codehawks.cyfrin.io/c/2024-02-Beanstalk-1/s/72)
- [CodeHawks Beanstalk Finale - Min/max answers not checked in LibChainlinkOracle](https://codehawks.cyfrin.io/c/2024-05-beanstalk-the-finale/s/506)

## Key Insight

The Venus/LUNA incident is the canonical example: when LUNA crashed, Chainlink's oracle kept reporting $0.10 (the minAnswer) even though LUNA was trading at fractions of a cent. Attackers bought massive amounts of LUNA cheaply on DEXes and deposited it into Venus (which still priced it at $0.10), draining millions in stablecoins. This pattern is especially dangerous for tokens that could experience catastrophic price drops (algorithmic stablecoins, wrapped tokens from vulnerable bridges, tokens with concentrated holder risk).
