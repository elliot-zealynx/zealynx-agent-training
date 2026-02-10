# Pattern: Incorrect Oracle Price Feed Address

**Severity:** Critical
**Category:** Oracle Manipulation
**Prevalence:** Uncommon but devastating when found

## Description

Some contracts hardcode oracle price feed addresses, either directly in the code or in constructor parameters. If the wrong address is used (e.g., ETH/USD instead of BTC/USD), the protocol will operate on completely incorrect pricing data. This can lead to under-collateralized positions, incorrect liquidations, or direct fund theft.

## Vulnerable Code Example

```solidity
// VULNERABLE: Wrong address in constructor (comment says BTC/USD but address is ETH/USD)
// chainlink btc/usd priceFeed 0xf4030086522a5beea4988f8ca5b36dbc97bee88c;
contract StableOracleWBTC is IStableOracle {
    AggregatorV3Interface priceFeed;

    constructor() {
        priceFeed = AggregatorV3Interface(
            0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419  // This is ETH/USD, not BTC/USD!
        );
    }
}
```

## Detection Strategy

1. Find all hardcoded oracle addresses in the codebase
2. Cross-reference each address against Chainlink's official feed list for the target chain
3. Check deploy scripts and configuration files for oracle addresses
4. Verify that comments match the actual address (comments lie, code doesn't)
5. For multi-chain deployments, verify that the correct chain-specific addresses are used
6. Use Etherscan to verify what the hardcoded address actually points to

## Fix Pattern

```solidity
// Option 1: Validate at deployment with description check
constructor(address _priceFeed) {
    AggregatorV3Interface feed = AggregatorV3Interface(_priceFeed);
    // Sanity check: verify the feed description matches expected pair
    string memory desc = feed.description();
    require(
        keccak256(bytes(desc)) == keccak256(bytes("BTC / USD")),
        "Wrong feed"
    );
    priceFeed = feed;
}

// Option 2: Admin-configurable with verification
function setPriceFeed(address _feed) external onlyOwner {
    require(_feed != address(0), "Zero address");
    // Optionally: verify the feed returns reasonable values
    (, int256 price, , , ) = AggregatorV3Interface(_feed).latestRoundData();
    require(price > 0, "Feed not responding");
    priceFeed = AggregatorV3Interface(_feed);
}
```

## Real Examples

- [Sherlock USSD - Wrong address: ETH/USD used instead of BTC/USD](https://github.com/sherlock-audit/2023-05-USSD-judging) (StableOracleWBTC.sol)
- [Sherlock Blueberry - Incorrect oracle feed address](https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/152)

## Key Insight

This is fundamentally a "typo" bug but with catastrophic impact. Common address reference:
- ETH/USD (Mainnet): `0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419`
- BTC/USD (Mainnet): `0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c`

Always verify addresses directly on Etherscan, not just from comments. In deploy scripts, add assertions that the feed's `description()` matches the expected pair name.
