# Pattern: Unhandled Oracle Revert Causing Denial of Service

**Severity:** High
**Category:** Oracle Manipulation / Denial of Service
**Prevalence:** Common in lending/borrowing and stablecoin protocols

## Description

Calls to Chainlink oracles (or any external oracle) can revert. Chainlink multisigs can block access to price feeds at any time. If a smart contract doesn't handle oracle reverts gracefully (via try/catch), a reverting oracle will cascade and brick all contract functions that depend on price data. For lending protocols, this means users cannot withdraw collateral, repay loans, or interact with the protocol at all.

## Vulnerable Code Example

```solidity
// VULNERABLE: Unhandled oracle revert = complete DoS
function getCollateralValue(address user) public view returns (uint256) {
    // If this reverts, ALL functions calling getCollateralValue() revert too
    (, int256 price, , , ) = priceFeed.latestRoundData();
    return userCollateral[user] * uint256(price) / 1e8;
}

function withdraw(uint256 amount) external {
    // This entire function is bricked if oracle reverts
    require(getCollateralValue(msg.sender) >= minCollateral, "Undercollateralized");
    // ... withdrawal logic
}
```

## Detection Strategy

1. Search for all `latestRoundData()` calls
2. Check if they're wrapped in `try/catch` blocks
3. Verify that the contract has a fallback oracle or emergency withdrawal mechanism
4. Look for admin functions to update/replace oracle feed addresses
5. Check if critical user-facing functions (withdraw, repay) can still execute if the oracle is down

## Fix Pattern

```solidity
// Option 1: try/catch with fallback oracle
function getPrice() public view returns (uint256) {
    try priceFeed.latestRoundData() returns (
        uint80, int256 price, uint256, uint256 updatedAt, uint80
    ) {
        if (price > 0 && block.timestamp - updatedAt <= STALENESS_THRESHOLD) {
            return uint256(price);
        }
    } catch {}

    // Fallback to secondary oracle
    try fallbackFeed.latestRoundData() returns (
        uint80, int256 price, uint256, uint256 updatedAt, uint80
    ) {
        if (price > 0 && block.timestamp - updatedAt <= FALLBACK_STALENESS) {
            return uint256(price);
        }
    } catch {}

    revert("All oracles failed");
}

// Option 2: Allow oracle address updates
function updatePriceFeed(address newFeed) external onlyOwner {
    require(newFeed != address(0), "Zero address");
    priceFeed = AggregatorV3Interface(newFeed);
}

// Option 3: Emergency withdrawal bypassing oracle
function emergencyWithdraw() external {
    require(oracleDown, "Oracle is operational");
    // Allow users to withdraw collateral without price check
}
```

## Real Examples

- [C4 Juicebox - Unhandled Chainlink revert locks price access](https://code4rena.com/reports/2022-07-juicebox#m-09-unhandled-chainlink-revert-would-lock-all-price-oracle-access)
- [C4 Inverse - Protocol usability limited when oracle blocked](https://code4rena.com/reports/2022-10-inverse#m-18-protocols-usability-becomes-very-limited-when-access-to-chainlink-oracle-data-feed-is-blocked)
- [Sherlock Blueberry - Chainlink revert DoS](https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/161)

## Key Insight

The protocol MUST have an escape hatch. If the oracle is the sole path to price data and it goes down, users lose access to their funds indefinitely. Best practice: dual oracle system (Chainlink + TWAP), ability to swap oracle addresses, and an emergency mode that allows withdrawals (possibly with a conservative price or full collateral return) when all oracles fail.
