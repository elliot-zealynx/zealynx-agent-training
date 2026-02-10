# Pattern: Oracle Price Update Front-Running (Sandwich Attack)

**Severity:** Medium-High
**Category:** Oracle Manipulation / MEV
**Prevalence:** Affects stablecoin protocols and lending platforms

## Description

Oracle price updates are submitted as on-chain transactions, meaning they are visible in the mempool before execution. Attackers can front-run these updates by:
1. Observing an upcoming price update in the mempool
2. Executing a transaction before the update (e.g., minting stablecoins at the old, favorable price)
3. Waiting for the oracle update to execute
4. Executing a reverse transaction after the update (e.g., redeeming at the new price)

This "sandwich" pattern extracts value from the protocol with each oracle update. The attack is particularly effective when the oracle update reflects a significant price change.

## Vulnerable Code Example

```solidity
// VULNERABLE: Mint/burn at oracle price without front-running protection
contract StablecoinProtocol {
    AggregatorV3Interface priceFeed;

    function mint(uint256 collateralAmount) external {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        uint256 stablecoinAmount = collateralAmount * uint256(price) / 1e8;
        // User can see price update in mempool and sandwich it
        _mint(msg.sender, stablecoinAmount);
    }

    function redeem(uint256 stablecoinAmount) external {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        uint256 collateralAmount = stablecoinAmount * 1e8 / uint256(price);
        _burn(msg.sender, stablecoinAmount);
        collateral.transfer(msg.sender, collateralAmount);
    }
}
```

## Attack Flow

1. Current ETH price in oracle: $2,000
2. Attacker sees oracle update to $2,100 in mempool
3. Attacker front-runs: deposits 1 ETH, mints 2,000 stablecoins
4. Oracle updates: ETH = $2,100
5. Attacker back-runs: redeems 2,000 stablecoins, gets ~0.952 ETH
6. Net cost: 0.048 ETH. But attacker still has ~48 "free" stablecoins worth ~$100
7. Repeat with flash-loaned capital for amplified extraction

## Detection Strategy

1. Look for mint/burn/swap functions that read oracle prices directly
2. Check if there's any delay between deposit and withdrawal
3. Look for missing fees on mint/burn operations
4. Check if the protocol has cooldown periods
5. Identify if price updates can be observed in the mempool (public L1 vs private L2 sequencer)

## Fix Pattern

```solidity
// Mitigation 1: Add mint/burn fees
uint256 constant MINT_FEE_BPS = 30; // 0.3% fee

function mint(uint256 collateralAmount) external {
    (, int256 price, , , ) = priceFeed.latestRoundData();
    uint256 stablecoinAmount = collateralAmount * uint256(price) / 1e8;
    uint256 fee = stablecoinAmount * MINT_FEE_BPS / 10000;
    _mint(msg.sender, stablecoinAmount - fee);
}

// Mitigation 2: Deposit-withdrawal delay
mapping(address => uint256) public depositTimestamp;

function deposit(uint256 amount) external {
    depositTimestamp[msg.sender] = block.timestamp;
    // ... deposit logic
}

function withdraw(uint256 amount) external {
    require(
        block.timestamp >= depositTimestamp[msg.sender] + MIN_DELAY,
        "Too soon"
    );
    // ... withdrawal logic
}
```

## Real Examples

- [Sherlock Olympus - Oracle update sandwich attack](https://github.com/sherlock-audit/2023-03-olympus-judging/issues/1)
- [Sherlock USSD - Oracle front-running](https://github.com/sherlock-audit/2023-05-USSD-judging/issues/836)
- [Consensys Bancor V2 - Oracle front-running depletes reserves](https://solodit.xyz/issues/oracle-front-running-could-deplete-reserves-over-time-addressed-consensys-bancor-v2-amm-security-audit-markdown)
- [Synthetix - Historical front-running problems](https://blog.synthetix.io/frontrunning-synthetix-a-history/)
- [Angle Protocol - Oracle front-running research](https://blog.angle.money/angle-research-series-part-1-oracles-and-front-running-d75184abc67)

## Key Insight

On L1 (Ethereum mainnet), all oracle updates are visible in the mempool. On L2s with a centralized sequencer (Arbitrum, Optimism), front-running is harder but not impossible (sequencer can be monitored via RPC). Effective mitigations combine: (a) mint/burn fees that exceed the maximum oracle deviation per update, (b) time delays between deposit and withdrawal, and (c) commit-reveal schemes for large operations.
