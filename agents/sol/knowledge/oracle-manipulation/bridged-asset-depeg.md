# Pattern: Unhandled Depeg of Bridged/Wrapped Assets

**Severity:** Critical
**Category:** Oracle Manipulation
**Prevalence:** Growing concern with increasing bridge exploits

## Description

Protocols that use the native asset's price feed (e.g., BTC/USD) for a wrapped/bridged version of that asset (e.g., WBTC) assume a permanent 1:1 peg. If the bridge backing the wrapped asset is compromised, the wrapped asset depegs but the oracle continues reporting the native asset's price. Attackers can buy the depegged wrapped asset cheaply on DEXes and deposit it into the protocol at the higher native-asset price to drain funds.

## Vulnerable Code Example

```solidity
// VULNERABLE: Uses BTC/USD feed for WBTC, doesn't monitor WBTC/BTC peg
contract WBTCLending {
    AggregatorV3Interface btcUsdFeed; // BTC/USD feed

    function getWBTCValueInUSD(uint256 wbtcAmount) external view returns (uint256) {
        (, int256 btcPrice, , , ) = btcUsdFeed.latestRoundData();
        // Assumes WBTC == BTC always. If WBTC depegs, this is wrong
        return wbtcAmount * uint256(btcPrice) / 1e8;
    }
}
```

## Detection Strategy

1. Identify all wrapped/bridged assets in the protocol (WBTC, WETH on L2s, stETH, etc.)
2. Check if the protocol uses the native asset's feed (BTC/USD) for the wrapped version
3. Look for missing depeg monitoring feeds (Chainlink's WBTC/BTC, stETH/ETH feeds)
4. Consider LSTs (liquid staking tokens) that may trade at a discount
5. Check if the protocol has circuit breakers for depeg events

## Fix Pattern

```solidity
contract SecureWBTCLending {
    AggregatorV3Interface btcUsdFeed;   // BTC/USD
    AggregatorV3Interface wbtcBtcFeed;  // WBTC/BTC peg monitor
    uint256 constant MAX_DEPEG_BPS = 200; // 2% max acceptable depeg

    function getWBTCValueInUSD(uint256 wbtcAmount) external view returns (uint256) {
        // Check WBTC/BTC peg
        (, int256 pegPrice, , uint256 pegUpdatedAt, ) = wbtcBtcFeed.latestRoundData();
        require(block.timestamp - pegUpdatedAt <= 86400, "Peg feed stale");

        // pegPrice should be close to 1e8 (1.0 in 8 decimals)
        uint256 depegBps = pegPrice < 1e8
            ? (1e8 - uint256(pegPrice)) * 10000 / 1e8
            : (uint256(pegPrice) - 1e8) * 10000 / 1e8;
        require(depegBps <= MAX_DEPEG_BPS, "WBTC depegged beyond threshold");

        // Get BTC price and apply peg ratio
        (, int256 btcPrice, , , ) = btcUsdFeed.latestRoundData();
        return wbtcAmount * uint256(btcPrice) * uint256(pegPrice) / (1e8 * 1e8);
    }
}
```

## Affected Asset Categories

| Asset Type | Risk | Example Feeds |
|-----------|------|---------------|
| Wrapped BTC | Bridge compromise | WBTC/BTC, cbBTC/BTC |
| Liquid Staking | Depegging | stETH/ETH, rETH/ETH |
| Bridged stablecoins | Bridge hack | USDC.e on Arbitrum |
| Wrapped ETH on L2s | Sequencer/bridge risk | WETH/ETH |

## Real Examples

- [Sherlock USSD - Unhandled depeg of bridged assets](https://github.com/sherlock-audit/2023-05-USSD-judging/issues/310)
- [FTX/Solana WBTC scenario - bridge compromise risk analysis](https://rekt.news/)
- Ronin Bridge hack ($600M) - affected wrapped assets on Ronin chain
- Wormhole Bridge hack ($320M) - minted unbacked wrapped ETH on Solana

## Key Insight

Every wrapped/bridged asset is an implicit trust assumption about the bridge. Chainlink offers peg monitoring feeds (WBTC/BTC at `0xfdFD9C85aD200c506Cf9e21F1FD8dd01932FBB23` on mainnet) specifically for this purpose. Protocols should either: (a) use the peg feed to apply a depeg discount, or (b) have a circuit breaker that pauses operations when depeg exceeds a threshold. This is increasingly important as cross-chain bridges remain the #1 attack surface in DeFi.
