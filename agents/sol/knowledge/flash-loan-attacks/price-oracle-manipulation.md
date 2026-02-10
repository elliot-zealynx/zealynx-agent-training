# Flash Loan: Price Oracle Manipulation

## Description
Flash loans enable attackers to temporarily acquire massive capital ($100M+) within a single transaction. When protocols rely on spot prices from AMM pools (e.g., Uniswap, PancakeSwap) as oracles, attackers can execute large swaps to skew the pool's price ratio, then exploit the manipulated price for profit before repaying the loan.

The key insight: AMM spot prices reflect only the last trade in an isolated pool (x*y=k invariant), NOT global market value. With sufficient capital, these prices are trivially manipulated.

## Vulnerable Code Pattern

```solidity
// VULNERABLE: Using spot price as oracle
function getPrice(address token) external view returns (uint256) {
    (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
    // Direct spot price calculation - easily manipulated
    return (uint256(reserve1) * 1e18) / uint256(reserve0);
}

// VULNERABLE: Minting based on manipulated price
function mintTokens(uint256 collateralAmount) external {
    uint256 price = getPrice(collateralToken);
    uint256 tokensToMint = collateralAmount * price / 1e18;
    _mint(msg.sender, tokensToMint);  // Mints at manipulated price
}
```

## Detection Strategy

1. **Identify price sources**: Look for any function reading reserves or prices from AMM pairs
2. **Check for single-source pricing**: If only one pool is queried, vulnerability likely
3. **Look for value-sensitive operations**: Minting, borrowing, liquidation that use the price
4. **Trace the call flow**: Price read → value calculation → state change in same tx = exploitable
5. **Check for time component**: Absence of TWAP or multi-block averaging is red flag

Key code patterns to grep for:
- `getReserves()`
- `token0()/token1()` with reserve calculations
- `balanceOf` used for pricing
- Missing `block.timestamp` checks in price calculations

## Fix Pattern

```solidity
// SECURE: Time-Weighted Average Price (TWAP) Oracle
contract TWAPOracle {
    struct Observation {
        uint32 blockTimestamp;
        uint256 price0Cumulative;
        uint256 price1Cumulative;
    }
    
    mapping(address => Observation) public pairObservations;
    uint32 public constant MIN_PERIOD = 30 minutes;  // Manipulation window
    
    function update(address pairAddress) external {
        IUniswapV2Pair pair = IUniswapV2Pair(pairAddress);
        (uint256 price0Cumulative, uint256 price1Cumulative, uint32 blockTimestamp) = 
            UniswapV2OracleLibrary.currentCumulativePrices(pairAddress);
            
        pairObservations[pairAddress] = Observation({
            blockTimestamp: blockTimestamp,
            price0Cumulative: price0Cumulative,
            price1Cumulative: price1Cumulative
        });
    }
    
    function consult(address pairAddress, uint256 amountIn) 
        external view returns (uint256 amountOut) 
    {
        Observation memory lastObs = pairObservations[pairAddress];
        
        (uint256 price0Cumulative, , uint32 blockTimestamp) = 
            UniswapV2OracleLibrary.currentCumulativePrices(pairAddress);
            
        uint32 timeElapsed = blockTimestamp - lastObs.blockTimestamp;
        require(timeElapsed >= MIN_PERIOD, "TWAP period too short");
        
        // Calculate time-weighted average
        uint256 priceAverage = (price0Cumulative - lastObs.price0Cumulative) / timeElapsed;
        amountOut = priceAverage * amountIn / (2**112);
    }
}

// Alternative: Use Chainlink or other decentralized oracles
function getPrice(address token) external view returns (uint256) {
    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt < STALENESS_THRESHOLD, "Stale price");
    require(price > 0, "Invalid price");
    return uint256(price);
}
```

## Real Examples

### PancakeBunny ($45M - May 2021)
- **Attack**: Borrowed 2.3M BNB via flash loan, swapped to skew BNB/USDT pool
- **Exploit**: Protocol read manipulated price, minted 7M BUNNY tokens
- **Root cause**: Single spot price source from PancakeSwap pool
- **Solodit**: https://solodit.xyz/issues/pancakebunny-flash-loan-attack

### Warp Finance ($7.7M - December 2020)
- **Attack**: Flash loaned DAI, deposited to Uniswap LP, used inflated LP value as collateral
- **Exploit**: Borrowed more stablecoins than actual collateral value
- **Root cause**: LP token valuation based on reserve ratios
- **Reference**: https://www.rekt.news/warp-finance-rekt/

### Harvest Finance ($33.8M - October 2020)
- **Attack**: Flash loan to manipulate USDC/USDT Curve pool price
- **Exploit**: Deposited at manipulated low price, withdrew at real price
- **Root cause**: fUSDC vault used spot Curve pool prices
- **Reference**: https://www.rekt.news/harvest-finance-rekt/

## Additional Mitigations

1. **Use Chainlink Price Feeds**: Aggregated from multiple off-chain sources
2. **Multi-source validation**: Require consensus from multiple oracles
3. **Price deviation checks**: Reject prices that deviate >X% from stored value
4. **Delay mechanisms**: Add time delays between price reads and value-sensitive operations
5. **Liquidity depth checks**: Verify pool has sufficient liquidity before trusting price
