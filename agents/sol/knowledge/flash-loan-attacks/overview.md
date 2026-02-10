# Flash Loan Attacks: Overview

## What Are Flash Loans?

Flash loans are uncollateralized loans that must be borrowed and repaid within a single atomic transaction. If the borrower fails to repay, the entire transaction reverts as if it never happened. This EVM-native primitive enables anyone to access unlimited capital for the cost of a transaction fee.

**Key characteristics:**
- No collateral required
- Must repay principal + fee in same transaction
- Atomic: all-or-nothing execution
- Available from Aave, dYdX, Uniswap, Balancer, and others

## Why Flash Loans Are Dangerous

Flash loans fundamentally change the threat model for smart contracts:

1. **Democratized whale power**: Any user can temporarily command $100M+ capital
2. **Risk-free attacks**: Failed attacks just revert, attacker loses only gas
3. **Amplification**: Small vulnerabilities become catastrophic when capital is unlimited
4. **Single-transaction exploits**: No time for monitoring systems to react

## The Universal Attack Pattern

Every flash loan attack follows three steps:

```
1. BORROW  → Acquire massive capital from flash loan provider
2. EXPLOIT → Manipulate prices, state, or governance with borrowed funds
3. REPAY   → Return loan + fee, pocket the profit
```

## Attack Categories

| Category | Description | Total Losses | Key Examples |
|----------|-------------|--------------|--------------|
| **Oracle Manipulation** | Skew AMM prices to affect protocol pricing | $200M+ | PancakeBunny, Warp, Harvest |
| **Token Callback Reentrancy** | Exploit ERC-777/1155 hooks | $50M+ | Cream Finance, imBTC |
| **Governance Takeover** | Acquire temporary voting power | $185M+ | Beanstalk, Build Finance |
| **Donation Attacks** | Manipulate share prices via balance inflation | $200M+ | Euler, Zunami, Wise Lending |
| **Business Logic** | Exploit complex multi-function interactions | $250M+ | Euler, Hundred, Platypus |

## Flash Loan Providers

| Protocol | Max Loan | Fee | Networks |
|----------|----------|-----|----------|
| Aave V3 | Pool liquidity | 0.05% | ETH, Polygon, Arbitrum, etc. |
| dYdX | Pool liquidity | 0 (2 wei) | Ethereum |
| Uniswap V3 | Pool liquidity | 0.3% swap fee | ETH, Polygon, Arbitrum, etc. |
| Balancer | Pool liquidity | 0% | ETH, Polygon, Arbitrum |

## Defense Principles

### 1. Never Trust Spot Prices
```solidity
// BAD: Spot price from AMM
uint256 price = reserve1 / reserve0;

// GOOD: TWAP or Chainlink
uint256 price = chainlinkFeed.latestRoundData();
```

### 2. Internal Accounting Over Balance Checks
```solidity
// BAD: Can be manipulated by donation
uint256 assets = token.balanceOf(address(this));

// GOOD: Track deposits internally
uint256 assets = totalDeposited;
```

### 3. Checks-Effects-Interactions Pattern
```solidity
// BAD: External call before state update
token.transfer(to, amount);
balance[msg.sender] -= amount;

// GOOD: State update before external call
balance[msg.sender] -= amount;
token.transfer(to, amount);
```

### 4. Timelock Critical Operations
```solidity
// BAD: Immediate governance execution
function execute(bytes calldata data) external {
    if (votes > quorum) target.call(data);
}

// GOOD: Enforce delay
function execute(uint256 proposalId) external {
    require(block.timestamp >= proposals[proposalId].executionTime);
    // ...
}
```

### 5. Reentrancy Protection
```solidity
// Always use on external functions
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Secure is ReentrancyGuard {
    function withdraw() external nonReentrant { ... }
}
```

## Audit Checklist for Flash Loan Resistance

- [ ] Price sources: TWAP, Chainlink, or multi-oracle consensus?
- [ ] Share calculations: Internal accounting or balanceOf?
- [ ] CEI pattern: All state updates before external calls?
- [ ] Reentrancy guards: On all external functions?
- [ ] Governance timelocks: Minimum 24-48h delays?
- [ ] Token hooks: ERC-777/1155 callback handling?
- [ ] First depositor: Dead shares or minimum deposit?
- [ ] Invariant checks: Critical properties asserted?
- [ ] Interest accrual: Atomic with position changes?
- [ ] Liquidation: Can't be self-liquidated profitably?

## Tools for Detection

1. **Slither**: Static analysis detectors for reentrancy, price manipulation
2. **Echidna**: Fuzzing with flash loan scenarios
3. **Foundry**: Write flash loan attack test cases
4. **DeFiHackLabs**: Repository of real attack reproductions

## Further Reading

- [Solodit Flash Loan Findings](https://solodit.xyz/search?q=flash%20loan)
- [DeFiHackLabs Repo](https://github.com/SunWeb3Sec/DeFiHackLabs)
- [Rekt News](https://www.rekt.news)
- [Chainlink TWAP Best Practices](https://blog.chain.link/flash-loans-and-the-importance-of-tamper-proof-oracles/)
