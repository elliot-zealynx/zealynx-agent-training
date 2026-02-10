# Cross-Contract Reentrancy

**Category:** Reentrancy  
**Severity:** Critical  
**Last Updated:** 2026-02-03  
**Tags:** reentrancy, cross-contract, composability, multi-protocol, DeFi-integration

---

## Pattern Summary

Reentrancy exploited across contract boundaries — the attacker re-enters a DIFFERENT contract that shares state or depends on the calling contract's state. This is the hardest variant to detect because the vulnerability spans multiple codebases.

## Root Cause

In DeFi's composable architecture, contracts interact with each other and share trust assumptions. When Contract A makes an external call with incomplete state updates, Contract B (which trusts A's state) can be exploited through the reentrancy window.

## Historical Exploits

| Protocol | Date | Loss | Vector |
|----------|------|------|--------|
| PenPie (via Pendle) | Sep 2024 | $27M | Cross-contract reentrancy via fake Pendle market + reward harvesting |
| Fei Protocol | Apr 2022 | $80M | Cross-contract via Rari Fuse pools |
| Orion Protocol | Feb 2023 | $3M | Cross-contract via custom token with transfer callback |

## Vulnerable Architecture Pattern

```
┌──────────────────┐     ┌──────────────────┐
│   Protocol A     │     │   Protocol B     │
│   (Pendle)       │────▶│   (PenPie)       │
│                  │     │                  │
│  redeemRewards() │     │  harvestRewards()│
│  ↓ callback      │     │  reads A's state │
│  to B            │     │                  │
└──────────────────┘     └──────────────────┘
         │                        ▲
         │    Reentrancy window   │
         └────────────────────────┘
```

## PenPie Attack (September 2024 — $27M)

### Vulnerable Code Flow
```solidity
// PenPie's reward harvester — NO reentrancy guard
function _harvestBatchMarketRewards(address[] memory markets) internal {
    for (uint i = 0; i < markets.length; i++) {
        // Get token balances BEFORE
        uint256 balanceBefore = rewardToken.balanceOf(address(this));
        
        // Call into Pendle to redeem rewards
        // This triggers a callback to the market's SY contract
        IPendleMarket(markets[i]).redeemRewards(address(this));
        
        // Get token balances AFTER
        uint256 balanceAfter = rewardToken.balanceOf(address(this));
        
        // Reward = difference (attacker inflates this via reentrancy)
        uint256 reward = balanceAfter - balanceBefore;
        // ... distribute reward
    }
}
```

### Attack Steps
1. **Deploy malicious SY (Synthetic Yield) contract** — this is the callback vector
2. **Register fake Pendle market** using the malicious SY (Pendle's market creation was permissionless)
3. **Flash loan** large amounts of wstETH, sUSDe, egETH, rswETH
4. **Call `batchHarvestMarketRewards()`** on PenPie
5. **During `redeemRewards()` callback:** malicious SY contract deposits flash-loaned tokens into PenPie
6. **Balance inflation:** `balanceAfter - balanceBefore` shows massive "rewards" that are actually the attacker's own deposits
7. **Claim all rewards** — attacker is the only depositor in the fake market, gets everything
8. **Repay flash loans** — profit = $27M

## Detection Strategy

### Architecture Review
1. **Map all external contract calls** — where does your protocol call OUT to?
2. **Map all incoming calls** — what external protocols call IN to your functions?
3. **Identify trust boundaries** — what state do you trust from external protocols?
4. **Check permissionless registration** — can attackers register malicious contracts?

### Cross-Contract State Dependencies
```
For each external call in your protocol:
  1. What state is READ before the call?
  2. What state is WRITTEN after the call?
  3. Can any OTHER contract read that stale state during the call?
  4. Can the called contract trigger a callback to ANY of your functions?
```

### Red Flags
- Permissionless market/pool/strategy registration
- Balance-difference accounting (`balanceAfter - balanceBefore`)
- External calls to user-controlled addresses during reward calculations
- No reentrancy guards on harvest/claim/compound functions
- Protocol integrates with protocols that have callback mechanisms

## Fix / Remediation

### 1. Reentrancy Guards on ALL Sensitive Functions
```solidity
function _harvestBatchMarketRewards(address[] memory markets) 
    internal nonReentrant 
{
    // ...
}
```

### 2. Validate External Contracts
```solidity
// Whitelist approach — don't allow arbitrary contracts
require(isApprovedMarket[market], "Not approved");

// Or: verify contract code/interface before interaction
require(IPendleMarket(market).isVerified(), "Unverified market");
```

### 3. Pull-Over-Push for Rewards
```solidity
// Instead of push-based balance-difference accounting:
// Use explicit reward tracking
mapping(address => uint256) public pendingRewards;

function harvest(address market) external nonReentrant {
    uint256 reward = IMarket(market).claimReward(address(this));
    pendingRewards[msg.sender] += reward;
}

function claimRewards() external nonReentrant {
    uint256 amount = pendingRewards[msg.sender];
    pendingRewards[msg.sender] = 0;
    rewardToken.transfer(msg.sender, amount);
}
```

### 4. Snapshot Balances Atomically
```solidity
// If balance-difference is needed, prevent re-entry inflation
function harvest(address market) external nonReentrant {
    uint256 balBefore = token.balanceOf(address(this));
    IMarket(market).redeemRewards(address(this));
    uint256 balAfter = token.balanceOf(address(this));
    // nonReentrant prevents inflation during redeemRewards callback
}
```

## Key Takeaways

- **Cross-contract reentrancy is the most dangerous variant** — it crosses audit boundaries
- PenPie lost $27M despite having audits from 2 separate firms
- **Permissionless registration + callbacks = deadly combination**
- Audit scope MUST include integration points with external protocols
- Balance-difference accounting is inherently risky when external calls are involved
- Every yield aggregator, vault wrapper, and reward distributor is a potential target
