# Pattern: Early Return Blocks Critical State Updates

**Severity:** Medium-High
**Source:** Morpheus Capital Protocol (C4, Aug 2025) — M-04
**Category:** Logic / State Management / Lifecycle

## Description
A function with an early `return` (or `revert`) based on one condition skips state updates that are needed independently of that condition. When the triggering condition becomes permanent (e.g., rewards exhausted), the state becomes permanently stale.

## Vulnerable Pattern
```solidity
function distributeRewards(uint256 poolIndex) public {
    uint256 rewards = rewardPool.getPeriodRewards(poolIndex, lastTimestamp, block.timestamp);
    
    if (rewards == 0) return; // ❌ EARLY RETURN — skips everything below
    
    lastTimestamp = block.timestamp; // State update skipped
    
    // Update balance accounting — ALSO skipped
    for (uint i = 0; i < pools.length; i++) {
        uint256 balance = token.balanceOf(address(this));
        pools[i].lastBalance = balance; // ❌ Never updated after rewards end
    }
    
    // Distribute rewards
    // ...
}
```

After `maxEndTime`, `getPeriodRewards()` returns 0 forever. But yield continues accruing. The `lastBalance` is never updated, so:
- `yield = currentBalance - lastBalance` grows but is never recognized
- `_withdrawYield()` calculates yield from stale `lastBalance`
- If `_withdrawYield` depends on `distributeRewards` being called first, yield is permanently locked

## Detection Strategy
1. Find ALL `return` statements in the middle of functions
2. For each early return, identify ALL state updates that are skipped
3. Ask: "Is any skipped state update needed INDEPENDENTLY of the return condition?"
4. Ask: "Can the return condition become permanently true?" (exhausted rewards, paused state, etc.)
5. Check: Does any other function depend on the skipped state being up-to-date?

## Fix Pattern
```solidity
function distributeRewards(uint256 poolIndex) public {
    // Always update balance accounting
    for (uint i = 0; i < pools.length; i++) {
        uint256 balance = token.balanceOf(address(this));
        pools[i].lastBalance = balance; // ✅ Updated regardless of rewards
    }
    
    uint256 rewards = rewardPool.getPeriodRewards(poolIndex, lastTimestamp, block.timestamp);
    if (rewards == 0) return; // Now safe — balance accounting already done
    
    lastTimestamp = block.timestamp;
    // Distribute rewards...
}
```

Or: add a separate function for balance updates that doesn't depend on rewards.

## Lifecycle Analysis Framework
For every time-bounded component, ask:
- **Before start:** What happens if called before payout begins?
- **During active period:** Normal operation
- **After end:** What happens when rewards/emissions run out?
  - Can users still interact (stake/unstake/claim)?
  - Does yield still accrue?
  - Are accounting updates still possible?
  - What state becomes permanently frozen?

## Real-World Examples
- Morpheus M-04: yield locked after reward distribution ends
- Any protocol with emission schedules + continuing staking
- Liquidity mining programs that expire but LPs remain
