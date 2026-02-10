# Pool Cap Bypass via Organic Earnings Growth

**Severity:** High
**Category:** Invariant Violation / Accounting
**Source:** Megapot C4 Contest (Nov 2025, H-03), 2 wardens found it

## Pattern
When a protocol:
1. Enforces a pool/cap limit on deposits (e.g., `lpPoolTotal + pendingDeposits <= poolCap`)
2. Does NOT enforce the same cap after earnings-driven growth during settlement
3. The cap exists to maintain a safety invariant (e.g., bit packing limits, bonusball max)

Then after profitable periods (no winners claiming prizes), the pool naturally grows beyond the cap, breaking downstream invariants.

## Key Insight
**Always check both directions in accounting invariants:**
- Underflow: Can the value go below zero? (Solidity 0.8 protects against this)
- Overflow: Can the value exceed a safe upper bound? (Often missed!)

Pool caps enforced on deposits are useless if earnings can push the pool above the cap without any deposit.

## Detection Checklist
1. Is there a cap enforced on deposits/inflows?
2. Are there earnings/profits that bypass the cap check?
3. Does exceeding the cap break any downstream invariant?
4. How fast can the pool grow through earnings? (e.g., LP edge = 30% per draw)

## Mitigation
- Enforce caps in settlement/earnings distribution too
- Cap the newLPValue in `processDrawingSettlement()` to the pool cap
- Alternatively, redistribute excess earnings to prevent cap breach

## Real-World Instance
```solidity
// VULNERABLE: JackpotLPManager.processDrawingSettlement()
// Cap enforced on deposits:
//   lpPoolTotal + pendingDeposits <= lpPoolCap  ✅
// But NOT enforced on earnings:
//   newLPValue = postDrawLpValue + pendingDeposits - withdrawalsInUSDC  ❌ no cap check
// If lpEdgeTarget = 30% and no winners, pool grows 30% per draw, exceeding cap
```

## Downstream Impact in Megapot
When pool exceeds calculated safe limit:
- `bonusballMax` calculation: `ceil(minTickets / combosPerBonusball)` yields value > 255 - normalBallMax
- Bit packing in `TicketComboTracker.insert()`: `1 << (bonusball + normalMax)` overflows uint256
- Ticket purchases with max bonusball revert, creating unfair betting
