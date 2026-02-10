# Callback Gas DoS from Quadratic/Cubic Loops

**Severity:** High
**Category:** Gas / DoS
**Source:** Megapot C4 Contest (Nov 2025, H-02), 8 wardens found it

## Pattern
When an external callback (e.g., VRF/entropy callback, oracle callback):
1. Contains loops with complexity O(n*m) or worse
2. Where n or m are dynamic parameters that grow with protocol state
3. And the callback has a gas limit set by the external provider

Then as the protocol grows, the callback can exceed the gas limit, permanently bricking the operation.

## Key Elements
- **External callbacks have gas budgets** — Chainlink VRF, Pyth Entropy, etc. set gas limits
- **Growing parameters** — bonusballMax, number of tiers, number of assets, etc.
- **Redundant computation** — Generating same subsets repeatedly inside nested loops

## Detection Checklist
1. Find all external callbacks (VRF, oracle, entropy, keeper)
2. Trace the computation inside: are there nested loops?
3. What determines loop bounds? Are they dynamic/growing?
4. Calculate worst-case gas for realistic parameter values
5. Compare against chain gas limits (Base: 25M, Ethereum: 30M)

## Mitigation
- Cache expensive computations outside the inner loop
- Set hard limits on dynamic parameters
- Split settlement into multiple transactions
- Pre-compute results off-chain with proof verification

## Real-World Instance
```solidity
// VULNERABLE: TicketComboTracker._countSubsetMatches()
for (uint8 i = 1; i <= _tracker.bonusballMax; i++) {           // O(bonusballMax)
    for (uint8 k = 1; k <= _tracker.normalTiers; k++) {        // O(5)
        uint256[] memory subsets = Combinations.generateSubsets(  // EXPENSIVE - regenerated every iteration!
            _normalBallsBitVector, k);
        for (uint256 l = 0; l < subsets.length; l++) {          // O(C(5,k))
            // storage reads...
        }
    }
}
// Total: bonusballMax * 5 * 31 = ~20,000 iterations for bonusballMax=129
// Gas: 25.8M (exceeds Base chain's 25M limit)

// FIX: Cache subsets outside the bonusball loop
uint256[][] memory subsetsArr = new uint256[][](_tracker.normalTiers);
for (uint i; i < _tracker.normalTiers; i++) {
    subsetsArr[i] = Combinations.generateSubsets(_normalBallsBitVector, i + 1);
}
// Reduces to 15.7M gas
```
