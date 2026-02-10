# Pattern: Piecewise Function Boundary Verification

**Category:** Arithmetic / Math Verification  
**Severity:** Medium  
**Chains:** All  
**Source:** Pump Science M-03 (Code4rena, Jan 2025)  
**Last Updated:** 2026-02-03  

## Root Cause

Protocol implements a piecewise/phased formula (fees, pricing, rewards) where different formulas apply to different ranges. The formula coefficients are miscalibrated, causing a discontinuity at phase boundaries — the end of one phase doesn't match the start of the next.

## Real-World Exploit

**Pump Science (Jan 2025)** — Fee structure has 3 phases:
- Phase 1 (slots 0-149): 99% fee
- Phase 2 (slots 150-250): Linear decrease from ~92% to ??? 
- Phase 3 (slots 251+): 1% fee

The linear formula at slot 250 produces **8.76%**, but Phase 3 starts at **1%** → a 7.76% discontinuity. Users could time transactions to avoid/exploit the fee cliff.

```rust
// ❌ Phase 2 endpoint doesn't match Phase 3 start
if slots_passed >= 150 && slots_passed <= 250 {
    let fee_bps = (-8_300_000_i64)
        .checked_mul(slots_passed as i64)?
        .checked_add(2_162_600_000)?
        .checked_div(100_000)?;
    // At slot 250: (-8300000 * 250 + 2162600000) / 100000 = 876 bps = 8.76%
} else if slots_passed > 250 {
    sol_fee = bps_mul(100, amount, 10_000)?;  // 100 bps = 1%
    // Jump from 8.76% to 1% — 7.76% discontinuity!
}
```

## Detection Strategy

### The Boundary Value Test
For ANY piecewise function, compute the value at EVERY boundary:

```
Phase boundary verification:
├── Phase 1 end value → should match Phase 2 start value
├── Phase 2 end value → should match Phase 3 start value
└── ... and so on for all phases
```

### Step-by-step:
1. **Identify all phase boundaries** (the threshold values)
2. **Evaluate each formula at its endpoints**
3. **Compare:** Does Phase N's last value ≈ Phase N+1's first value?
4. **If not:** The formula coefficients are wrong

### Example verification:
```
Phase 2 formula: fee_bps = (-8300000 * slot + 2162600000) / 100000

Expected: fee_bps(250) should equal 100 (to match Phase 3's 1%)
Actual:   fee_bps(250) = (-8300000 * 250 + 2162600000) / 100000
        = (-2075000000 + 2162600000) / 100000
        = 87600000 / 100000
        = 876 ≠ 100  ← BUG!

Correct formula would need:
(-X * 250 + Y) / 100000 = 100
AND (-X * 150 + Y) / 100000 = 9900

Solving: X = 9800000, Y = 2550100000
```

### Automated detection:
```bash
# Find piecewise/conditional math
grep -n "if.*slot\|if.*time\|if.*block\|if.*phase" src/ | grep -A 5 "else if\|else"
# For each: extract formula and boundary values, compute endpoints
```

## Secure Pattern

```rust
// ✅ SECURE: Formula calibrated to match boundaries
const PHASE1_END_BPS: u64 = 9900;   // 99% at slot 149
const PHASE3_START_BPS: u64 = 100;   // 1% at slot 251
const TRANSITION_START: u64 = 150;
const TRANSITION_END: u64 = 250;

if slots_passed < TRANSITION_START {
    fee_bps = PHASE1_END_BPS;
} else if slots_passed <= TRANSITION_END {
    // Linear interpolation: guaranteed to match at boundaries
    let progress = slots_passed - TRANSITION_START;      // 0 to 100
    let range = TRANSITION_END - TRANSITION_START;        // 100
    let bps_drop = PHASE1_END_BPS - PHASE3_START_BPS;    // 9800
    fee_bps = PHASE1_END_BPS - (bps_drop * progress / range);
    // At slot 150: 9900 - 0 = 9900 ✓ (matches Phase 1)
    // At slot 250: 9900 - 9800 = 100 ✓ (matches Phase 3)
} else {
    fee_bps = PHASE3_START_BPS;
}
```

## Variants

### Price curves with phase transitions
Same pattern in pricing: different formulas for different supply ranges.

### Reward decay schedules  
Emission rates that change at epoch/block boundaries.

### Vesting schedules
Cliff + linear vesting — verify the cliff amount matches the linear formula's start point.

## Audit Checklist

- [ ] Every piecewise function: evaluate at ALL boundary points
- [ ] Verify adjacent phases produce matching values at transitions
- [ ] Test: first value, last value, boundary-1, boundary, boundary+1
- [ ] Check integer division rounding near boundaries
- [ ] Use interpolation formulas that are DEFINED by their boundary values (inherently correct)
- [ ] Add unit tests that specifically assert boundary continuity
