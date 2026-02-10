# 🔧 Forge — Shadow Audit Report
**Date:** 2026-02-03 13:20 UTC  
**Contest:** Pump Science (Code4rena, Jan 15-23, 2025)  
**Chain:** Solana | **Language:** Rust (Anchor)  
**Prize Pool:** $20,000 USDC  
**Scope:** 25 contracts, 2,030 SLOC  
**Actual Results:** 2 High, 3 Medium, 8 Low/QA

---

## Contest Overview

Pump Science is a Solana bonding curve protocol for token fundraising. Key mechanics:
- Constant product bonding curve (x * y = k) for token launches
- Dynamic fee structure: 99% → linear decrease → 1% over ~250 slots (anti-sniping)
- Migration to Meteora DAMM when bonding curve completes (85 SOL raised)
- Whitelist system for curve creators
- LP token locking with claim authority

**Key files reviewed:**
- `swap.rs` (343 SLOC) — Token buying/selling with fee calculation
- `create_pool.rs` (323 SLOC) — Migration to Meteora pool
- `curve.rs` (289 SLOC) — Bonding curve math + fee formula
- `lock_pool.rs` (184 SLOC) — LP locking + escrow creation
- `global.rs` (141 SLOC) — Global settings/configuration

---

## Shadow Audit Findings

### Applying Knowledge Patterns

**Pattern scan methodology applied:**
1. ✅ Signer checks on all privileged operations
2. ✅ Owner checks before deserialization  
3. ✅ Account relationship constraints (has_one, seeds, mint matching)
4. ✅ Discriminator validation
5. ✅ CPI target validation
6. ✅ Post-CPI data reload
7. ✅ Initialization guards
8. 🆕 Mathematical boundary verification (fee formula)
9. 🆕 Rent-exemption accounting in balance comparisons

---

### Finding 1: PDA Front-Running on Lock Escrow (H-01) — ✅ CAUGHT

**My detection:** Pattern #01 (Basic Signer Bypass) + Pattern #07 (Account Reinitialization)

Scanning `lock_pool.rs` → CPI to Meteora's `create_lock_escrow`:
- `owner: UncheckedAccount<'info>` — **no signer constraint**
- PDA derived from `["lock_escrow", pool, owner]` — predictable seeds
- `init` constraint means it fails if account exists

**Analysis:** Anyone can call Meteora's `create_lock_escrow` directly (it's a separate program) with the expected pool + owner before Pump Science does. When Pump Science's `lock_pool` tries to create it via CPI, the `init` fails → **DoS on migration**.

**Knowledge pattern match:** Direct match to Pattern #01 grep: `grep -rn "UncheckedAccount.*owner"` would flag this. The CPI dimension adds nuance — the vulnerability is in how Pump Science relies on an external program's account creation without checking if it already exists.

**Severity assessment:** HIGH ✓ — Blocks migration entirely, funds could be stuck.

---

### Finding 2: Missing State Update in Setter (H-02) — ❌ MISSED

**Actual issue:** `Global::update_settings()` accepts `GlobalSettingsInput` with `migration_token_allocation` field but never writes it to the `Global` struct. The field stays at its default value forever.

**Why I missed it:** My pattern library focuses on Solana-specific attack vectors (signers, CPIs, PDAs). This is a **pure logic bug** — a forgotten field in a setter function. No amount of grep patterns would catch this without line-by-line code review comparing input struct fields to the update function body.

**Lesson extracted:** Need a new pattern: **"Incomplete Setter/Update Functions"**
- Detection: For every update/setter function, enumerate ALL fields in the input struct and verify each is written to the target struct
- Automated check: Compare `GlobalSettingsInput` fields vs `update_settings` body — any field present in input but absent from update body is a bug
- This is NOT a Solana-specific pattern — it's a general software defect that becomes critical in smart contracts because there's no "fix and redeploy" option

---

### Finding 3: Fee Calculation Before Price Adjustment (M-01) — ❌ MISSED

**Actual issue:** In `swap.rs`, `calculate_fee(exact_in_amount)` is called BEFORE `apply_buy()`. On the "last buy" (when remaining token reserves are exhausted), `apply_buy()` recalculates the actual SOL amount. But the fee was already computed on the original input amount → **incorrect fee charged**.

**Why I missed it:** This is an **ordering dependency** in the buy flow. My patterns focus on account validation, not on the temporal relationship between fee calculation and state mutation. The issue requires understanding the "last buy" edge case in the bonding curve math.

**Lesson extracted:** New pattern: **"Fee/Computation Ordering Dependencies"**
- In any swap/buy/sell function: verify that fees computed on input amounts still hold after state adjustments
- Especially check edge cases: first buy, last buy, boundary crossings
- If the protocol adjusts amounts post-fee-calculation, fees MUST be recalculated
- Related: Also check if the user has enough funds after recalculation

---

### Finding 4: Rent-Inclusive Invariant Check (M-02) — ⚠️ PARTIAL CATCH

**My detection:** Partial — I know about rent-exemption from Solana fundamentals but don't have a specific pattern for it in balance comparisons.

Scanning `curve.rs`:
```rust
let sol_escrow_lamports = sol_escrow.lamports();  // includes rent!
if sol_escrow_lamports < bonding_curve.real_sol_reserves {  // excludes rent!
```

**Analysis:** `lamports()` returns total balance (reserves + rent). `real_sol_reserves` tracks only business-logic SOL. The comparison `lamports >= reserves` will almost always pass because rent inflates the left side. This means the invariant check is weaker than intended — it won't catch actual balance shortfalls up to the rent amount (~0.002 SOL).

The commented-out code is a dead giveaway:
```rust
// let rent_exemption_balance = Rent::get()?.minimum_balance(...)
// let bonding_curve_pool_lamports = lamports - rent_exemption_balance;
```

**Severity assessment:** Medium ✓ — Invariant check is weakened but not completely broken.

**Lesson extracted:** New pattern: **"Rent-Exemption in Balance Comparisons"**
- Any time `account.lamports()` is compared to tracked reserves, verify rent is accounted for
- Look for commented-out rent code — it often means the developer intended to handle it but didn't
- Solana rent = ~0.002 SOL for typical accounts (2,039,280 lamports)

---

### Finding 5: Fee Formula Boundary Discontinuity (M-03) — ✅ CAUGHT

**My detection:** Mathematical boundary verification

Scanning `curve.rs` fee formula:
```rust
if slots_passed >= 150 && slots_passed <= 250 {
    let fee_bps = (-8_300_000_i64)
        .checked_mul(slots_passed as i64)?
        .checked_add(2_162_600_000)?
        .checked_div(100_000)?;
} else if slots_passed > 250 {
    sol_fee = bps_mul(100, amount, 10_000).unwrap();  // 1% = 100 bps
}
```

**Boundary check:** Plug slot=250 into Phase 2 formula:
`(-8,300,000 × 250 + 2,162,600,000) / 100,000 = 87,600,000 / 100,000 = 876 bps = 8.76%`

Phase 3 starts at slot 251: `100 bps = 1%`

**Result:** 8.76% → 1% = **7.76% discontinuity** at the phase boundary. The formula coefficients were miscalibrated.

**Knowledge pattern match:** Basic boundary value analysis. For any piecewise function, always verify that boundary values of adjacent phases match. Here, Phase 2 at slot 250 should produce 100 bps (1%), not 876 bps.

**Severity assessment:** Medium ✓ — Users pay incorrect fees during Phase 2, especially near the boundary.

---

## Performance Summary

| # | Finding | Severity | Caught? | Pattern Used | Notes |
|---|---------|----------|---------|-------------|-------|
| H-01 | Lock escrow DoS | High | ✅ YES | #01 Signer Bypass + CPI awareness | UncheckedAccount owner + PDA front-running |
| H-02 | Missing field update | High | ❌ NO | None (logic bug) | Need "Incomplete Setter" pattern |
| M-01 | Fee before price adjust | Medium | ❌ NO | None (ordering dep) | Need "Computation Ordering" pattern |
| M-02 | Rent in invariant | Medium | ⚠️ PARTIAL | General Solana knowledge | Commented code was the clue |
| M-03 | Fee formula boundary | Medium | ✅ YES | Math boundary verification | Basic boundary value testing |

### Metrics

- **True Positives (caught):** 2 (H-01, M-03)
- **Partial Catches:** 1 (M-02)
- **False Negatives (missed):** 2 (H-02, M-01)
- **False Positives:** 0

**Precision:** 100% (2/2 flagged were real)  
**Recall:** 40-60% (2-3 out of 5, depending on partial credit)  
**Conservative Recall:** 40% (2/5)  
**Generous Recall:** 60% (3/5 with M-02 partial)

---

## Key Lessons & New Patterns to Add

### 1. Incomplete Setter Functions (NEW PATTERN — from H-02)
**Category:** Logic Errors / State Management  
**Detection:** For every `update_*` / `set_*` function:
1. List ALL fields in the input struct
2. Verify each field is written to the target struct
3. Any input field not written = bug
**Automated grep:**
```bash
# Extract input struct fields, then check if each appears in update function body
```
**Priority:** HIGH — Simple bug, catastrophic impact in immutable programs

### 2. Fee/Computation Ordering Dependencies (NEW PATTERN — from M-01)
**Category:** Business Logic / Arithmetic  
**Detection:** In any swap/trade/buy function:
1. Identify where fees/costs are calculated
2. Identify where amounts may be adjusted (edge cases, boundaries, last-buy)
3. Verify fees are recalculated after ANY amount adjustment
4. Check edge cases: first operation, last operation, boundary crossings
**Priority:** HIGH — Common in bonding curve / AMM protocols

### 3. Rent-Exemption in Balance Comparisons (NEW PATTERN — from M-02)
**Category:** Solana-Specific / Arithmetic  
**Detection:** Whenever `account.lamports()` appears in comparison with tracked reserves:
1. Check if rent-exemption is subtracted
2. Look for commented-out rent handling code (dev intended but didn't implement)
3. Remember: `lamports()` = business_funds + rent
**Priority:** MEDIUM — Subtle but important for invariant checks

### 4. Piecewise Function Boundary Verification (NEW PATTERN — from M-03)
**Category:** Arithmetic / Math Verification  
**Detection:** For any piecewise/phase-based calculation:
1. Evaluate the formula at EVERY boundary point
2. Verify adjacent phases produce matching values at transitions
3. Test: first value, last value, boundary-1, boundary, boundary+1
**Priority:** MEDIUM — Catches miscalibrated formulas

---

## Gap Analysis: Knowledge Base vs. This Contest

| Knowledge Area | Coverage | Findings Caught | Gap |
|---------------|----------|----------------|-----|
| Signer/Access Control | ✅ Strong | H-01 | None — pattern worked |
| CPI Security | ✅ Strong | H-01 (partial) | Need CPI + PDA front-running combo |
| Logic Bugs (setters) | ❌ Missing | H-02 missed | Need general logic bug patterns |
| Ordering Dependencies | ❌ Missing | M-01 missed | Need computation ordering pattern |
| Rent Accounting | ⚠️ Partial | M-02 partial | Need explicit rent comparison pattern |
| Math Verification | ⚠️ Partial | M-03 caught | Boundary testing worked, formalize it |

**Overall assessment:** My Solana-specific security patterns (signer checks, CPI, PDAs) are solid. The gaps are in **general smart contract logic** (incomplete setters, ordering bugs) and **Solana-specific arithmetic** (rent accounting). These are the next categories to study.

---

## Next Steps
1. Create pattern files for the 4 new patterns identified
2. Add these to `/root/clawd/knowledge/rust/` as new categories
3. Next shadow audit: target a DeFi/AMM contest to practice arithmetic patterns
4. Prepare for Jupiter Lend contest (Feb 6) — lending protocols have heavy arithmetic
