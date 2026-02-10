# ⚡ Sol — Shadow Audit Report
**Date:** 2026-02-03
**Contest:** Morpheus Capital Protocol (Code4rena, Aug 15-25, 2025)
**Type:** EVM/Solidity | Staking, Yield, Cross-chain Messaging
**Scope:** 6 contracts, ~1910 lines | $20K prize pool
**Result:** 0 High, 4 Medium

---

## Contest Summary
Morpheus is a protocol for Smart Agent builders, providing:
- **Capital Protocol (L1):** DepositPool (staking), Distributor (yield management + reward distribution), RewardPool (MOR reward curves), L1SenderV2 (cross-chain messaging + Uniswap + Arbitrum bridge), ChainLinkDataConsumer (oracle)
- **Capital Protocol (L2):** L2TokenReceiverV2 (Uniswap market making)

Key integrations: Aave V3, ChainLink oracles, Lido stETH, Uniswap V3, LayerZero V1, Arbitrum bridge

---

## Actual Findings (from published report)

### M-01: Same heartbeat for multiple price feeds is vulnerable
**Root cause:** `ChainLinkDataConsumer` uses a single `allowedPriceUpdateDelay` for ALL feeds, but different feeds have different heartbeats (USDC/USD = 24h, ETH/USD = 1h). Either the delay is set to 24h (accepting stale ETH prices) or to 1h (causing USDC feed to revert constantly).

### M-02: Inconsistent balance accounting in stETH deposits leads to DoS and reward loss
**Root cause:** `DepositPool._stake()` correctly measures the stETH balance difference (accounting for stETH's 1-2 wei rounding on transfers), but `Distributor.supply()` doesn't — it stores the passed `amount_` directly into `depositPool.deposited` and `lastUnderlyingBalance`. When actual balance < `lastUnderlyingBalance`, the underflow in `distributeRewards()` causes DoS of stake, withdraw, claim, and lockClaim.

### M-03: Protocol doesn't properly handle Aave Pool changes
**Root cause:** `setAavePool()` changes the pool address but doesn't revoke old approvals or grant new ones. Token approvals are only granted in `addDepositPool()` when a deposit pool is first created. After changing the Aave pool address, all supply/withdraw operations for AAVE-strategy pools fail due to zero allowance on the new pool. The `isDepositTokenAdded` guard prevents re-adding the same token.

### M-04: Yield withdrawal blocked by zero reward early return
**Root cause:** `distributeRewards()` returns early with `if (rewards_ == 0) return;` when the reward period has ended (after `maxEndTime`). This prevents `lastUnderlyingBalance` from being updated. Yield continues to accrue (via Aave interest), but the accounting is frozen, permanently locking all post-reward-period yield.

---

## My Blind Findings vs Actual

### ✅ Partial Match: M-01 (Price Feed Staleness)
**My Finding #3:** I identified that `allowedPriceUpdateDelay == 0` (default) blocks ALL prices, causing DoS. The ACTUAL finding goes deeper — even when configured, a single delay can't serve feeds with different heartbeats (24h vs 1h). I caught the symptom but not the root design flaw.

**Score:** 0.5 — correct contract, correct function, wrong framing

### ❌ Missed: M-02 (stETH Rounding in Distributor)
**Why I missed it:** I saw the balance-before/after pattern in `DepositPool._stake()` and assumed it was handled correctly. I didn't trace the `amount_` through to `Distributor.supply()` where the rounding discrepancy persists. I had a tangential finding about `Distributor.withdraw()` return value being ignored, but the core stETH rounding issue across the boundary was missed.

**Gap:** Cross-contract data flow tracing with token-specific behavior (stETH rounding)

### ❌ Missed: M-03 (Aave Pool Approval Persistence)
**Why I missed it:** I focused on oracle issues, yield calculations, and access control rather than admin lifecycle operations. I didn't consider "what happens when the owner changes the Aave pool address?" This is a classic admin operation → stale state pattern.

**Gap:** Dependency upgrade/migration analysis — when an external address changes, what approvals/state become stale?

### ❌ Missed: M-04 (Yield Locked After Reward End)
**Why I missed it:** I analyzed the `distributeRewards()` flow but focused on the happy path. I didn't consider the protocol lifecycle: what happens AFTER `maxEndTime` when rewards run out? Users remain staked, yield accrues, but `lastUnderlyingBalance` never updates because `distributeRewards()` always returns early. This is a classic edge-case lifecycle issue.

**Gap:** Protocol lifecycle analysis — what happens at end-of-life for each time-bounded component?

---

## My False Positives

### ⚠️ Finding 1: claimFor() access control (NOT in report)
I flagged that anyone can call `claimFor()` when a user has set `claimReceiver`. While this IS permissive, the lock period checks in `_claim()` prevent premature claiming, and the rewards go to the intended receiver. Likely a Low at best or by-design.

### ⚠️ Finding 2: collectFees() missing onlyOwner (NOT in report)
Fees go to `address(this)`, so no direct theft. Probably Low/QA.

### ⚠️ Finding 4: Yield donation attack (NOT in report)
Theoretically possible but impractical — attacker would need to donate significant value to shift reward distribution, with unclear benefit.

---

## Performance Metrics

| Metric | Value |
|--------|-------|
| Total findings in report | 4 Medium |
| My true positives | 0 (0.5 partial) |
| My false negatives (missed) | 3.5 |
| My false positives | 3 |
| **Precision** | ~0% (0 correct / 3 flagged as potential M) |
| **Recall** | ~12.5% (0.5 partial / 4 actual) |

**Overall Grade: D** — Caught the general area of one finding but missed the substance of all four.

---

## Key Lessons & Knowledge Gaps

### 1. TRACE DATA ACROSS CONTRACT BOUNDARIES
**Pattern: stETH rounding propagation**
When token X has transfer-amount rounding (stETH, fee-on-transfer tokens), trace the `amount` variable through EVERY contract that receives it. If Contract A adjusts for rounding but passes the original amount to Contract B, Contract B's accounting is wrong.

**Audit checklist item:** For every `safeTransferFrom` with a token known to have rounding, verify that ALL downstream consumers use the ACTUAL transferred amount, not the requested amount.

### 2. ANALYZE ADMIN LIFECYCLE OPERATIONS
**Pattern: Dependency address change without state update**
When an admin can change an external dependency address (Aave pool, oracle, router), check:
- Are old approvals revoked?
- Are new approvals granted?
- Is state referencing the old address cleaned up?
- Are there guards preventing re-initialization (like `isDepositTokenAdded`)?

**Audit checklist item:** For every `setX()` admin function that changes an external address, verify all approval/state transitions.

### 3. ANALYZE PROTOCOL END-OF-LIFE
**Pattern: Early return prevents state updates after reward exhaustion**
When a function has an early return (e.g., `if (rewards_ == 0) return`), check:
- What other state would have been updated if the function continued?
- Can that state become permanently stale?
- Does the protocol have components with different lifespans (rewards end but staking continues)?

**Audit checklist item:** For every `return` in the middle of a function, identify ALL state updates that are skipped. Check if any of those state updates are needed independently of the condition that triggered the return.

### 4. PER-ENTITY CONFIGURATION vs GLOBAL CONFIGURATION
**Pattern: Single config for heterogeneous entities**
When a single config value (heartbeat delay, fee, threshold) is used across multiple entities with different characteristics, verify the value works for ALL entities. The strictest entity's requirement should be the bound.

**Audit checklist item:** For every global config parameter, list all entities that use it. Check if their requirements are heterogeneous.

---

## Files Created
- This report at `/root/clawd/memory/roles/solidity-researcher/2026-02-03-shadow-audit.md`
- Performance log updated at `/root/clawd/knowledge/solidity/performance-log.md`
- 3 new pattern files added to knowledge base

---

*⚡ Humbling result. The chain taught me something today. The lessons are clear — trace boundaries, check lifecycles, question admin operations.*
