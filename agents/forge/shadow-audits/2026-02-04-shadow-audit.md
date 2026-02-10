# 🔧 Forge — Shadow Audit Report
**Date:** 2026-02-04 13:20 UTC  
**Contest:** Orderly Network Solana Vault (Sherlock, Contest #524, Sep-Oct 2024)  
**Chain:** Solana + EVM (Orderly Chain via LayerZero)  
**Language:** Rust (Anchor) + Solidity  
**Prize Pool:** $56,500 USDC  
**Scope:** Solana Vault program + SolConnector EVM contract  
**Actual Results:** 2 High, 1 Medium

---

## Contest Overview

Orderly Network's Solana Vault enables cross-chain USDC deposits and withdrawals between Solana and an OP Stack L2 (Orderly Chain) via LayerZero v2. Core mechanics:
- **Deposits:** User deposits USDC on Solana → LZ message → credited on Orderly Chain ledger
- **Withdrawals:** User initiates on Orderly Chain → LZ message → vault releases USDC on Solana
- **Token whitelisting:** Allowed tokens/brokers stored as PDA accounts
- **Nonce ordering:** Optional sequential nonce enforcement on both sides

**Key files reviewed:**
- `deposit.rs` (~120 SLOC) — Token deposit with cross-chain message
- `oapp_lz_receive.rs` (~250 SLOC) — LZ message handler for withdrawals
- `lib.rs` (~100 SLOC) — Program entry points
- `SolConnector.sol` (~120 SLOC) — EVM-side message sender
- `allowed_token.rs` (~12 SLOC) — Token whitelist state
- `errors.rs` (~30 SLOC) — Error definitions

---

## Shadow Audit Findings

### Applying Knowledge Patterns

**Pattern scan methodology applied:**
1. ✅ Signer checks on all privileged operations
2. ✅ Account data matching (mint/owner relationships)
3. ✅ Owner checks before deserialization
4. ✅ Account relationship constraints (has_one, seeds, constraints)
5. ✅ Discriminator validation (Anchor handles)
6. ✅ CPI target validation
7. ✅ Post-CPI data reload
8. ✅ PDA seed verification
9. 🆕 Cross-chain message integrity verification
10. 🆕 LayerZero integration pattern analysis

---

### Finding 1: Missing Deposit Token Validation (H-1) — ✅ CAUGHT

**My detection:** Pattern #04 (Account Data Matching Failure) — direct hit

Scanning `deposit.rs` → Account struct analysis:
```rust
#[account()]
pub deposit_token: Box<Account<'info, Mint>>,

#[account(
    seeds = [TOKEN_SEED, deposit_params.token_hash.as_ref()],
    bump = allowed_token.bump,
    constraint = allowed_token.allowed == true @ VaultError::TokenNotAllowed
)]
pub allowed_token: Box<Account<'info, AllowedToken>>,
```

**Critical gap identified:** `deposit_token` has NO constraint linking it to `allowed_token.mint_account`. The `allowed_token` state struct has a `mint_account: Pubkey` field (confirmed in `allowed_token.rs`), but the Deposit account validation never enforces `deposit_token.key() == allowed_token.mint_account`.

**Attack path:**
1. Attacker creates a worthless token (e.g., "SCAM" mint)
2. Calls `deposit()` with:
   - `deposit_token` = SCAM mint address
   - `deposit_params.token_hash` = hash of USDC (known/public)
3. `allowed_token` PDA validates: seeded correctly ✓, `allowed == true` ✓
4. But `deposit_token` is SCAM, not USDC — no check blocks this
5. Transfer succeeds: SCAM tokens go to vault
6. LZ message says USDC was deposited (because `token_hash` = USDC hash)
7. Attacker credited with USDC on Orderly Chain

**Pattern match:** Direct match to Pattern #04 audit checklist item: "Every token account has mint and owner/authority constraints" — the `deposit_token` fails this check. The `user_token_account` and `vault_token_account` are associated with `deposit_token`, but `deposit_token` itself isn't bound to `allowed_token.mint_account`.

**Missing constraint:**
```rust
#[account(
    constraint = deposit_token.key() == allowed_token.mint_account @ VaultError::InvalidDepositToken
)]
pub deposit_token: Box<Account<'info, Mint>>,
```

**Severity assessment:** HIGH ✓ — Complete fund drain. Attacker deposits worthless tokens, gets credited with USDC.

---

### Finding 2: Unauthorized Withdrawal Redirection (H-2) — ✅ CAUGHT

**My detection:** Pattern #01 (Basic Signer Bypass) — `/// CHECK` on `user` account

Scanning `oapp_lz_receive.rs` → Account struct:
```rust
/// CHECK
#[account()]
pub user: AccountInfo<'info>,

#[account(
    mut,
    associated_token::mint = deposit_token,
    associated_token::authority = user
)]
pub user_deposit_wallet: Account<'info, TokenAccount>,
```

**Critical gap identified:** The `user` account is `AccountInfo<'info>` with `/// CHECK` and NO constraints whatsoever. The `user_deposit_wallet` is derived from `user`, so whoever controls which `user` account is passed controls where funds go.

The withdrawal payload contains a `receiver: [u8; 32]` field:
```rust
pub struct AccountWithdrawSol {
    pub account_id: [u8; 32],
    pub sender: [u8; 32],
    pub receiver: [u8; 32],  // intended recipient
    // ...
}
```

But the code NEVER validates that `user.key()` matches `withdraw_params.receiver`:
```rust
let withdraw_params = AccountWithdrawSol::decode_packed(&lz_message.payload).unwrap();
let vault_authority_seeds = &[VAULT_AUTHORITY_SEED, &[ctx.accounts.vault_authority.bump]];
let amount_to_transfer = withdraw_params.token_amount - withdraw_params.fee;
transfer(
    ctx.accounts.transfer_token_ctx().with_signer(&[&vault_authority_seeds[..]]),
    amount_to_transfer,
)?;
```

**Attack path:**
1. User B initiates withdrawal on Orderly Chain → LZ message sent to Solana
2. Attacker (User A) front-runs the `lz_receive` call on Solana
3. Passes `user = Attacker's pubkey` instead of User B's
4. `user_deposit_wallet` resolves to Attacker's ATA
5. Vault transfers USDC to Attacker
6. User B's funds stolen

The `payer: Signer` only pays for the transaction — it doesn't prove they're the rightful recipient. The vault authority PDA seeds are shared (`VAULT_AUTHORITY_SEED` + bump), so the signing authority is the same regardless of who calls.

**Pattern match:** Direct hit on Pattern #01 checklist: "`AccountInfo<'info>` is never used where `Signer<'info>` is appropriate" — but more precisely this is an account relationship gap. The `user` should be constrained against the withdrawal message payload.

**Severity assessment:** HIGH ✓ — Direct theft of withdrawal funds.

---

### Finding 3: Missing LayerZero Ordered Execution Option (M-1) — ✅ CAUGHT

**My detection:** Cross-chain protocol integrity analysis

Scanning `SolConnector.sol` → `withdraw()` function:
```solidity
bytes memory withdrawOptions = OptionsBuilder.newOptions().addExecutorLzReceiveOption(
    msgOptions[uint8(MsgCodec.MsgType.Withdraw)].gas,
    msgOptions[uint8(MsgCodec.MsgType.Withdraw)].value
);
```

Only `addExecutorLzReceiveOption` is used — sets gas/value for execution. But `addExecutorOrderedExecutionOption()` is **absent**.

Meanwhile on Solana (`oapp_lz_receive.rs`):
```rust
if ctx.accounts.vault_authority.order_delivery {
    require!(
        params.nonce == ctx.accounts.vault_authority.inbound_nonce + 1,
        OAppError::InvalidInboundNonce
    );
}
```

And the `initialize()` sets `orderDelivery = true` by default.

**Inconsistency:** The Solana vault REQUIRES sequential nonces (`inbound_nonce + 1`), but the EVM sender doesn't request ordered delivery from LayerZero. Without the ordered execution option, LayerZero may deliver messages out of order.

**Impact path:**
1. User A withdraws → nonce 5
2. User B withdraws → nonce 6
3. LZ delivers nonce 6 first (no ordering guarantee)
4. Solana vault: `6 != inbound_nonce(4) + 1` → `InvalidInboundNonce` error
5. Nonce 6 fails. When nonce 5 arrives and succeeds, nonce 6 needs retry
6. Ledger on Orderly Chain already debited both users
7. State inconsistency — funds locked until admin intervention

**Not from a stored pattern** — caught via cross-chain integration logic analysis. This is a **consistency gap** between the sender's options and the receiver's expectations.

**Severity assessment:** MEDIUM ✓ — DoS/funds-lock for users, requires admin intervention to resolve.

---

## Performance Summary

| # | Finding | Severity | Caught? | Pattern Used | Notes |
|---|---------|----------|---------|-------------|-------|
| H-1 | Missing deposit token validation | High | ✅ YES | #04 Account Data Matching | `deposit_token` not bound to `allowed_token.mint_account` |
| H-2 | Unauthorized withdrawal redirect | High | ✅ YES | #01 Signer Bypass + `///CHECK` | `user` account unchecked, not bound to payload `receiver` |
| M-1 | Missing LZ ordered execution | Medium | ✅ YES | Cross-chain analysis | Sender options inconsistent with receiver nonce requirements |

### Metrics

- **True Positives (caught):** 3 (H-1, H-2, M-1)
- **False Negatives (missed):** 0
- **False Positives:** 0

**Precision:** 100% (3/3 flagged were real)
**Recall:** 100% (3/3 actual findings caught)

---

## Key Takeaways

### Why This Went Better Than Pump Science (40% → 100%)

1. **Stored patterns directly applied.** Pattern #04 (Account Data Matching) was a direct hit for H-1. Pattern #01 (Signer Bypass) caught H-2. These patterns were built from the initial knowledge mining sessions.

2. **Smaller, focused codebase.** The Orderly vault had ~500 SLOC total scope vs Pump Science's 2,030 SLOC. Fewer files = deeper analysis per file.

3. **Classic vulnerability types.** Both Highs are textbook Solana access control bugs — missing constraints on account relationships. These are the bread and butter of signer/validation patterns.

4. **Cross-chain scope added value.** The Medium required understanding LayerZero's execution model, not just Solana patterns. This is a new dimension worth formalizing.

### Patterns That Delivered

| Pattern | Finding Caught | Why It Worked |
|---------|---------------|---------------|
| #04 Account Data Matching | H-1 | "Could an attacker substitute a different but valid account here?" — yes, any Mint passes |
| #01 Basic Signer Bypass | H-2 | `/// CHECK` on `AccountInfo` in a withdrawal context = immediate red flag |

### New Pattern to Add

**Cross-Chain Message Binding (NEW PATTERN)**
- **Category:** Cross-Chain / LayerZero Integration
- **Detection:** When a cross-chain message contains recipient/destination data, verify it's bound to the on-chain accounts handling the funds
- **Specifically:** If a withdrawal message has `receiver`, the on-chain `user` account MUST be constrained to match
- **Also:** Verify sender and receiver ordering options are consistent (if receiver requires ordered delivery, sender must request it)

---

## Gap Analysis

| Knowledge Area | Coverage | Findings Caught | Status |
|---------------|----------|----------------|--------|
| Signer/Access Control | ✅ Strong | H-2 | Pattern library working |
| Account Data Matching | ✅ Strong | H-1 | Direct hit |
| Cross-Chain Integration | ⚠️ New | M-1 | Need formalized patterns |
| PDA Security | ✅ Strong | (not needed here) | Covered from morning mining |
| Arithmetic | ✅ Covered | (no arithmetic bugs) | Not tested this round |

**Overall assessment:** The core Solana security pattern library (signer checks, account validation, PDA) is proving solid for access control bugs. The gap is in cross-chain integration patterns — need to formalize LayerZero-specific checks.

---

## Next Steps
1. Create cross-chain message binding pattern in `/root/clawd/knowledge/rust/`
2. Add LayerZero integration checklist (options consistency, nonce ordering, message payload validation)
3. Target a larger DeFi contest next (AMM/lending) to test arithmetic patterns
4. Jupiter Lend (Feb 6) will be ideal for this

---
*Memory safe, as always. The forge doesn't rust.* 🔧
