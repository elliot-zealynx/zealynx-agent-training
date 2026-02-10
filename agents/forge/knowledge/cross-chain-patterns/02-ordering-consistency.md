# Pattern: Cross-Chain Ordering Consistency

**Category:** Cross-Chain Security / LayerZero Integration  
**Severity:** Medium-High  
**Chains:** Solana ↔ EVM (via LayerZero v2)  
**Last Updated:** 2026-02-04  
**Source:** Orderly Network Solana Vault (Sherlock, $56.5K, M-1)

## Root Cause

The sender and receiver have mismatched expectations about message ordering. The receiver enforces sequential nonce processing, but the sender doesn't request ordered delivery from the messaging layer. This creates a state where valid messages are rejected due to out-of-order arrival.

## Real-World Exploit

### Orderly Network — M-1: Missing Ordered Execution
- SolConnector (EVM) sends withdrawal messages with only `gas` and `value` options
- Missing: `addExecutorOrderedExecutionOption()` in LayerZero options
- Solana vault requires `params.nonce == inbound_nonce + 1` when `order_delivery = true`
- LayerZero delivers messages out of order → nonce mismatch → `InvalidInboundNonce` error
- Ledger already debited users on Orderly Chain → state inconsistency, funds locked

## Vulnerable Code Pattern

### EVM Sender (Missing Ordering)
```solidity
// ❌ VULNERABLE: Only gas/value options, no ordering
function withdraw(WithdrawDataSol calldata _data) external onlyLedger {
    bytes memory options = OptionsBuilder.newOptions()
        .addExecutorLzReceiveOption(
            msgOptions[uint8(MsgType.Withdraw)].gas,
            msgOptions[uint8(MsgType.Withdraw)].value
        );
    // Missing: .addExecutorOrderedExecutionOption()
    
    _lzSend(solEid, message, options, fee, address(this));
}
```

### Solana Receiver (Expects Ordering)
```rust
// Receiver assumes ordered delivery
if ctx.accounts.vault_authority.order_delivery {
    require!(
        params.nonce == ctx.accounts.vault_authority.inbound_nonce + 1,
        OAppError::InvalidInboundNonce
    );
}
```

## Impact Path

1. Multiple withdrawals happen in quick succession (nonce 5, 6, 7)
2. LZ delivers nonce 6 before nonce 5 (no ordering guarantee)
3. Solana vault: `6 != 4 + 1` → REJECTED
4. Nonce 5 arrives, succeeds: `5 == 4 + 1` ✓
5. Nonce 6 needs retry, may succeed: `6 == 5 + 1` ✓
6. But if nonce 7 arrived between 5 and 6's retry: cascading failures
7. On source chain, ledger already debited all three users
8. Cross-chain state inconsistency until manual resolution

## Detection Strategy

1. **Check both sides of the bridge:**
   ```bash
   # EVM side: Look for ordered execution option
   grep -n "OrderedExecution\|orderedExecution" contracts/*.sol
   
   # Solana side: Look for nonce enforcement
   grep -n "nonce.*+.*1\|order_delivery\|inbound_nonce" src/*.rs
   ```

2. **Consistency check:**
   - If receiver enforces `nonce == expected_nonce + 1` → sender MUST use ordered execution
   - If sender doesn't use ordered execution → receiver MUST handle out-of-order gracefully

3. **LayerZero v2 specific:**
   - Check `OptionsBuilder` calls for `addExecutorOrderedExecutionOption()`
   - Check `nextNonce()` implementation aligns with actual behavior

## Secure Fix

### Option A: Add Ordered Execution to Sender
```solidity
// ✅ SECURE: Include ordered execution option
bytes memory options = OptionsBuilder.newOptions()
    .addExecutorLzReceiveOption(gas, value)
    .addExecutorOrderedExecutionOption();  // Ensures ordering
```

### Option B: Handle Out-of-Order on Receiver
```rust
// ✅ SECURE: Buffer out-of-order messages
// (more complex, but doesn't depend on LZ ordering)
if params.nonce != vault_authority.inbound_nonce + 1 {
    // Store in pending buffer, process when gap fills
    store_pending_message(params)?;
    return Ok(());
}
```

## Audit Checklist

- [ ] If receiver enforces sequential nonces, sender requests ordered delivery
- [ ] If sender doesn't guarantee ordering, receiver handles out-of-order messages
- [ ] `nextNonce()` on both sides returns consistent expectations
- [ ] State updates on source chain are reversible if destination rejects the message
- [ ] Admin recovery mechanism exists for stuck/inconsistent states
- [ ] Rate of message sending vs processing capacity analyzed (burst scenarios)

## LayerZero v2 Integration Notes

- `addExecutorLzReceiveOption(gas, value)` — only sets execution params, NOT ordering
- `addExecutorOrderedExecutionOption()` — explicitly requests ordered delivery
- Without ordered execution, LZ relayer may process messages in any order
- The `_nextNonce()` function determines expected nonce but doesn't enforce delivery order
- Cross-chain nonce tracking must be symmetric: sender and receiver agree on strategy

## Related Patterns
- Pattern #01 (Cross-Chain Message Payload Binding) — message content vs on-chain accounts
- General: Any stateful cross-chain protocol where order matters (DEX fills, nonce-based vaults)
