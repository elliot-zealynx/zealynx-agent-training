# Callback/Hook Reentrancy

**Category:** Reentrancy  
**Severity:** Critical  
**Last Updated:** 2026-02-03  
**Tags:** reentrancy, callback, hook, burn-hook, ERC-777, ERC-721, ERC-1155, safeTransfer

---

## Pattern Summary

Token standards and protocol-level hooks (burn hooks, mint hooks, transfer callbacks) create re-entry points that are often overlooked. When a contract calls a hook or callback during token operations, the hook recipient can re-enter before state is fully updated.

## Root Cause

Protocol design includes callback mechanisms (for extensibility) that execute user-controlled code during critical state transitions. If state updates are split around the callback, the callback executes with inconsistent state.

## Historical Exploits

| Protocol | Date | Loss | Vector |
|----------|------|------|--------|
| CloberDEX | Dec 2024 | $501K (133.7 ETH) | `_burn()` function's `burnHook` callback before reserve updates |
| imBTC/Uniswap | Apr 2020 | $300K | ERC-777 `tokensReceived` hook |
| HypeBears NFT | Feb 2022 | ? | ERC-721 `onERC721Received` during mint |
| C.R.E.A.M. Finance | Aug 2021 | $18.8M | AMP token ERC-777 callback |
| Akropolis | Nov 2020 | $2M | ERC-777 token deposit callback |

## Vulnerable Code Pattern (CloberDEX Style)

```solidity
function _burn(address user, uint256 shareAmount) internal {
    // Calculate withdrawal amounts based on current reserves
    uint256 withdrawalA = (shareAmount * pool.reserveA) / totalShares;
    uint256 withdrawalB = (shareAmount * pool.reserveB) / totalShares;
    
    // Burn shares
    totalShares -= shareAmount;
    
    // Transfer tokens to user BEFORE updating reserves
    bookKeyA.quote.transfer(user, withdrawalA);  // ← External call
    bookKeyA.base.transfer(user, withdrawalB);   // ← External call
    
    // Execute burn hook — user-controlled callback!
    strategy.burnHook(user, shareAmount);  // ← RE-ENTRY POINT
    
    // Update reserves AFTER transfers and hooks — TOO LATE
    pool.reserveA -= withdrawalA;
    pool.reserveB -= withdrawalB;
}
```

## Common Callback Re-entry Vectors

### ERC-777 `tokensReceived`
```solidity
// ERC-777 automatically calls tokensReceived on recipient
// If your contract receives ERC-777 tokens, the sender gets a callback
IERC777(token).send(recipient, amount, "");
// → recipient.tokensReceived() is called DURING the transfer
```

### ERC-721 `onERC721Received`
```solidity
// safeTransferFrom calls onERC721Received on recipient
_safeMint(to, tokenId);  // → to.onERC721Received() callback
// Any state depending on totalSupply is stale during callback
```

### ERC-1155 `onERC1155Received`
```solidity
_safeTransferFrom(from, to, id, amount, data);
// → to.onERC1155Received() callback
```

### Protocol-Level Hooks
```solidity
// Custom hooks in DeFi protocols
strategy.burnHook(user, amount);   // CloberDEX
pool.afterSwap(params);            // Uniswap V4 hooks
receiver.onFlashLoan(...)          // ERC-3156 flash loan
```

## Attack Flow (CloberDEX)

1. Attacker deploys malicious strategy contract registered with CloberDEX
2. Attacker calls burn on the vault to withdraw LP
3. `_burn()` calculates `withdrawalA` and `withdrawalB` based on current reserves
4. Tokens are transferred to attacker
5. `burnHook` calls attacker's malicious strategy contract
6. **In the hook callback:** Attacker re-enters to burn MORE, and reserves haven't been updated yet
7. Each re-entrant burn calculates withdrawals based on ORIGINAL (inflated) reserves
8. Attacker drains significantly more than their share
9. **Total loss: 133.7 ETH (~$501K)**

## Detection Strategy

### Audit Checklist
- [ ] Identify ALL external calls that could trigger user-controlled code
- [ ] For each: check if ALL related state updates happen BEFORE the call
- [ ] Map ALL hook/callback mechanisms in the protocol
- [ ] Check ERC-777 compatibility — does the protocol receive any ERC-777 tokens?
- [ ] Check `safeMint`, `safeTransferFrom` (ERC-721/1155) — callbacks before state finalization?
- [ ] Custom protocol hooks (afterSwap, burnHook, onDeposit, etc.)

### Static Analysis
- Search for: `safeTransfer`, `safeMint`, `onERC721Received`, `tokensReceived`, `onERC1155Received`
- Any function with "hook", "callback", "notify" in its name
- External calls to user-provided addresses (strategy contracts, receivers)

### Red Flags
- Protocol allows users to register custom strategy/handler contracts
- Token operations use `safe*` variants with callbacks
- Hook/callback functions are called between state reads and state writes

## Fix / Remediation

### 1. CEI — Update State Before Callbacks
```solidity
function _burn(address user, uint256 shareAmount) internal {
    uint256 withdrawalA = (shareAmount * pool.reserveA) / totalShares;
    uint256 withdrawalB = (shareAmount * pool.reserveB) / totalShares;
    
    // Effects FIRST — update ALL state
    totalShares -= shareAmount;
    pool.reserveA -= withdrawalA;
    pool.reserveB -= withdrawalB;
    
    // Interactions LAST — transfers and hooks
    bookKeyA.quote.transfer(user, withdrawalA);
    bookKeyA.base.transfer(user, withdrawalB);
    strategy.burnHook(user, shareAmount);
}
```

### 2. Reentrancy Guard on Hook-Containing Functions
```solidity
function _burn(address user, uint256 shareAmount) internal nonReentrant {
    // Even if CEI is perfect, guard prevents re-entry
    ...
}
```

### 3. Validate Hook Contracts
```solidity
// Whitelist allowed strategy contracts
require(isApprovedStrategy[address(strategy)], "Unapproved strategy");
// Limit gas forwarded to hooks
strategy.burnHook{gas: 50000}(user, shareAmount);
```

## Key Takeaways

- **Every hook/callback is a re-entry vector** — treat them with the same suspicion as `call{value:}`
- ERC-777 tokens are especially dangerous — any contract receiving them gets a callback
- `safeMint` and `safeTransferFrom` (ERC-721/1155) include callbacks that many devs forget about
- Protocol-level hooks (Uniswap V4, custom strategies) are the **new frontier** of callback reentrancy
- **CloberDEX lost $501K in Dec 2024** — this is not a theoretical risk
