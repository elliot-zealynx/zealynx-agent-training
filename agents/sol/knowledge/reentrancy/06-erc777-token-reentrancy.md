# ERC-777 Token Transfer Reentrancy

**Category:** Reentrancy  
**Severity:** High/Critical  
**Last Updated:** 2026-02-03  
**Tags:** reentrancy, ERC-777, tokensReceived, tokensToSend, token-hooks, DeFi

---

## Pattern Summary

ERC-777 tokens include built-in hooks (`tokensToSend` and `tokensReceived`) that execute recipient/sender code during every transfer. Any protocol that handles ERC-777 tokens without reentrancy protection is vulnerable — the token transfer itself becomes the re-entry vector.

## Root Cause

ERC-777's hook mechanism calls user-registered contracts (via ERC-1820 registry) during token transfers. If a protocol performs an ERC-777 token transfer before updating state, the hook gives the recipient control flow to re-enter.

## Historical Exploits

| Protocol | Date | Loss | Chain |
|----------|------|------|-------|
| imBTC/Uniswap V1 | Apr 2020 | ~$300K | Ethereum |
| Lendf.Me | Apr 2020 | $25M | Ethereum |
| C.R.E.A.M. Finance | Aug 2021 | $18.8M | Ethereum |
| Akropolis | Nov 2020 | $2M | Ethereum |

## ERC-777 Hook Mechanism

```
Token.send(recipient, amount)
  │
  ├─ 1. Call sender's tokensToSend hook (if registered)
  │     → Sender gets callback BEFORE tokens move
  │
  ├─ 2. Update balances
  │
  └─ 3. Call recipient's tokensReceived hook (if registered)
        → Recipient gets callback AFTER tokens arrive
        → THIS IS THE RE-ENTRY POINT
```

## Vulnerable Code Pattern

```solidity
// Uniswap V1 style — vulnerable to ERC-777 reentrancy
function tokenToEthSwap(uint256 tokenAmount, uint256 minEth) external {
    uint256 ethAmount = getPrice(tokenAmount);
    
    // Transfer tokens FROM user (triggers tokensToSend on user)
    // If token is ERC-777, user gets a callback HERE
    token.transferFrom(msg.sender, address(this), tokenAmount);
    
    // Send ETH to user  
    (bool success, ) = msg.sender.call{value: ethAmount}("");
    require(success);
    
    // Price is calculated based on reserves that haven't been
    // updated yet during the tokensToSend callback
}
```

```solidity
// Lending protocol deposit — vulnerable
function deposit(uint256 amount) external {
    // Transfer ERC-777 token — triggers tokensToSend on sender
    token.transferFrom(msg.sender, address(this), amount);
    
    // During tokensToSend callback, attacker can call deposit again
    // with the same tokens (they haven't been transferred yet in
    // the first call's context)
    
    shares[msg.sender] += calculateShares(amount);
    totalDeposited += amount;
}
```

## Attack Flow (imBTC/Uniswap V1)

1. imBTC is an ERC-777 token
2. Attacker registers a `tokensToSend` hook via ERC-1820 registry
3. Attacker calls `tokenToEthSwap()` on Uniswap V1
4. Uniswap calls `imBTC.transferFrom()` → triggers attacker's `tokensToSend` hook
5. In the hook, attacker calls `tokenToEthSwap()` AGAIN
6. Reserves haven't been updated — attacker gets the same favorable exchange rate
7. Repeated re-entry drains the ETH in the pool

## Detection Strategy

### Token Analysis
```
For every token the protocol interacts with:
1. Is it ERC-777 compatible?
2. Does it have transfer hooks?
3. Check: does the token implement IERC777?
4. Check: does the token register with ERC-1820 registry?
5. Even "normal" ERC-20 tokens might be ERC-777 (backward compatible)
```

### Code Patterns to Flag
- `transferFrom()` or `transfer()` before state updates
- No reentrancy guards on deposit/swap/liquidation functions
- Protocol doesn't check token type before interaction
- Any function that reads `balanceOf` before and after a transfer

### Slither Detectors
- `reentrancy-eth` — catches some ERC-777 patterns
- Custom detector for `transferFrom` before state writes

## Fix / Remediation

### 1. CEI Pattern (Always)
```solidity
function deposit(uint256 amount) external nonReentrant {
    // Effects FIRST
    shares[msg.sender] += calculateShares(amount);
    totalDeposited += amount;
    
    // Interaction LAST
    token.transferFrom(msg.sender, address(this), amount);
}
```

### 2. Reentrancy Guard
```solidity
function swap(uint256 amount) external nonReentrant {
    // Even with ERC-777 hooks, reentrancy guard prevents re-entry
    ...
}
```

### 3. Token Whitelist
```solidity
// Only allow known-safe tokens
mapping(address => bool) public allowedTokens;

function deposit(address token, uint256 amount) external {
    require(allowedTokens[token], "Token not allowed");
    // Known ERC-20 without hooks
    ...
}
```

### 4. Balance-Check Pattern
```solidity
function deposit(uint256 amount) external nonReentrant {
    uint256 balBefore = token.balanceOf(address(this));
    token.transferFrom(msg.sender, address(this), amount);
    uint256 balAfter = token.balanceOf(address(this));
    uint256 actualDeposited = balAfter - balBefore;
    // Use actualDeposited, not amount (also handles fee-on-transfer)
}
```

## Key Takeaways

- **ERC-777 tokens are ERC-20 backward compatible** — a protocol may unknowingly accept them
- Any `transferFrom`/`transfer` of an ERC-777 token triggers hooks = re-entry
- `tokensToSend` fires BEFORE the transfer — even more dangerous than `receive()`
- **$46M+ lost** across multiple protocols to ERC-777 reentrancy
- Modern protocols should either: (a) use reentrancy guards everywhere, or (b) explicitly whitelist tokens
- Uniswap V2+ is immune because it uses the balance-check pattern
