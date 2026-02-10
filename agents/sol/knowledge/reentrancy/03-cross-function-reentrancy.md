# Cross-Function Reentrancy

**Category:** Reentrancy  
**Severity:** High/Critical  
**Last Updated:** 2026-02-03  
**Tags:** reentrancy, cross-function, shared-state, multiple-functions

---

## Pattern Summary

An attacker re-enters a DIFFERENT function (not the one making the external call) that shares state variables with the calling function. The second function operates on stale state because the first function's state update hasn't completed.

This bypasses simple reentrancy guards that only protect individual functions.

## Root Cause

Multiple functions read/write shared state variables. Function A makes an external call before updating state. During the callback, Function B is called which reads the same stale state — even if Function A has a reentrancy guard, Function B may not, or they may have separate guards.

## Historical Exploits

| Protocol | Date | Loss | Vector |
|----------|------|------|--------|
| Agave Finance | Mar 2022 | $5.5M | ERC-667 callback → borrow after deposit |
| Hundred Finance | Mar 2022 | $6.2M | Same as Agave — Aave fork on Gnosis |
| Rari Capital | May 2021 | $10M | Cross-function via CEther |

## Vulnerable Code Pattern

```solidity
contract VulnerableBank {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        
        // External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        
        balances[msg.sender] -= amount;
    }
    
    // Cross-function vulnerability: transfer reads stale balance
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
```

## Attack Flow

1. Attacker deposits 10 ETH → `balances[attacker] = 10`
2. Attacker calls `withdraw(10)`
3. Contract sends 10 ETH to attacker
4. In `fallback()`, attacker calls `transfer(accomplice, 10)` — NOT withdraw again
5. `transfer()` check passes: `balances[attacker]` is still 10 (not yet decremented)
6. Transfer completes: `balances[attacker] = 0`, `balances[accomplice] = 10`
7. `withdraw()` resumes: `balances[attacker] -= 10` → underflow (pre-0.8) or revert (0.8+)
8. In pre-0.8, attacker has extracted 10 ETH AND transferred 10 ETH worth of balance

### Solidity 0.8+ Variant
With overflow protection, the attacker modifies the strategy:
- Deposit 20 ETH
- Withdraw 10 ETH → during callback, transfer 10 ETH to accomplice
- Withdraw completes: `balances[attacker] = 20 - 10(transfer) - 10(withdraw) = 0`
- But attacker got 10 ETH back + accomplice has 10 ETH balance = 20 extracted from 20 deposited = need more sophistication

**More dangerous variant:** Re-enter into a function that uses the stale balance for a DIFFERENT purpose (e.g., borrowing, minting, collateral calculation).

## Detection Strategy

### Mapping Shared State
1. Identify all state variables modified by external-call-containing functions
2. Find ALL other functions that read those same state variables  
3. Check if those other functions are callable during the reentrancy window
4. A single `nonReentrant` modifier on `withdraw()` doesn't protect `transfer()` unless BOTH use the same guard

### Static Analysis
- Slither: `reentrancy-eth`, `reentrancy-no-eth` catch some
- Build a state-dependency graph: variable → functions that read → functions that write → external calls

### Key Questions
- Are ALL functions sharing state protected by the SAME reentrancy guard?
- Can any function be called by an attacker during another function's external call?
- What about functions in OTHER contracts that share storage (proxy patterns)?

## Fix / Remediation

### 1. Global Reentrancy Guard
```solidity
contract SecureBank is ReentrancyGuard {
    // ALL state-mutating functions use the SAME nonReentrant lock
    function withdraw(uint256 amount) external nonReentrant { ... }
    function transfer(address to, uint256 amount) external nonReentrant { ... }
    function deposit() external payable nonReentrant { ... }
}
```

### 2. CEI on ALL Functions
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;  // Effect first
    (bool success, ) = msg.sender.call{value: amount}("");  // Interaction last
    require(success);
}
```

### 3. Mutex Pattern (Custom)
```solidity
bool private locked;
modifier globalLock() {
    require(!locked, "Locked");
    locked = true;
    _;
    locked = false;
}
// Apply to ALL related functions
```

## Key Takeaways

- **A `nonReentrant` on one function does NOT protect other functions** unless they share the same lock
- Always map the FULL state dependency graph across ALL functions
- In multi-contract systems (Diamond proxy, etc.), reentrancy guards must be at the STORAGE level, not contract level
- ERC-677/ERC-777 token callbacks are the most common re-entry vector for cross-function reentrancy
