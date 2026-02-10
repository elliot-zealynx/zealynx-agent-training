# Classic Single-Function Reentrancy

**Category:** Reentrancy  
**Severity:** Critical/High  
**Last Updated:** 2026-02-03  
**Tags:** reentrancy, CEI-violation, ETH-transfer, withdraw, drain

---

## Pattern Summary

The most fundamental reentrancy pattern. A function sends ETH (or makes an external call) before updating internal state. The recipient's `fallback()`/`receive()` re-enters the same function, which still sees stale state.

## Root Cause

**Checks-Effects-Interactions (CEI) violation:** State updates happen AFTER an external call, allowing re-entrant invocations to operate on stale (pre-update) state.

## Historical Exploits

| Protocol | Date | Loss | Chain |
|----------|------|------|-------|
| The DAO | June 2016 | ~$60M | Ethereum |
| SpankChain | Oct 2018 | $40K | Ethereum |
| XSURGE | Aug 2021 | $5M | BSC |
| Grim Finance | Dec 2021 | $30M | Fantom |

## Vulnerable Code Pattern

```solidity
function withdraw(uint256 amount) public {
    // Check
    require(balances[msg.sender] >= amount, "Insufficient");
    
    // Interaction BEFORE Effect — VULNERABLE
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    
    // Effect (too late — attacker already re-entered)
    balances[msg.sender] -= amount;
}
```

## Attack Flow

1. Attacker deposits funds, establishing a legitimate balance
2. Attacker calls `withdraw()`
3. Contract sends ETH via `msg.sender.call{value: amount}("")`
4. Attacker's `fallback()` triggers, calling `withdraw()` again
5. Balance hasn't been updated — check passes again
6. Repeat until contract is drained
7. All nested calls unwind, each decrementing the balance (underflow possible pre-0.8)

## Detection Strategy

### Static Analysis
- **Slither detectors:** `reentrancy-eth`, `reentrancy-no-eth`, `reentrancy-benign`
- Look for `call{value:}`, `transfer()`, `send()` before state variable writes
- Flag any external call where a state variable read precedes the call AND the same variable is written after

### Manual Review
- Trace every external call — what state has changed before it? What hasn't?
- Check if `nonReentrant` modifier is applied to all state-mutating functions
- Map all `call`, `delegatecall`, token `transfer`, `safeTransfer` as potential re-entry points

### Invariant Testing
- Property: `contract.balance >= sum(all_user_balances)` should always hold
- Fuzz with attacker contracts that re-enter on receive

## Fix / Remediation

### 1. Checks-Effects-Interactions Pattern (Primary)
```solidity
function withdraw(uint256 amount) public {
    require(balances[msg.sender] >= amount, "Insufficient");
    
    // Effect BEFORE Interaction
    balances[msg.sender] -= amount;
    
    // Interaction (now safe — state already updated)
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
```

### 2. Reentrancy Guard (Defense in Depth)
```solidity
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract Vault is ReentrancyGuard {
    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
```

### 3. ReentrancyGuardTransient (Gas-Optimized, Solidity ≥0.8.24)
```solidity
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
// Uses TSTORE/TLOAD — cheaper than SSTORE/SLOAD, auto-clears at end of transaction
```

## Key Takeaways

- CEI is the **primary** defense — reentrancy guards are **defense in depth**
- Even with Solidity 0.8.x overflow protection, reentrancy still drains via repeated valid withdrawals
- `transfer()` and `send()` (2300 gas limit) are NOT sufficient protection — gas costs change with EIPs
- Every `external call` is a potential re-entry point, not just ETH transfers
