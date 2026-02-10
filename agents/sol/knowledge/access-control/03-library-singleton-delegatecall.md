# Library-as-Singleton / Delegatecall Misuse

**Category:** Access Control  
**Severity:** Critical  
**Last Updated:** 2026-02-04  
**Tags:** access-control, delegatecall, library, singleton, selfdestruct, parity

---

## Pattern Summary

A shared library contract is deployed as a regular `contract` (not a Solidity `library`), making it a singleton with its own state. If this singleton has unprotected initialization or destructive functions, an attacker can take ownership and destroy it — bricking all contracts that delegatecall to it.

## Root Cause

Confusing Solidity `library` keyword (which is stateless, uses DELEGATECALL by design) with a regular `contract` used as a shared logic base. When wallets use `DELEGATECALL` to a regular contract, they share logic but each has separate storage. However, the shared contract itself has its own storage that can be independently manipulated.

## The Parity Freeze — The Canonical Example

**Date:** November 6, 2017  
**Loss:** ~$150M frozen permanently  
**Chain:** Ethereum

The Parity multi-sig wallet system had two components:
1. **WalletLibrary** — A regular `contract` (not `library`) containing all wallet logic
2. **Individual wallets** — Lightweight proxies that `DELEGATECALL` to WalletLibrary

The WalletLibrary contract had `initWallet()` as a public function that could set ownership. After the July 2017 fix for the first Parity hack, the library was redeployed — but **nobody called `initWallet()` on the library contract itself**. Its owner was address(0).

User `devops199` called `initWallet()` on the WalletLibrary, became its owner, then called `kill()` (which executed `selfdestruct`). Since the library was destroyed, all ~587 wallets that delegatecalled to it became permanently non-functional. ~$150M in ETH is still locked today.

## Vulnerable Code Pattern

```solidity
// VULNERABLE — Library deployed as regular contract with unprotected init
contract WalletLibrary {
    address public owner;
    
    // This can be called by ANYONE on the library contract itself
    function initWallet(address _owner) public {
        owner = _owner;
    }
    
    // Owner can destroy the library — killing all dependent wallets
    function kill(address _to) public {
        require(msg.sender == owner);
        selfdestruct(payable(_to));
    }
    
    // ... wallet logic that proxies delegatecall to ...
}

// Wallet proxies use DELEGATECALL to WalletLibrary
contract Wallet {
    address constant library = 0x...; // WalletLibrary address
    
    fallback() external payable {
        (bool success,) = library.delegatecall(msg.data);
        require(success);
    }
}
```

## Detection Strategy

1. **Identify delegatecall targets:** Find all contracts that are targets of `DELEGATECALL` from other contracts
2. **Check if target is initialized:** Is the delegatecall target contract's state properly set/locked?
3. **Look for selfdestruct:** Any `selfdestruct` in a delegatecall target is extremely high risk
4. **Library vs Contract:** Is shared logic deployed as `library` (safe) or `contract` (risky)?
5. **Post-EIP-6780 (Dencun):** `selfdestruct` no longer destroys contracts except in the creation tx, reducing but not eliminating this class

## Fix Pattern

```solidity
// APPROACH 1: Use actual Solidity library
library WalletLibrary {
    // Libraries can't have state, can't be selfdestructed
    // All functions are called via DELEGATECALL automatically
    function transfer(address to, uint256 amount) internal {
        // ...
    }
}

// APPROACH 2: If you must use a contract, lock it
contract WalletLibrary {
    bool private initialized;
    
    constructor() {
        initialized = true; // Lock on deployment
    }
    
    function initWallet(address _owner) public {
        require(!initialized, "Already initialized");
        initialized = true;
        owner = _owner;
    }
    
    // NEVER include selfdestruct in a shared logic contract
}

// APPROACH 3: Modern proxy pattern with _disableInitializers()
contract WalletLogicV1 is Initializable {
    constructor() {
        _disableInitializers();
    }
}
```

## Audit Checklist

- [ ] No `selfdestruct` in any contract that is a delegatecall target
- [ ] Shared logic contracts are either Solidity `library` types or properly locked
- [ ] Delegatecall targets cannot have their ownership changed by external callers
- [ ] All initialization on shared contracts is performed at deployment time
- [ ] Post-Dencun: `selfdestruct` behavior has changed but storage wiping on delegatecall targets is still dangerous

## Key Insight

The Parity freeze is a masterclass in why **separation of concerns** matters. The library contract shouldn't have had `selfdestruct` capability at all. And it shouldn't have been a regular `contract` with mutable state. Two architectural decisions, both wrong, compounded into permanent loss.

## References

- [Parity Postmortem](https://www.parity.io/blog/a-postmortem-on-the-parity-multi-sig-library-self-destruct/)
- [Ethereum Stack Exchange - Parity Library Suicide Explanation](https://ethereum.stackexchange.com/questions/30128/explanation-of-parity-library-suicide)
- [EIP-6780 - SELFDESTRUCT only in same transaction](https://eips.ethereum.org/EIPS/eip-6780)
