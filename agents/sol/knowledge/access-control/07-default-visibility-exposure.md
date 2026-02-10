# Default Visibility / Unintended Exposure

**Category:** Access Control  
**Severity:** High  
**Last Updated:** 2026-02-04  
**Tags:** access-control, visibility, public, internal, default-visibility, constructor

---

## Pattern Summary

Functions or state variables are exposed with higher visibility than intended. Pre-Solidity 0.5, functions defaulted to `public` if no visibility was specified. Even in modern Solidity, developers may accidentally use `public` instead of `internal` on helper functions, or expose state variables that leak sensitive information (e.g., passwords, private keys stored on-chain).

## Root Cause

1. **Legacy default visibility:** Solidity <0.5 defaulted functions to `public`
2. **Copy-paste errors:** Developer copies an interface function signature (which is always `external`) into the implementation but forgets to change visibility
3. **Internal helpers made public:** Utility functions that should be `internal` or `private` accidentally declared `public`
4. **Constructor name mismatch (pre-0.4.22):** Before `constructor()` keyword, constructors were functions with the contract name. A typo meant the "constructor" became a regular public function

## Historical Exploits

| Protocol | Date | Loss | Chain | Details |
|----------|------|------|-------|---------|
| Rubixi | 2016 | ~$0.1M | ETH | Constructor was named `DynamicPyramid()` but contract was renamed to `Rubixi` — the "constructor" became a public function anyone could call to claim ownership |
| Parity (1st hack) | Jul 2017 | $31M | ETH | `initWallet()` was public on the library contract |
| Various Ethernaut CTFs | N/A | N/A | N/A | Multiple challenge contracts use visibility bugs as teaching examples |

## Vulnerable Code Pattern

```solidity
// VULNERABLE — Pre-0.5 default visibility
pragma solidity ^0.4.24;

contract OldContract {
    // This function is PUBLIC by default (Solidity <0.5)
    function _internalHelper() {
        // Sensitive logic that should be internal
    }
}

// VULNERABLE — Constructor name mismatch (pre-0.4.22)
pragma solidity ^0.4.21;

contract Rubixi {
    address public owner;
    
    // BUG: Contract was renamed from DynamicPyramid to Rubixi
    // but the "constructor" function wasn't renamed
    // This is now just a regular public function!
    function DynamicPyramid() public {
        owner = msg.sender;
    }
}

// VULNERABLE — Sensitive data in public state variable
contract VaultWithPassword {
    // "private" doesn't mean hidden! It's still on-chain in storage
    // Anyone can read slot 1 with eth_getStorageAt
    bytes32 private password;
    
    function unlock(bytes32 _password) public {
        require(_password == password);
        locked = false;
    }
}

// VULNERABLE — Helper function unnecessarily public
contract Token {
    function _calculateReward(address user) public view returns (uint256) {
        // Should be internal — leaks reward calculation logic
        // and could be used in flash loan oracle manipulation
        return balances[user] * rewardRate / totalSupply;
    }
}
```

## Detection Strategy

1. **Compiler version check:** If Solidity <0.5, audit ALL functions for implicit `public` visibility
2. **Constructor pattern:** For <0.4.22, verify the constructor function name matches the contract name exactly
3. **Visibility audit:** List every `public`/`external` function and ask "does this NEED to be callable from outside?"
4. **Underscore convention:** Functions starting with `_` that are `public` or `external` are suspicious — convention says they should be `internal`/`private`
5. **Storage reading:** Remember `private` variables are NOT hidden — they're readable via `eth_getStorageAt`
6. **Tooling:** Slither `external-function` detector, Solhint visibility rules

## Fix Pattern

```solidity
// FIXED — Modern Solidity requires explicit visibility
pragma solidity ^0.8.20;

contract SecureContract {
    // Explicit visibility on everything
    function _internalHelper() internal {
        // Now truly internal
    }
    
    // Use constructor keyword (no naming issues)
    constructor() {
        owner = msg.sender;
    }
    
    // Don't store secrets on-chain at all
    // Use commit-reveal or ZK proofs instead
    bytes32 public commitmentHash; // Store hash, not secret
}
```

## Audit Checklist

- [ ] Compiler version ≥0.5 (explicit visibility required)
- [ ] No functions with `_` prefix are `public` or `external`
- [ ] No sensitive data stored in contract state (even `private` is readable)
- [ ] All helper/utility functions are `internal` or `private`
- [ ] View functions don't leak sensitive calculation logic unnecessarily
- [ ] Constructor uses the `constructor()` keyword, not a named function

## Key Insight

"Private" in Solidity means **access-restricted at the language level**, not **hidden on-chain**. Every byte of contract storage is publicly readable. Never store passwords, API keys, private keys, or unencrypted secrets in contract storage. If you see `private bytes32 password` in an audit, that's always a finding.

## References

- [SWC-100: Function Default Visibility](https://swcregistry.io/docs/SWC-100)
- [SWC-118: Incorrect Constructor Name](https://swcregistry.io/docs/SWC-118)
- [Solidity 0.5 Breaking Changes](https://docs.soliditylang.org/en/v0.5.0/050-breaking-changes.html)
