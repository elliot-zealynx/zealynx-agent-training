# tx.origin Authentication Bypass

**Category:** Access Control  
**Severity:** High  
**Last Updated:** 2026-02-04  
**Tags:** access-control, tx.origin, phishing, authentication, msg.sender

---

## Pattern Summary

Using `tx.origin` for authentication instead of `msg.sender`. `tx.origin` is always the EOA that initiated the transaction, while `msg.sender` is the immediate caller. If a contract uses `tx.origin == owner` for auth, an attacker can trick the owner into calling a malicious contract, which then calls the vulnerable contract — passing the `tx.origin` check.

## Root Cause

**Misunderstanding the call chain.** `tx.origin` traverses the entire call stack to find the original signer. In a chain: `EOA → Attacker Contract → Victim Contract`, `tx.origin` is the EOA but `msg.sender` is the attacker contract. Using `tx.origin` for auth means any intermediary contract can impersonate the original signer.

## How It Works

```
Alice (owner) → MaliciousContract.attack() → VulnerableWallet.transfer()
                                               │
                                               ├─ tx.origin = Alice ✓ (passes check!)
                                               └─ msg.sender = MaliciousContract ✗ (would fail)
```

The attacker sends Alice a link or tricks her into interacting with `MaliciousContract`. When Alice calls any function on it, the malicious contract internally calls `VulnerableWallet.transfer()`. Since `tx.origin` is Alice (the EOA), the auth check passes.

## Vulnerable Code Pattern

```solidity
// VULNERABLE — uses tx.origin for authentication
contract VulnerableWallet {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    function transfer(address to, uint256 amount) public {
        // BUG: tx.origin can be spoofed via intermediate contracts
        require(tx.origin == owner, "Not owner");
        payable(to).transfer(amount);
    }
}

// Attacker's contract
contract TxOriginAttack {
    VulnerableWallet wallet;
    address attacker;
    
    constructor(VulnerableWallet _wallet) {
        wallet = _wallet;
        attacker = msg.sender;
    }
    
    // Trick owner into calling this (phishing, fake airdrop, etc.)
    function claimReward() external {
        // This call has tx.origin = real owner
        wallet.transfer(attacker, address(wallet).balance);
    }
    
    receive() external payable {
        wallet.transfer(attacker, address(wallet).balance);
    }
}
```

## Detection Strategy

1. **Grep for `tx.origin`:** Any use of `tx.origin` in access control logic is a red flag
2. **Slither detector:** `tx-origin` detector flags this automatically
3. **Context matters:** `tx.origin` used only to check "is caller an EOA" (not for auth) is a different pattern — less dangerous but still worth noting
4. **Watch for:** `require(tx.origin == ...)`, `if (tx.origin == ...)`, `modifier` using `tx.origin`

## Fix Pattern

```solidity
// FIXED — use msg.sender
contract SecureWallet {
    address public owner;
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    function transfer(address to, uint256 amount) public onlyOwner {
        payable(to).transfer(amount);
    }
}
```

## Edge Cases & Nuance

### Legitimate use of tx.origin
```solidity
// ACCEPTABLE — checking if caller is an EOA (not for auth)
// Used to prevent contract interactions (e.g., anti-flash-loan)
require(tx.origin == msg.sender, "No contracts");
// NOTE: This will break with EIP-3074 (AUTH/AUTHCALL) and 
// account abstraction (EIP-4337). Not future-proof.
```

### EIP-3074 and Account Abstraction Impact
- **EIP-3074 (AUTH/AUTHCALL):** Allows EOAs to delegate execution to contracts. After this, even `tx.origin == msg.sender` is unreliable as a "no contracts" check.
- **EIP-4337 (Account Abstraction):** Smart contract wallets become primary accounts. `tx.origin` loses its meaning when the "EOA" is itself a contract.

## Audit Checklist

- [ ] No `tx.origin` used for authentication or authorization
- [ ] If `tx.origin == msg.sender` is used as EOA check, flag as future-incompatible
- [ ] All auth uses `msg.sender` with proper modifier patterns
- [ ] Document any intentional `tx.origin` usage with rationale

## References

- [SWC-115: Authorization through tx.origin](https://swcregistry.io/docs/SWC-115)
- [Solidity Docs - tx.origin warning](https://docs.soliditylang.org/en/latest/security-considerations.html#tx-origin)
- [EIP-3074 implications for tx.origin](https://eips.ethereum.org/EIPS/eip-3074)
