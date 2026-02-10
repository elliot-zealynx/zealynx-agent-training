# Cross-Contract Privilege Escalation

**Category:** Access Control  
**Severity:** Critical  
**Last Updated:** 2026-02-04  
**Tags:** access-control, cross-contract, privilege-escalation, bridge, cross-chain, poly-network

---

## Pattern Summary

When Contract A trusts Contract B to perform privileged operations, but Contract B's access to A isn't properly scoped, an attacker can manipulate B to execute unauthorized operations on A. This is especially devastating in cross-chain bridges where the trust boundary spans multiple networks.

## Root Cause

**Mismanaged trust boundaries between contracts.** Contract A grants broad `DELEGATECALL` or `call` privileges to Contract B, but B's own entry points aren't sufficiently restricted. The attacker doesn't break A's access control directly — they go through B's weaker gate.

## Historical Exploits

| Protocol | Date | Loss | Chain | Details |
|----------|------|------|-------|---------|
| Poly Network | Aug 2021 | $611M | ETH/BSC/Polygon | EthCrossChainManager had implicit trust to modify EthCrossChainData's keeper keys |
| Ronin Bridge | Mar 2022 | $625M | ETH/Ronin | 5 of 9 validator keys compromised — trust model too permissive |
| Wormhole | Feb 2022 | $326M | Solana/ETH | Verification bypass in guardian signature validation |
| Nomad Bridge | Aug 2022 | $190M | Multi-chain | Trusted root in replica contract initialized to 0x00, confirming every message |

## Vulnerable Code Pattern

```solidity
// Contract A — Data store with privileged setter
contract CrossChainData {
    address public crossChainManager;
    bytes public curEpochConPubKey;
    
    modifier onlyManager() {
        require(msg.sender == crossChainManager);
        _;
    }
    
    // Only CrossChainManager can update keys
    function putCurEpochConPubKeyBytes(bytes memory key) public onlyManager {
        curEpochConPubKey = key; // Replaces validator keys!
    }
}

// Contract B — Manager that processes cross-chain messages
contract CrossChainManager {
    // VULNERABLE: Processes arbitrary cross-chain messages
    // and can be tricked into calling putCurEpochConPubKeyBytes
    function verifyAndExecute(
        bytes memory proof,
        bytes memory rawHeader,
        bytes memory toContract,
        bytes memory method,
        bytes memory args
    ) public {
        // Verifies proof... but the verification can be bypassed
        // by crafting a message that targets CrossChainData
        
        // This line executes arbitrary calls as CrossChainManager
        (bool success,) = toContract.call(
            abi.encodePacked(bytes4(keccak256(method)), args)
        );
    }
}
```

## The Poly Network Attack Flow

1. Attacker crafted a cross-chain message targeting `EthCrossChainData.putCurEpochConPubKeyBytes()`
2. They brute-forced the `method` parameter to match the function selector
3. `EthCrossChainManager.verifyAndExecute()` processed the message and called `putCurEpochConPubKeyBytes()`
4. Since the call came from `CrossChainManager` (trusted), it passed the `onlyManager` check
5. Attacker replaced the legitimate keeper public key with their own
6. Now controlling the keeper key, they authorized withdrawal of all bridge funds
7. Repeated across Ethereum, BSC, and Polygon — $611M total

## Detection Strategy

1. **Map trust relationships:** Draw a graph of which contracts can call which privileged functions
2. **Identify transitive trust:** If A trusts B, and B processes external input, can external input reach A's privileged functions through B?
3. **Check call forwarding:** Any contract that forwards arbitrary `call` or `delegatecall` based on user input is high risk
4. **Cross-chain message handlers:** Verify they whitelist which contracts and functions can be targeted
5. **Ask:** "If I control the input to Contract B, what can I make Contract B do to Contract A?"

## Fix Pattern

```solidity
// FIXED — Whitelist allowed target contracts and methods
contract CrossChainManager {
    mapping(address => mapping(bytes4 => bool)) public allowedCalls;
    
    function verifyAndExecute(
        bytes memory proof,
        address toContract,
        bytes4 method,
        bytes memory args
    ) public {
        // Verify proof...
        
        // CRITICAL: Whitelist check
        require(allowedCalls[toContract][method], "Call not whitelisted");
        
        // CRITICAL: Never allow calls to modify the manager itself
        // or the data contract's admin functions
        require(toContract != address(this), "Cannot self-call");
        
        (bool success,) = toContract.call(abi.encodePacked(method, args));
        require(success);
    }
}

// FIXED — Scope the trust relationship
contract CrossChainData {
    mapping(bytes4 => bool) public managerAllowedMethods;
    
    modifier onlyManagerAllowed(bytes4 selector) {
        require(msg.sender == crossChainManager, "Not manager");
        require(!isAdminFunction(selector), "Admin functions blocked via manager");
        _;
    }
}
```

## Audit Checklist

- [ ] All cross-contract trust relationships are explicitly mapped and documented
- [ ] Contracts that forward calls whitelist allowed targets AND methods
- [ ] Admin functions on data/storage contracts cannot be reached through manager contracts
- [ ] Cross-chain message handlers validate source chain, source contract, and target function
- [ ] No contract accepts arbitrary calldata to forward via `.call()`

## Key Insight

The Poly Network hack wasn't a bug in any single contract — both EthCrossChainData and EthCrossChainManager were individually "correct." The vulnerability existed in the **relationship** between them. When auditing, always think about the system as a whole, not just individual contracts.

## References

- [Poly Network Attack Analysis - SlowMist](https://slowmist.medium.com/the-root-cause-of-poly-network-being-hacked-ec2ee1b0c68f)
- [Nomad Bridge Hack - Rekt](https://rekt.news/nomad-rekt/)
- [Wormhole Hack Analysis](https://extropy-io.medium.com/solana-wormhole-hack-analysis-11ce6f0b7f4f)
