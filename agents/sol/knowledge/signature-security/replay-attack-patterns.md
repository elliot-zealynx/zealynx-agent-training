# Signature Replay Attack Patterns

## Pattern: Missing Nonce in EIP-712 Structures
*Successfully applied in Krystal DeFi shadow audit (2026-02-09)*

### Vulnerable Code Pattern
```solidity
// EIP-712 struct WITHOUT nonce field
struct Order {
    // Various fields but NO nonce
    uint256 deadline;
    address recipient;
    // ... other fields
    // 🚨 MISSING: uint256 nonce;
}

function execute(ExecuteParams calldata params) external {
    _validateOrder(params.userOrder, params.orderSignature, positionOwner);
    // Execute using different params than what user signed!
    _execute(params, positionOwner);
}

function _validateOrder(Order memory order, bytes memory signature, address actor) internal {
    address userAddress = recover(order, signature);
    require(userAddress == actor);
    require(!_cancelledOrder[keccak256(signature)]); // Only checks cancellation
}
```

### Double Vulnerability: Parameter Mismatch
```solidity
struct ExecuteParams {
    // Actual execution parameters (controlled by operator)
    Action action;
    uint256 tokenId;
    address targetToken;
    uint256 amountIn0;
    // ... many more fields
    
    // User signature validates THIS (often empty/minimal)
    StructHash.Order userOrder;  
    bytes orderSignature;
}
```

### Attack Scenarios
1. **Pure Replay:** Same signature used multiple times
2. **Parameter Substitution:** User signs minimal order, operator executes with different params
3. **Compromised Operator:** Attacker replays old signatures with new execution parameters

### Detection Checklist
- [ ] Does EIP-712 struct have `nonce` field?
- [ ] Are signed parameters identical to execution parameters?
- [ ] Can same signature be used multiple times?
- [ ] Is there proper nonce incrementing/tracking?
- [ ] Are there separate "user signed" vs "operator controlled" parameters?

### Secure Pattern
```solidity
struct Order {
    uint256 nonce;      // 🛡️ REQUIRED
    uint256 deadline;
    address recipient;
    // ... other fields
}

mapping(address => uint256) public nonces;

function _validateOrder(Order memory order, bytes memory signature, address actor) internal {
    address userAddress = recover(order, signature);
    require(userAddress == actor);
    require(order.nonce == nonces[actor]++); // 🛡️ Nonce validation
    // Also validate that order params match execution params
}
```

### Red Flags in Tests
```solidity
// Test using empty/default struct - RED FLAG!
StructHash.Order emptyUserConfig; // Default values
bytes memory signature = _signOrder(emptyUserConfig, privateKey);
```

### Common Locations
- **Automation protocols** (user signs general permission, operator executes specifics)
- **Meta-transactions** (relayer executes signed transactions)
- **Limit orders** (market makers execute user-signed orders)
- **Vault operations** (managers execute user-approved strategies)

## Pattern Success Rate
- **Applied in:** Krystal DeFi (M-02)
- **Detection Rate:** 1/1 (100%)
- **Impact:** High to Medium severity (fund loss possible)

## Related Patterns
- **Parameter Validation Gaps** - Different validation vs execution params
- **EIP-712 Implementation Issues** - Missing domain separators, wrong typehashes
- **Access Control Bypasses** - Signature validation replacing proper access controls