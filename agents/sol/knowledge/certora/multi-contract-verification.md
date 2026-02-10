# Multi-Contract Verification

**Topic:** Handling protocols with multiple interacting contracts — scene setup, linking, DISPATCHER summaries, unknown contract modeling

**Study Date:** 2026-02-08

**Sources:** 
- [docs.certora.com/en/latest/docs/user-guide/multicontract/index.html](https://docs.certora.com/en/latest/docs/user-guide/multicontract/index.html)
- [docs.certora.com/en/latest/docs/cvl/methods.html](https://docs.certora.com/en/latest/docs/cvl/methods.html) (DISPATCHER summaries)
- [Certora Examples - LiquidityPool](https://github.com/Certora/Examples/tree/7dfc379423202c90cf284eb42800b97cf5c95d83/DEFI/LiquidityPool)

---

## Key Concepts

### 1. The Scene
The **scene** is the set of contracts that the Prover knows about during verification. Adding contracts to the scene enables:
- Resolving external calls using actual contract code
- Using DISPATCHER summaries to model unknown implementations
- Accessing contracts directly from CVL specs

**Adding to scene:** Pass contract files via CLI or config:
```bash
certoraRun contracts/Pool.sol contracts/Asset.sol --verify Pool:spec.spec
```

### 2. Default Behavior: HAVOC on Unresolved Calls
When the Prover encounters calls to unknown contracts:
- **View functions** → `NONDET` summary (return any value, no state change)
- **Non-view functions** → `HAVOC_ECF` summary (can change all storage except caller contract)

This leads to spurious counterexamples because unknown contracts can "do anything."

### 3. Linking: Known Contract Connections
**Purpose:** Connect contract fields to specific implementations when you know the exact contract.

**Syntax:**
```bash
--link "Pool:asset=Asset"
```

**Effect:** Tells Prover that `Pool.asset` field points to the `Asset` contract instance in the scene.

**When to use:** 
- Fixed dependencies (e.g., specific ERC20 token)
- Known protocol components
- When you have the implementation source code

### 4. Using Statements: CVL Access to Scene Contracts
```cvl
using Asset as underlying;
using Pool as pool;

rule exampleRule {
    // Direct calls to scene contracts
    mathint balance = underlying.balanceOf(currentContract);
    
    // currentContract refers to the main verified contract
    require e.msg.sender != currentContract;
}
```

**Benefits:**
- Call contract methods directly from CVL
- Access view functions without going through main contract
- Use `currentContract` for main verified contract reference

**envfree declarations for scene contracts:**
```cvl
methods {
    function underlying.balanceOf(address) external returns(uint256) envfree;
}
```

### 5. DISPATCHER Summaries: Unknown Contract Modeling

**Purpose:** Handle cases where contract addresses are unknown at verification time (user-provided addresses, multiple implementations).

**Basic syntax:**
```cvl
methods {
    function _.executeOperation(uint256,uint256,address) external => DISPATCHER(true);
}
```

**How it works:**
- When encountering `receiver.executeOperation(...)`, tries ALL contracts in the scene that implement this method
- Constructs counterexamples by choosing any viable implementation
- Uses `_` wildcard to apply regardless of receiver contract

**⚠️ DISPATCHER IS UNSOUND:**
- Only considers contracts YOU provide in the scene
- Missing a malicious implementation = missed vulnerability
- Forces you to think about threat model explicitly

### 6. DISPATCHER Patterns

#### Basic Pattern: Known Implementations
```cvl
methods {
    function _.transfer(address,uint256) external => DISPATCHER(true);
    function _.balanceOf(address) external returns(uint256) => DISPATCHER(true);
}
```

Add all relevant ERC20 implementations to scene for comprehensive testing.

#### Flexible Receiver Pattern
Instead of writing separate receivers for each attack vector, create one flexible receiver:

```solidity
contract FlexibleReceiver is IFlashLoanReceiver, ArbitraryValues {
    IPool token;
    
    function executeOperation(...) external override returns (bool) {
        uint callbackChoice = arbitraryUint();
        
        if (callbackChoice == 0)
            token.deposit(arbitraryUint());
        else if (callbackChoice == 1)
            token.transferFrom(arbitraryAddress(), arbitraryAddress(), arbitraryUint());
        else if (callbackChoice == 2)
            token.withdraw(arbitraryUint());
        // ... more callback options
            
        return true;
    }
}
```

**ArbitraryValues helper** provides `arbitraryUint()`, `arbitraryAddress()`, etc. — the Prover chooses different values for each call.

**Benefits:**
- Single receiver covers multiple attack vectors
- Prover explores all possible method calls with arbitrary arguments
- Simulates reentrancy attacks systematically

**Limitations:**
- Only makes one reentrant call (not chains)
- Doesn't work for invariant initial state checks (storage starts at 0)
- Still bounded by contracts in scene

### 7. ERC20 DISPATCHER Pattern
**Common use case:** Contract works with arbitrary ERC20 tokens.

**Reusable spec pattern:**
```cvl
// erc20.spec - import this
methods {
    function _.transfer(address,uint256) external => DISPATCHER(true);
    function _.transferFrom(address,address,uint256) external => DISPATCHER(true);
    function _.balanceOf(address) external returns(uint256) => DISPATCHER(true);
    function _.allowance(address,address) external returns(uint256) => DISPATCHER(true);
    function _.approve(address,uint256) external => DISPATCHER(true);
    function _.totalSupply() external returns(uint256) => DISPATCHER(true);
}

// Your main spec
import "../helpers/erc20.spec";
```

Add multiple ERC20 implementations to scene: standard tokens, fee-on-transfer, rebasing, etc.

### 8. Summary Resolution Priority
When multiple patterns match the same method call:
1. **Exact entries** (`Contract.method(...)`) — highest priority
2. **Wildcard entries** (`_.method(...)`)
3. **Catch-all entries** (`Contract._`)
4. **Catch unresolved-calls** (`unresolved external in ...`)
5. **AUTO summary** (default)

### 9. Scene Configuration Best Practices

**Config file structure:**
```json
{
    "files": [
        "contracts/Pool.sol",
        "contracts/Asset.sol", 
        "receivers/TrivialReceiver.sol",
        "receivers/FlexibleReceiver.sol"
    ],
    "verify": "Pool:specs/multi.spec",
    "link": [
        "Pool:asset=Asset",
        "FlexibleReceiver:token=Pool"
    ]
}
```

**Threat modeling approach:**
1. Start with trivial implementations (TrivialReceiver)
2. Add malicious implementations you can think of (TransferReceiver)
3. Use flexible receivers for broader coverage
4. Include edge-case tokens (zero-address, reverting, etc.)

### 10. Advanced: Catch Unresolved-Calls
For fine-grained control over unresolved external calls:

```cvl
methods {
    // Apply to unresolved calls within specific method
    unresolved external in Pool.flashLoan() => DISPATCHER [
        FlexibleReceiver.executeOperation(uint256,uint256,address)
    ] default HAVOC_ECF;
    
    // Global catch-all for unresolved calls
    unresolved external in _._ => NONDET;
}
```

---

## Security Insights

### **Multi-Contract Attack Surface**
Real protocols have complex inter-contract dependencies. Single-contract verification misses:
- **Reentrancy through callbacks** (flash loan receivers, ERC777 hooks)
- **Cross-contract state inconsistencies** (vault/token balance mismatches)
- **Interface assumption violations** (non-standard ERC20 behavior)

### **DISPATCHER Threat Modeling**
DISPATCHER forces explicit threat modeling — what attacks are you defending against?
- **Too narrow:** Miss sophisticated attacks (only test TrivialReceiver)
- **Too broad:** Computational explosion, timeouts
- **Just right:** Cover realistic attack vectors with flexible patterns

### **The Linking vs DISPATCHER Decision**
- **Use linking** when you know the exact contract and want to verify against its specific implementation
- **Use DISPATCHER** when the contract address is user-controlled or when you want to verify compatibility with multiple implementations
- **Combine both** for complex protocols (link known dependencies, dispatch unknown ones)

### **Flash Loan Security Pattern**
Flash loans are the canonical multi-contract security challenge:
1. **Temporary state inconsistency** — borrowed funds create "impossible" intermediate states
2. **Arbitrary external code execution** — receiver can call back into protocol
3. **Reentrancy variants** — direct calls, cross-function reentrancy, cross-contract reentrancy

Formal verification with DISPATCHER + flexible receivers catches reentrancy bugs that traditional testing misses because it exhaustively explores the callback space.

### **ERC20 Compatibility Trap**
Many DeFi exploits stem from ERC20 implementation differences:
- **Fee-on-transfer tokens** break balance assumptions
- **Rebasing tokens** change balances over time
- **Non-standard return values** break `require(token.transfer(...));`
- **Reentrancy hooks** (ERC777) enable unexpected callbacks

DISPATCHER with diverse ERC20 implementations in the scene catches these systematically.

---

## Example: Pool + Asset + FlashLoanReceiver
```cvl
using Asset as underlying;

methods {
    // Link asset field, dispatch flash loan receivers
    function _.executeOperation(uint256,uint256,address) external => DISPATCHER(true);
    function underlying.balanceOf(address) external returns(uint256) envfree;
}

rule flashLoanIncreasesBalance {
    address receiver; uint256 amount; env e;
    
    mathint balance_before = underlying.balanceOf(currentContract);
    
    flashLoan(e, receiver, amount);
    
    mathint balance_after = underlying.balanceOf(currentContract);
    
    assert balance_after >= balance_before,
        "flash loans must not decrease pool balance";
}
```

**Scene setup:**
- `Pool.sol` (main contract)
- `Asset.sol` (linked to `pool.asset`)
- `TrivialReceiver.sol`, `FlexibleReceiver.sol` (DISPATCHER targets)

**This catches:** Reentrancy attacks where flash loan receiver drains the pool through callback combinations.