# Ghost Variables & Hooks in Certora CVL

*Session 3 — 2026-02-05*

## Overview

Ghosts and hooks work together as CVL's primary mechanism for tracking state changes during verification:
- **Ghosts** = additional state variables for use during verification
- **Hooks** = CVL code that executes when contracts perform specific operations (storage access, opcodes)
- **Purpose**: Communicate information from contract execution back to rules/invariants

## Ghost Variables

### Declaration Syntax

```cvl
// Simple ghost variable
ghost uint x;
ghost mathint counter;
ghost bool flag;

// Ghost mapping (single-level)
ghost mapping(address => mathint) balances;

// Nested ghost mapping
ghost mapping(uint => mapping(uint => mathint)) delegations;
```

### Key Properties

1. **Behave like contract storage**: Roll back on revert, havoc with storage havoc
2. **Prover considers ALL possible initial values** (subject to axioms)
3. **Can read/write directly in CVL** using normal variable syntax
4. **Support `sum` expressions** for calculating totals across ghost mappings

### Type Restrictions

- Keys must be CVL types (not structs, arrays, or interfaces)
- Values can be CVL types or nested mappings
- No tuples as ghost types

---

## Ghost Axioms

### Global Axioms

Constrain ghost behavior for ALL verification (rules + invariants):

```cvl
ghost bar(uint256) returns uint256 {
    axiom forall uint256 x. bar(x) > 10;
}
```

**Restrictions**:
- Cannot reference Solidity functions
- Cannot reference other ghosts (only the ghost itself)
- Must use `forall` to reference "parameters" (no named params in ghost signature)

### Init-State Axioms

Constrain ghost state ONLY at constructor check (invariant base step):

```cvl
ghost mathint sumBalances {
    init_state axiom sumBalances == 0;
}

ghost mapping(uint256 => uint256) func {
    init_state axiom forall uint256 x. (x % 2 == 0) => (func(x) == x);
}
```

**Critical**: Init-state axioms do NOT constrain:
- Rule verification
- Invariant preservation checks (only base step)

**Anti-pattern**: Don't copy init_state axiom to `require` statements. This excludes valid post-constructor states. Instead, prove an invariant about valid ghost states and use `requireInvariant`.

---

## Persistent vs Non-Persistent Ghosts

### Non-Persistent Ghosts (Default)

- **Havoc on storage havoc**: When Prover havocs storage (unresolved calls), non-persistent ghosts are havoced too
- **Revert with storage**: Roll back to pre-state on function revert
- **Restore with storage**: Affected by `at storageVar` statements

### Persistent Ghosts

```cvl
persistent ghost bool reentrancy_happened {
    init_state axiom !reentrancy_happened;
}
```

**Never havoced, never reverted.** Use for:

1. **Tracking across havocs** (reentrancy detection)
2. **Surviving reverts** (detecting revert types)

### Critical Example: Reentrancy Detection

```cvl
persistent ghost bool reentrancy_happened {
    init_state axiom !reentrancy_happened;
}

hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength,
          uint retOffset, uint retLength) uint rc {
    if (addr == currentContract) {
        reentrancy_happened = reentrancy_happened
            || executingContract == currentContract;
    }
}

invariant no_reentrant_calls !reentrancy_happened;
```

**Why persistent is required**: If `reentrancy_happened` were non-persistent, an unresolved external call would havoc it, potentially setting it to `true` before the CALL hook executes. This creates false positives where reentrancy is "detected" even when addresses are distinct.

### Detecting User-Defined Reverts (Persistent Survives Revert)

```cvl
persistent ghost bool saw_user_defined_revert_msg;

hook REVERT(uint offset, uint size) {
    if (size > 0) {
        saw_user_defined_revert_msg = true;
    }
}

rule mark_methods_that_have_user_defined_reverts(method f, env e, calldataarg args) {
    require !saw_user_defined_revert_msg;
    f@withrevert(e, args);
    satisfy saw_user_defined_revert_msg;
}
```

If this ghost were non-persistent, it would reset on revert, making it impossible to detect which methods revert with user messages.

---

## Storage Hooks

### Hook Patterns

```cvl
// Store hook with old value
hook Sstore C.balances[KEY address user] uint balance (uint old_balance) {
    // Executes BEFORE write
}

// Store hook without old value
hook Sstore C.totalSupply uint ts { ... }

// Load hook
hook Sload address o C.owner { ... }

// Transient storage hooks
hook Tstore C.transientVar uint v { ... }
hook Tload uint v C.transientVar { ... }
```

### Access Path Syntax

| Pattern | Matches |
|---------|---------|
| `C.field` | Specific field of contract C |
| `field` | Field of currentContract |
| `C.mapping[KEY type var]` | Any key access to mapping |
| `C.array[INDEX type var]` | Any index access to array |
| `C.struct.field` | Nested struct field |
| `C.array.length` | Dynamic array length |
| `(slot N)` | Raw slot number |
| `(slot N).(offset M)` | Bytes offset from slot |

### Hook Execution Order

1. Specific pattern hooks (Sload/Sstore) execute first
2. ALL_SLOAD/ALL_SSTORE hooks execute after
3. Hooks are NOT recursively applied (inner calls don't trigger while a hook is executing)

### Contract Qualification

```cvl
using ERC20 as asset;

// Hook on currentContract
hook Sstore balanceOf[KEY address u] uint v { ... }

// Hook on specific contract instance
hook Sstore asset.balanceOf[KEY address u] uint v { ... }
```

---

## Opcode Hooks

Execute after (not before) contract executes specific EVM opcodes:

### Common Patterns

```cvl
// Detect external calls
hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, 
          uint retOffset, uint retLength) uint rc {
    made_call = true;
}

// Restrict chain ID
hook CHAINID uint id {
    require id == 1;  // Mainnet only
}

// Track self-balance checks
hook SELFBALANCE uint v {
    selfBalance = v;
}

// Block dangerous opcodes
hook DELEGATECALL(uint g, address addr, uint argsOffset, uint argsLength, 
                  uint retOffset, uint retLength) uint rc {
    assert(executingContract != currentContract || addr == currentContract,
           "should only delegatecall into ourselves");
}
```

### Special Variables in Hook Bodies

- `executingContract`: Address of contract whose code triggered the hook
- `selector`: For CALL opcodes, the function selector being called (0 if args < 4 bytes)

### All Supported Opcodes

ADDRESS, BALANCE, ORIGIN, CALLER, CALLVALUE, CODESIZE, CODECOPY, GASPRICE, EXTCODESIZE, EXTCODECOPY, EXTCODEHASH, BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT, CHAINID, SELFBALANCE, BASEFEE, MSIZE, GAS, LOG0-LOG4, CREATE1, CREATE2, CALL, CALLCODE, DELEGATECALL, STATICCALL, REVERT, BLOBHASH, SELFDESTRUCT

---

## Common Ghost+Hook Patterns

### 1. Sum Tracking (ERC20 Total Supply)

```cvl
ghost mathint sumBalances {
    init_state axiom sumBalances == 0;
}

hook Sstore balanceOf[KEY address user] uint256 newBalance (uint256 oldBalance) {
    sumBalances = sumBalances + newBalance - oldBalance;
}

invariant totalIsSumBalances()
    to_mathint(totalSupply()) == sumBalances;
```

### 2. Mirror Mapping (Solvency Checks)

```cvl
ghost mapping(address => uint256) balanceOfMirror {
    init_state axiom forall address a. (balanceOfMirror[a] == 0);
}

// Store hook updates mirror
hook Sstore balanceOf[KEY address user] uint256 newValue (uint256 oldValue) {
    balanceOfMirror[user] = newValue;
}

// Load hook enforces consistency
hook Sload uint256 value balanceOf[KEY address user] {
    require value == balanceOfMirror[user];
}
```

### 3. Count Tracking (Vote Counting)

```cvl
ghost mathint numVoted {
    init_state axiom numVoted == 0;
}

hook Sstore _hasVoted[KEY address voter] bool newVal (bool oldVal) {
    numVoted = numVoted + 1;
}

invariant sumResultsEqualsTotalVotes()
    to_mathint(totalVotes()) == numVoted;
```

### 4. Update Detection (Specific User Affected)

```cvl
ghost mapping(address => bool) updated;

hook Sstore userInfo[KEY address u] uint i {
    updated[u] = true;
}

rule update_changes_only_user(address user, address other) {
    require user != other;
    require updated[other] == false;
    
    do_update(user);
    
    assert updated[other] == false, "should not affect other users";
}
```

### 5. Emergency Mode: No External Calls

```cvl
ghost bool made_call;

hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, 
          uint retOffset, uint retLength) uint rc {
    made_call = true;
}

rule no_call_during_emergency {
    require !made_call;
    require emergencyMode();
    
    method f; env e; calldataarg args;
    f(e, args);
    
    assert !made_call;
}
```

---

## Security Implications

### When to Use Ghosts + Hooks

| Scenario | Pattern |
|----------|---------|
| Verify totalSupply == sum(balances) | Sum tracking ghost |
| Detect reentrancy vulnerabilities | Persistent ghost + CALL hook |
| Ensure access control on state changes | Store hook with address checks |
| Track method call ordering | Persistent ghost state machine |
| Verify no external calls in critical mode | Ghost bool + CALL hook |
| Mirror storage for cross-invariant | Mirror mapping + load/store hooks |

### Pitfalls to Avoid

1. **Non-persistent ghost for reentrancy**: Will produce false positives due to havoc
2. **Init_state axiom in `require`**: Excludes valid post-constructor states
3. **Forgetting old value parameter**: Miss delta calculations
4. **Not qualifying contract in hook**: May match wrong contract's storage
5. **Expecting hooks to fire from CVL access**: Hooks only fire on Solidity storage access
6. **Recursive hook expectations**: Inner hooks are skipped while a hook executes

### DeFi-Specific Applications

1. **Vault solvency**: `totalAssets() >= totalSupply() * exchangeRate`
2. **Flash loan safety**: Track balances before/after with persistent ghost
3. **No bad debt**: Sum of liabilities <= sum of collateral
4. **Unique manager per vault**: Mirror mapping enforces 1:1
5. **Withdrawal ordering**: State machine ghost tracks queue position

---

## Key Takeaways

1. **Ghosts extend contract state** for verification purposes
2. **Init_state axioms** only apply to constructor checks
3. **Persistent ghosts** survive havocs and reverts (essential for reentrancy/revert detection)
4. **Hooks execute on Solidity storage access**, not CVL access
5. **Opcode hooks** provide low-level EVM visibility
6. **Mirror patterns** enable cross-validation between storage and expected state
7. **Sum patterns** are the canonical way to verify supply/balance invariants
8. **Hook bodies can call Solidity functions** but not parametric methods
