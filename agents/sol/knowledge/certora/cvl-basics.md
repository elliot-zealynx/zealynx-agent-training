# CVL Basics — Certora Verification Language

> ⚡ Sol's Certora Study Notes | Session 1 | 2026-02-03
> Source: docs.certora.com/en/latest/docs/cvl/

## What Is Certora?

Certora Prover is a **formal verification** tool for smart contracts. It mathematically proves that a contract satisfies a set of **rules** written in CVL (Certora Verification Language). Unlike fuzzing or testing which check specific inputs, Certora checks **all possible inputs** using an SMT solver.

**Key insight:** The Prover translates contract code + CVL rules into a logical formula. If the SMT solver finds the formula satisfiable, it means a counterexample exists (rule violated). If unsatisfiable, the rule holds for ALL possible states.

---

## Spec File Structure

A CVL `.spec` file can contain:

| Component | Purpose |
|-----------|---------|
| **Import statements** | Import contents of other CVL files |
| **Use statements** | Check rules imported from another spec or built-in rules |
| **Using statements** | Reference multiple contracts |
| **Methods blocks** | Declare how contract methods should be summarized |
| **Rules** | Expected behavior of contract methods |
| **Invariants** | State properties that should always be true |
| **Functions** | Reusable CVL code |
| **Definitions** | Reusable CVL expressions |
| **Sorts** | Simple types comparable for equality |
| **Ghosts** | Additional state-tracking variables |
| **Hooks** | Instrument contracts to insert CVL on specific EVM operations |

---

## Rules

Rules are the **primary entry points** for verification. A rule defines a sequence of commands simulated during verification.

### Basic Rule Pattern
```cvl
rule integrityOfDeposit {
    mathint balance_before = underlyingBalance();

    env e; uint256 amount;
    safeAssumptions(_, e);

    deposit(e, amount);

    mathint balance_after = underlyingBalance();

    assert balance_after == balance_before + amount,
        "deposit must increase the underlying balance of the pool";
}
```

### How Rules Work
1. Prover generates **every possible combination** of undefined variable values
2. If a `require` fails → that example is **ignored** (filtered out)
3. All remaining examples must pass every `assert`
4. If any assert fails → Prover outputs a **counterexample**
5. If all pass → rule is **verified** ✅

### Parametric Rules
Rules with **undefined `method` variables** generate a separate report for each contract method:

```cvl
rule sanity(method f) {
    env e;
    calldataarg args;
    f(e, args);
    assert false; // Sanity check: should fail for every reachable method
}
```

- Prover generates separate counterexample for each violating method
- Indicates which methods always satisfy the rule
- Can restrict with `--method` CLI flag or filters

### Filters
Restrict which methods a parametric rule runs against:

```cvl
rule r(method f, method g) filtered {
    f -> f.isView,
    g -> g.selector != exampleMethod(uint,uint).selector
         && g.selector != otherExample(address).selector
} {
    // rule body
}
```

- `f -> f.isView` — only verify with view methods
- Filter on `.selector`, `.isView`, etc.
- **Method must be a rule parameter** (not declared inside body) for filters to work

### Multiple Assertions
- Default: any failure = whole rule fails, one counterexample
- With `--multi_assert_check`: separate counterexample per assert, each passes all earlier asserts

---

## Invariants

Invariants describe properties that should **always be true** in every reachable state.

### Weak vs Strong Invariants

| Type | When it holds |
|------|--------------|
| **Weak** (default) | True whenever no method is currently executing ("representation invariant") |
| **Strong** | Also holds before/after every unresolved external call (reentrancy protection) |

### Verification Process
1. **Base step:** Check invariant holds after constructor
2. **Induction step:** Assume invariant holds before method → assert it holds after

```cvl
invariant totalSupplyIsSumOfBalances()
    totalSupply() == sumOfBalances
```

### ⚠️ Unsoundness Sources
1. **Preserved blocks** — adding `require` can mask counterexamples
2. **Filters** — skipping methods means they're not verified
3. **Reverting invariants** — if invariant expression reverts in pre-state but not post-state, counterexamples get discarded silently

**Classic unsoundness example:**
```cvl
// This PASSES but is FALSE — reverts in pre-state hide the violation
invariant all_elements_are_zero(uint i) get(i) == 0;
// Calling add(2) would violate it, but get(i) reverts when array is shorter
```

### Preserved Blocks
Add assumptions needed for preservation proofs:

```cvl
invariant solvencyAsInv() asset.balanceOf() >= internalAccounting() {
    preserved withdrawExcess(address token) {
        require token != asset;
    }
    preserved asset.transfer(address x, uint y) with (env e) {
        require e.msg.sender != currentContract;
    }
}
```

- Generic preserved block (no method sig) = applies to all unmatched methods
- Contract-specific: `asset.transfer(...)` — only for that contract's method
- Wildcard: `_.transfer(...)` — for all contracts with that method
- `with (env e)` binds the environment for the method call
- `preserved constructor()` — for base step only

---

## Methods Block

Declares info about contract methods and how to summarize them.

### Two Kinds of Entries
1. **Non-summary declarations** — document interface, envfree annotations
2. **Summary declarations** — replace calls (useful for unavailable code, timeouts)

### Entry Patterns

```cvl
methods {
    // Exact: matches specific contract method
    function C.f(uint x) external returns(uint);

    // Wildcard: matches any contract's f(uint)
    function _.f(uint x) external => NONDET;

    // Catch-all: summarize ALL methods of a contract
    function SomeLibrary._ external => NONDET;

    // Envfree: no env needed to call
    function totalSupply() external returns(uint256) envfree;
}
```

### Summary Types

| Summary | Behavior | Soundness |
|---------|----------|-----------|
| `NONDET` | Returns arbitrary value each time | Sound for view functions |
| `CONSTANT` | Returns same value for all calls | Unsound |
| `PER_CALLEE_CONSTANT` | Same value per callee contract | Unsound |
| `HAVOC_ALL` | Havocs all storage + returns arbitrary | **Always sound** |
| `HAVOC_ECF` | Havocs external contracts only | Unsound |
| `DISPATCHER` | Resolves to known implementations | Unsound |
| `AUTO` | Default for unresolved calls | — |
| `ASSERT_FALSE` | Asserts the call never happens | Unsound |

---

## Ghosts

Additional variables for tracking state during verification. Act as **extensions to contract state**.

```cvl
ghost uint x;
ghost mapping(address => mathint) balances;
ghost mapping(uint => mapping(uint => mathint)) delegations;
```

### Key Properties
- Revert with contract state (unless `persistent`)
- Havoc when unresolved calls havoc (unless `persistent`)
- Restore with `at storageVar` statements
- **Persistent ghosts** — never havoced, never reverted (survive everything)

### Ghost Axioms
```cvl
ghost bar(uint256) returns uint256 {
    axiom forall uint256 x. bar(x) > 10;         // Always true
    init_state axiom sumBalances == 0;             // Only for invariant base step
}
```

### Common Pattern: Ghost + Hook Communication
```cvl
ghost mapping(address => bool) updated;

hook Sstore userInfo[KEY address u] uint i {
    updated[u] = true;
}

rule update_changes_user(address user) {
    updated[user] = false;
    do_update(user);
    assert updated[user] == true;
}
```

---

## Hooks

Attach CVL code to **low-level EVM operations** (storage loads/stores, opcodes).

### Storage Hooks
```cvl
// Store hook — triggered on writes
hook Sstore C.totalSupply uint ts (uint old_ts) {
    // ts = new value, old_ts = previous value
}

// Load hook — triggered on reads
hook Sload address o C.owner {
    // o = value being read
}
```

### Access Paths
- `C.field` — contract field
- `C.field[KEY uint k]` — mapping key
- `C.field[INDEX uint i]` — array index
- `(slot 5)` — raw slot number
- Can chain: `C.info[KEY address u].balance`

### Important Notes
- Hooks are NOT triggered by CVL code, only by contract execution
- Each pattern can only have ONE hook (no duplicates)
- Hooks cannot call contract functions

---

## Environment (env)

The `env` type encapsulates transaction context:

```cvl
rule example {
    env e;
    // e.msg.sender, e.msg.value, e.block.timestamp, etc.
    myContract.deposit(e, amount);
}
```

- `envfree` methods don't need an env parameter
- Use `require e.msg.value == 0` to constrain non-payable calls

---

## Key Types

| CVL Type | Description |
|----------|-------------|
| `mathint` | Unbounded integer (no overflow!) |
| `address`, `uint256`, etc. | Standard Solidity types |
| `env` | Transaction environment |
| `method` | Represents a contract method (for parametric rules) |
| `calldataarg` | Arbitrary calldata |
| `storage` | Snapshot of full storage state |

**`mathint` is critical** — use it for intermediate calculations to avoid overflow/underflow that would hide bugs.

---

## Verification Flow

```
1. Write .spec file (rules, invariants, ghosts, hooks)
2. Create .conf file (contract paths, verification targets)
3. Run: certoraRun MyContract.sol --verify MyContract:spec.spec
4. Prover translates to SMT formula
5. SMT solver checks satisfiability
6. Result: VERIFIED ✅ or COUNTEREXAMPLE ❌
```

---

## Security Audit Relevance

| CVL Feature | Audit Use Case |
|-------------|---------------|
| Parametric rules | Verify property holds for ALL contract functions |
| Invariants | Token supply == sum of balances, access control always enforced |
| Ghost + Hook | Track reentrancy state, count storage changes |
| Strong invariants | Reentrancy protection verification |
| Methods summaries | Handle external dependencies without full code |
| `mathint` | Catch overflow/underflow impossible in fuzzing |

### Common Spec Patterns for Auditors
1. **Balance integrity:** `totalSupply == sum(balances)`
2. **Monotonicity:** Certain values only increase
3. **Access control:** Only owner can call restricted functions
4. **No-revert conditions:** Functions succeed under valid inputs
5. **State machine correctness:** Valid state transitions only
