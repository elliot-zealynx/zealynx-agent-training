# Certora CVL: Invariants Deep Dive

> Session 2 — 2026-02-04 (Sol's Certora Night Study)
> Sources: docs.certora.com/en/latest/docs/cvl/invariants.html, Certora tutorials (lesson4), allthingsfuzzy Substack

---

## 1. What Are Invariants?

Invariants describe a property of contract state that must **always hold** across all reachable states. The Prover checks two things:

1. **Base case (constructor):** Invariant holds after any constructor call on a freshly deployed contract
2. **Inductive step (preservation):** If invariant holds before a method call, it still holds after

This is classic **proof by induction** over the number of method calls.

---

## 2. Weak vs Strong Invariants

### Weak Invariants (default)
- Property holds whenever **no contract method is currently executing**
- Also called "representation invariants"
- Checked at method boundaries only (pre-state and post-state)

```cvl
invariant totalSupplyIsSumOfBalances()
    totalSupply() == sumOfBalances;
```

### Strong Invariants
- Property holds at method boundaries **AND during execution** at unresolved external call points
- Critical for **reentrancy protection** in contracts without global locks
- For every unresolved external call `c`:
  1. **Before call c:** Assert invariant holds (catches mid-execution violations)
  2. **After call c:** Assume invariant holds (external call didn't break it)
  3. **If delegatecall:** After assuming, havoc storage and assert again

```cvl
strong invariant solvency()
    underlying.balanceOf(currentContract) >= totalAssets();
```

### When to Use Each
- **Weak:** Standard state properties (totalSupply tracking, access control)
- **Strong:** Properties that must hold during flash loans, callbacks, cross-contract calls where reentrancy is a concern. Provides defense against read-only reentrancy.

**Security insight:** Strong invariants are the formal verification equivalent of reentrancy guards. They catch violations that weak invariants miss because weak invariants only check at method boundaries, not during execution.

---

## 3. Three Sources of Unsoundness (Critical!)

Unsoundness = Prover says "verified" but the property can still be violated in practice.

### 3.1. Reverting Invariant Expressions
**The most dangerous trap.** If the invariant expression **reverts in the pre-state** but succeeds in the post-state, the Prover discards the counterexample because the `require` (pre-state check) reverted.

**Classic example:**
```solidity
contract Example {
    uint[] private a;
    function add(uint i) external { a.push(i); }
    function get(uint i) external returns(uint) { return a[i]; }
}
```

```cvl
// UNSOUND! Prover says verified, but add(2) clearly breaks this
invariant all_elements_are_zero(uint i)
    get(i) == 0;
```

Why it passes: Before `add(2)`, the array has length `i-1`, so `get(i)` reverts in pre-state. The Prover assumes `require` of a reverting expression discards the trace.

**Mitigation:** Only use **view functions** in invariants. Be suspicious of invariants that access array elements by index, mapping values that may not exist, or external contract state.

### 3.2. Preserved Block `require` Statements
Adding `require` to preserved blocks adds assumptions that may not hold for all method invocations.

```cvl
invariant myProperty()
    someCondition()
    {
        preserved with (env e) {
            require e.msg.sender != 0;  // UNSOUND: what if 0 can call?
        }
    }
```

**Mitigation:** Prefer `requireInvariant` over `require`. The former is sound (assuming the required invariant is proven). The latter introduces arbitrary assumptions.

### 3.3. Filters
Filtering out methods from invariant checking means those methods are never verified for preservation.

```cvl
invariant balance_is_0(address a)
    balanceOf(a) == 0
    filtered { f -> f.selector != sig:deposit(uint).selector }
    // deposit is never checked! Completely unsound for deposit().
```

**Mitigation:** Avoid filters. If a method fails preservation, fix it with a preserved block (which at least allows fine-grained assumptions) instead of skipping the check entirely.

---

## 4. Preserved Blocks (In Depth)

Preserved blocks execute **after the pre-state check** but **before method execution**. They add assumptions needed for the inductive step.

### Syntax Variants

**Generic preserved block** — applies to all methods without a specific block:
```cvl
invariant myInv()
    condition()
    {
        preserved {
            requireInvariant otherInv();
        }
    }
```

**Method-specific preserved block:**
```cvl
invariant collateralCoversBalance(address account)
    collateralOf(account) >= balanceOf(account)
    {
        preserved transferDebt(address recipient) with (env e) {
            requireInvariant collateralCoversBalance(e.msg.sender);
        }
    }
```

**Contract-specific preserved block:**
```cvl
invariant solvency()
    asset.balanceOf() >= internalAccounting()
    {
        preserved asset.transfer(address x, uint y) with (env e) {
            require e.msg.sender != currentContract;
        }
    }
```

**Wildcard contract preserved block** (`_` matches all contracts):
```cvl
invariant solvency()
    asset.balanceOf() >= internalAccounting()
    {
        preserved _.transfer(address x, uint y) with (env e) {
            require e.msg.sender != currentContract;
        }
    }
```

**Constructor preserved block** (for base case):
```cvl
preserved constructor() { /* assumptions for constructor check */ }
```

### Priority Rules
- Specific preserved block > generic preserved block (not both)
- Contract-specific > wildcard
- If a method has a preserved block, it's verified even if a filter would exclude it

---

## 5. `requireInvariant` — The Sound Way

**Key insight:** `requireInvariant` is **always sound** in preserved blocks, even for:
- Self-referential invariants (`requireInvariant myInv(x)` inside `myInv`'s preserved block)
- Mutually dependent invariants (A requires B, B requires A)
- Different parameter instantiations (`requireInvariant myInv(f(x))`)

### Why Self-Reference is Not Circular

For `invariant i(x)` with `preserved { requireInvariant i(x); }`:

The preservation check proves:
```
forall n, forall x: P_i(x, n) AND P_i(x, n) => P_i(x, n+1)
```
Which simplifies to just:
```
forall n, forall x: P_i(x, n) => P_i(x, n+1)
```
Identical to the standard preservation check.

### Why Mutual Dependency Works

For `invariant i` requiring `j` and `invariant j` requiring `i`:

Combined, we get:
```
forall n, forall x: P_i(x,n) AND P_j(x,n) => P_i(x,n+1) AND P_j(x,n+1)
```
This is a valid joint inductive proof of both invariants.

### The `require` vs `requireInvariant` Rule

| | `require` | `requireInvariant` |
|---|---|---|
| Soundness | **Unsound** — adds arbitrary assumption | **Sound** — adds proven fact |
| When to use | Last resort, with documentation | Default choice |
| Risk | Can mask real bugs | Safe (if required invariant passes) |

---

## 6. Writing Invariants as Rules

Any invariant can be rewritten as a parametric rule. Useful for:
- Understanding exactly what the Prover checks
- Breaking down complex invariants with intermediate variables
- Adding custom logic between pre-state and method call

```cvl
// Invariant form:
invariant myInv(uint x) property(x)
    { preserved with (env e) { require e.msg.sender != 0; } }

// Equivalent rule form:
rule myInv_as_rule(uint x, method f) {
    require property(x);              // pre-state check
    env e;
    require e.msg.sender != 0;       // preserved block
    calldataarg args;
    f(e, args);                       // any method
    assert property(x);              // post-state check
}
```

---

## 7. Common Invariant Patterns for DeFi Security

### Token Supply Integrity
```cvl
ghost mathint sumOfBalances {
    init_state axiom sumOfBalances == 0;
}
hook Sstore _balances[KEY address a] uint256 newVal (uint256 oldVal) {
    sumOfBalances = sumOfBalances + newVal - oldVal;
}

invariant totalSupplyIsSumOfBalances()
    to_mathint(totalSupply()) == sumOfBalances;
```

### Vault Solvency
```cvl
strong invariant vaultSolvency()
    underlying.balanceOf(currentContract) >= totalAssets();
```
Using `strong` to protect against flash loan / reentrancy attacks on vault accounting.

### Access Control Consistency
```cvl
invariant ownerIsNonZero()
    owner() != 0;
```

### No Bad Debt (Lending)
```cvl
invariant collateralCoversDebt(address user)
    collateralValueOf(user) >= debtOf(user)
    {
        preserved liquidate(address borrower, uint amount) with (env e) {
            requireInvariant collateralCoversDebt(e.msg.sender);
        }
    }
```

### Unique Manager Pattern
```cvl
invariant uniqueManagers(uint fundA, uint fundB)
    fundA != fundB => managerOf(fundA) != managerOf(fundB)
    {
        preserved claimManagement(uint fundId) with (env e) {
            requireInvariant managerIsActive(fundId);
        }
    }
```

---

## 8. Environment Pitfall

**Common mistake:** Confusing the invariant's `env` parameter with the preserved block's `with (env e)`.

```cvl
// WRONG — restricts env for balanceOf, not for the called method
invariant bad(env e)
    balanceOf(e, 0) == 0
    { preserved { require e.msg.sender != 0; } }

// RIGHT — restricts env for the called method
invariant good()
    balanceOf(0) == 0
    { preserved with (env e) { require e.msg.sender != 0; } }
```

The `with (env e)` binds to the environment used when invoking the method being checked. The invariant's env parameter binds to the environment used for evaluating the invariant expression.

---

## 9. Transient Storage (EIP-1153)

Since Solidity supports `tload`/`tstore`, the Prover automatically adds an extra induction step:
1. Assume invariant in pre-state
2. Reset all transient storage
3. Assert invariant still holds

This ensures invariants are independent of transient storage values.

---

## 10. Practical Workflow for Writing Invariants

1. **Start simple:** Write the invariant without preserved blocks
2. **Check counterexamples:** If Prover finds a violation, determine if it's real or an artifact
3. **If artifact:** Add a preserved block with `requireInvariant` (sound) or `require` (document why)
4. **Prefer method-specific blocks:** Target only the methods that need assumptions
5. **Never use filters** to hide failing methods — that's sweeping bugs under the rug
6. **Watch for reverting expressions:** If your invariant accesses dynamic data (arrays, external state), verify the pre-state won't revert
7. **Use `strong` for DeFi:** Any contract with external callbacks, flash loans, or cross-contract calls

---

## Key Takeaway

Invariants are the most powerful CVL construct for proving global properties, but also the most dangerous if misused. The three unsoundness traps (reverting expressions, `require` in preserved blocks, filters) can produce "verified" results that are meaningless. Always prefer `requireInvariant` over `require`, use `strong` for reentrancy-sensitive properties, and treat filters as a last resort.
