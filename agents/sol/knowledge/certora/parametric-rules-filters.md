# Parametric Rules & Filters — Certora/CVL Deep Dive

**Purpose:** Understand CVL parametric rules, method filters, and type system for universal property verification
**Study Session:** 2026-02-07 (Session 4)
**Sources:** 
- docs.certora.com/en/latest/docs/cvl/rules.html
- docs.certora.com/en/latest/docs/cvl/types.html
- Certora Examples reentrancy spec

---

## Core Concepts

### What Are Parametric Rules?

**Parametric rules** contain undefined `method` variables that get instantiated across ALL methods in the verification scene. Each method gets its own separate verification report, allowing universal property checking.

```cvl
// This rule runs for EVERY method in every contract
rule universal_property() {
    method f;           // Undefined method variable
    env e; 
    calldataarg args;   // Generic arguments
    
    // Pre-state
    mathint balance_before = getBalance();
    
    f(e, args);         // Call ANY method with ANY args
    
    // Post-state  
    mathint balance_after = getBalance();
    
    // Universal property: no method can decrease balance
    assert balance_after >= balance_before;
}
```

**Key insight:** This generates reports for `deposit()`, `withdraw()`, `transfer()`, etc. — each tested independently against the same property.

### The `method` Type

Method variables expose metadata through field access:

```cvl
rule authorization_check(method f) {
    require f.numberOfArguments <= 3;  // Skip methods with many args
    require !f.isPure;                  // Skip pure functions
    require f.contract == currentContract; // Only check this contract
    
    env e;
    calldataarg args;
    f(e, args);
    
    // Property: all non-view methods require authorization
    assert f.isView || is_authorized(e.msg.sender, f.selector);
}
```

**Available fields:**
- `f.selector` — ABI signature (bytes4)
- `f.isPure` — declared with `pure` attribute
- `f.isView` — declared with `view` attribute  
- `f.isFallback` — is the fallback function
- `f.numberOfArguments` — parameter count
- `f.contract` — receiver contract

### The `calldataarg` Type

**`calldataarg`** represents generic method arguments. Cannot be inspected directly — only passed to method calls.

```cvl
rule generic_call(method f) {
    env e;
    calldataarg args;    // Unknown argument set
    
    f(e, args);          // Valid: pass to method call
    
    // Invalid: cannot examine args contents
    // require args.amount > 0;  // ❌ ERROR
}
```

**Limitation:** Content is opaque because argument types vary per method. For partial parametricity, see Certora's "partially parametric rules" pattern.

---

## Rule Filters

### Syntax & Purpose

**Rule filters** exclude specific methods from parametric rule verification — more efficient than `require` statements that generate counterexamples first.

```cvl
rule filtered_example(method f, method g) filtered {
    f -> f.isView,                                  // Only view functions for f
    g -> g.selector != dangerous(uint).selector     // Exclude specific method for g
        && !g.isFallback                            // No fallback
        && g.numberOfArguments <= 2                 // Max 2 parameters
} {
    // Rule body only runs for methods that pass filters
    env e; calldataarg args;
    f(e, args);
    g(e, args);
}
```

**Critical rule:** Method must be declared as **rule parameter**, not inside rule body:

```cvl
// ❌ WRONG: f not accessible to filter
rule bad_filter() filtered { f -> f.isView } {
    method f;  // Too late - f is internal variable
}

// ✅ CORRECT: f is rule parameter
rule good_filter(method f) filtered { f -> f.isView } {
    // f is already declared as parameter
}
```

### Filter Expressions

Boolean expressions can reference:
- Method fields (`f.isView`, `g.selector`)
- Comparison with specific methods (`f.selector != target().selector`)
- Compound conditions (`!f.isPure && f.numberOfArguments <= 3`)
- **Cannot reference:** other method parameters, rule variables, or internal state

### Performance Benefits

```cvl
// Inefficient: generates counterexamples, then ignores them
rule slow_approach(method f) {
    require f.isView;  // ❌ Wasteful - prover still checks all methods
    // ... rule body
}

// Efficient: prover skips non-view methods entirely  
rule fast_approach(method f) filtered { f -> f.isView } {  // ✅ Smart filtering
    // ... rule body (only runs for view methods)
}
```

---

## Real-World Examples

### Reentrancy Detection

From **Certora Examples repository** — sophisticated reentrancy detection using ghost tracking:

```cvl
persistent ghost bool called_extcall;
persistent ghost bool g_reverted;
persistent ghost uint32 g_sighash;

// CALL opcode hook simulates reentrancy attacks
hook CALL(uint g, address addr, uint value, uint argsOffset, 
          uint argsLength, uint retOffset, uint retLength) uint rc {
    called_extcall = true;
    env e;
    
    if (g_sighash == sig:withdrawAll().selector) {
        withdrawAll@withrevert(e);
        g_reverted = lastReverted;
    }
    else if (g_sighash == sig:withdraw(uint256).selector) {
        calldataarg args;
        withdraw@withrevert(e, args);
        g_reverted = lastReverted;
    }
    else {
        g_reverted = true;  // Conservative: assume revert
    }
}

// Main rule: only non-view methods can cause reentrancy
rule no_reentrancy(method f, method g) filtered { 
    f -> !f.isView,   // Only state-changing functions 
    g -> !g.isView    // can be dangerous for reentrancy
} {
    require !called_extcall;
    require !g_reverted;
    env e; calldataarg args;
    require g_sighash == g.selector;
    
    f@withrevert(e, args);
    
    // If external call happened, reentrancy must revert
    assert called_extcall => g_reverted, "Reentrancy weakness exists";
}
```

**Security insight:** Filters ensure the rule only runs for methods that can actually modify state. Checking view functions would be meaningless for reentrancy detection.

### Access Control Pattern

```cvl
rule admin_only_functions(method f) filtered {
    f -> f.selector == setAdmin(address).selector 
      || f.selector == pause().selector
      || f.selector == updateConfig(bytes32,uint256).selector
} {
    env e; calldataarg args;
    
    require e.msg.sender != admin();  // Non-admin caller
    
    f@withrevert(e, args);
    
    assert lastReverted, "Admin function must revert for non-admin";
}
```

### ERC20 Invariant Testing

```cvl
rule totalSupply_equals_sum_of_balances(method f) filtered {
    f -> !f.isView           // Only state-changing methods
      && f.selector != mint(address,uint256).selector  // Exclude mint (changes totalSupply)
      && f.selector != burn(address,uint256).selector  // Exclude burn (changes totalSupply) 
} {
    // Pre-state
    mathint total_before = totalSupply();
    mathint sum_before = sumOfBalances();  // Ghost-tracked
    require total_before == sum_before;
    
    env e; calldataarg args;
    f(e, args);
    
    // Post-state: invariant preserved
    mathint total_after = totalSupply();
    mathint sum_after = sumOfBalances();
    assert total_after == sum_after, "TotalSupply must equal sum of balances";
}
```

---

## Common Patterns & Best Practices

### 1. **View/Non-View Partitioning**

Most security properties only apply to state-changing functions:

```cvl
rule no_unauthorized_state_change(method f) filtered { f -> !f.isView } {
    require !isAuthorized(e.msg.sender, f.selector);
    // ... expect revert
}
```

### 2. **Selector-Based Exclusions**

Complex protocols often need granular method filtering:

```cvl
rule deposit_withdraw_symmetry(method f) filtered {
    f -> f.selector == deposit(uint256).selector 
      || f.selector == withdraw(uint256).selector
      // Exclude emergency functions
      && f.selector != emergencyWithdraw().selector
      && f.selector != pause().selector
} {
    // Test symmetric deposit/withdraw behavior
}
```

### 3. **Contract-Specific Rules**

Multi-contract scenes need scoping:

```cvl
using Vault as vault;
using Token as token;

rule vault_solvency(method f) filtered { 
    f -> f.contract == vault     // Only vault methods
      && !f.isView               // Only state changes
      && f.numberOfArguments <= 2  // Skip complex methods
} {
    mathint assets_before = token.balanceOf(vault);
    mathint shares_before = vault.totalSupply();
    
    env e; calldataarg args;
    vault.f(e, args);
    
    mathint assets_after = token.balanceOf(vault);
    mathint shares_after = vault.totalSupply();
    
    // Vault solvency: assets >= shares
    assert assets_after >= shares_after;
}
```

### 4. **Parameter Count Filtering**

Skip methods with complex signatures that are hard to reason about:

```cvl
rule simple_methods_only(method f) filtered {
    f -> f.numberOfArguments <= 3     // Skip complex functions
      && !f.isFallback                // Skip fallback
      && f.contract == currentContract
} {
    // Focus verification on simple, core methods
}
```

---

## Security Implications

### 1. **Universal Property Verification**

Parametric rules excel at finding **universal violations** — properties that must hold for ALL methods:

**Bad:**
```cvl
rule test_specific_method() {
    transfer(...);  // Only tests one method
    assert invariant_holds();
}
```

**Good:**
```cvl  
rule universal_invariant(method f) {
    f(...);  // Tests ALL methods against same invariant
    assert invariant_holds();
}
```

### 2. **Filter Precision Matters**

**Over-filtering (too restrictive):** Misses vulnerable methods
```cvl
// Dangerous: might exclude methods that should be tested
rule too_restrictive(method f) filtered { f -> f.isView } {
    // Only tests view functions — misses state changes!
}
```

**Under-filtering (too broad):** Inefficient, false negatives
```cvl
// Inefficient: tests methods that can't violate the property
rule too_broad(method f) {  // No filter
    require expensive_precondition();  // Computed for every method
}
```

### 3. **Reentrancy Detection Pattern**

The example shows sophisticated defense:
- **Persistent ghosts** track call state across transactions
- **Opcode hooks** detect external calls at EVM level
- **Filters** focus only on dangerous (non-view) methods
- **Concrete reentrancy simulation** via specific method calls

This catches reentrancy vulnerabilities that static analysis might miss.

---

## Key Learnings

### **Technical Insights:**
1. **Method parameters must be rule parameters** for filter access — declaring inside rule body breaks filtering
2. **Calldataarg opacity** prevents inspection but enables generic method calls across different signatures
3. **Filter efficiency** is crucial for large codebases — avoids generating useless counterexamples
4. **Multi-contract filtering** requires explicit contract qualification (`f.contract == target`)
5. **Opcode hooks + parametric rules** create powerful reentrancy detection patterns

### **Security Insights:**
1. **Parametric rules find universal violations** — properties that must hold regardless of method called
2. **View/non-view partitioning** is fundamental — most security properties only apply to state changes
3. **Reentrancy detection** requires sophisticated ghost tracking + selective method filtering
4. **Filter precision** directly impacts security — too narrow misses vulnerabilities, too broad wastes compute
5. **Universal invariants** (like totalSupply = sum(balances)) are perfect for parametric verification

### **DeFi Applications:**
- **Vault solvency:** Assets backing must always cover shares issued
- **Token invariants:** Supply/balance consistency across ALL operations  
- **Access control:** Admin functions must reject unauthorized callers universally
- **Reentrancy shields:** External calls during state changes must be safe
- **Flash loan protection:** Invariants must hold even with temporary inconsistencies

**Bottom line:** Parametric rules + filters are the formal verification equivalent of "fuzz testing every method against universal properties" — but mathematically exhaustive, not probabilistic.