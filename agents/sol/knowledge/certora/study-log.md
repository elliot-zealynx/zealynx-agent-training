# Certora/CVL Study Log

## Study Plan (Rotation)
1. ✅ CVL Basics — spec structure, rules, invariants, ghosts, hooks, methods
2. ✅ Invariants Deep Dive — strong vs weak, preserved blocks, unsoundness traps
3. ✅ Ghost Variables & Hooks — persistent ghosts, axioms, tracking patterns
4. ✅ Parametric Rules & Filters — method types, calldataarg, rule filters
5. ✅ Multi-Contract Verification — using statements, DISPATCHER, scene config
6. ⬜ Spec Patterns — common security properties, ERC20/vault patterns
7. ⬜ Gambit — mutation testing for specs, measuring coverage
8. ⬜ Real Protocol Specs — study Aave, Compound, OpenZeppelin specs

---

## Session 5 — 2026-02-08 (Multi-Contract Verification)
- **Topic:** Scene setup, linking known contracts, DISPATCHER summaries for unknown contracts, flexible receiver patterns
- **Sources:** docs.certora.com/en/latest/docs/user-guide/multicontract/index.html, docs.certora.com/en/latest/docs/cvl/methods.html, Certora Examples LiquidityPool
- **Output:** `/root/clawd/knowledge/solidity/certora/multi-contract-verification.md`
- **Key Learnings:**
  - **Scene is the contract universe** — only contracts in scene can be DISPATCHER targets, unresolved calls default to HAVOC_ECF (non-view) or NONDET (view)
  - **Linking vs DISPATCHER decision** — link when you know exact contract, dispatch when address is user-controlled or multiple implementations needed
  - **DISPATCHER is unsound but useful** — only considers contracts YOU provide, forces explicit threat modeling, misses attacks from implementations not in scene
  - **Flexible receiver pattern** leverages Prover's arbitrary value exploration — `arbitraryUint()` from storage lets single receiver simulate all possible reentrancy attacks
  - **Using statements enable CVL → scene calls** — `underlying.balanceOf(currentContract)` instead of adding wrapper methods to main contract
  - **ERC20 DISPATCHER pattern is reusable** — import standard erc20.spec for token compatibility verification across protocols
  - **Summary resolution hierarchy** — exact > wildcard > catch-all > catch-unresolved > AUTO, allows fine-grained control
  - **Multi-step attack limitation** — flexible receivers only make one reentrant call, complex attack chains require multiple receiver contracts
  - **Flash loan security model** — temporary state inconsistency + arbitrary external execution = canonical formal verification challenge
  - **Inter-contract invariant violations** are the blind spot of single-contract verification
- **Security Insight:** Multi-contract verification addresses the fundamental limitation of isolated contract testing — real exploits happen at protocol boundaries. Flash loans exemplify this: they create "impossible" intermediate states (borrowed funds) while executing arbitrary external code (receiver callbacks). DISPATCHER with flexible receivers systematically explores the reentrancy attack space that manual testing can't cover. The Pool + Asset + FlashLoanReceiver setup catches cross-contract state manipulation bugs that single-contract specs miss entirely. However, DISPATCHER's unsoundness means your threat model determines your security — the attacks you don't think of are the ones you'll miss.

## Session 4 — 2026-02-07 (Parametric Rules & Filters)
- **Topic:** Universal property verification via method variables, calldataarg type, rule filters for efficiency
- **Sources:** docs.certora.com/en/latest/docs/cvl/rules.html, docs.certora.com/en/latest/docs/cvl/types.html, Certora Examples reentrancy spec
- **Output:** `/root/clawd/knowledge/solidity/certora/parametric-rules-filters.md`
- **Key Learnings:**
  - **Method parameters must be rule parameters** for filter access — declaring `method f` inside rule body breaks `filtered { f -> f.isView }` syntax
  - **Calldataarg type is opaque** — cannot inspect contents, only pass to method calls, because argument types vary per method
  - **Rule filters are performance-critical** — prevent verification of excluded methods entirely vs `require` which generates counterexamples first
  - **Method type exposes rich metadata** — `f.selector`, `f.isView`, `f.isPure`, `f.isFallback`, `f.numberOfArguments`, `f.contract`
  - **View/non-view partitioning is fundamental** — most security properties only apply to state-changing functions
  - **Multi-contract filtering** requires explicit scoping: `f.contract == vault` to target specific contracts in scene
  - **Reentrancy detection pattern** combines persistent ghosts, CALL opcode hooks, and filtered parametric rules targeting non-view methods
  - **Universal property verification** — parametric rules test that ALL methods preserve invariants (e.g., totalSupply == sum(balances))
  - **Filter precision impacts security** — too restrictive misses vulnerable methods, too broad wastes computation
- **Security Insight:** Parametric rules + filters are formal verification's answer to "fuzz test every method against universal properties" but mathematically exhaustive. Essential for DeFi protocols where invariants like vault solvency must hold regardless of which method is called. The reentrancy example shows sophisticated attack simulation: persistent ghosts track external calls, opcode hooks detect EVM-level reentrancy, filters focus on state-changing methods only.

---

## Session 3 — 2026-02-05 (Ghost Variables & Hooks)
- **Topic:** Persistent vs non-persistent ghosts, init_state vs global axioms, storage hooks, opcode hooks, tracking patterns
- **Sources:** docs.certora.com/en/latest/docs/cvl/ghosts.html, docs.certora.com/en/latest/docs/cvl/hooks.html, docs.certora.com/en/latest/docs/user-guide/ghosts.html, docs.certora.com/en/latest/docs/user-guide/opcodes.html, docs.certora.com/en/latest/docs/user-guide/patterns/sums.html, Certora tutorials lesson 4, Certora ERC4626 Workshop spec
- **Output:** `/root/clawd/knowledge/solidity/certora/ghost-variables-hooks.md`
- **Key Learnings:**
  - **Persistent ghosts are essential for reentrancy detection** — without them, unresolved calls havoc the ghost before the CALL hook executes, creating false positives
  - **Init_state axioms ONLY apply to constructor checks** (invariant base step), NOT to rules or preservation — copying them to `require` statements excludes valid states
  - **Hooks execute on Solidity storage access, not CVL** — reading ghosts in CVL doesn't trigger hooks
  - **Hooks are NOT recursive** — if a hook calls a function that would trigger another hook, the inner hook is skipped
  - **Store hooks can capture old value** with `(uint oldValue)` syntax for delta calculations
  - **Contract qualification matters** — `hook Sstore C.balances[...]` vs `hook Sstore balances[...]` (currentContract)
  - **Sum tracking pattern** is canonical for totalSupply == sum(balances) invariants
  - **Mirror mapping pattern** + load hooks enable cross-validation (Sload requires value matches mirror)
  - **Opcode hooks provide EVM visibility** for CHAINID, CALL, DELEGATECALL, REVERT, etc.
  - **`executingContract` and `selector`** are special variables available in hook bodies
- **Security Insight:** Persistent ghosts solve a fundamental formal verification challenge: tracking state across operations that havoc storage. For any protocol with flash loans, callbacks, or cross-contract calls, using non-persistent ghosts for reentrancy detection will produce false positives due to the havoc-before-hook execution order. This is why all major audit specs use persistent ghosts for call tracking.

## Session 2 — 2026-02-04 (Invariants Deep Dive)
- **Topic:** Weak vs strong invariants, unsoundness traps, preserved blocks, induction proofs, DeFi patterns
- **Sources:** docs.certora.com/en/latest/docs/cvl/invariants.html (full page), Certora tutorials lesson 4 (preserved blocks), allthingsfuzzy Substack intro
- **Output:** `/root/clawd/knowledge/solidity/certora/invariants-deep-dive.md`
- **Key Learnings:**
  - Three sources of unsoundness: reverting expressions, `require` in preserved blocks, filters. All can produce false "verified" results.
  - Strong invariants assert/assume at every unresolved external call — formal verification equivalent of reentrancy guards
  - `requireInvariant` is ALWAYS sound in preserved blocks, even self-referential or mutually dependent — proven via joint induction
  - `require` in preserved blocks is unsound — adds arbitrary assumption that may not hold for all invocations
  - The "reverting pre-state" trap is the most dangerous: if invariant expression reverts before a method call, counterexamples are silently discarded
  - Environment pitfall: `with (env e)` in preserved binds to the method's env, NOT to the invariant's env parameter
  - EIP-1153 transient storage gets automatic induction step (reset + re-assert)
  - 7 DeFi invariant patterns documented: token supply, vault solvency, access control, no bad debt, unique managers, etc.
- **Security Insight:** Strong invariants are essential for any DeFi contract with flash loans, callbacks, or cross-contract interactions. A weak invariant on a vault could pass formal verification while a flash loan attack drains it mid-execution.

## Session 1 — 2026-02-03 (CVL Basics)
- **Topic:** Full CVL language overview
- **Sources:** docs.certora.com/en/latest/docs/cvl/ (overview, rules, invariants, methods, ghosts, hooks)
- **Output:** `/root/clawd/knowledge/solidity/certora/cvl-basics.md`
- **Key Learnings:**
  - CVL translates rules + contract code into SMT formulas — satisfiable = counterexample exists
  - `mathint` is critical — unbounded integers prevent overflow masking real bugs
  - Invariant unsoundness is a real trap: reverting expressions in pre-state silently discard counterexamples
  - Strong invariants add reentrancy protection by asserting at unresolved external call boundaries
  - Ghost + Hook pattern is the primary mechanism for tracking state changes across calls
  - `HAVOC_ALL` is the only always-sound summary type
  - Parametric rules generate separate reports per method — powerful for "does ANY function break this?"
- **Security Insight:** Formal verification catches what fuzzing can't — properties that must hold for ALL inputs, ALL states, ALL method sequences. Especially valuable for invariant violations that require multi-step attack paths.
