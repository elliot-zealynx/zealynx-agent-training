# Cross-Chain Integration Patterns

Security patterns for cross-chain bridge/vault protocols, particularly Solana ↔ EVM via LayerZero.

## Patterns

| # | Pattern | Severity | Source |
|---|---------|----------|--------|
| 01 | Message Payload Binding | High-Critical | Orderly (Sherlock, H-1 & H-2) |
| 02 | Ordering Consistency | Medium-High | Orderly (Sherlock, M-1) |

## Common Cross-Chain Vulnerability Classes

1. **Payload-Account Mismatch** — Message says X, on-chain uses Y
2. **Ordering Assumptions** — Sender/receiver disagree on message ordering
3. **Replay Attacks** — Messages re-executed after initial processing
4. **State Inconsistency** — Source debits before destination confirms
5. **Spoofed Messages** — Fake cross-chain messages bypass peer validation

## Key Detection Questions

- Are all cross-chain message fields validated against on-chain accounts?
- Do sender and receiver agree on ordering semantics?
- Can a message be replayed or front-run?
- What happens if the destination rejects a message the source already committed?
- Is there admin recovery for stuck states?
