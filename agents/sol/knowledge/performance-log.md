# Solidity Shadow Audit Performance

| Date | Contest | Findings Found | Findings Missed | Precision | Recall | Key Lessons
2026-02-10 | Merkl (C4) | 0/3 | 3/3 | 0% | 0% | Validation timing, try/catch asymmetry, state reference bugs |
|------|---------|---------------|----------------|-----------|--------|-------------|
| 2026-02-03 | Morpheus (C4, Aug 2025) | 0.5/4 | 3.5/4 | ~0% | ~12.5% | Cross-contract data flow tracing (stETH rounding), admin lifecycle state (Aave approvals), protocol end-of-life (yield locked after rewards end), per-feed config heterogeneity |
| 2026-02-05 | Megapot (C4, Nov 2025) | 2.0/11 | 9.0/11 | ~100% | ~18% | LP pool cap overflow from earnings (check both directions), complete exploitation chains for arbitrary calls, admin trust boundaries during active operations |
| 2026-02-07 | Merkl (C4, Nov 2025) | 0/3 | 3/3 | 0% | 0% | Order of operations in validation (gross vs net), try/catch error handling asymmetry, state validation against wrong base (overrides vs originals), avoid over-specialization on approval patterns |
| 2026-02-08 | Panoptic Next Core (C4, Dec 2025) | **PENDING** | **PENDING** | **PENDING** | **PENDING** | **RESULTS NOT PUBLISHED** - Predicted: 10 findings (5H,3M,2L) focusing on integer overflow in DeFi math |
| 2026-02-09 | Krystal DeFi (C4, June 2024) | 5/5 | 0/5 | 80% | 100% | **BREAKTHROUGH:** Token compatibility patterns (zero transfers, approvals), logic condition patterns (impossible state checks), signature security (replay without nonce). Perfect recall on core issues! |
