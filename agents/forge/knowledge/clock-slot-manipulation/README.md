# Clock/Slot Manipulation Vulnerabilities

Clock and slot manipulation vulnerabilities in Solana smart contracts occur when programs make incorrect assumptions about time, timestamps, or slot ordering, allowing attackers to manipulate temporal logic.

## Overview

Solana's unique Proof-of-History (PoH) consensus creates verifiable timestamps, but smart contracts can still be vulnerable to time-based attacks through:

1. **Clock Sysvar Dependencies** - Relying on inaccurate or manipulated timestamps
2. **Slot Ordering Assumptions** - Assuming transactions execute in expected order within slots  
3. **Timestamp Drift Exploitation** - Taking advantage of 25% allowed timestamp deviation
4. **RecentBlockhash MEV** - Exploiting 150-block validity window for transaction timing
5. **Oracle Staleness** - Using outdated time-dependent oracle data

## Historical Context

The Bank Timestamp Correction proposal (Agave) revealed that Clock sysvar timestamps have been "quite inaccurate" since genesis, using theoretical slots-per-second instead of reality. This fundamental timing issue affects time-based lockups and can be exploited in smart contracts.

## Detection Strategy

- Look for direct Clock sysvar usage without validation
- Check for assumptions about slot ordering or timing
- Audit time-based logic (lockups, vesting, cooldowns)
- Review oracle timestamp validation
- Test with edge cases around timestamp drift

## Common Patterns

1. **Clock Sysvar Timestamp Dependency**
2. **Slot Height Manipulation**  
3. **Timestamp Drift Exploitation**
4. **Recent Blockhash MEV Attacks**
5. **Oracle Timestamp Staleness**
6. **Cross-Slot Transaction Ordering**

## Total Impact

While less common than access control issues, time manipulation can enable MEV extraction, oracle manipulation, and bypass of time-based security mechanisms like cooldowns and vesting schedules.