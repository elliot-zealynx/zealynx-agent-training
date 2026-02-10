# Pattern: Division by Zero Panic

## Classification
- **Severity:** High (DoS) / Medium (Logic Error)
- **Category:** Arithmetic / Denial of Service
- **Affected:** Any program dividing by user-influenced or state-derived values
- **CWE:** CWE-369 (Divide By Zero)

## Description
In Rust, division by zero ALWAYS panics, in both debug and release mode. Unlike overflow (which wraps silently in release), division by zero causes the program to abort.

On Solana, this means:
- The transaction fails with a runtime error
- No state changes occur (atomic rollback)
- But it can be weaponized as a Denial of Service (DoS) vector

If an attacker can force a divisor to zero, they can:
- Block critical operations (e.g., liquidations, withdrawals)
- Prevent protocol governance actions
- Stall time-sensitive operations

Even `checked_div` and `saturating_div` won't help if you don't handle the `None`/0 result properly.

## Vulnerable Code Example

```rust
// VULNERABLE: Division by potentially zero value
pub fn calculate_exchange_rate(
    total_supply: u64,
    total_value: u64,
) -> Result<u64, ProgramError> {
    // If total_supply is 0 (empty pool), this panics
    let rate = total_value / total_supply;
    Ok(rate)
}

// VULNERABLE: User-controlled divisor
pub fn distribute_rewards(
    total_rewards: u64,
    num_stakers: u64,
) -> Result<u64, ProgramError> {
    // Attacker unstakes all, leaving num_stakers = 0
    // Next reward distribution panics
    let per_staker = total_rewards / num_stakers;
    Ok(per_staker)
}
```

### Attack Scenario
1. Lending protocol calculates exchange rate: `total_deposited / total_shares`
2. Attacker is last depositor, withdraws everything
3. `total_shares = 0`
4. Next user trying to deposit triggers division by zero
5. Protocol deposits are permanently bricked until admin intervention

## Detection Strategy

### Manual Audit
1. Find all division operations (`/`, `%`, `checked_div`, `div`)
2. Trace the divisor back to its origin: can it ever be zero?
3. Check: is the divisor derived from user input, pool state, or counter?
4. Look for empty-pool edge cases (first deposit, last withdrawal)
5. Check modulo operations too (`%` also panics on zero)

### Automated
- `cargo clippy -- -W clippy::integer_division`
- grep: `rg '\b(amount|total|supply|count|num)\b.*/' --type rust`

### Key Questions
- Can the divisor reach zero through normal operations?
- What happens when a pool/vault is completely empty?
- Is the first deposit / last withdrawal handled as a special case?
- Are checked_div results properly unwrapped with error handling?

## Fix Pattern

```rust
// SAFE: Explicit zero check
pub fn calculate_exchange_rate(
    total_supply: u64,
    total_value: u64,
) -> Result<u64, ProgramError> {
    if total_supply == 0 {
        // First deposit: 1:1 rate, or return error
        return Ok(1);  // Or appropriate default
    }
    
    total_value
        .checked_div(total_supply)
        .ok_or(ProgramError::ArithmeticOverflow)
}

// SAFE: Guard against empty state
pub fn distribute_rewards(
    total_rewards: u64,
    num_stakers: u64,
) -> Result<u64, ProgramError> {
    if num_stakers == 0 {
        // No stakers: rewards go to treasury or are queued
        return Err(ProgramError::NoStakers);
    }
    
    total_rewards
        .checked_div(num_stakers)
        .ok_or(ProgramError::ArithmeticOverflow)
}
```

### Edge Cases to Handle
- **Empty pool:** First deposit, exchange rate = 1:1
- **Last withdrawal:** Ensure no pending operations depend on the pool
- **Zero-amount operations:** Validate inputs > 0 at instruction entry
- **Token decimals:** Amount might be 0 after decimal conversion

## References
- [SlowMist: Panic Due to Division by Zero](https://github.com/slowmist/solana-smart-contract-security-best-practices)
- [Cantina: Solana Security Guide](https://cantina.xyz/blog/securing-solana-a-developers-guide)
