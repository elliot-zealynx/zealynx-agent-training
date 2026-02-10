# Pattern: Multiplication-Before-Division Precision Loss

## Classification
- **Severity:** High
- **Category:** Arithmetic / Precision Loss
- **Affected:** DeFi programs with fee/interest/exchange rate calculations
- **CWE:** CWE-682 (Incorrect Calculation)

## Description
Integer division in Rust truncates (floors) the result. When division happens before multiplication, precision is lost. This is especially dangerous in financial math where:
- Exchange rates multiply and divide token amounts
- Fee calculations involve percentages
- Interest accrual compounds over time

The order of operations matters enormously:
- `(a / b) * c` loses precision from the division first
- `(a * c) / b` preserves precision but risks intermediate overflow

Both are wrong if not handled carefully. The correct approach uses u128 intermediates with checked math.

## Vulnerable Code Example

```rust
// VULNERABLE: Division before multiplication loses precision
pub fn calculate_interest(principal: u64, rate: u64, time: u64) -> u64 {
    // rate = 5 (0.05%), principal = 1000, time = 365
    // (1000 / 10000) * 5 * 365 = 0 * 5 * 365 = 0 (should be 182)
    principal / 10000 * rate * time
}

// VULNERABLE: Rounding direction favors attacker
pub fn collateral_to_liquidity(collateral: u64, ratio: u64) -> u64 {
    // Using try_round_u64() rounds to nearest, can favor attacker
    Decimal::from(collateral)
        .try_div(ratio)?
        .try_round_u64()
}

// VULNERABLE: Floating point for financial math
pub fn calculate_stake_percent(current: u64, total: u64) -> f64 {
    // Floating point cannot accurately represent most decimals
    (current * 100) as f64 / total as f64
}
```

### Attack Scenario (Precision Arbitrage)
1. Protocol calculates exchange rate: `output = input * rate / PRECISION`
2. Rate = 1000003 (slight premium), PRECISION = 1000000
3. For small amounts: `1 * 1000003 / 1000000 = 1` (rounds down, user gets 1)
4. Attacker makes many small swaps: each time protocol rounds in attacker's favor
5. Over thousands of transactions, attacker extracts dust that accumulates to significant value

## Real Examples

### Solana Watchtower Precision Loss
- **Source:** [solana-labs/solana commit 5ae37b9](https://github.com/solana-labs/solana/commit/5ae37b9675888c1eb218780d778c0825460f8105)
- **Bug:** Integer division between `total_current_stake * 100` and `total_stake` loses precision
- **Fix:** Changed variables to `f64` type (though f64 for money is also problematic)

### SlowMist: try_round_u64() Arbitrage
- **Source:** [SlowMist Solana Best Practices](https://github.com/slowmist/solana-smart-contract-security-best-practices)
- **Bug:** `collateral_to_liquidity` using `try_round_u64()` allows rounding exploitation
- **Fix:** Use `try_floor_u64()` to always round in protocol's favor

### OWASP Solana Top 10: Arithmetic Accuracy Deviation
- **Source:** [OWASP Issue #1](https://github.com/OWASP/www-project-solana-programs-top-10/issues/1)
- **Bug:** Interest calculation where `numerator / denominator` = 0 for small durations
- **Impact:** Users can skip interest payments by choosing specific durations

## Detection Strategy

### Manual Audit
1. Look for division (`/`) before multiplication (`*`) in any expression
2. Check rounding direction: does it favor the protocol or the user?
3. Verify interest/fee calculations with small inputs (1, 2, 3 tokens)
4. Test with amounts that are NOT nice round numbers
5. Check for floating point usage in financial math (`f32`, `f64`)

### Key Questions
- Is multiplication done before division? `(a * b) / c` not `(a / c) * b`
- Does rounding favor the protocol? (Floor for payouts, ceil for fees)
- Are intermediates widened to u128 to prevent overflow?
- Are divisors validated as non-zero?
- Is floating point used for currency? (Almost always wrong)

### Automated
- Look for patterns: `amount\s*/\s*\d+\s*\*` (division before multiplication)
- Check for `f32`/`f64` in financial calculation paths

## Fix Pattern

```rust
// SAFE: Multiply first, use u128 intermediate, round in protocol's favor
pub fn calculate_fee(amount: u64, fee_bps: u64) -> Result<u64, ProgramError> {
    // fee_bps in basis points (100 = 1%)
    let fee = (amount as u128)
        .checked_mul(fee_bps as u128)
        .ok_or(ProgramError::ArithmeticOverflow)?
        .checked_add(9999)  // Round UP (ceiling) for fees
        .ok_or(ProgramError::ArithmeticOverflow)?
        .checked_div(10000)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    u64::try_from(fee).map_err(|_| ProgramError::ArithmeticOverflow)
}

// SAFE: Floor for payouts (protocol keeps dust)
pub fn calculate_payout(amount: u64, rate: u64, precision: u64) -> Result<u64, ProgramError> {
    let payout = (amount as u128)
        .checked_mul(rate as u128)
        .ok_or(ProgramError::ArithmeticOverflow)?
        .checked_div(precision as u128)  // Floor (truncate) for payouts
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    u64::try_from(payout).map_err(|_| ProgramError::ArithmeticOverflow)
}
```

### Rules
- **Multiply before divide:** `(a * b) / c`, never `(a / c) * b`
- **Widen intermediates:** Cast to u128 before multiplying two u64 values
- **Round in protocol's favor:** Floor for payouts, ceil for fees
- **Never use f32/f64 for currency:** Use fixed-point decimal types instead
- **Validate divisors:** Always check for zero before division

## References
- [Zealynx Solana Security Checklist](https://www.zealynx.io/blogs/solana-security-checklist)
- [SlowMist: Solana Best Practices](https://github.com/slowmist/solana-smart-contract-security-best-practices)
- [OWASP Solana Top 10](https://github.com/OWASP/www-project-solana-programs-top-10/issues/1)
- [Sec3: Arithmetic Errors in Solana](https://www.sec3.dev/blog/understanding-arithmetic-overflow-underflows-in-rust-and-solana-smart-contracts)
