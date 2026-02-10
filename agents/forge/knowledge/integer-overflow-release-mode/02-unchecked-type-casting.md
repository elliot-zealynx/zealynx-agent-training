# Pattern: Unchecked Type Casting

## Classification
- **Severity:** High
- **Category:** Arithmetic / Type Truncation
- **Affected:** Programs using `as` keyword for integer conversion
- **CWE:** CWE-681 (Incorrect Conversion between Numeric Types)

## Description
Rust's `as` keyword for type casting silently truncates values when converting between integer types. Unlike arithmetic overflow, this is NOT caught even with `overflow-checks = true` in Cargo.toml. The `as` cast always truncates.

Examples:
- `300u64 as u8` = `44` (truncated to lower 8 bits)
- `u64::MAX as u32` = `4294967295` (u32::MAX)
- `256u16 as u8` = `0`
- `-1i32 as u32` = `4294967295` (reinterpretation)

This is especially dangerous in Solana programs where:
- Token amounts in u64 get cast to u32 for some calculation
- Cross-program call parameters need type conversion
- Fee calculations mix different integer sizes

## Vulnerable Code Example

```rust
// VULNERABLE: Truncation via `as`
pub fn calculate_fee(amount: u64, percentage: f32) -> u64 {
    let precision_factor: f32 = 1000000.0;
    let factor = (percentage / 100.0 * precision_factor) as u128;
    // If amount * factor overflows u128, cast back to u64 truncates
    (amount as u128 * factor / precision_factor as u128) as u64
}

// VULNERABLE: u64 to u32 truncation
pub fn process_withdrawal(amount: u64) -> ProgramResult {
    // If amount > u32::MAX, it silently wraps
    let amount_u32 = amount as u32;
    invoke_transfer(amount_u32)?;
    Ok(())
}
```

### Attack Scenario
1. Program expects a u32 fee value but receives u64 input
2. Attacker passes `amount = 4294967296 + desired_small_value` (e.g., 4294967396)
3. `amount as u32` = `100` (only lower 32 bits kept)
4. Balance check uses the original u64, fee calculation uses truncated u32
5. Attacker pays 100 in fees but withdraws billions

## Real Examples

### OWASP Solana Top 10 - Fee Calculation
- **Source:** [OWASP Solana Programs Top 10, Issue #1](https://github.com/OWASP/www-project-solana-programs-top-10/issues/1)
- **Bug:** `(amount as u128 * factor / precision_factor as u128) as u64` - if intermediate result exceeds u64::MAX, cast silently truncates
- **Impact:** Incorrect fee calculation, potential arbitrage

### Neodyme Audit Findings
- **Source:** [Neodyme Blog: Common Pitfalls](https://blog.neodyme.io/posts/solana_common_pitfalls)
- **Quote:** "We've seen a few contracts use unchecked casts, e.g. via using `as u32` on a u64 value. Rust will simply truncate the value to its last 32 bits."

## Detection Strategy

### Manual Audit
1. Grep for `as u8`, `as u16`, `as u32`, `as u64` in arithmetic contexts
2. Check every `as` cast: is the source type wider than the destination?
3. Look for casts in fee calculations, balance updates, token math
4. Check signed-to-unsigned casts (`as u64` on i64) for sign issues

### Automated
- `cargo clippy -- -W clippy::cast_possible_truncation`
- `cargo clippy -- -W clippy::cast_sign_loss`
- `cargo clippy -- -W clippy::cast_possible_wrap`
- grep: `rg '\bas\s+u(8|16|32|64)\b' --type rust`

### Key Questions
- Are any narrowing casts (`u64 -> u32`, `u128 -> u64`) present?
- Is the source value bounded/validated before the cast?
- Could a user-controlled input reach a narrowing cast?

## Fix Pattern

```rust
// SAFE: Using TryFrom for checked conversion
use std::convert::TryFrom;

pub fn process_withdrawal(amount: u64) -> ProgramResult {
    // TryFrom returns Err if value doesn't fit
    let amount_u32 = u32::try_from(amount)
        .map_err(|_| ProgramError::InvalidArgument)?;
    invoke_transfer(amount_u32)?;
    Ok(())
}

// SAFE: Using TryInto trait
pub fn calculate_fee(amount: u64, rate: u64) -> Result<u64, ProgramError> {
    let result_u128 = (amount as u128)
        .checked_mul(rate as u128)
        .ok_or(ProgramError::ArithmeticOverflow)?
        .checked_div(10000)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    u64::try_from(result_u128)
        .map_err(|_| ProgramError::ArithmeticOverflow)
}
```

### Rules
- **Never** use `as` for narrowing casts in financial math
- Use `TryFrom`/`TryInto` for all conversions between integer types
- Widen to u128 for intermediate calculations, then `TryFrom` back to u64
- `overflow-checks = true` does NOT protect against `as` truncation

## References
- [Rust Reference: Type Cast Expressions](https://doc.rust-lang.org/reference/expressions/operator-expr.html#type-cast-expressions)
- [Rust std::convert::TryFrom](https://doc.rust-lang.org/std/convert/trait.TryFrom.html)
- [Neodyme: Common Pitfalls](https://blog.neodyme.io/posts/solana_common_pitfalls)
- [OWASP Solana Top 10](https://github.com/OWASP/www-project-solana-programs-top-10/issues/1)
