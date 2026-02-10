# Pattern: Intermediate Overflow in Compound Expressions

## Classification
- **Severity:** High to Critical
- **Category:** Arithmetic / Intermediate Overflow
- **Affected:** Programs with multi-step financial calculations
- **CWE:** CWE-190 (Integer Overflow)

## Description
Even when the final result fits in the target type, intermediate values in a calculation can overflow. This is especially common when:
- Multiplying two large u64 values (result needs u128)
- Chaining multiple operations that individually don't overflow
- Calculating percentages: `amount * rate / precision`

The intermediate `amount * rate` can overflow u64 even though the final `/ precision` brings it back to range. Without widening to u128, the intermediate overflow corrupts the result.

## Vulnerable Code Example

```rust
// VULNERABLE: Intermediate overflow in percentage calculation
pub fn calculate_fee(amount: u64, fee_rate: u64) -> u64 {
    // fee_rate = 300 (3%), PRECISION = 10000
    // amount = 10^18 (1 token with 18 decimals)
    // amount * fee_rate = 3 * 10^20 > u64::MAX (1.8 * 10^19)
    // Intermediate overflow wraps, giving wrong fee
    amount * fee_rate / 10000
}

// VULNERABLE: Compound interest with intermediate overflow
pub fn compound_interest(principal: u64, rate: u64, periods: u64) -> u64 {
    let mut result = principal;
    for _ in 0..periods {
        // result * (10000 + rate) can overflow before / 10000
        result = result * (10000 + rate) / 10000;
    }
    result
}

// VULNERABLE: Price calculation with two large numbers
pub fn get_output_amount(
    input_amount: u64,
    input_reserve: u64,
    output_reserve: u64,
) -> u64 {
    // Classic AMM formula: output = (input * output_reserve) / (input_reserve + input)
    // input_amount * output_reserve can overflow u64
    let numerator = input_amount * output_reserve;
    let denominator = input_reserve + input_amount;
    numerator / denominator
}
```

### Attack Scenario (AMM)
1. AMM pool has large reserves: input_reserve = 10^15, output_reserve = 10^15
2. User swaps input_amount = 10^10
3. `input_amount * output_reserve = 10^25` overflows u64 (max ~1.8 * 10^19)
4. Wrapped result is much smaller than expected
5. User receives incorrect (possibly zero or inflated) output amount
6. Attacker profits from mispriced swap

## Real Examples

### Solana BPF Loader Compound Overflow
- **Source:** [solana-labs commit ebbaa1f](https://github.com/solana-labs/solana/commit/ebbaa1f8ea4d12c44d0ca0392e2a1712968bc372)
- **Bug:** `num_accounts * size_of::<AccountMeta>() + data_len` - the multiplication overflows, THEN the addition compounds it
- **Fix:** `num_accounts.saturating_mul(size).saturating_add(data_len)`

### Jet Protocol v1 Compound Operations
- **Source:** [jet-lab/jet-v1 PR #259](https://github.com/jet-lab/jet-v1/pull/259/commits/40590cebed0ae36b1ac20fa41e2a05fc43a47f46)
- **Bug:** Multiple arithmetic operations on loan/deposit amounts without overflow checks
- **Impact:** Corrupted accounting state

### Gaming Protocol Fee Calculation
- **Source:** [Gaming Protocol Audit](https://github.com/mrfomoweb3/Solana-Smart-Contract-Improvement-Audit-for-Gaming-Protocol)
- **Bug:** Critical finding: `earnings calculation uses unchecked_mul` in distribute_winnings
- **Fix:** `checked_mul` and `checked_div` with proper error handling

## Detection Strategy

### Manual Audit
1. Identify any expression with multiple arithmetic operations
2. Calculate maximum possible intermediate values given maximum inputs
3. Check if intermediate exceeds the type's max (u64::MAX = 1.8 * 10^19)
4. Pay special attention to: `a * b / c` patterns
5. Look for token amounts (often 10^9 to 10^18) multiplied together

### Size Quick Reference
| Type | Max Value | Decimal Digits |
|------|-----------|----------------|
| u32  | 4.29 * 10^9  | ~9 digits |
| u64  | 1.84 * 10^19 | ~19 digits |
| u128 | 3.40 * 10^38 | ~38 digits |

**Rule of thumb:** If two u64 values are multiplied, you need u128 for the intermediate.

### Key Questions
- Are any two u64 values multiplied without widening to u128?
- Do token amounts have high decimals (9, 12, 18)?
- Is the final result small but the intermediate huge?
- Are compound operations (loops, multi-step) checked at each step?

## Fix Pattern

```rust
// SAFE: Widen to u128 for intermediate calculation
pub fn calculate_fee(amount: u64, fee_rate: u64) -> Result<u64, ProgramError> {
    let fee = (amount as u128)
        .checked_mul(fee_rate as u128)
        .ok_or(ProgramError::ArithmeticOverflow)?
        .checked_div(10000)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    u64::try_from(fee).map_err(|_| ProgramError::ArithmeticOverflow)
}

// SAFE: AMM output calculation with u128 intermediates
pub fn get_output_amount(
    input_amount: u64,
    input_reserve: u64,
    output_reserve: u64,
) -> Result<u64, ProgramError> {
    let numerator = (input_amount as u128)
        .checked_mul(output_reserve as u128)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    let denominator = (input_reserve as u128)
        .checked_add(input_amount as u128)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    let result = numerator
        .checked_div(denominator)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    u64::try_from(result).map_err(|_| ProgramError::ArithmeticOverflow)
}
```

### Rules
- When multiplying two u64s: cast BOTH to u128 BEFORE multiplying
- Use `checked_` operations at every step of the chain
- Convert back to u64 with `TryFrom` at the end
- For u128 * u128, consider using a 256-bit library (e.g., `uint` crate)

## References
- [Sec3: Arithmetic Overflow in Solana](https://www.sec3.dev/blog/understanding-arithmetic-overflow-underflows-in-rust-and-solana-smart-contracts)
- [Neodyme: Common Pitfalls](https://blog.neodyme.io/posts/solana_common_pitfalls)
- [Cantina: Solana Security Guide](https://cantina.xyz/blog/securing-solana-a-developers-guide)
