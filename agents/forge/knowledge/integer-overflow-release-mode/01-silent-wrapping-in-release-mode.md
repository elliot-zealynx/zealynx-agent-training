# Pattern: Silent Wrapping in Rust Release Mode

## Classification
- **Severity:** Critical
- **Category:** Arithmetic / Integer Overflow
- **Affected:** All Solana programs using raw `+`, `-`, `*`, `**` operators
- **CWE:** CWE-190 (Integer Overflow), CWE-191 (Integer Underflow)

## Description
Rust's behavior on integer overflow differs between debug and release mode:
- **Debug mode:** Panics (program halts) on overflow/underflow
- **Release mode:** Silent two's complement wrapping

Solana BPF programs compile in release mode (`cargo build-bpf`). This means:
- `255u8 + 1 = 0` (wraps around)
- `0u64 - 1 = 18446744073709551615` (u64::MAX)
- `u64::MAX + 1 = 0`

Attackers exploit this to bypass balance checks, mint tokens beyond limits, or drain funds.

## Vulnerable Code Example

```rust
// VULNERABLE: Balance check can be bypassed via overflow
fn withdraw_token(accounts: &[AccountInfo], amount: u32) -> ProgramResult {
    let FEE: u32 = 1000;
    
    // If amount = u32::MAX - 100, then amount + FEE wraps to 899
    // This passes the check even though amount > user_balance
    if amount + FEE > vault.user_balance[user_id] {
        return Err(ProgramError::AttemptToWithdrawTooMuch);
    }
    
    // Transfers amount (billions of tokens) from vault
    transfer_tokens(vault, user, amount)?;
    Ok(())
}
```

### Attack Scenario (from Neodyme)
1. User deposits 100,000 tokens
2. Calls withdraw with `amount = u32::MAX - 100` (4,294,967,195)
3. `amount + FEE` = `4,294,967,195 + 1000` wraps to `899`
4. `899 < 100,000` passes the check
5. Contract withdraws 4.29 billion tokens to attacker

## Real Examples

### Jet Protocol v1 (Underflow/Overflow)
- **Source:** [jet-lab/jet-v1 PR #163](https://github.com/jet-lab/jet-v1/pull/163/commits/7cf43321a0357a70e295a4f2b57725bc6cb6266e)
- **Bug:** `total_loan_notes -= note_amount` (u64 underflow) and `total_deposit += token_amount` (u64 overflow)
- **Fix:** Replace `-` with `checked_sub`, `+` with `checked_add`

### Solana BPF Loader (Core Runtime)
- **Source:** [solana-labs/solana commit ebbaa1f](https://github.com/solana-labs/solana/commit/ebbaa1f8ea4d12c44d0ca0392e2a1712968bc372)
- **Bug:** `num_accounts * size_of::<AccountMeta>() + data_len` can overflow
- **Fix:** Replace `*` with `saturating_mul`, `+` with `saturating_add`

### Solana Runtime (9+ overflow fixes)
- [9 separate commits](https://www.sec3.dev/blog/understanding-arithmetic-overflow-underflows-in-rust-and-solana-smart-contracts) fixing overflow in Solana's core validator runtime

## Detection Strategy

### Manual Audit
1. Search for raw arithmetic operators: `+`, `-`, `*`, `/`, `**`, `%`
2. Grep for absence of `checked_` or `saturating_` in financial math
3. Check `Cargo.toml` for `overflow-checks = true` under `[profile.release]`
4. Pay special attention to user-controlled inputs in arithmetic expressions
5. Look for balance comparisons that use addition instead of subtraction

### Automated
- `cargo clippy -- -W clippy::arithmetic_side_effects` (Rust 1.64+)
- Sec3's X-Ray tool has built-in overflow detection
- grep: `rg '\b(amount|balance|fee|price|rate|supply)\b.*[+\-\*]' --type rust`

### Key Questions
- Is `overflow-checks = true` in `[profile.release]`?
- Are ALL arithmetic operations using checked/saturating variants?
- Can any user-controlled value reach an arithmetic expression unchecked?
- Are comparisons structured to avoid overflow in the comparison itself?

## Fix Pattern

```rust
// SAFE: Using checked arithmetic
fn withdraw_token(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let fee: u64 = 1000;
    
    // Option 1: checked_add returns None on overflow
    let total = amount.checked_add(fee)
        .ok_or(ProgramError::InvalidArgument)?;
    
    if total > vault.user_balance[user_id] {
        return Err(ProgramError::AttemptToWithdrawTooMuch);
    }
    
    // Option 2: Restructure to avoid overflow entirely
    // Instead of: amount + fee > balance
    // Use:        amount > balance - fee (check balance >= fee first)
    if vault.user_balance[user_id] < fee {
        return Err(ProgramError::InsufficientFunds);
    }
    if amount > vault.user_balance[user_id] - fee {
        return Err(ProgramError::AttemptToWithdrawTooMuch);
    }
    
    transfer_tokens(vault, user, amount)?;
    Ok(())
}
```

### Global Fix
In `Cargo.toml`:
```toml
[profile.release]
overflow-checks = true
```
This enables panic-on-overflow even in release mode, matching debug behavior. Note: This has minimal performance impact on Solana (unlike EVM gas costs).

## References
- [Rust Book: Integer Overflow](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow)
- [Sec3: Understanding Arithmetic Overflow/Underflows in Rust and Solana](https://www.sec3.dev/blog/understanding-arithmetic-overflow-underflows-in-rust-and-solana-smart-contracts)
- [Neodyme: Solana Smart Contracts: Common Pitfalls](https://blog.neodyme.io/posts/solana_common_pitfalls)
- [Cargo Profiles: overflow-checks](https://doc.rust-lang.org/cargo/reference/profiles.html#overflow-checks)
