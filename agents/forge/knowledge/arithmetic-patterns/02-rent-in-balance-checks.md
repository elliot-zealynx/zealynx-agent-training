# Pattern: Rent-Exemption in Balance Comparisons

**Category:** Solana-Specific / Arithmetic  
**Severity:** Medium  
**Chains:** Solana  
**Source:** Pump Science M-02 (Code4rena, Jan 2025)  
**Last Updated:** 2026-02-03  

## Root Cause

Solana accounts must maintain a minimum balance (rent-exemption) to avoid garbage collection. When a protocol compares `account.lamports()` (total balance including rent) against tracked reserves (business logic only), the comparison is skewed by the rent amount.

## Real-World Exploit

**Pump Science (Jan 2025)** — Bonding curve invariant check compared `sol_escrow.lamports()` (includes ~0.002 SOL rent) against `real_sol_reserves` (excludes rent). The invariant `lamports >= reserves` would pass even if actual reserves were short by up to the rent amount.

## Key Fact: Solana Rent Values

| Account Size | Rent-Exemption |
|-------------|---------------|
| 0 bytes | 890,880 lamports (~0.0009 SOL) |
| 128 bytes | 1,447,680 lamports (~0.0014 SOL) |
| 200 bytes | 2,039,280 lamports (~0.002 SOL) |
| 1 KB | 8,011,200 lamports (~0.008 SOL) |
| 10 KB | 72,691,200 lamports (~0.073 SOL) |

## Vulnerable Code Pattern

```rust
// ❌ VULNERABLE: lamports() includes rent, reserves don't
let sol_escrow_lamports = sol_escrow.lamports();  // = reserves + rent

if sol_escrow_lamports < bonding_curve.real_sol_reserves {
    // This check is weaker than intended!
    // It passes even if actual reserves are short by up to rent amount
    return Err(ContractError::BondingCurveInvariant.into());
}

// Also suspicious: commented-out rent handling
// let rent_exemption_balance = Rent::get()?.minimum_balance(...);
// let actual_balance = lamports - rent_exemption_balance;
```

## Detection Strategy

1. **Search for lamports() in comparisons:**
```bash
grep -n "lamports()" src/ | grep -v "//\|#\[" 
# For each: check if result is compared to tracked reserves
# If yes: check if rent is subtracted first
```

2. **Look for commented-out rent code:** Often means developer intended to handle it
```bash
grep -n "rent\|Rent::get\|minimum_balance" src/ | grep "//\|/*"
```

3. **Track the semantics:**
   - `lamports()` = total balance = business_funds + rent
   - `real_reserves` / `tracked_balance` = business_funds only
   - Mixing these two in comparisons = bug

## Secure Pattern

```rust
// ✅ SECURE: Subtract rent before comparison
let sol_escrow_lamports = sol_escrow.lamports();
let rent_exemption = Rent::get()?.minimum_balance(sol_escrow.data_len());
let actual_balance = sol_escrow_lamports
    .checked_sub(rent_exemption)
    .ok_or(ContractError::InsufficientBalance)?;

if actual_balance < bonding_curve.real_sol_reserves {
    return Err(ContractError::BondingCurveInvariant.into());
}
```

## Variants

### 1. Over-withdrawal
If protocol allows withdrawing `balance - tracked_amount`, and balance includes rent:
```rust
// ❌ Could drain below rent exemption
let withdrawable = escrow.lamports() - minimum_required;
// If minimum_required doesn't include rent → account gets garbage collected
```

### 2. Under-counting deposits
```rust
// ❌ If deposit tracking uses lamports() difference
let deposit = escrow.lamports() - pre_lamports;
// First deposit includes rent transfer → over-counts by rent amount
```

## Audit Checklist

- [ ] Every `lamports()` comparison accounts for rent-exemption
- [ ] Tracked reserves are consistent in including/excluding rent
- [ ] Commented-out rent code is investigated (likely indicates a missed fix)
- [ ] Withdrawal logic ensures account stays above rent-exemption minimum
- [ ] Deposit tracking handles the first deposit (which includes rent) correctly
