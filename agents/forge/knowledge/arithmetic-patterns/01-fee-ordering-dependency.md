# Pattern: Fee / Computation Ordering Dependencies

**Category:** Business Logic / Arithmetic  
**Severity:** Medium-High  
**Chains:** All (especially AMM/bonding curve protocols)  
**Source:** Pump Science M-01 (Code4rena, Jan 2025)  
**Last Updated:** 2026-02-03  

## Root Cause

Protocol computes fees on the raw input amount BEFORE the actual operation adjusts the amount. When the operation modifies the effective amount (e.g., "last buy" adjustments, boundary corrections, rounding), the pre-computed fee becomes incorrect.

## Real-World Exploit

**Pump Science (Jan 2025)** — `calculate_fee(exact_in_amount)` called BEFORE `apply_buy()`. On the last buy, `apply_buy()` recalculates the actual SOL needed (to match the curve endpoint), but the fee was already locked to the original input. Users pay incorrect fees.

## Vulnerable Code Pattern

```rust
// ❌ VULNERABLE: Fee computed on raw input, then amount changes
pub fn process_swap(ctx: Context<Swap>, exact_in_amount: u64) -> Result<()> {
    // Step 1: Compute fee on raw input
    let fee_lamports = bonding_curve.calculate_fee(exact_in_amount, clock.slot)?;
    let buy_amount_applied = exact_in_amount - fee_lamports;
    
    // Step 2: Apply buy — but this may ADJUST the amount on "last buy"
    let buy_result = bonding_curve.apply_buy(buy_amount_applied)?;
    
    // Problem: If apply_buy changed the actual SOL amount (last buy edge case),
    // fee_lamports is now WRONG — it was computed on original input, not adjusted amount
    
    // Step 3: Transfer uses original fee_lamports — incorrect!
    transfer_fee(fee_lamports)?;
    transfer_to_escrow(buy_result.sol_amount)?;
    
    Ok(())
}
```

The "last buy" adjustment in `apply_buy`:
```rust
if token_amount >= self.real_token_reserves {
    // Last Buy — recalculate actual SOL needed
    token_amount = self.real_token_reserves;
    sol_amount = self.get_sol_for_sell_tokens(token_amount)?;
    // sol_amount != buy_amount_applied — but fee was already computed!
}
```

## Detection Strategy

1. **Identify fee calculation points** in swap/buy/sell functions
2. **Trace the amount flow** from fee calculation through the actual operation
3. **Check for amount adjustments** after fee computation:
   - "Last buy" / "last sell" edge cases
   - Rounding adjustments
   - Boundary crossings (e.g., pool depletion)
   - Slippage adjustments
4. **Verify fee consistency:** After the operation, does `fee + actual_amount_used == original_input`?

```bash
# Find fee calculation followed by amount adjustment
grep -n "calculate_fee\|compute_fee\|fee_amount" src/
grep -n "apply_buy\|apply_sell\|execute_swap" src/
# Check: Is fee calculated BEFORE the apply/execute function?
# If yes: Does the apply function ever adjust amounts? → Potential bug
```

## Secure Pattern

```rust
// ✅ SECURE: Recalculate fee after amount adjustment
pub fn process_swap(ctx: Context<Swap>, exact_in_amount: u64) -> Result<()> {
    // Step 1: Apply buy first to get actual amounts
    let preliminary_fee = bonding_curve.calculate_fee(exact_in_amount, clock.slot)?;
    let buy_amount_applied = exact_in_amount - preliminary_fee;
    
    let buy_result = bonding_curve.apply_buy(buy_amount_applied)?;
    
    // Step 2: If amount was adjusted, RECALCULATE fee
    let actual_fee = if buy_result.sol_amount != buy_amount_applied {
        bonding_curve.calculate_fee(
            buy_result.sol_amount + preliminary_fee, // Reconstruct true input
            clock.slot
        )?
    } else {
        preliminary_fee
    };
    
    // Step 3: Verify user has enough funds after recalculation
    require!(
        ctx.accounts.user.get_lamports() >= buy_result.sol_amount + actual_fee + min_rent,
        ContractError::InsufficientFunds
    );
    
    transfer_fee(actual_fee)?;
    transfer_to_escrow(buy_result.sol_amount)?;
    
    Ok(())
}
```

## Related Patterns
- Slippage protection (does min_out still hold after adjustment?)
- First/last operation edge cases in AMMs
- Rounding direction attacks (round fee down → protocol loses)

## Audit Checklist

- [ ] Fee is recalculated if the underlying operation adjusts amounts
- [ ] "Last buy" / "last sell" edge cases are explicitly tested
- [ ] User balance is re-verified after any amount adjustment
- [ ] Slippage checks apply to the FINAL amounts, not preliminary ones
- [ ] Fee direction: fees should round in protocol's favor (ceil), not user's (floor)
