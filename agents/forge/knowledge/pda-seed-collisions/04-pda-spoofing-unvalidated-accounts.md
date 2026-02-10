# Pattern 04: PDA Spoofing via Unvalidated Account Relationships

**Severity:** Critical
**Category:** PDA Seed Collisions
**CVSS-like:** 9.0-10.0
**Prevalence:** High — the root cause behind several of the largest Solana exploits

## Description

Even when individual PDAs are verified, the **relationships between PDAs** may not be validated. An attacker can pass a legitimate PDA from one context where it shouldn't be used, or construct a chain of accounts where each individual account is valid but the combination is not.

This is more sophisticated than Pattern 03 — individual accounts may pass derivation checks, but the program fails to verify they belong together.

## Vulnerable Code Example

```rust
// VULNERABLE: Each account is validated individually, but relationships aren't verified
pub fn swap(ctx: Context<Swap>, amount: u64) -> Result<()> {
    // pool is a valid PDA ✓
    // token_a_vault is a valid token account ✓
    // token_b_vault is a valid token account ✓
    // price_oracle is a valid oracle account ✓
    
    // But are they for the SAME pool? ⚠️
    let price = get_price(&ctx.accounts.price_oracle)?;
    
    // What if price_oracle is from a DIFFERENT pool with manipulated price?
    let output_amount = amount * price / PRECISION;
    
    // Transfer based on wrong price...
    token::transfer(ctx.accounts.into_transfer_context(), output_amount)?;
    
    Ok(())
}

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(
        mut,
        seeds = [b"pool", pool.token_a_mint.as_ref(), pool.token_b_mint.as_ref()],
        bump = pool.bump,
    )]
    pub pool: Account<'info, Pool>,
    
    #[account(mut)]  // ⚠️ Not linked to pool!
    pub token_a_vault: Account<'info, TokenAccount>,
    
    #[account(mut)]  // ⚠️ Not linked to pool!
    pub token_b_vault: Account<'info, TokenAccount>,
    
    /// CHECK: Oracle account
    pub price_oracle: AccountInfo<'info>,  // ⚠️ Not verified against pool!
}
```

## Attack Scenario

```
1. Protocol has Pool A (ETH/USDC) and Pool B (SHITCOIN/USDC)
2. Attacker manipulates SHITCOIN/USDC price on Pool B's oracle
3. Attacker calls swap on Pool A but passes Pool B's oracle
4. Program reads inflated SHITCOIN price as if it were ETH price
5. Attacker swaps a tiny amount at the inflated rate
6. Pool A drained based on wrong oracle data

Individual validations:
  - Pool A PDA: valid ✓
  - Pool B oracle: valid PDA ✓
  - But oracle doesn't belong to Pool A ✗
```

## Detection Strategy

1. **Map all account relationships:** For every instruction, draw which accounts should be linked
2. **Check constraint chains:** 
   - `token_a_vault.owner == pool.key()` (vault belongs to pool)
   - `price_oracle == pool.oracle` (oracle matches pool's stored reference)
3. **Verify "has_one" constraints:** Anchor's `has_one` attribute enforces that a field in one account matches another account's key
4. **Cross-instruction consistency:** Same PDA set used across instructions? Verify relationships in ALL of them
5. **Look for `AccountInfo` (unchecked) types** in Anchor — these bypass automatic validation

## Fix Pattern

```rust
#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(
        mut,
        seeds = [b"pool", pool.token_a_mint.as_ref(), pool.token_b_mint.as_ref()],
        bump = pool.bump,
        has_one = token_a_vault,    // ✅ Vault must match pool's stored reference
        has_one = token_b_vault,    // ✅ Vault must match pool's stored reference
        has_one = price_oracle,     // ✅ Oracle must match pool's stored reference
    )]
    pub pool: Account<'info, Pool>,
    
    #[account(mut)]
    pub token_a_vault: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub token_b_vault: Account<'info, TokenAccount>,
    
    /// CHECK: Verified via has_one on pool
    pub price_oracle: AccountInfo<'info>,
}

#[account]
pub struct Pool {
    pub token_a_mint: Pubkey,
    pub token_b_mint: Pubkey,
    pub token_a_vault: Pubkey,   // Store vault references
    pub token_b_vault: Pubkey,   // Store vault references
    pub price_oracle: Pubkey,    // Store oracle reference
    pub bump: u8,
}
```

## Real Examples

- **Cashio ($52M, March 2022)** — The program verified that collateral accounts existed but didn't verify they belonged to the correct collateral type. The attacker created a fake collateral chain: fake bank → fake collateral → real minting, each individually valid but collectively fraudulent.

- **Solend Oracle Manipulation ($1.26M, November 2022)** — The protocol accepted USDH collateral priced from a single Saber pool. The oracle was a valid price feed, but it wasn't the right price feed for accurate market pricing. The attacker manipulated the Saber pool while the true market price on other DEXes remained stable.

- **Crema Finance ($8.8M, July 2022)** — Fake tick account accepted because the program verified it was a valid account but not that it was the tick account belonging to the specific pool being operated on.

## Key Insight

> "Validating accounts in isolation is like checking IDs at a party — you might verify each person is real, but you also need to check they're on the guest list for THIS party."

**The validation chain must be complete:**
```
Program → owns Pool PDA
Pool PDA → references Vault PDA, Oracle PDA
Vault PDA → references correct Mint
Oracle PDA → references correct price feed

Break ANY link → exploit
```
