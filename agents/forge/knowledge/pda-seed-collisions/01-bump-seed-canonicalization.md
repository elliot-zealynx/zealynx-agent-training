# Pattern 01: Bump Seed Canonicalization

**Severity:** High
**Category:** PDA Seed Collisions
**CVSS-like:** 7.5-8.5
**Prevalence:** Very common in native Solana programs; mitigated by Anchor if used correctly

## Description

`find_program_address` iterates from bump=255 downward to find the first valid PDA (canonical bump). However, other bump values (254, 253, etc.) may also produce valid PDAs at **different addresses** for the **same seeds**.

If a program accepts a user-provided bump or fails to enforce the canonical bump, an attacker can:
1. Create a "shadow" PDA at a non-canonical address
2. Initialize it with attacker-controlled data
3. Pass it to the program, which accepts it as legitimate

**Fundamental issue:** One set of seeds ≠ one address, unless the canonical bump is enforced.

## Vulnerable Code Example

```rust
// VULNERABLE: User supplies bump, no canonicalization check
pub fn create_profile(
    ctx: Context<CreateProfile>, 
    user_id: u64, 
    bump: u8  // ⚠️ User-controlled bump
) -> Result<()> {
    let seeds: &[&[u8]] = &[b"profile", &user_id.to_le_bytes(), &[bump]];
    let (derived_address, _) = Pubkey::create_program_address(seeds, ctx.program_id)?;
    
    if derived_address != ctx.accounts.profile.key() {
        return Err(ProgramError::InvalidSeeds);
    }
    
    // Proceeds with non-canonical PDA...
    Ok(())
}
```

## Attack Scenario

```
Seeds: [b"vault", user_pubkey]
Canonical bump: 255 → Address 0xAAA (legitimate vault)
Non-canonical bump: 254 → Address 0xBBB (shadow vault)
Non-canonical bump: 252 → Address 0xCCC (another shadow)

1. User's real vault at 0xAAA with bump 255
2. Attacker calls create with bump=254, gets shadow vault at 0xBBB
3. Program accepts both as valid PDAs (both pass create_program_address)
4. Attacker initializes shadow vault with their own authority
5. Depending on program logic: double-spending, bypassing restrictions, accounting errors
```

## Detection Strategy

1. **Search for `create_program_address`** — if used without prior `find_program_address` validation, flag it
2. **Check if bump is user-supplied** — any instruction parameter or account data field used as bump
3. **Verify bump storage** — canonical bump should be stored at initialization and verified on subsequent use
4. **Anchor-specific:** Check if `bump` in seeds constraint references a stored value vs. re-deriving
5. **Automated:** sec3 Pro / Soteria flags `BumpSeedNotValidated`; Trail of Bits solana-lints has `bump_seed_canonicalization`

## Fix Pattern

### Approach 1: Use `find_program_address` (most common)
```rust
// SAFE: Always derive canonical bump
let (expected_pda, canonical_bump) = Pubkey::find_program_address(
    &[b"vault", user_pubkey.as_ref()],
    program_id
);

if account_key != expected_pda {
    return Err(ProgramError::InvalidSeeds);
}

// Store canonical bump for future use
vault.bump = canonical_bump;
```

### Approach 2: Anchor seeds constraint
```rust
#[account(
    init,
    payer = user,
    space = 8 + Vault::INIT_SPACE,
    seeds = [b"vault", user.key().as_ref()],
    bump  // Anchor finds and stores canonical bump automatically
)]
pub vault: Account<'info, Vault>,
```

### Approach 3: Verify stored bump on subsequent calls
```rust
#[account(
    mut,
    seeds = [b"vault", user.key().as_ref()],
    bump = vault.bump  // Must match previously stored canonical bump
)]
pub vault: Account<'info, Vault>,
```

## Real Examples

- **Found in numerous audits** — sec3/Soteria reports this as one of the most common Solana findings
- **Armani Ferrante (Anchor creator) tweeted** about this being a common pitfall (Jul 2021)
- Particularly dangerous in programs migrating from native Solana to Anchor, where old PDAs may have non-canonical bumps

## Key Insight

> "A PDA is not just an address — it's a commitment to a specific derivation path. If you don't enforce the canonical bump, you've broken that commitment."

Anchor handles this automatically with `seeds` + `bump` constraints, but **only if you use them consistently on every instruction that touches the PDA**, not just init.
