# Pattern: Incomplete Setter / Update Functions

**Category:** Logic Errors / State Management  
**Severity:** High-Critical  
**Chains:** All (Solana, EVM, CosmWasm)  
**Source:** Pump Science H-02 (Code4rena, Jan 2025)  
**Last Updated:** 2026-02-03  

## Root Cause

An `update_settings` / `set_params` function accepts an input struct with N fields but only writes N-1 (or fewer) fields to the target state. The missing field retains its default/initial value permanently, with no way to change it after deployment.

## Real-World Exploit

**Pump Science (Jan 2025)** — `Global::update_settings()` accepted `GlobalSettingsInput` with `migration_token_allocation` field but never wrote it to the `Global` struct. The migration token allocation stayed at its default value indefinitely, breaking the migration process.

## Vulnerable Code Pattern

```rust
// Input struct with 10 fields
pub struct GlobalSettingsInput {
    pub initial_virtual_token_reserves: u64,
    pub initial_virtual_sol_reserves: u64,
    pub initial_real_token_reserves: u64,
    pub token_total_supply: u64,
    pub mint_decimals: u8,
    pub migrate_fee_amount: u64,
    pub migration_token_allocation: u64,  // <-- THIS ONE
    pub fee_receiver: Pubkey,
    pub whitelist_enabled: bool,
    pub meteora_config: Pubkey,
}

// ❌ VULNERABLE: Only updates 9/10 fields
pub fn update_settings(&mut self, params: GlobalSettingsInput, timestamp: i64) {
    self.initial_virtual_token_reserves = params.initial_virtual_token_reserves;
    self.initial_virtual_sol_reserves = params.initial_virtual_sol_reserves;
    self.initial_real_token_reserves = params.initial_real_token_reserves;
    self.token_total_supply = params.token_total_supply;
    self.mint_decimals = params.mint_decimals;
    self.migrate_fee_amount = params.migrate_fee_amount;
    // ❌ MISSING: self.migration_token_allocation = params.migration_token_allocation;
    self.fee_receiver = params.fee_receiver;
    self.whitelist_enabled = params.whitelist_enabled;
    self.meteora_config = params.meteora_config;
}
```

## Detection Strategy

### Manual Review
1. For every `update_*`, `set_*`, `configure_*` function:
   - List ALL fields in the input parameter struct
   - List ALL assignments in the function body
   - **Any field in input but NOT in assignments = BUG**

### Automated Check
```bash
# Extract fields from input struct and check against update function
# Step 1: Find input struct fields
grep -A 50 "pub struct.*Input\|pub struct.*Params\|pub struct.*Settings" src/ | grep "pub "

# Step 2: For each field, check if it appears in the update function
# If a field from the input struct doesn't appear in the update body, flag it
```

### Unit Test Pattern
```rust
#[test]
fn test_all_settings_updated() {
    let mut state = State::default();
    let input = SettingsInput {
        field_a: 42,
        field_b: 99,
        field_c: 123,
    };
    state.update_settings(input.clone());
    
    // Verify EVERY field was written
    assert_eq!(state.field_a, input.field_a);
    assert_eq!(state.field_b, input.field_b);
    assert_eq!(state.field_c, input.field_c);  // Would have caught Pump Science bug
}
```

## Secure Pattern

```rust
// ✅ SECURE: Explicit mapping of ALL fields
pub fn update_settings(&mut self, params: GlobalSettingsInput) {
    self.initial_virtual_token_reserves = params.initial_virtual_token_reserves;
    self.initial_virtual_sol_reserves = params.initial_virtual_sol_reserves;
    self.initial_real_token_reserves = params.initial_real_token_reserves;
    self.token_total_supply = params.token_total_supply;
    self.mint_decimals = params.mint_decimals;
    self.migrate_fee_amount = params.migrate_fee_amount;
    self.migration_token_allocation = params.migration_token_allocation;  // ✅ Included
    self.fee_receiver = params.fee_receiver;
    self.whitelist_enabled = params.whitelist_enabled;
    self.meteora_config = params.meteora_config;
}

// ✅ EVEN BETTER: Use destructuring to get compiler warnings for unused fields
pub fn update_settings(&mut self, params: GlobalSettingsInput) {
    let GlobalSettingsInput {
        initial_virtual_token_reserves,
        initial_virtual_sol_reserves,
        initial_real_token_reserves,
        token_total_supply,
        mint_decimals,
        migrate_fee_amount,
        migration_token_allocation,
        fee_receiver,
        whitelist_enabled,
        meteora_config,
    } = params;
    
    // Compiler will warn about any unused variables from destructuring
    self.initial_virtual_token_reserves = initial_virtual_token_reserves;
    // ... all fields ...
}
```

## Audit Checklist

- [ ] Every update/setter function covers ALL fields from the input struct
- [ ] Unit tests verify all fields are updated (not just a subset)
- [ ] Consider using destructuring to leverage compiler warnings
- [ ] Check initialize functions too — do they set all fields?
- [ ] Look for TODO/FIXME comments near setter functions
