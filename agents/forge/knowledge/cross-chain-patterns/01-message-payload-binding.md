# Pattern: Cross-Chain Message Payload Binding

**Category:** Cross-Chain Security / LayerZero Integration  
**Severity:** High-Critical  
**Chains:** Solana ↔ EVM (via LayerZero, Wormhole, etc.)  
**Last Updated:** 2026-02-04  
**Source:** Orderly Network Solana Vault (Sherlock, $56.5K, H-1 & H-2)

## Root Cause

Cross-chain messages carry payload data (recipient, token, amounts) but the receiving program fails to validate that the on-chain accounts match the message payload. The program trusts the message content but doesn't enforce that the accounts provided by the transaction caller correspond to what the message specifies.

## Real-World Exploit

### Orderly Network — H-1: Deposit Token Mismatch
- Vault accepted any SPL token mint as `deposit_token`
- `allowed_token` PDA validated that a token_hash was whitelisted
- But NO constraint enforced `deposit_token.key() == allowed_token.mint_account`
- Attacker deposits worthless tokens, gets credited with USDC on destination chain

### Orderly Network — H-2: Withdrawal Recipient Mismatch
- Withdrawal message contains `receiver: [u8; 32]` (intended recipient)
- On-chain `user` account was `/// CHECK` with NO constraints
- No validation that `user.key()` matched `withdraw_params.receiver`
- Anyone could front-run withdrawals and redirect funds to their own account

## Vulnerable Code Pattern

### Missing Token Binding (Deposit Side)
```rust
// ❌ VULNERABLE: deposit_token not bound to allowed_token
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account()]
    pub deposit_token: Box<Account<'info, Mint>>,  // ANY mint passes
    
    #[account(
        seeds = [TOKEN_SEED, params.token_hash.as_ref()],
        bump = allowed_token.bump,
        constraint = allowed_token.allowed == true
    )]
    pub allowed_token: Box<Account<'info, AllowedToken>>,
}
```

### Missing Recipient Binding (Withdrawal Side)
```rust
// ❌ VULNERABLE: user not bound to message payload
#[derive(Accounts)]
pub struct LzReceive<'info> {
    /// CHECK: No validation!
    #[account()]
    pub user: AccountInfo<'info>,
    
    #[account(
        mut,
        associated_token::mint = token,
        associated_token::authority = user  // derived from unchecked user!
    )]
    pub user_wallet: Account<'info, TokenAccount>,
}

// In apply():
let withdraw = decode(&message.payload);
// NEVER checks: user.key() == Pubkey::from(withdraw.receiver)
transfer(ctx.accounts.transfer_ctx(), amount)?;
```

## Attack Patterns

### Type 1: Deposit Token Substitution
1. Attacker knows the `token_hash` for USDC (public info from PDA seeds)
2. Creates a worthless SPL token mint
3. Calls deposit with: `deposit_token = worthless_mint`, `token_hash = USDC_hash`
4. Vault transfers worthless tokens into itself
5. Cross-chain message says USDC was deposited
6. Attacker credited with USDC on destination chain

### Type 2: Withdrawal Redirection
1. Legitimate user initiates withdrawal on source chain
2. Attacker front-runs the `lz_receive` call on destination chain
3. Passes `user = attacker_pubkey` in the transaction
4. Vault transfers tokens to attacker's associated token account
5. Legitimate user's funds are stolen

## Detection Strategy

1. **For deposits:** Verify that the actual token being transferred matches the whitelisted token:
   ```bash
   # Check if deposit_token has constraint against allowed_token
   grep -A5 "deposit_token" src/deposit.rs | grep -i "constraint\|mint_account\|allowed"
   ```

2. **For withdrawals:** Verify that the on-chain recipient matches the message payload:
   ```bash
   # Check if user/receiver is validated against message data
   grep -B2 -A10 "CHECK" src/lz_receive.rs
   # Look for receiver comparison in apply()
   grep "receiver" src/lz_receive.rs
   ```

3. **General rule:** For EVERY account that handles funds, ask: "Is this account cryptographically bound to the cross-chain message payload?"

## Secure Fix

### Deposit Token Binding
```rust
// ✅ SECURE: deposit_token bound to allowed_token
#[account(
    constraint = deposit_token.key() == allowed_token.mint_account 
        @ VaultError::InvalidDepositToken
)]
pub deposit_token: Box<Account<'info, Mint>>,
```

### Withdrawal Recipient Binding
```rust
// ✅ SECURE: user validated against message payload
pub fn apply(ctx: &mut Context<LzReceive>, params: &LzReceiveParams) -> Result<()> {
    let withdraw = AccountWithdrawSol::decode(&message.payload)?;
    
    // Bind on-chain user to message receiver
    require!(
        ctx.accounts.user.key().to_bytes() == withdraw.receiver,
        VaultError::InvalidWithdrawReceiver
    );
    
    transfer(...)?;
    Ok(())
}
```

## Audit Checklist

- [ ] Every token mint in a cross-chain deposit is bound to the whitelisted token's actual mint address
- [ ] Every recipient in a cross-chain withdrawal is validated against the message payload's receiver field
- [ ] User-controlled fields in deposit params (token_hash, broker_hash) are verified to match the actual accounts
- [ ] `/// CHECK` accounts in cross-chain handlers are scrutinized — they're often the vulnerability
- [ ] PDA seeds derived from user input are validated against corresponding account data
- [ ] No account substitution is possible between the message payload and on-chain accounts

## Related Patterns
- Pattern #01 (Basic Signer Bypass) — `/// CHECK` is often the root cause
- Pattern #04 (Account Data Matching) — missing relationship constraint between accounts
- Pattern #03 (Missing PDA Derivation) — PDA seeds may not bind all relevant data
