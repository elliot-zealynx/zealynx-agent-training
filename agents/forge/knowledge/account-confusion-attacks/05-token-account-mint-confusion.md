# Token Account Mint Confusion

**Severity:** CRITICAL  
**CVSS Score:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**Real Exploit:** Cashio Protocol ($52M loss, March 2022)

## Description

Token account mint confusion occurs when a program accepts a token account without properly validating its mint address. Attackers can substitute token accounts for worthless tokens while the protocol treats them as valuable collateral, leading to unauthorized minting, borrowing, or withdrawals.

## Vulnerable Code Pattern

```rust
use spl_token::{state::Account as TokenAccount};

// VULNERABLE: No mint validation
pub fn deposit_collateral(
    accounts: &[AccountInfo],
    amount: u64,
) -> Result<(), ProgramError> {
    let account_iter = &mut accounts.iter();
    let user_token_account = next_account_info(account_iter)?;
    let protocol_vault = next_account_info(account_iter)?;
    let user_balance_account = next_account_info(account_iter)?;
    
    // VULNERABLE: Unpacks token account but doesn't validate mint
    let token_account = TokenAccount::unpack(&user_token_account.data.borrow())?;
    
    // CRITICAL: No check if token_account.mint == EXPECTED_MINT
    // Attacker can pass account for any token (even worthless ones)
    
    if token_account.amount < amount {
        return Err(ProgramError::InsufficientFunds);
    }
    
    // Protocol credits user with valuable collateral for worthless tokens
    let mut user_balance = UserBalance::unpack(&user_balance_account.data.borrow())?;
    user_balance.deposited_amount += amount;
    
    // Transfer tokens to vault (but they could be worthless!)
    transfer_tokens(user_token_account, protocol_vault, amount)?;
    
    Ok(())
}
```

## Attack Vector

1. **Create Worthless Token:** Deploy new token mint with large supply
2. **Create Token Account:** Create token account for worthless token  
3. **Mint Worthless Tokens:** Mint large amounts to attacker's account
4. **Deposit as Collateral:** Pass worthless token account as valuable collateral
5. **Extract Value:** Borrow/mint valuable tokens against worthless collateral

## Real-World Example: Cashio Protocol Exploit

```rust
// Cashio's vulnerable collateral validation
pub fn create_collateral_tokens(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    saber_swap: SaberSwap,
) -> Result<(), ProgramError> {
    let account_iter = &mut accounts.iter();
    let bank_account = next_account_info(account_iter)?;
    let saber_swap_account = next_account_info(account_iter)?;
    
    // VULNERABLE: No validation of saber_swap.mint field
    let bank = Bank::unpack(&bank_account.data.borrow())?;
    
    // CRITICAL FLAW: Doesn't verify saber_swap.mint matches expected token
    // Attacker created fake Bank with worthless token mint
    
    // Protocol assumes valid Saber LP tokens without verification
    mint_cash_tokens(&bank, saber_swap.amount)?;
    
    Ok(())
}

// The fix would have been:
pub fn create_collateral_tokens_secure(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    saber_swap: SaberSwap,
) -> Result<(), ProgramError> {
    let account_iter = &mut accounts.iter();
    let bank_account = next_account_info(account_iter)?;
    let saber_swap_account = next_account_info(account_iter)?;
    
    let bank = Bank::unpack(&bank_account.data.borrow())?;
    
    // SECURE: Validate mint matches expected collateral token
    if saber_swap.mint != bank.collateral_mint {
        return Err(ProgramError::InvalidMint);
    }
    
    // SECURE: Additional validation of Bank authenticity
    if bank.magic != BANK_MAGIC || bank.version != CURRENT_VERSION {
        return Err(ProgramError::InvalidAccountData);
    }
    
    mint_cash_tokens(&bank, saber_swap.amount)?;
    
    Ok(())
}
```

## Secure Implementation

```rust
use spl_token::{state::Account as TokenAccount, state::Mint};

const ACCEPTED_MINT: Pubkey = solana_program::pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"); // USDC

pub fn deposit_collateral_secure(
    accounts: &[AccountInfo],
    amount: u64,
) -> Result<(), ProgramError> {
    let account_iter = &mut accounts.iter();
    let user_token_account = next_account_info(account_iter)?;
    let mint_account = next_account_info(account_iter)?;
    let protocol_vault = next_account_info(account_iter)?;
    let user_balance_account = next_account_info(account_iter)?;
    
    // SECURE: Validate mint account
    if *mint_account.key != ACCEPTED_MINT {
        return Err(ProgramError::InvalidMint);
    }
    
    // SECURE: Unpack and validate token account
    let token_account = TokenAccount::unpack(&user_token_account.data.borrow())?;
    
    // SECURE: Verify token account mint matches expected mint
    if token_account.mint != ACCEPTED_MINT {
        return Err(ProgramError::InvalidMint);
    }
    
    // SECURE: Validate token account is owned by SPL Token program
    if *user_token_account.owner != spl_token::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    
    // SECURE: Check sufficient balance
    if token_account.amount < amount {
        return Err(ProgramError::InsufficientFunds);
    }
    
    // Now safe to proceed with deposit
    let mut user_balance = UserBalance::unpack(&user_balance_account.data.borrow())?;
    user_balance.deposited_amount += amount;
    UserBalance::pack(&user_balance, &mut user_balance_account.data.borrow_mut())?;
    
    transfer_tokens(user_token_account, protocol_vault, amount)?;
    
    Ok(())
}

// SECURE: Using Anchor framework
#[derive(Accounts)]
pub struct DepositCollateral<'info> {
    #[account(
        mut,
        token::mint = ACCEPTED_MINT,  // Anchor validates mint
        token::authority = user,
    )]
    pub user_token_account: Account<'info, TokenAccount>,
    
    #[account(
        address = ACCEPTED_MINT  // Explicit mint validation
    )]
    pub mint: Account<'info, Mint>,
    
    #[account(
        mut,
        token::mint = ACCEPTED_MINT,
        token::authority = vault_authority,
    )]
    pub vault: Account<'info, TokenAccount>,
    
    pub user: Signer<'info>,
}

pub fn deposit_collateral_anchor(
    ctx: Context<DepositCollateral>,
    amount: u64,
) -> Result<()> {
    // Anchor already validated mint matches expected value
    let user_token_account = &ctx.accounts.user_token_account;
    let vault = &ctx.accounts.vault;
    
    require!(user_token_account.amount >= amount, ErrorCode::InsufficientFunds);
    
    // Safe to transfer - mint already validated
    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: user_token_account.to_account_info(),
                to: vault.to_account_info(),
                authority: ctx.accounts.user.to_account_info(),
            },
        ),
        amount,
    )?;
    
    Ok(())
}
```

## Detection Strategy

### Static Analysis
- Look for `TokenAccount::unpack` without mint validation
- Search for token operations without mint address checks
- Check if programs accept arbitrary token accounts
- Identify hardcoded mint addresses that aren't validated

### Dynamic Testing
```rust
#[test]
fn test_token_mint_confusion_attack() {
    // Create worthless token mint
    let worthless_mint = Keypair::new();
    let worthless_mint_account = create_mint(
        &mut banks_client,
        &payer,
        &worthless_mint.pubkey(),
        None,
        9,
    ).unwrap();
    
    // Create token account for worthless token
    let attacker_token_account = create_token_account(
        &mut banks_client,
        &payer,
        &worthless_mint.pubkey(),
        &attacker.pubkey(),
    ).unwrap();
    
    // Mint large amount of worthless tokens
    mint_to(
        &mut banks_client,
        &payer,
        &worthless_mint.pubkey(),
        &attacker_token_account,
        &worthless_mint,
        1_000_000_000,  // Huge amount of worthless tokens
    ).unwrap();
    
    // Try to deposit worthless tokens as valuable collateral
    let deposit_instruction = create_deposit_instruction(
        &program_id,
        &attacker_token_account,  // Worthless token account
        1_000_000,
    );
    
    let result = process_instruction(
        &mut banks_client,
        deposit_instruction,
        &attacker,
    );
    
    // Should fail due to invalid mint
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().unwrap(), ProgramError::InvalidMint);
}

#[test]
fn test_associated_token_account_confusion() {
    let fake_mint = Keypair::new();
    
    // Create ATA for wrong mint
    let fake_ata = get_associated_token_address(&user.pubkey(), &fake_mint.pubkey());
    
    let instruction = create_deposit_instruction(&program_id, &fake_ata, 1000);
    
    let result = process_instruction(&mut banks_client, instruction, &user);
    assert_eq!(result.unwrap_err().unwrap(), ProgramError::InvalidMint);
}
```

## Associated Token Account Validation

```rust
// SECURE: Validate Associated Token Account derivation
use spl_associated_token_account::get_associated_token_address;

pub fn validate_ata(
    token_account_info: &AccountInfo,
    owner: &Pubkey,
    mint: &Pubkey,
) -> Result<(), ProgramError> {
    let expected_ata = get_associated_token_address(owner, mint);
    
    if *token_account_info.key != expected_ata {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Additional validation: check account is actually owned by Token program
    if *token_account_info.owner != spl_token::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    
    Ok(())
}
```

## Fix Pattern

1. **Always validate mint:** Check `token_account.mint == EXPECTED_MINT`
2. **Explicit mint accounts:** Pass mint account separately for validation
3. **Use constraints:** Leverage Anchor's `token::mint` constraint
4. **Validate ownership:** Ensure token account is owned by SPL Token program
5. **Associated Token Account derivation:** Re-derive and validate ATA addresses

## Prevention Checklist

- [ ] All token account operations validate mint address
- [ ] Hardcoded expected mints are explicitly checked
- [ ] Token account ownership verified (SPL Token program)
- [ ] Associated Token Account addresses re-derived and validated
- [ ] Tests include wrong mint attack scenarios
- [ ] Multi-token protocols validate each token type separately

## Common Mistakes

1. **Trusting user-provided token accounts:** Not validating mint
2. **Partial validation:** Checking some but not all token accounts  
3. **Wrong mint constants:** Using incorrect hardcoded mint addresses
4. **ATA assumption:** Assuming all token accounts are ATAs without verification
5. **Missing owner checks:** Not validating token account is owned by SPL Token

## Related Patterns

- [Associated Token Account Validation](07-associated-token-account-validation.md)
- [Account Type/Discriminator Confusion](02-account-type-discriminator-confusion.md)
- [Cross-Program Account Injection](06-cross-program-account-injection.md)

## References

- [Cashio Exploit Analysis](https://www.halborn.com/blog/post/explained-the-cashio-hack-march-2022)
- [SPL Token Program Documentation](https://spl.solana.com/token)
- [Anchor Token Constraints](https://book.anchor-lang.com/anchor_bts/token_constraints.html)
- [CertiK Cashio Analysis](https://www.certik.com/resources/blog/3bHgCDnWaqUeQJn6695bea-cashio-app-incident-analysis)