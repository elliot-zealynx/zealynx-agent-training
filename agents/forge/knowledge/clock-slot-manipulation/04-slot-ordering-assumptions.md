# Slot Ordering Assumptions

## Description

Smart contracts that make incorrect assumptions about transaction ordering within slots or across slots can be exploited through strategic transaction placement and MEV techniques.

## Vulnerability Pattern

Programs that assume transactions execute in a specific order or that certain operations will complete before others within the same or consecutive slots.

## Vulnerable Code Example

```rust
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    sysvar::Sysvar,
    msg,
};

#[derive(Clone)]
pub struct OrderbookData {
    pub last_trade_slot: u64,
    pub last_price: u64,
    pub volume: u64,
}

// VULNERABLE: Assumes trades execute in slot order
pub fn process_trade(accounts: &[AccountInfo], price: u64) -> Result<(), ProgramError> {
    let clock = Clock::get()?;
    let mut orderbook = OrderbookData::try_from_slice(&accounts[0].data.borrow())?;
    
    // Vulnerable: Assumes this trade is "after" previous trades in the same slot
    if clock.slot == orderbook.last_trade_slot {
        // This logic can be exploited through transaction ordering
        if price < orderbook.last_price {
            return Err(ProgramError::InvalidInstructionData);
        }
    }
    
    orderbook.last_trade_slot = clock.slot;
    orderbook.last_price = price;
    orderbook.volume += 1;
    
    serialize_orderbook(accounts, &orderbook)?;
    Ok(())
}

// VULNERABLE: Cross-instruction ordering assumption
pub struct MultiStepOperation {
    pub step: u8,
    pub initiator: Pubkey,
    pub init_slot: u64,
}

pub fn execute_step(accounts: &[AccountInfo], step_num: u8) -> Result<(), ProgramError> {
    let clock = Clock::get()?;
    let mut operation = MultiStepOperation::try_from_slice(&accounts[0].data.borrow())?;
    
    // Vulnerable: Assumes steps execute in order
    if step_num != operation.step + 1 {
        return Err(ProgramError::InvalidInstructionData);
    }
    
    // Vulnerable: Same-slot operations can be reordered
    if clock.slot == operation.init_slot && step_num > 2 {
        // This can be exploited by reordering transactions
        apply_bonus_logic(accounts)?;
    }
    
    operation.step = step_num;
    serialize_operation(accounts, &operation)?;
    Ok(())
}
```

## Attack Vector

1. **Intra-Slot Reordering**: Validators can reorder transactions within the same slot for MEV
2. **Cross-Slot Race Conditions**: Operations spanning multiple slots can be interleaved unexpectedly
3. **Bundle Manipulation**: Using Jito bundles to guarantee specific transaction ordering
4. **Leader Schedule Exploitation**: Timing operations based on validator leader schedules

## Real-World Examples

- **AMM Front-Running**: Reordering trades within slots to extract MEV from price movements
- **Liquidation Ordering**: Manipulating liquidation order to maximize extraction
- **Auction Sniping**: Using slot ordering to ensure bids land in specific positions
- **Bridge Settlement**: Exploiting cross-chain message ordering assumptions

## Detection Strategy

```rust
// Check for slot-based ordering assumptions
grep -r "last.*slot\|prev.*slot" src/
grep -r "step.*order\|sequence" src/

// Look for same-slot logic
grep -r "clock.slot.*==" src/
grep -r "if.*slot.*==" src/
```

## Secure Implementation

```rust
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    sysvar::Sysvar,
    msg,
    keccak,
};

#[derive(Clone)]
pub struct SecureOrderbookData {
    pub trades: Vec<TradeRecord>,
    pub nonce: u64,
}

#[derive(Clone)]
pub struct TradeRecord {
    pub price: u64,
    pub slot: u64,
    pub instruction_hash: [u8; 32],
    pub sequence_number: u64,
}

// Secure: Uses instruction hash to prevent reordering exploits
pub fn secure_process_trade(accounts: &[AccountInfo], price: u64) -> Result<(), ProgramError> {
    let clock = Clock::get()?;
    let mut orderbook = SecureOrderbookData::try_from_slice(&accounts[0].data.borrow())?;
    
    // Create unique instruction hash to prevent replay/reordering
    let instruction_data = format!("{}-{}-{}", price, clock.slot, orderbook.nonce);
    let instruction_hash = keccak::hash(instruction_data.as_bytes()).to_bytes();
    
    // Check for duplicate instruction hash
    for trade in &orderbook.trades {
        if trade.instruction_hash == instruction_hash {
            return Err(ProgramError::Custom(100)); // Duplicate trade
        }
    }
    
    let trade_record = TradeRecord {
        price,
        slot: clock.slot,
        instruction_hash,
        sequence_number: orderbook.nonce,
    };
    
    orderbook.trades.push(trade_record);
    orderbook.nonce += 1;
    
    // Remove old trades to prevent unbounded growth
    if orderbook.trades.len() > 100 {
        orderbook.trades.remove(0);
    }
    
    serialize_orderbook(accounts, &orderbook)?;
    Ok(())
}

// Atomic multi-step operations
#[derive(Clone)]
pub struct AtomicOperation {
    pub steps_completed: [bool; 5],
    pub all_steps_data: Vec<u8>,
    pub commitment_hash: [u8; 32],
    pub expiry_slot: u64,
}

pub fn commit_atomic_operation(
    accounts: &[AccountInfo], 
    steps_data: Vec<Vec<u8>>
) -> Result<(), ProgramError> {
    let clock = Clock::get()?;
    
    // Create commitment hash for all steps
    let combined_data = steps_data.iter().flatten().cloned().collect::<Vec<u8>>();
    let commitment_hash = keccak::hash(&combined_data).to_bytes();
    
    let operation = AtomicOperation {
        steps_completed: [false; 5],
        all_steps_data: combined_data,
        commitment_hash,
        expiry_slot: clock.slot + 10, // 10 slot expiry
    };
    
    serialize_operation(accounts, &operation)?;
    msg!("Atomic operation committed with hash: {:?}", commitment_hash);
    Ok(())
}

pub fn execute_atomic_step(
    accounts: &[AccountInfo], 
    step_index: usize,
    step_data: Vec<u8>
) -> Result<(), ProgramError> {
    let clock = Clock::get()?;
    let mut operation = AtomicOperation::try_from_slice(&accounts[0].data.borrow())?;
    
    // Check expiry
    if clock.slot > operation.expiry_slot {
        return Err(ProgramError::Custom(101)); // Expired
    }
    
    // Verify step data matches commitment
    let step_start = step_index * (operation.all_steps_data.len() / 5);
    let step_end = step_start + (operation.all_steps_data.len() / 5);
    let committed_step_data = &operation.all_steps_data[step_start..step_end];
    
    if step_data != committed_step_data {
        return Err(ProgramError::InvalidInstructionData);
    }
    
    if operation.steps_completed[step_index] {
        return Err(ProgramError::AlreadyInUse);
    }
    
    // Execute step
    execute_individual_step(accounts, step_index, &step_data)?;
    operation.steps_completed[step_index] = true;
    
    // Check if all steps completed
    if operation.steps_completed.iter().all(|&completed| completed) {
        finalize_atomic_operation(accounts)?;
        msg!("Atomic operation completed successfully");
    }
    
    serialize_operation(accounts, &operation)?;
    Ok(())
}
```

## Advanced Anti-MEV Patterns

```rust
// Commit-reveal scheme for sensitive operations
#[derive(Clone)]
pub struct CommitRevealData {
    pub commitment: [u8; 32],
    pub reveal_deadline: u64,
    pub commit_slot: u64,
    pub revealed: bool,
}

pub fn commit_action(
    accounts: &[AccountInfo], 
    commitment_hash: [u8; 32]
) -> Result<(), ProgramError> {
    let clock = Clock::get()?;
    
    let commit_data = CommitRevealData {
        commitment: commitment_hash,
        reveal_deadline: clock.slot + 50, // ~20 seconds
        commit_slot: clock.slot,
        revealed: false,
    };
    
    serialize_commit(accounts, &commit_data)?;
    Ok(())
}

pub fn reveal_action(
    accounts: &[AccountInfo], 
    action_data: Vec<u8>,
    nonce: u64
) -> Result<(), ProgramError> {
    let clock = Clock::get()?;
    let mut commit_data = CommitRevealData::try_from_slice(&accounts[0].data.borrow())?;
    
    // Verify timing
    if clock.slot >= commit_data.reveal_deadline {
        return Err(ProgramError::Custom(102)); // Too late
    }
    
    if clock.slot < commit_data.commit_slot + 5 {
        return Err(ProgramError::Custom(103)); // Too early
    }
    
    // Verify commitment
    let combined_data = [action_data.clone(), nonce.to_le_bytes().to_vec()].concat();
    let revealed_hash = keccak::hash(&combined_data).to_bytes();
    
    if revealed_hash != commit_data.commitment {
        return Err(ProgramError::InvalidInstructionData);
    }
    
    // Execute the revealed action
    execute_committed_action(accounts, &action_data)?;
    commit_data.revealed = true;
    
    serialize_commit(accounts, &commit_data)?;
    Ok(())
}

// Randomized execution delays
fn get_randomized_execution_slot(base_slot: u64, action_hash: &[u8]) -> u64 {
    let hash_sum = action_hash.iter().map(|&b| b as u64).sum::<u64>();
    let random_delay = (hash_sum % 20) + 5; // 5-25 slot delay
    base_slot + random_delay
}
```

## Mitigation Strategies

1. **Atomic Operations**: Bundle related operations together
2. **Commit-Reveal Schemes**: Use two-phase transactions for sensitive operations
3. **Instruction Hashing**: Include unique hashes to prevent reordering exploits
4. **Time Locks**: Add delays between operations
5. **Nonce Sequences**: Use incrementing nonces to enforce ordering
6. **State Validation**: Verify expected state before each operation
7. **Expiry Mechanisms**: Add expiration to multi-step operations

## Validator-Level Considerations

```rust
// Account for leader schedule when timing operations
pub fn get_next_leader_slots(current_slot: u64) -> Vec<u64> {
    // This would query the actual leader schedule
    // Implementation depends on leader schedule access
    vec![current_slot + 1, current_slot + 5, current_slot + 10]
}

// Avoid operations during known high-MEV periods
pub fn is_high_mev_period(slot: u64) -> bool {
    // Check if current leader is known MEV extractor
    // Check if this is a high-volume period
    false // Placeholder implementation
}
```

## References

- [Adevar Labs: MEV Challenges on Solana](https://www.adevarlabs.com/blog/unpacking-mev-on-solana-challenges-threats-and-developer-defenses)
- [bloXroute: Bundle-leak Exploitation](https://medium.com/bloxroute/a-new-era-of-mev-on-solana-ae5cff390b71)
- [Jito Foundation: Bundle Documentation](https://docs.jito.wtf/)
- [Solana Leader Schedule Documentation](https://docs.solana.com/cluster/leader-rotation)