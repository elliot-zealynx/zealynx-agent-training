# Oracle Timestamp Staleness

## Description

Smart contracts that rely on oracle data without validating timestamp freshness can be exploited when price data becomes stale, allowing manipulation during oracle update delays.

## Vulnerability Pattern

Programs that use oracle prices without checking the timestamp or age of the data, making them vulnerable during periods of oracle staleness.

## Vulnerable Code Example

```rust
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    sysvar::Sysvar,
    msg,
};

#[derive(Clone)]
pub struct PriceData {
    pub price: u64,
    pub timestamp: i64,
    pub confidence_interval: u64,
}

// VULNERABLE: No staleness check
pub fn liquidate_position(accounts: &[AccountInfo]) -> Result<(), ProgramError> {
    let oracle_account = &accounts[1];
    let price_data = PriceData::try_from_slice(&oracle_account.data.borrow())?;
    
    // Vulnerable: Uses price without checking if it's fresh
    let current_price = price_data.price;
    let position_value = calculate_position_value(current_price)?;
    
    if should_liquidate(position_value) {
        msg!("Liquidating position at price: {}", current_price);
        execute_liquidation(accounts)?;
    }
    
    Ok(())
}

// VULNERABLE: Accepts any oracle data
pub fn execute_swap(accounts: &[AccountInfo]) -> Result<(), ProgramError> {
    let price_oracle = &accounts[2];
    let price_feed = PriceData::try_from_slice(&price_oracle.data.borrow())?;
    
    // No validation of data freshness
    let exchange_rate = price_feed.price;
    perform_token_swap(accounts, exchange_rate)?;
    
    Ok(())
}
```

## Attack Vector

1. **Stale Price Exploitation**: Use outdated oracle prices during market volatility
2. **Oracle Downtime Windows**: Exploit periods when oracles aren't updating
3. **Cross-Chain Oracle Lag**: Take advantage of slower oracle updates on Solana vs. other chains
4. **Confidence Interval Manipulation**: Exploit wide confidence intervals in price feeds

## Real-World Examples

- **Lending Protocol Liquidations**: Liquidating positions using stale prices during oracle outages
- **DEX Arbitrage**: Exploiting price differences between stale oracle data and real market prices
- **Cross-Chain Bridge Attacks**: Using time delays between chain oracle updates
- **RedStone Oracle Issues**: Documented vulnerabilities in oracle timestamp validation

## Detection Strategy

```rust
// Check for oracle usage without staleness validation
grep -r "price.*timestamp\|oracle.*data" src/
grep -r "liquidate\|swap.*price" src/

// Look for missing timestamp checks
grep -A10 -B5 "oracle\|price_data" src/ | grep -v "timestamp.*check"
```

## Secure Implementation

```rust
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    sysvar::Sysvar,
    msg,
};

const MAX_ORACLE_AGE_SECONDS: i64 = 60;      // 1 minute max staleness
const MAX_CONFIDENCE_INTERVAL: u64 = 1000;   // 1% max confidence interval
const MIN_UPDATE_FREQUENCY: i64 = 30;        // Expect updates every 30s

#[derive(Clone)]
pub struct ValidatedPriceData {
    pub price: u64,
    pub timestamp: i64,
    pub confidence_interval: u64,
    pub last_update_slot: u64,
}

// Secure: Validates oracle freshness
pub fn secure_liquidate_position(accounts: &[AccountInfo]) -> Result<(), ProgramError> {
    let clock = Clock::get()?;
    let oracle_account = &accounts[1];
    let price_data = ValidatedPriceData::try_from_slice(&oracle_account.data.borrow())?;
    
    // Validate oracle data freshness
    let price_age = clock.unix_timestamp - price_data.timestamp;
    if price_age > MAX_ORACLE_AGE_SECONDS {
        msg!("Oracle data too stale: {} seconds old", price_age);
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Validate confidence interval
    if price_data.confidence_interval > MAX_CONFIDENCE_INTERVAL {
        msg!("Oracle confidence too low: {}", price_data.confidence_interval);
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Validate update frequency
    let slot_age = clock.slot - price_data.last_update_slot;
    let estimated_time_age = slot_age * 400 / 1000; // ~0.4s per slot
    if estimated_time_age > MIN_UPDATE_FREQUENCY as u64 {
        msg!("Oracle updates too infrequent");
        return Err(ProgramError::InvalidAccountData);
    }
    
    let current_price = price_data.price;
    let position_value = calculate_position_value(current_price)?;
    
    if should_liquidate(position_value) {
        msg!("Safely liquidating with fresh oracle data");
        execute_liquidation(accounts)?;
    }
    
    Ok(())
}

// Multiple oracle validation
pub fn cross_validate_price(oracle_accounts: &[AccountInfo]) -> Result<u64, ProgramError> {
    let clock = Clock::get()?;
    let mut valid_prices = Vec::new();
    
    for oracle_account in oracle_accounts {
        let price_data = ValidatedPriceData::try_from_slice(&oracle_account.data.borrow())?;
        
        // Validate each oracle independently
        let price_age = clock.unix_timestamp - price_data.timestamp;
        if price_age <= MAX_ORACLE_AGE_SECONDS 
            && price_data.confidence_interval <= MAX_CONFIDENCE_INTERVAL {
            valid_prices.push(price_data.price);
        }
    }
    
    if valid_prices.len() < 2 {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Use median of valid prices
    valid_prices.sort();
    let median_price = valid_prices[valid_prices.len() / 2];
    
    // Validate prices are within reasonable range of each other
    let price_deviation = calculate_price_deviation(&valid_prices)?;
    if price_deviation > 500 { // 5% max deviation
        return Err(ProgramError::InvalidAccountData);
    }
    
    Ok(median_price)
}
```

## Advanced Mitigation Strategies

```rust
// Circuit breaker for extreme price movements
pub fn validate_price_sanity(
    current_price: u64, 
    historical_prices: &[u64]
) -> Result<(), ProgramError> {
    if historical_prices.is_empty() {
        return Ok(());
    }
    
    let last_price = historical_prices[historical_prices.len() - 1];
    let price_change_pct = ((current_price as i64 - last_price as i64).abs() * 10000) / last_price as i64;
    
    // Reject extreme price movements (>20%)
    if price_change_pct > 2000 {
        msg!("Price movement too extreme: {}%", price_change_pct / 100);
        return Err(ProgramError::InvalidAccountData);
    }
    
    Ok(())
}

// Time-weighted average price (TWAP) implementation
pub struct TWAPData {
    pub prices: Vec<u64>,
    pub timestamps: Vec<i64>,
    pub window_seconds: i64,
}

impl TWAPData {
    pub fn get_twap(&self, current_time: i64) -> Result<u64, ProgramError> {
        let cutoff_time = current_time - self.window_seconds;
        
        let mut weighted_sum = 0u128;
        let mut total_weight = 0u64;
        
        for i in 0..self.prices.len() {
            if self.timestamps[i] >= cutoff_time {
                let weight = (current_time - self.timestamps[i]) as u64;
                weighted_sum += self.prices[i] as u128 * weight as u128;
                total_weight += weight;
            }
        }
        
        if total_weight == 0 {
            return Err(ProgramError::InvalidAccountData);
        }
        
        Ok((weighted_sum / total_weight as u128) as u64)
    }
}
```

## Mitigation Strategies

1. **Timestamp Validation**: Always check oracle data freshness
2. **Confidence Intervals**: Validate oracle confidence levels
3. **Multiple Oracles**: Cross-validate with multiple price sources
4. **Circuit Breakers**: Halt operations on extreme price movements
5. **TWAP Usage**: Use time-weighted average prices for stability
6. **Grace Periods**: Allow brief oracle staleness during normal operations
7. **Oracle Heartbeat**: Monitor oracle update frequency

## Oracle-Specific Considerations

```rust
// Pyth Network specific validation
pub fn validate_pyth_price(price_account: &AccountInfo) -> Result<u64, ProgramError> {
    let price_feed = load_price_feed_from_account_info(price_account)?;
    let current_price = price_feed.get_current_price();
    
    match current_price {
        Some(price) => {
            // Check confidence interval
            if price.conf > (price.price as u64 / 100) { // 1% max confidence
                return Err(ProgramError::InvalidAccountData);
            }
            Ok(price.price as u64)
        },
        None => Err(ProgramError::InvalidAccountData),
    }
}
```

## References

- [Certora: Lulo Oracle Update Failures](https://www.certora.com/reports/lulo-smart-contract-security-assessment-report)
- [Hacken: RedStone Oracle Audit](https://hacken.io/audits/redstone/sca-redstone-finance-solana-patch-may2025/)
- [Pyth Network Documentation](https://docs.pyth.network/)
- [DEV Community: Oracle Dependencies in Lending](https://dev.to/ohmygod/solana-lending-protocol-security-a-deep-dive-into-audit-best-practices-32np)