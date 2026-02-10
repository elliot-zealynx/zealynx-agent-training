# Flash Loan: Donation Attack (Share Price Manipulation)

## Description
Donation attacks exploit protocols that calculate share/token values based on contract balances. By "donating" (transferring directly without using protocol functions) large amounts of tokens to a vault or pool, attackers can manipulate the share price. Combined with flash loans, this enables:

1. **Inflation attacks**: Donate to inflate share price, making deposits round down
2. **First depositor attacks**: Manipulate empty vaults to steal from subsequent depositors
3. **Balance-based pricing attacks**: Inflate perceived collateral value

The core issue: Using `balanceOf(address(this))` for calculations instead of tracked internal accounting.

## Vulnerable Code Pattern

```solidity
// VULNERABLE: Share calculation based on raw balance
contract VulnerableVault {
    IERC20 public token;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    
    function deposit(uint256 amount) external returns (uint256 sharesMinted) {
        uint256 balance = token.balanceOf(address(this));  // DANGEROUS: Can be manipulated
        
        if (totalShares == 0) {
            sharesMinted = amount;  // VULNERABLE: First depositor attack
        } else {
            // shares = amount * totalShares / balance
            // If balance is inflated by donation, new deposits get fewer shares
            sharesMinted = amount * totalShares / balance;
        }
        
        shares[msg.sender] += sharesMinted;
        totalShares += sharesMinted;
        token.transferFrom(msg.sender, address(this), amount);
    }
    
    function withdraw(uint256 sharesToBurn) external returns (uint256 amount) {
        uint256 balance = token.balanceOf(address(this));
        amount = sharesToBurn * balance / totalShares;  // Attacker withdraws inflated amount
        
        shares[msg.sender] -= sharesToBurn;
        totalShares -= sharesToBurn;
        token.transfer(msg.sender, amount);
    }
}

// VULNERABLE: Zunami-style balance inflation
function cacheAssetPrice() external {
    // Price calculation includes donated tokens
    uint256 totalValue = calculateTotalValue();  // Uses balanceOf internally
    pricePerShare = totalValue / totalSupply();
}
```

## Detection Strategy

1. **Find balance-based calculations**: Search for `balanceOf(address(this))`
2. **Check for internal accounting**: Does the contract track deposits separately?
3. **Empty pool edge cases**: How are first deposits handled?
4. **Price/share calculations**: Are they based on spot balances?
5. **Rebasing token logic**: Any function that "caches" or "updates" prices based on current state

Key patterns to grep:
- `balanceOf(address(this))`
- `totalAssets()` that reads raw balance
- Share calculations without internal accounting
- `cachePrice()` / `updatePrice()` / `rebase()` functions

## Fix Pattern

```solidity
// SECURE: Internal accounting prevents donation manipulation
contract SecureVault {
    IERC20 public token;
    uint256 public totalShares;
    uint256 public totalDeposited;  // SECURE: Track deposits internally
    mapping(address => uint256) public shares;
    
    // SECURE: Minimum initial deposit to prevent first depositor attack
    uint256 public constant MINIMUM_INITIAL_DEPOSIT = 1000;
    uint256 public constant DEAD_SHARES = 1000;  // Burn to dead address
    
    function deposit(uint256 amount) external returns (uint256 sharesMinted) {
        require(amount > 0, "Zero deposit");
        
        // Use internal tracking, not balanceOf
        uint256 totalAssets = totalDeposited;
        
        if (totalShares == 0) {
            // SECURE: First deposit handling
            require(amount >= MINIMUM_INITIAL_DEPOSIT, "Below minimum");
            sharesMinted = amount - DEAD_SHARES;
            
            // Mint dead shares to prevent inflation attack
            _mintShares(address(0xdead), DEAD_SHARES);
        } else {
            sharesMinted = amount * totalShares / totalAssets;
            require(sharesMinted > 0, "Zero shares");  // Prevent rounding to zero
        }
        
        // Update internal accounting BEFORE external call
        totalDeposited += amount;
        _mintShares(msg.sender, sharesMinted);
        
        // External call last (CEI pattern)
        token.transferFrom(msg.sender, address(this), amount);
    }
    
    function withdraw(uint256 sharesToBurn) external returns (uint256 amount) {
        require(sharesToBurn > 0 && shares[msg.sender] >= sharesToBurn, "Invalid shares");
        
        // SECURE: Use internal accounting
        amount = sharesToBurn * totalDeposited / totalShares;
        
        // Update internal state first
        _burnShares(msg.sender, sharesToBurn);
        totalDeposited -= amount;
        
        // Transfer last
        token.transfer(msg.sender, amount);
    }
    
    // SECURE: Function to sync if needed, but doesn't affect share calculations
    function skim() external onlyOwner {
        uint256 excess = token.balanceOf(address(this)) - totalDeposited;
        if (excess > 0) {
            token.transfer(treasury, excess);  // Send donations to treasury
        }
    }
}
```

## Real Examples

### Zunami Protocol ($2.1M - August 2023)
- **Attack**: Flash loaned 7M USDT + 10K ETH + 7M USDC
- **Method**: Donated SDT tokens to MIMCurveStakeDao contract
- **Exploit**: Inflated UZD token balance via `cacheAssetPrice()` which read SDT balance
- **Root cause**: Price calculation included donated tokens
- **Reference**: https://medium.com/@seyyedaliayati/understanding-flash-loan-attacks

### Euler Finance ($197M - March 2023)
- **Attack**: Complex donation + self-collateralizing position
- **Method**: Created bad debt through donation logic flaw
- **Exploit**: Manipulated internal accounting to appear solvent
- **Root cause**: Donation function affected liquidation health calculations
- **Reference**: https://www.rekt.news/euler-rekt/

### Wise Lending ($464K - January 2024)
- **Attack**: Donated to inflate share price
- **Method**: First depositor attack variant
- **Exploit**: Subsequent depositors received zero shares due to rounding
- **Root cause**: No minimum deposit or dead share minting
- **Reference**: https://www.blocksec.com/wise-lending

### ERC-4626 Vault First Depositor Attack (Common Pattern)
- **Pattern**: Empty vault + small deposit + large donation
- **Method**: Deposit 1 wei → donate 1M tokens → victim deposits 1M tokens → victim gets 0 shares
- **Prevention**: Dead shares, minimum deposit, virtual offset
- **Reference**: https://docs.openzeppelin.com/contracts/4.x/erc4626

## Additional Mitigations

1. **Internal accounting**: NEVER use `balanceOf(address(this))` for share calculations
2. **Dead shares/virtual offset**: Mint shares to dead address on first deposit
3. **Minimum deposit amounts**: Prevent dust deposits
4. **Skim function**: Allow admin to remove unexpected donations
5. **Share rounding**: Always round against depositor (round down shares minted)
6. **Price bounds**: Reject operations if share price deviates from expected range
7. **Virtual liquidity**: ERC-4626 suggests adding 1 to total assets to prevent zero division
