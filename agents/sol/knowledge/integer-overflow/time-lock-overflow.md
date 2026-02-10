# Time Lock Overflow Vulnerability

## Description
Integer overflow in time-based calculations that allows users to bypass lock periods by setting future timestamps that wrap around to past values, enabling immediate withdrawal of locked funds.

## Vulnerable Code Pattern
```solidity
contract TimeVault {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public unlockTime;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        unlockTime[msg.sender] = block.timestamp + 1 weeks;
    }
    
    // VULNERABLE: Can overflow timestamp
    function extendLockTime(uint256 _additionalSeconds) public {
        unlockTime[msg.sender] += _additionalSeconds; // OVERFLOW RISK
    }
    
    function withdraw() external {
        require(block.timestamp > unlockTime[msg.sender]);
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
```

## Attack Vector
1. User deposits funds, gets lock time of `block.timestamp + 1 weeks`
2. User calls `extendLockTime(type(uint256).max - current_timestamp)`
3. Addition overflows: large number + current time = small past timestamp
4. `block.timestamp > unlockTime[msg.sender]` becomes true
5. User can immediately withdraw locked funds

## Real Examples

### TimeWrapVault (OWASP Example)
```solidity
function extendLockTime(uint256 _additionalSeconds) public {
    withdrawalUnlockTime[msg.sender] += _additionalSeconds; // Vulnerable
}
```
- User can pass `_additionalSeconds = type(uint256).max`
- Results in overflow to very small timestamp
- Bypasses entire lock mechanism

### Governance Time Delays
```solidity
function scheduleProposal(uint256 delay) external {
    proposals[proposalId].executeTime = block.timestamp + delay; // VULNERABLE
}
```

## Detection Strategy
1. **Time Arithmetic:** Look for additions to `block.timestamp`
2. **User-Controlled Delays:** Parameters that extend time locks
3. **Missing Validation:** No maximum bounds on time extensions
4. **Overflow Potential:** Large numbers added to timestamps

## Mathematical Analysis
```
Current time: 1640995200 (Jan 1, 2022)
Lock period: 604800 (1 week)
Normal unlock: 1641600000 (Jan 8, 2022)

Attack value: type(uint256).max = 2^256 - 1
Overflow calc: 1641600000 + (2^256 - 1) = 1641599999 (Jan 7, 2022 23:59:59)
Result: Past timestamp, immediate unlock
```

## Fix Patterns
```solidity
// Option 1: Maximum bounds checking
uint256 public constant MAX_LOCK_EXTENSION = 365 days;

function extendLockTime(uint256 _additionalSeconds) public {
    require(_additionalSeconds <= MAX_LOCK_EXTENSION);
    require(unlockTime[msg.sender] + _additionalSeconds >= unlockTime[msg.sender]); // Overflow check
    unlockTime[msg.sender] += _additionalSeconds;
}

// Option 2: SafeMath (pre-0.8.0)
using SafeMath for uint256;

function extendLockTime(uint256 _additionalSeconds) public {
    unlockTime[msg.sender] = unlockTime[msg.sender].add(_additionalSeconds); // Reverts on overflow
}

// Option 3: Solidity 0.8+ with validation
function extendLockTime(uint256 _additionalSeconds) public {
    require(_additionalSeconds <= MAX_LOCK_EXTENSION);
    unlockTime[msg.sender] += _additionalSeconds; // Automatic overflow protection
}

// Option 4: Set absolute time instead of extension
function setUnlockTime(uint256 _unlockTime) public {
    require(_unlockTime > block.timestamp);
    require(_unlockTime <= block.timestamp + MAX_LOCK_PERIOD);
    unlockTime[msg.sender] = _unlockTime;
}
```

## Additional Timestamp Vulnerabilities

### Approval Deadlines
```solidity
// Vulnerable: Can set past deadline via overflow
function approveWithDeadline(address spender, uint256 amount, uint256 deadline) {
    require(block.timestamp <= deadline);
    approvals[msg.sender][spender].deadline = block.timestamp + deadline; // WRONG
}

// Correct: Use deadline directly
function approveWithDeadline(address spender, uint256 amount, uint256 deadline) {
    require(block.timestamp <= deadline);
    approvals[msg.sender][spender].deadline = deadline;
}
```

### Reward Calculations
```solidity
// Vulnerable: Can overflow reward calculation
function calculateReward(uint256 multiplier) returns (uint256) {
    uint256 timeElapsed = block.timestamp - startTime;
    return baseReward * timeElapsed * multiplier; // Multiple overflow points
}
```

## Testing Scenarios
```solidity
function testTimeLockOverflow() {
    // Setup: User deposits and has normal lock time
    vm.prank(user);
    vault.deposit{value: 1 ether}();
    
    uint256 normalUnlock = vault.unlockTime(user);
    assertGt(normalUnlock, block.timestamp);
    
    // Attack: Try to overflow timestamp
    vm.prank(user);
    vm.expectRevert(); // Should revert, not succeed
    vault.extendLockTime(type(uint256).max);
    
    // Verify lock time hasn't changed after failed attack
    assertEq(vault.unlockTime(user), normalUnlock);
}

function testTimestampEdgeCases() {
    // Test with maximum reasonable extension
    vault.extendLockTime(365 days); // Should work
    
    // Test near overflow boundary
    vm.expectRevert();
    vault.extendLockTime(type(uint256).max - block.timestamp + 1);
}
```

## Business Logic Considerations
1. **Maximum Lock Periods:** Define reasonable upper bounds
2. **Minimum Extensions:** Prevent griefing with tiny extensions
3. **Emergency Unlocks:** Consider admin override for emergencies
4. **Time Zone Issues:** Use UTC timestamps consistently

## Audit Checklist
- [ ] All time arithmetic uses SafeMath or Solidity 0.8+
- [ ] Maximum bounds on user-controlled time parameters
- [ ] No addition of large values to timestamps
- [ ] Proper overflow checks before time calculations
- [ ] Test cases with edge case timestamps
- [ ] Review all `block.timestamp` usage patterns

## Prevention Summary
```solidity
// Time lock security pattern template
contract SecureTimeVault {
    uint256 public constant MAX_LOCK_PERIOD = 365 days;
    uint256 public constant MIN_LOCK_PERIOD = 1 hours;
    
    function setLockPeriod(uint256 _period) external {
        require(_period >= MIN_LOCK_PERIOD && _period <= MAX_LOCK_PERIOD);
        unlockTime[msg.sender] = block.timestamp + _period; // Safe in 0.8+
    }
    
    function extendLockTime(uint256 _extension) external {
        require(_extension <= MAX_LOCK_PERIOD);
        require(unlockTime[msg.sender] + _extension >= unlockTime[msg.sender]);
        unlockTime[msg.sender] += _extension;
    }
}
```

## Related Patterns
- [Batch Transfer Multiplication](./batch-transfer-multiplication.md)
- [Balance Underflow](./balance-underflow.md)  
- [Unchecked Block Misuse](./unchecked-block-misuse.md)