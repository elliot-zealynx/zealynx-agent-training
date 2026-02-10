# Unchecked Block Misuse (Solidity 0.8+)

## Description
Modern vulnerability where developers use `unchecked` blocks for gas optimization but accidentally disable overflow protection on operations that can actually overflow, reintroducing classic integer overflow bugs into Solidity 0.8+ contracts.

## Vulnerable Code Pattern
```solidity
function batchTransfer(address[] calldata recipients, uint256 amount) {
    unchecked {
        uint256 total = recipients.length * amount; // DANGEROUS: Can overflow
        require(balances[msg.sender] >= total);
        
        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amount;
        }
        balances[msg.sender] -= total;
    }
}

function complexCalculation(uint256 a, uint256 b, uint256 c) returns (uint256) {
    unchecked {
        return a * b + c; // DANGEROUS: Both operations can overflow
    }
}
```

## Attack Vector
1. Developer adds `unchecked` for gas optimization
2. Assumes overflow "cannot happen" based on business logic
3. Attacker finds edge case where overflow occurs
4. Classic overflow vulnerabilities return despite Solidity 0.8+

## Risk Scenarios

### Gas Optimization Gone Wrong
```solidity
// Intended: Save gas on safe loop counter
// Reality: Disables ALL overflow checks in block
unchecked {
    for (uint256 i = 0; i < users.length; i++) {
        uint256 reward = baseReward * multiplier[users[i]]; // CAN OVERFLOW
        balances[users[i]] += reward;
    }
}
```

### False Safety Assumptions
```solidity
function calculateFee(uint256 principal, uint256 rate) returns (uint256) {
    // Developer thinks: "rate is always < 100, so safe"
    // Reality: rate parameter not validated, can be any value
    unchecked {
        return principal * rate / 10000; // DANGEROUS
    }
}
```

## Detection Strategy
1. **Search for unchecked blocks:** Look for `unchecked {` patterns
2. **Analyze operations inside:** Check if multiplication, addition, subtraction can overflow
3. **Validate assumptions:** Test business logic assumptions with edge cases
4. **Review external inputs:** Ensure all external parameters are bounded
5. **Check loop variables:** Verify only loop counters are meant to be unchecked

## Real-World Examples

### Gas-Optimized Loops (Common Pattern)
```solidity
// SAFE: Only loop counter can "overflow" (intentional)
function distribute(address[] calldata users) {
    for (uint256 i = 0; i < users.length;) {
        balances[users[i]] += reward;
        unchecked { i++; } // SAFE: Only affects loop counter
    }
}

// DANGEROUS: All arithmetic unprotected
function distribute(address[] calldata users) {
    unchecked {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 bonus = reward * multiplier; // CAN OVERFLOW
            balances[users[i]] += bonus;
        }
    }
}
```

### Time-Based Calculations
```solidity
function vestingAmount(uint256 elapsed) returns (uint256) {
    unchecked {
        // Dangerous: elapsed can be large, rate can be configured
        return totalTokens * elapsed * vestingRate / (365 days * 10000);
    }
}
```

## Fix Patterns
```solidity
// Option 1: Granular unchecked (recommended)
function distribute(address[] calldata users, uint256 baseReward) {
    uint256 totalCost = users.length * baseReward; // Protected by Solidity 0.8+
    require(balances[msg.sender] >= totalCost);
    
    for (uint256 i = 0; i < users.length;) {
        balances[users[i]] += baseReward;
        unchecked { i++; } // Only loop counter unchecked
    }
}

// Option 2: Explicit bounds checking
function calculateReward(uint256 principal, uint256 multiplier) returns (uint256) {
    require(multiplier <= MAX_MULTIPLIER); // Ensure safe range
    unchecked {
        return principal * multiplier; // Safe due to bounds
    }
}

// Option 3: Mixed approach
function complexCalculation(uint256 a, uint256 b) returns (uint256) {
    uint256 product = a * b; // Protected overflow check
    unchecked {
        return product + CONSTANT_OFFSET; // Safe addition
    }
}
```

## Audit Guidelines

### Red Flags
- [ ] Large `unchecked` blocks with multiple operations
- [ ] Multiplication/addition of user-controlled inputs
- [ ] Missing bounds validation on external parameters
- [ ] Complex mathematical formulas in unchecked blocks
- [ ] Comments claiming "this cannot overflow" without proof

### Best Practices
- [ ] Use unchecked only for loop counters and provably safe operations
- [ ] Add explicit bounds checks before unchecked operations
- [ ] Document why each unchecked operation is safe
- [ ] Test with maximum possible input values
- [ ] Consider partial unchecked (only specific operations)

## Testing Strategy
```solidity
// Test unchecked blocks with edge cases
function testUncheckedOverflow() {
    // Test with maximum values
    vm.expectRevert(); // Should fail if not properly protected
    contract.batchTransfer(users, type(uint256).max);
    
    // Test with large arrays
    address[] memory manyUsers = new address[](1000);
    vm.expectRevert();
    contract.batchTransfer(manyUsers, type(uint128).max);
    
    // Test multiplication edge cases
    uint256 largeValue = type(uint128).max;
    vm.expectRevert();
    contract.calculateFee(largeValue, largeValue);
}
```

## Gas vs Security Analysis
```solidity
// Gas saved per operation in unchecked:
// - Addition/Subtraction: ~20-24 gas
// - Multiplication: ~20-24 gas  
// - Loop increment: ~20 gas

// Cost of vulnerability:
// - Unlimited token minting: $millions
// - Contract drainage: entire TVL
// - Reputation damage: immeasurable

// Conclusion: Only use unchecked for provably safe operations
```

## Modern Development Guidelines
1. **Default to protected:** Use Solidity 0.8+ default behavior
2. **Optimize carefully:** Only unchecked proven-safe operations
3. **Document reasoning:** Explain why each unchecked block is safe
4. **Test thoroughly:** Include overflow test cases
5. **Review regularly:** Audit unchecked blocks with special attention

## Related Patterns
- [Batch Transfer Multiplication](./batch-transfer-multiplication.md)
- [Balance Underflow](./balance-underflow.md)
- [Time Lock Overflow](./time-lock-overflow.md)