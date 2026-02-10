# Approval Race Conditions

**Severity:** HIGH  
**Category:** Approval/Allowance Bugs  
**Gas Impact:** Medium  
**Frequency:** Common in Complex Protocols  

## Description

Race conditions occur when multiple parties interact with approval mechanisms simultaneously, leading to unexpected states. This includes double-spending approvals, concurrent approval changes, and timing attacks on approval-dependent operations.

## Vulnerable Code Example

```solidity
contract VulnerableVoting {
    mapping(address => uint256) public delegatedPower;
    mapping(address => mapping(address => uint256)) public approvedPower;
    
    function approvePower(address delegate, uint256 amount) external {
        approvedPower[msg.sender][delegate] = amount;
    }
    
    function delegatePower(address from, uint256 amount) external {
        // VULNERABILITY: No check if power was already used
        require(approvedPower[from][msg.sender] >= amount, "Insufficient approval");
        
        // Race condition: delegate can call this multiple times
        // if approval is not atomically decremented
        delegatedPower[msg.sender] += amount;
        
        // Missing: approvedPower[from][msg.sender] -= amount;
    }
    
    function vote(uint256 proposalId, uint256 powerToUse) external {
        // Another race: delegate could vote while owner changes approval
        require(delegatedPower[msg.sender] >= powerToUse, "Insufficient power");
        delegatedPower[msg.sender] -= powerToUse;
        
        // Cast vote...
    }
}
```

## Detection Strategy

**Static Analysis:**
- Look for approval checks without atomic updates
- Flag missing allowance decrements after usage
- Check for non-atomic approval+transfer operations
- Identify concurrent access patterns

**Dynamic Analysis:**
- Simulate concurrent approval modifications
- Test race conditions with multiple transactions in same block
- Check for allowance inconsistencies after parallel operations

**Code Review Focus:**
- Atomic approval operations
- Proper allowance accounting
- Multi-step approval processes
- Access control on approval modifications

## Fix Pattern

**Atomic Approval Operations:**
```solidity
contract SecureVoting {
    mapping(address => uint256) public delegatedPower;
    mapping(address => mapping(address => uint256)) public approvedPower;
    
    // Use a lock to prevent race conditions
    mapping(address => bool) private locked;
    
    modifier noReentry(address account) {
        require(!locked[account], "Operation in progress");
        locked[account] = true;
        _;
        locked[account] = false;
    }
    
    function delegatePowerAtomic(address from, uint256 amount) external noReentry(from) {
        require(approvedPower[from][msg.sender] >= amount, "Insufficient approval");
        
        // Atomic update - check and modify in single operation
        approvedPower[from][msg.sender] -= amount;
        delegatedPower[msg.sender] += amount;
        
        emit PowerDelegated(from, msg.sender, amount);
    }
}
```

**Safe Approval Pattern with Nonce:**
```solidity
contract NonceBasedApproval {
    struct ApprovalData {
        uint256 allowance;
        uint256 nonce;
    }
    
    mapping(address => mapping(address => ApprovalData)) public approvals;
    
    function approveWithNonce(address spender, uint256 amount, uint256 expectedNonce) external {
        require(approvals[msg.sender][spender].nonce == expectedNonce, "Nonce mismatch");
        
        approvals[msg.sender][spender] = ApprovalData({
            allowance: amount,
            nonce: expectedNonce + 1
        });
    }
    
    function transferFromWithNonce(
        address owner,
        address to,
        uint256 amount,
        uint256 expectedNonce
    ) external {
        ApprovalData storage approval = approvals[owner][msg.sender];
        require(approval.nonce == expectedNonce, "Nonce mismatch");
        require(approval.allowance >= amount, "Insufficient allowance");
        
        // Atomic update with nonce increment
        approval.allowance -= amount;
        approval.nonce += 1;
        
        // Transfer logic...
    }
}
```

## Real Examples

1. **Early DEX Protocols** - Race conditions in order matching with approvals
2. **Governance Systems** - Voting power delegation race conditions
3. **Staking Protocols** - Concurrent stake/unstake with approval modifications
4. **Multi-signature Wallets** - Approval confirmations with timing attacks

## Exploitation Scenarios

**Double Spending Attack:**
```solidity
// Attacker exploits timing between approval check and usage
contract RaceExploiter {
    function doubleSpend(IERC20 token, address victim) external {
        // 1. Get approved for 100 tokens
        // 2. Call transferFrom for 100 tokens
        // 3. Quickly call transferFrom again before allowance is updated
        // 4. If race condition exists, can transfer 200 tokens total
        
        token.transferFrom(victim, address(this), 100);
        token.transferFrom(victim, address(this), 100); // Should fail but might not
    }
}
```

**Approval Timing Attack:**
```solidity
// Exploit window between approval change and usage
contract TimingAttacker {
    function exploitApprovalChange(IERC20 token, address victim) external {
        // Watch for victim changing approval from 100 to 50
        // Front-run to spend 100, then spend 50 after change
        // Total: 150 instead of intended 50
    }
}
```

## Prevention Best Practices

1. **Use atomic operations** for approval changes
2. **Implement proper reentrancy protection**
3. **Use nonce-based approval systems** for critical operations
4. **Check-effect-interaction pattern** for approval logic
5. **Consider commit-reveal schemes** for sensitive approvals
6. **Use SafeERC20** which handles many edge cases
7. **Test concurrent operation scenarios**

## Advanced Protection Patterns

**Time-locked Approvals:**
```solidity
contract TimeLockApproval {
    struct TimedApproval {
        uint256 amount;
        uint256 unlockTime;
        bool executed;
    }
    
    mapping(address => mapping(address => TimedApproval)) public timedApprovals;
    
    function requestApproval(address spender, uint256 amount, uint256 delay) external {
        timedApprovals[msg.sender][spender] = TimedApproval({
            amount: amount,
            unlockTime: block.timestamp + delay,
            executed: false
        });
    }
    
    function executeApproval(address owner, address spender) external {
        TimedApproval storage approval = timedApprovals[owner][spender];
        require(block.timestamp >= approval.unlockTime, "Still locked");
        require(!approval.executed, "Already executed");
        
        approval.executed = true;
        IERC20(tokenAddress).approve(spender, approval.amount);
    }
}
```

**Multi-sig Approval:**
```solidity
contract MultiSigApproval {
    struct Approval {
        uint256 amount;
        uint256 confirmations;
        mapping(address => bool) confirmed;
        bool executed;
    }
    
    mapping(bytes32 => Approval) public pendingApprovals;
    uint256 public requiredConfirmations = 2;
    
    function requestApproval(address spender, uint256 amount) external returns (bytes32 approvalId) {
        approvalId = keccak256(abi.encodePacked(msg.sender, spender, amount, block.timestamp));
        pendingApprovals[approvalId].amount = amount;
        return approvalId;
    }
    
    function confirmApproval(bytes32 approvalId) external {
        Approval storage approval = pendingApprovals[approvalId];
        require(!approval.confirmed[msg.sender], "Already confirmed");
        
        approval.confirmed[msg.sender] = true;
        approval.confirmations++;
        
        if (approval.confirmations >= requiredConfirmations && !approval.executed) {
            approval.executed = true;
            // Execute approval...
        }
    }
}
```

## Gas Optimization vs Security

- Atomic operations cost more gas but provide security
- Consider batching approvals for gas efficiency
- Use view functions to check state before modifications
- Balance between security and UX/gas costs

## Testing Strategies

```solidity
contract ApprovalRaceTest {
    function testConcurrentApprovals() external {
        // Simulate two approvals in same block
        // Check for race conditions
        // Verify final state consistency
    }
    
    function testApprovalUsageRace() external {
        // Approve amount A
        // Use amount B while changing approval to C
        // Verify security properties maintained
    }
}
```

## Related Patterns

- Approval Front-Running
- Reentrancy Attacks
- Time-of-Check Time-of-Use (TOCTOU)
- MEV Extraction