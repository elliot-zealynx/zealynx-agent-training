# Approval Front-Running Vulnerability

**Severity:** MEDIUM/HIGH  
**Category:** Approval/Allowance Bugs  
**Gas Impact:** Medium  
**Frequency:** Common  

## Description

ERC20 approve() function has a race condition where a spender can front-run approval changes to spend both the old and new allowance amounts. This occurs when users try to reduce an existing non-zero allowance.

## Vulnerable Code Example

```solidity
// ERC20 standard approve implementation
function approve(address spender, uint256 amount) public returns (bool) {
    allowances[msg.sender][spender] = amount;
    emit Approval(msg.sender, spender, amount);
    return true;
}

// Attack scenario:
// 1. Alice approves Bob for 100 tokens
// 2. Alice wants to reduce to 50 tokens, calls approve(Bob, 50)
// 3. Bob front-runs the transaction and spends 100 tokens
// 4. After Alice's tx confirms, Bob can spend another 50 tokens
// Total: Bob spent 150 tokens instead of intended 50
```

## Detection Strategy

**Static Analysis:**
- Look for direct approve() calls on non-zero allowances
- Check for missing increaseAllowance/decreaseAllowance usage
- Flag protocols not using permit patterns

**Dynamic Analysis:**
- Monitor mempool for approval changes on existing allowances
- Test approval change scenarios in forked environments

**Code Review Focus:**
- Approval update patterns in frontend code
- Smart contract functions that change user approvals
- Missing allowance checks before approve calls

## Fix Pattern

**Safe Approval Pattern:**
```solidity
// Option 1: Reset to 0 first
function safeApprove(IERC20 token, address spender, uint256 amount) internal {
    uint256 currentAllowance = token.allowance(address(this), spender);
    if (currentAllowance != 0) {
        token.approve(spender, 0);
    }
    token.approve(spender, amount);
}

// Option 2: Use increaseAllowance/decreaseAllowance
function adjustApproval(IERC20 token, address spender, uint256 newAmount) internal {
    uint256 currentAllowance = token.allowance(address(this), spender);
    
    if (newAmount > currentAllowance) {
        token.increaseAllowance(spender, newAmount - currentAllowance);
    } else if (newAmount < currentAllowance) {
        token.decreaseAllowance(spender, currentAllowance - newAmount);
    }
}
```

**OpenZeppelin SafeERC20:**
```solidity
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

using SafeERC20 for IERC20;

contract SafeApprovalExample {
    function updateApproval(IERC20 token, address spender, uint256 amount) external {
        // SafeERC20 handles the reset automatically
        token.safeApprove(spender, amount);
        
        // Or use increase/decrease
        token.safeIncreaseAllowance(spender, additionalAmount);
        token.safeDecreaseAllowance(spender, reductionAmount);
    }
}
```

## Real Examples

1. **Early DeFi Protocols** - Many suffered from approval race conditions
2. **1inch Exchange** - Implemented careful approval management to prevent races
3. **Uniswap V2/V3** - Uses permit patterns to avoid approval altogether
4. **Various DEX Aggregators** - Had to implement safe approval patterns

## Exploitation Scenarios

**MEV Attack:**
```solidity
// Malicious contract watching for approval changes
contract ApprovalFrontRunner {
    function frontRunApproval(
        IERC20 token,
        address victim,
        uint256 oldAmount,
        uint256 newAmount
    ) external {
        // 1. See victim's approve(spender, newAmount) in mempool
        // 2. Front-run and call transferFrom for oldAmount
        token.transferFrom(victim, address(this), oldAmount);
        // 3. After victim's tx, can spend newAmount too
    }
}
```

## Prevention Best Practices

1. **Always reset allowance to 0** before setting new value
2. **Use SafeERC20** from OpenZeppelin
3. **Prefer increaseAllowance/decreaseAllowance** over approve
4. **Implement permit patterns** to eliminate approvals
5. **Check current allowance** before making changes
6. **Consider timelock mechanisms** for approval changes

## Gas Considerations

- Two-step approval (0 then amount) costs more gas
- increaseAllowance/decreaseAllowance are more gas-efficient for adjustments
- Permit patterns save gas by eliminating approval transactions

## Related Patterns

- Infinite Approval
- Permit Signature Issues
- Allowance Griefing