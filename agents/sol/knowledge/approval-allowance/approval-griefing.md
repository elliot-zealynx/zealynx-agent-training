# Approval Griefing Attack

**Severity:** MEDIUM  
**Category:** Approval/Allowance Bugs  
**Gas Impact:** Medium  
**Frequency:** Uncommon but Critical  

## Description

Attackers can manipulate ERC20 approve() functions to cause legitimate transactions to fail by front-running approvals or exploiting tokens that revert on approve() calls to non-zero allowances. This creates denial-of-service conditions and can break protocol functionality.

## Vulnerable Code Example

```solidity
contract VulnerableSwap {
    function swapTokens(IERC20 tokenA, IERC20 tokenB, uint256 amountA) external {
        // VULNERABILITY: Assumes approve always succeeds
        tokenA.approve(address(SWAP_ROUTER), amountA);
        
        // If approve fails due to existing allowance, entire tx reverts
        SWAP_ROUTER.exactInputSingle(ISwapRouter.ExactInputSingleParams({
            tokenIn: address(tokenA),
            tokenOut: address(tokenB),
            fee: 3000,
            recipient: msg.sender,
            deadline: block.timestamp + 300,
            amountIn: amountA,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        }));
    }
}

// Some tokens (like USDT) revert on approve() to non-zero allowance
contract ProblematicToken is ERC20 {
    function approve(address spender, uint256 amount) public override returns (bool) {
        require(allowance(msg.sender, spender) == 0 || amount == 0, "Must reset allowance first");
        return super.approve(spender, amount);
    }
}
```

## Detection Strategy

**Static Analysis:**
- Look for approve() calls without error handling
- Check for missing allowance checks before approve
- Flag protocols not using SafeERC20
- Identify batch operations that could fail on single approve

**Dynamic Analysis:**
- Test with tokens that have non-standard approve behavior
- Simulate front-running scenarios on approve calls
- Test approve failures in complex transaction flows

**Code Review Focus:**
- Error handling around approve() calls
- Batch transaction atomic requirements
- Token compatibility assumptions

## Fix Pattern

**Defensive Approval Pattern:**
```solidity
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract SecureSwap {
    using SafeERC20 for IERC20;
    
    function swapTokens(IERC20 tokenA, IERC20 tokenB, uint256 amountA) external {
        // SafeERC20 handles problematic tokens automatically
        tokenA.safeApprove(address(SWAP_ROUTER), amountA);
        
        // Proceed with swap...
    }
    
    // Alternative: Manual approval handling
    function manualSafeApprove(IERC20 token, address spender, uint256 amount) internal {
        // Check current allowance
        uint256 currentAllowance = token.allowance(address(this), spender);
        
        if (currentAllowance > 0) {
            // Reset to 0 first for problematic tokens
            token.approve(spender, 0);
        }
        
        // Set desired allowance
        bool success = token.approve(spender, amount);
        require(success, "Approve failed");
        
        // Verify allowance was set correctly
        require(token.allowance(address(this), spender) == amount, "Allowance not set");
    }
}
```

**Griefing-Resistant Pattern:**
```solidity
contract GriefingResistant {
    using SafeERC20 for IERC20;
    
    function batchOperation(IERC20[] calldata tokens, uint256[] calldata amounts) external {
        // Prepare all approvals first, handle failures gracefully
        for (uint i = 0; i < tokens.length; i++) {
            try tokens[i].safeApprove(address(TARGET_CONTRACT), amounts[i]) {
                // Approval succeeded
            } catch {
                // Handle approval failure - maybe skip this token
                emit ApprovalFailed(address(tokens[i]), amounts[i]);
                continue;
            }
        }
        
        // Execute operations only for successfully approved tokens
        TARGET_CONTRACT.batchProcess(tokens, amounts);
    }
}
```

## Real Examples

1. **USDT Approval Issues** - Many protocols failed with USDT due to non-zero allowance restrictions
2. **Uniswap V2 Router** - Early versions had approval griefing vulnerabilities
3. **DEX Aggregators** - Multiple incidents of failed swaps due to approval issues
4. **Yield Farming Protocols** - Batch operations failing on single approval failure

## Griefing Attack Scenarios

**Front-Running Griefing:**
```solidity
// Attacker watches for victim's approve() transaction
// Front-runs to set small allowance, causing victim's approve to fail
contract ApprovalGriefer {
    function griefApproval(IERC20 token, address victim, address spender) external {
        // If victim is about to approve, front-run with dust amount
        // Some tokens will revert on subsequent approve() calls
        token.transferFrom(victim, address(this), 1);
        // Now victim's approve() will fail due to existing allowance
    }
}
```

**MEV Griefing:**
```solidity
// Sandwiching approval transactions to extract value
// While causing target transaction to fail
```

## Token Compatibility Issues

**Problematic Tokens:**
- USDT: Requires allowance reset to 0 before new approval
- Some tokens revert on approve() to existing allowance
- Tokens with approval fees
- Tokens with transfer/approval hooks that can fail

**Testing Matrix:**
```solidity
contract TokenCompatibilityTest {
    function testApprovalBehavior(IERC20 token) external {
        // Test 1: Approve from 0
        token.approve(address(this), 100);
        assert(token.allowance(address(this), address(this)) == 100);
        
        // Test 2: Approve over existing (problematic for USDT-like tokens)
        try token.approve(address(this), 200) {
            // Token allows overwriting allowance
        } catch {
            // Token requires reset to 0 first
            token.approve(address(this), 0);
            token.approve(address(this), 200);
        }
        
        // Test 3: Approve to 0
        token.approve(address(this), 0);
        assert(token.allowance(address(this), address(this)) == 0);
    }
}
```

## Prevention Best Practices

1. **Always use SafeERC20** from OpenZeppelin
2. **Test with problematic tokens** (USDT, etc.)
3. **Handle approval failures gracefully** in batch operations
4. **Reset allowances to 0** before setting new values
5. **Implement approval retry logic** for mission-critical operations
6. **Monitor for front-running** on approval transactions
7. **Use permit patterns** to avoid approvals altogether

## Gas Considerations

- Failed approve() still consumes gas
- Reset-then-approve pattern costs extra gas
- Consider approval batching for multiple operations
- Permit patterns can save gas overall

## Related Patterns

- Infinite Approval
- Approval Front-Running
- Permit Signature Issues
- Token Transfer Failures