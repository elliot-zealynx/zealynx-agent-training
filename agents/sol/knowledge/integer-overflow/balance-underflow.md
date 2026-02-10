# Balance Underflow Vulnerability

## Description
Integer underflow in balance subtraction operations that allows users to withdraw more tokens than they own, resulting in a wrapped-around balance of massive value (2^256 - 1).

## Vulnerable Code Pattern
```solidity
function withdraw(uint256 _amount) {
    require(balances[msg.sender] - _amount >= 0); // ALWAYS TRUE (unsigned)
    balances[msg.sender] -= _amount; // UNDERFLOWS TO MAX_UINT
    payable(msg.sender).transfer(_amount);
}

function transfer(address _to, uint256 _value) {
    require(balances[msg.sender] >= _value); // Check should be BEFORE subtraction
    balances[msg.sender] = balances[msg.sender] - _value; // VULNERABLE
    balances[_to] = balances[_to] + _value;
}
```

## Attack Vector
1. User has balance of `0` tokens
2. User calls `withdraw(1)` or `transfer(1)`
3. Subtraction `0 - 1` underflows to `2^256 - 1`
4. User now has maximum possible balance
5. User can drain entire contract

## Detection Strategy
1. **Unsigned Arithmetic:** Look for subtraction on `uint` types
2. **Invalid Checks:** `require(unsigned_var - amount >= 0)` is always true
3. **Order of Operations:** Subtraction before proper balance validation
4. **Missing SafeMath:** Pre-0.8.0 without overflow protection

## Real Examples

### PoWH (Proof of Weak Hands) - Ethereum Ponzi
- Underflow in withdrawal function
- Allowed unlimited token generation
- Contract drained of legitimate funds

### Simple Token Contract (Educational)
```solidity
// Vulnerable pattern from Conflux docs
function send(address _recipient, uint _amount) public returns (bool) {
    require(accounts[msg.sender] - _amount >= 0); // ALWAYS TRUE
    accounts[msg.sender] -= _amount; // UNDERFLOWS
    accounts[_recipient] += _amount;
    return true;
}
```

## Fix Patterns
```solidity
// Option 1: Correct require order (pre-0.8.0)
function withdraw(uint256 _amount) {
    require(balances[msg.sender] >= _amount); // Check BEFORE operation
    balances[msg.sender] -= _amount;
    payable(msg.sender).transfer(_amount);
}

// Option 2: SafeMath (pre-0.8.0)
using SafeMath for uint256;
function withdraw(uint256 _amount) {
    balances[msg.sender] = balances[msg.sender].sub(_amount); // Reverts on underflow
    payable(msg.sender).transfer(_amount);
}

// Option 3: Solidity 0.8+ (automatic protection)
function withdraw(uint256 _amount) {
    balances[msg.sender] -= _amount; // Reverts on underflow automatically
    payable(msg.sender).transfer(_amount);
}

// Option 4: Explicit checks with unchecked (gas optimization)
function withdraw(uint256 _amount) {
    require(balances[msg.sender] >= _amount);
    unchecked {
        balances[msg.sender] -= _amount; // Safe due to require check
    }
    payable(msg.sender).transfer(_amount);
}
```

## Common Misconceptions
1. **"unsigned >= 0 is always true"** - Classic red flag
2. **"require protects against underflow"** - Only if check is correct
3. **"Addition is safe"** - Can still overflow on receiving end
4. **"Solidity 0.8 fixes everything"** - Not if using unchecked blocks

## Audit Techniques
1. **Static Analysis:** Flag all `unsigned - value >= 0` patterns
2. **Symbolic Execution:** Test with edge cases (0 balance, max withdrawals)
3. **Mutation Testing:** Change balances to 0 and try operations
4. **Code Review:** Check order of operations vs checks

## Testing Scenarios
```solidity
// Test cases for underflow detection
function testUnderflow() {
    // Setup: User with 0 balance
    vm.prank(user);
    vm.expectRevert(); // Should revert, not succeed
    token.withdraw(1);
    
    // Edge case: Withdraw exact balance should work
    token.transfer(user, 100);
    vm.prank(user);
    token.withdraw(100); // Should succeed
    
    // Edge case: Withdraw more than balance should fail
    vm.prank(user);
    vm.expectRevert();
    token.withdraw(1); // Should fail with 0 balance
}
```

## Related Patterns
- [Batch Transfer Multiplication](./batch-transfer-multiplication.md)
- [Time Lock Overflow](./time-lock-overflow.md)
- [Unchecked Block Misuse](./unchecked-block-misuse.md)

## Prevention Checklist
- [ ] Never use `unsigned - value >= 0` as a check
- [ ] Always validate balance before subtraction
- [ ] Use SafeMath (pre-0.8.0) or Solidity 0.8+
- [ ] Test with zero balances and edge cases
- [ ] Review all arithmetic operations in token/balance logic
- [ ] Ensure proper order: check → update state → external calls