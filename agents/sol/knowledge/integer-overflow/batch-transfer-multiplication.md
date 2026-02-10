# Batch Transfer Multiplication Overflow

## Description
A critical integer overflow vulnerability in batch transfer functions where the multiplication of recipient count and transfer value can overflow, allowing attackers to bypass balance checks and mint unlimited tokens.

## Vulnerable Code Pattern
```solidity
function batchTransfer(address[] recipients, uint256 _value) {
    uint256 amount = uint256(recipients.length) * _value; // VULNERABLE LINE
    require(balanceOf[msg.sender] >= amount);
    
    for (uint256 i = 0; i < recipients.length; i++) {
        balances[recipients[i]] += _value;
    }
    balances[msg.sender] -= amount;
}
```

## Attack Vector
1. Attacker calls with `recipients.length = 2` and `_value = 2^255`
2. Multiplication overflows: `2 * 2^255 = 0`
3. Balance check passes: `require(balance >= 0)` 
4. Loop executes: each recipient gets `2^255` tokens
5. Sender balance decreases by `0` (overflow result)

## Real Examples

### BeautyChain (BEC) - April 2018
- **Contract:** [0xc5d105e63711398af9bbff092d4b6769c82f793d](https://etherscan.io/address/0xc5d105e63711398af9bbff092d4b6769c82f793d)
- **Attack TX:** [0xad89ff16fd1ebe3a0a7cf4ed282302c06626c1af33221ebe0d3a470aba4a660f](https://etherscan.io/tx/0xad89ff16fd1ebe3a0a7cf4ed282302c06626c1af33221ebe0d3a470aba4a660f)
- **Impact:** 10^58 BEC tokens generated, price crashed to $0
- **Attack Value:** `_value = 0x8000000000000000000000000000000000000000000000000000000000000000`
- **Recipients:** Array of length 2

### SmartMesh (SMT) - April 2018
- Similar batch overflow vulnerability in identical contract code
- Multiple other ERC-20s affected (12+ contracts with same vulnerability)

## Detection Strategy
1. **Function Signature:** Look for `batchTransfer` with signature `0x83f12fec`
2. **Multiplication Pattern:** `count * value` without overflow protection
3. **Missing SafeMath:** Pre-0.8.0 contracts without OpenZeppelin SafeMath
4. **Balance Check Logic:** Requirement based on multiplication result

## Fix Patterns
```solidity
// Option 1: Use SafeMath (pre-0.8.0)
using SafeMath for uint256;
uint256 amount = uint256(recipients.length).mul(_value);

// Option 2: Solidity 0.8.0+ (automatic overflow protection)
uint256 amount = uint256(recipients.length) * _value; // Reverts on overflow

// Option 3: Manual checks
require(recipients.length > 0 && _value <= type(uint256).max / recipients.length);
uint256 amount = uint256(recipients.length) * _value;

// Option 4: Unchecked with explicit validation (gas optimization)
unchecked {
    require(_value == 0 || recipients.length <= type(uint256).max / _value);
    uint256 amount = uint256(recipients.length) * _value;
}
```

## Audit Checklist
- [ ] Check all batch/multi-transfer functions
- [ ] Verify multiplication operations use SafeMath or Solidity 0.8+
- [ ] Test with edge case values (2^255, max uint, etc.)
- [ ] Confirm balance checks happen AFTER safe arithmetic
- [ ] Review unchecked blocks for overflow potential

## Gas vs Security Trade-offs
- SafeMath adds ~200 gas per operation
- Solidity 0.8+ built-in checks add ~24 gas per operation
- Unchecked blocks save gas but require manual validation
- Always prefer security over minor gas savings in financial functions

## Related Patterns
- [Generic Multiplication Overflow](./multiplication-overflow.md)
- [Balance Underflow](./balance-underflow.md)
- [Unchecked Block Misuse](./unchecked-block-misuse.md)