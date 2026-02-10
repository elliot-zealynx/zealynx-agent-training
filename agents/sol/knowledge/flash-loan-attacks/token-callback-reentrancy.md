# Flash Loan: Token Callback Reentrancy

## Description
ERC-777 tokens and other callback-enabled tokens (ERC-1155, some ERC-721 implementations) include hooks that execute code during transfers. When protocols integrate these tokens without proper state management, attackers can use flash loans to acquire tokens and exploit the callback mechanism for reentrancy attacks.

The classic pattern: Protocol transfers tokens BEFORE updating internal state, allowing the callback to re-enter and exploit the stale state.

## Vulnerable Code Pattern

```solidity
// VULNERABLE: External call before state update
function borrow(address token, uint256 amount) external {
    require(collateral[msg.sender] >= calculateRequired(amount), "Insufficient collateral");
    
    // DANGEROUS: Transfer happens BEFORE debt update
    IERC20(token).transfer(msg.sender, amount);  // ERC-777 triggers tokensReceived hook here
    
    // TOO LATE: Attacker already re-entered via callback
    debt[msg.sender] += amount;
}

// VULNERABLE: ERC-1155 callback exploitation
function withdraw(uint256 tokenId, uint256 amount) external {
    require(balances[msg.sender][tokenId] >= amount, "Insufficient balance");
    
    // DANGEROUS: safeTransferFrom calls onERC1155Received on recipient
    IERC1155(nft).safeTransferFrom(address(this), msg.sender, tokenId, amount, "");
    
    balances[msg.sender][tokenId] -= amount;  // State update after callback
}
```

## Detection Strategy

1. **Identify callback-enabled tokens**: ERC-777, ERC-1155, ERC-721 (safeTransfer variants)
2. **Check CEI compliance**: Any external call (especially transfers) before state updates
3. **Look for missing reentrancy guards**: Absence of `nonReentrant` modifier
4. **Trace token flow**: Token transfer → callback → state read = vulnerable
5. **Check integration contracts**: Lending protocols with multi-token support are high risk

Code patterns to watch:
- `IERC777.send()` / `IERC777.operatorSend()`
- `safeTransfer()` / `safeTransferFrom()` (ERC-721, ERC-1155)
- `tokensReceived()` / `onERC1155Received()` implementations
- External calls followed by state modifications

## Fix Pattern

```solidity
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureLending is ReentrancyGuard {
    // SECURE: Checks-Effects-Interactions + ReentrancyGuard
    function borrow(address token, uint256 amount) external nonReentrant {
        // 1. CHECKS
        require(collateral[msg.sender] >= calculateRequired(amount), "Insufficient collateral");
        require(amount <= availableLiquidity(token), "Insufficient liquidity");
        
        // 2. EFFECTS (update state FIRST)
        debt[msg.sender] += amount;
        totalBorrowed[token] += amount;
        
        // 3. INTERACTIONS (external call LAST)
        IERC20(token).transfer(msg.sender, amount);
    }
    
    // For known ERC-777 tokens, consider blocking or special handling
    function _beforeTokenTransfer(address token) internal {
        // Check if token is ERC-777 and apply additional guards
        if (isERC777[token]) {
            require(!_reentrancyGuardEntered(), "ERC777 reentrancy blocked");
        }
    }
}

// Alternative: Disable ERC-777 hooks by using transfer() wrapper
library SafeERC777 {
    function safeTransferWithoutHook(
        IERC777 token,
        address to,
        uint256 amount
    ) internal {
        // Use low-level call to bypass hooks
        (bool success, ) = address(token).call(
            abi.encodeWithSelector(IERC20.transfer.selector, to, amount)
        );
        require(success, "Transfer failed");
    }
}
```

## Real Examples

### Cream Finance ($18.8M - August 2021)
- **Token**: AMP (ERC-777)
- **Attack**: Flash loan AMP, borrow() transferred before debt update
- **Exploit**: `tokensReceived` hook re-entered borrow(), drained pool
- **Root cause**: Violated Checks-Effects-Interactions pattern
- **Reference**: https://www.rekt.news/cream-rekt-2/

### imBTC/Uniswap ($300K - April 2020)
- **Token**: imBTC (ERC-777)
- **Attack**: Uniswap V1's `tokenToEthSwapInput` was vulnerable
- **Exploit**: Callback during swap allowed double-spending
- **Root cause**: Uniswap V1 didn't account for ERC-777 callbacks
- **Reference**: https://www.rekt.news/imbtc-uniswap-rekt/

### Bacon Protocol ($1M - March 2022)
- **Token**: Multiple ERC-777 tokens
- **Attack**: Flash loan + callback exploitation in lending function
- **Exploit**: Borrowed multiple times with same collateral
- **Root cause**: Missing reentrancy protection
- **Reference**: https://blocksecteam.medium.com/

## Additional Mitigations

1. **Always use ReentrancyGuard**: Apply `nonReentrant` to ALL external-facing functions
2. **Strict CEI pattern**: Effects MUST precede interactions, no exceptions
3. **Token whitelist**: Only support audited tokens without callback mechanisms
4. **ERC-777 detection**: Implement checks for ERC-777 introspection
5. **Pull over push**: Let users withdraw rather than pushing tokens to them
6. **Pausability**: Include emergency pause for discovered vulnerabilities
