# Missing Authorization Modifier

**Category:** Access Control  
**Severity:** Critical/High  
**Last Updated:** 2026-02-04  
**Tags:** access-control, missing-modifier, public-function, onlyOwner, unauthorized

---

## Pattern Summary

The most fundamental access control bug. A sensitive function (burn, mint, withdraw, pause, upgrade) is declared `public` or `external` without any authorization modifier. Any address on the network can call it.

## Root Cause

Developer oversight — forgetting to add `onlyOwner`, `onlyRole(ADMIN)`, or a custom access control check to a function that modifies critical state. In Solidity <0.5, functions defaulted to `public` visibility if not specified, making this even more dangerous.

## Historical Exploits

| Protocol | Date | Loss | Chain | Details |
|----------|------|------|-------|---------|
| HospoWise | Mar 2023 | Token drain | ETH | Public `burn(address, uint256)` — anyone could burn any holder's tokens |
| LAND NFT | 2023 | NFT theft | BSC | Missing access control on sensitive NFT function |
| UvToken | Oct 2022 | $1.5M | ETH | Insufficient access controls on token operations |
| Rubixi | 2016 | ~$0.1M | ETH | Constructor name mismatch left ownership unprotected |

## Vulnerable Code Pattern

```solidity
// VULNERABLE — no access control on burn
function burn(address account, uint256 amount) public {
    _burn(account, amount);
}

// VULNERABLE — no access control on mint
function mint(address to, uint256 amount) external {
    _mint(to, amount);
}

// VULNERABLE — no access control on withdraw
function withdrawAll() public {
    payable(msg.sender).transfer(address(this).balance);
}

// VULNERABLE — no access control on price update
function setPrice(uint256 newPrice) external {
    price = newPrice;
}
```

## Detection Strategy

1. **Static analysis:** Scan all `public`/`external` functions for state-changing operations (storage writes, ETH transfers, token mints/burns) that lack modifier checks
2. **Grep pattern:** Look for functions containing `_mint`, `_burn`, `transfer`, `selfdestruct`, `delegatecall`, `.call{value:` without `onlyOwner`/`onlyRole`/`require(msg.sender ==` checks
3. **Manual review:** For every state-changing function, ask: "Who should be allowed to call this? Is that enforced?"
4. **Tooling:** Slither's `missing-access-control` detector, Aderyn access control checks

## Fix Pattern

```solidity
// FIXED — OpenZeppelin Ownable
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureToken is ERC20, Ownable {
    function burn(address account, uint256 amount) public onlyOwner {
        _burn(account, amount);
    }
}

// FIXED — OpenZeppelin AccessControl (RBAC)
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureToken is ERC20, AccessControl {
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    
    function burn(address account, uint256 amount) public onlyRole(BURNER_ROLE) {
        _burn(account, amount);
    }
}

// FIXED — Custom modifier
modifier onlyAuthorized() {
    require(authorized[msg.sender], "Not authorized");
    _;
}

function withdrawAll() public onlyAuthorized {
    payable(msg.sender).transfer(address(this).balance);
}
```

## Audit Checklist

- [ ] Every `public`/`external` state-changing function has explicit access control
- [ ] No function visibility defaults (Solidity <0.5 issue)
- [ ] Burn/mint functions restricted to appropriate roles
- [ ] Admin functions use least-privilege roles, not blanket `onlyOwner`
- [ ] `selfdestruct` calls are protected (or removed entirely)

## References

- [OWASP SC04 - Access Control Vulnerabilities](https://owasp.org/www-project-smart-contract-top-10/2023/en/src/SC04-access-control-vulnerabilities.html)
- [HospoWise Hack Analysis - SolidityScan](https://blog.solidityscan.com/access-control-vulnerabilities-in-smart-contracts-a31757f5d707)
- [Solodit Access Control Tag](https://solodit.cyfrin.io)
