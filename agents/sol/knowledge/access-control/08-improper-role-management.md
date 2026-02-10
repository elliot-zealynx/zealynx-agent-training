# Improper Role Assignment / RBAC Logic Errors

**Category:** Access Control  
**Severity:** High  
**Last Updated:** 2026-02-04  
**Tags:** access-control, rbac, role-assignment, privilege-escalation, governance, bitmap

---

## Pattern Summary

Logic errors in role-based access control (RBAC) systems that allow unintended role grants, role escalation, or failure to properly revoke roles. This includes bitwise operation errors on role bitmaps, missing checks in role transfer functions, and governance manipulation.

## Root Cause

1. **Bitwise logic errors:** When roles are stored as bitmaps, XOR/AND/OR operations can accidentally grant roles during removal
2. **Missing validation:** Role assignment functions don't verify the caller has authority to grant that specific role
3. **Self-assignment:** Users can assign roles to themselves due to missing checks
4. **Role inheritance gaps:** Parent roles don't properly cascade revocation to child roles
5. **Governance voting manipulation:** Flash loan governance attacks, proposal threshold bypasses

## Historical Exploits & Audit Findings

| Protocol | Source | Severity | Details |
|----------|--------|----------|---------|
| Audit 507 (C4) | Code4rena | Medium | Role removal logic using XOR unintentionally grants roles that weren't held |
| Beanstalk | Apr 2022 | $182M | Flash-loaned governance tokens to pass malicious proposal |
| Build Finance DAO | Feb 2022 | $470K | Hostile governance takeover — attacker acquired enough tokens to pass proposals |
| Various DAOs | 2022-2024 | Various | Proposal timing attacks, quorum manipulation |

## Vulnerable Code Pattern

### Bitmap Role XOR Bug
```solidity
// VULNERABLE — XOR during role removal can GRANT new roles
contract RoleManager {
    // Roles stored as bitmap: ADMIN=0x01, MINTER=0x02, PAUSER=0x04
    mapping(address => uint256) public roles;
    
    function removeRole(address user, uint256 role) external onlyAdmin {
        // BUG: XOR toggles bits — if user doesn't have the role,
        // this GRANTS it instead of removing it!
        roles[user] = roles[user] ^ role;
        
        // Example: user has roles = 0x01 (ADMIN only)
        // removeRole(user, 0x06) // trying to remove MINTER+PAUSER
        // Result: 0x01 ^ 0x06 = 0x07 (ADMIN + MINTER + PAUSER!)
        // User just GOT two new roles instead of losing them
    }
}

// VULNERABLE — No check on who can grant which roles
contract BadRBAC {
    function grantRole(address user, bytes32 role) external {
        // BUG: Any role holder can grant ANY role, including ADMIN
        require(hasRole(msg.sender, DEFAULT_ADMIN_ROLE), "Not admin");
        _grantRole(user, role);
        // What if there's a ROLE_GRANTER role that shouldn't
        // be able to grant ADMIN? No scope check.
    }
}

// VULNERABLE — Self-assignment
contract SelfAssign {
    mapping(address => bool) public isAdmin;
    
    function setAdmin(address addr, bool status) public {
        // BUG: No access control at all — anyone can make themselves admin
        isAdmin[addr] = status;
    }
}
```

### Governance Flash Loan Attack
```solidity
// VULNERABLE — No snapshot or time-lock on governance power
contract VulnerableGovernance {
    function propose(bytes memory data) external {
        // Checks current balance — can be flash-loaned
        require(token.balanceOf(msg.sender) >= proposalThreshold);
        proposals.push(Proposal(data, 0, 0, block.number + votingPeriod));
    }
    
    function vote(uint256 proposalId, bool support) external {
        // Checks current balance — can be flash-loaned
        uint256 weight = token.balanceOf(msg.sender);
        if (support) proposals[proposalId].forVotes += weight;
        else proposals[proposalId].againstVotes += weight;
    }
}
```

## Detection Strategy

1. **Bitmap operations:** Any XOR (`^`) on role bitmaps is suspicious for role removal — should use AND-NOT (`& ~role`)
2. **Role hierarchy:** Can a lower-privilege role grant a higher-privilege role?
3. **Self-referential grants:** Can `grantRole(msg.sender, ADMIN)` be called without proper auth?
4. **Governance snapshots:** Does voting use historical balances (snapshots) or current balances (flash-loanable)?
5. **Proposal execution timelock:** Can proposals execute immediately after passing?
6. **Role renouncement:** Can roles be renounced? What happens to the protocol if the last admin renounces?

## Fix Pattern

```solidity
// FIXED — Proper bitmap role removal with AND-NOT
function removeRole(address user, uint256 role) external onlyAdmin {
    // AND with complement — only clears bits that are set
    roles[user] = roles[user] & ~role;
    // If user has 0x01 and we remove 0x06: 0x01 & ~0x06 = 0x01 & 0xF9 = 0x01
    // Correctly leaves ADMIN unchanged
}

// FIXED — Scoped role granting (OpenZeppelin pattern)
// Use AccessControl with role admin hierarchy
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureRBAC is AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    
    constructor() {
        // Only ADMIN can grant MINTER
        _setRoleAdmin(MINTER_ROLE, ADMIN_ROLE);
        // Only DEFAULT_ADMIN can grant ADMIN
        _setRoleAdmin(ADMIN_ROLE, DEFAULT_ADMIN_ROLE);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }
}

// FIXED — Snapshot-based governance (resistant to flash loans)
import "@openzeppelin/contracts/governance/Governor.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";

contract SecureGovernor is Governor, GovernorVotes {
    // Uses ERC20Votes snapshots — voting power is based on
    // balance at proposal creation block, not current block
    // Flash loans can't retroactively change past snapshots
}
```

## Audit Checklist

- [ ] Role removal uses AND-NOT (`& ~role`), never XOR (`^`)
- [ ] Role granting is scoped — each role has an explicit admin role
- [ ] No self-assignment vectors (msg.sender can't grant themselves higher roles)
- [ ] Governance uses balance snapshots, not current balances
- [ ] Proposal execution has a timelock (48h+ recommended)
- [ ] Quorum requirements can't be manipulated by flash loans
- [ ] Last admin can't accidentally renounce (or protocol handles gracefully)
- [ ] Role admin hierarchy is documented and matches intent

## Key Insight

The bitmap XOR bug is subtle and dangerous. `a ^ b` toggles bits — it removes bits that are set AND sets bits that aren't. For role removal you want `a & ~b` which only clears. This is exactly the kind of bug that passes casual review because XOR "looks like" a removal operation.

## References

- [Code4rena Audit 507 - Role removal XOR bug](https://solodit.cyfrin.io/issues/m-02-critical-access-control-flaw-role-removal-logic-incorrectly-grants-unauthorized-roles-code4rena-audit-507-audit-507-git)
- [Beanstalk Governance Attack - Rekt](https://rekt.news/beanstalk-rekt/)
- [OpenZeppelin AccessControl](https://docs.openzeppelin.com/contracts/4.x/access-control)
