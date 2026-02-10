# Overpowered Roles & Centralization Risk

**Category:** Access Control  
**Severity:** High/Medium  
**Last Updated:** 2026-02-04  
**Tags:** access-control, centralization, admin-key, rug-pull, timelock, governance

---

## Pattern Summary

A single address (or small set) has excessive privilege: ability to pause, upgrade, drain, change fees, modify critical parameters, or rug users. Even if the code is "correct," centralized control is a trust assumption that creates existential risk. If the admin key is compromised, everything is lost.

## Root Cause

**Over-centralization of power.** Contracts give `owner`/`admin` roles too much capability without:
- Timelocks for sensitive operations
- Multi-sig requirements
- Role separation (different admins for different functions)
- Upper bounds on parameter changes

## Risk Scenarios

| Scenario | Impact | Example |
|----------|--------|---------|
| Admin key compromise | Total fund drain | DeFi protocol owner EOA gets phished |
| Insider rug pull | Users lose all deposits | Admin calls `emergencyWithdraw()` |
| Malicious upgrade | Arbitrary code execution | Admin upgrades proxy to backdoored implementation |
| Fee manipulation | Users overcharged silently | Admin sets fees to 100% |
| Pause without unpause | Permanent DoS | Admin pauses and loses/destroys the key |

## Vulnerable Code Pattern

```solidity
// VULNERABLE — Owner has god-mode powers
contract DeFiVault is Ownable, UUPSUpgradeable {
    uint256 public fee;
    
    // Owner can set ANY fee, including 100%
    function setFee(uint256 newFee) external onlyOwner {
        fee = newFee; // No upper bound!
    }
    
    // Owner can drain all funds
    function emergencyWithdraw(address to) external onlyOwner {
        IERC20(token).transfer(to, IERC20(token).balanceOf(address(this)));
    }
    
    // Owner can upgrade to anything — including a contract that steals funds
    function _authorizeUpgrade(address) internal override onlyOwner {}
    
    // Owner can pause with no mechanism to unpause if key is lost
    function pause() external onlyOwner {
        _pause();
    }
    
    // Single EOA owner — one compromised key = game over
}
```

## Detection Strategy

1. **Enumerate admin functions:** List every function with `onlyOwner`, `onlyRole(ADMIN)`, or similar modifiers
2. **Assess each function's impact:** Can it drain funds? Change critical parameters unboundedly? Upgrade logic?
3. **Check for timelocks:** Are sensitive operations delayed to give users time to exit?
4. **Check owner type:** Is `owner` an EOA or a multisig? Gnosis Safe multisig >> single EOA
5. **Parameter bounds:** Can admin set fees to 100%? Can they set interest rates to drain reserves?
6. **Upgrade authority:** Who can upgrade? Is there a timelock? Can users exit before upgrade takes effect?

## Fix Pattern

```solidity
// IMPROVED — Bounded parameters, timelock, multi-sig
contract SecureVault is AccessControl, UUPSUpgradeable {
    uint256 public constant MAX_FEE = 1000; // 10% max
    uint256 public constant TIMELOCK_DELAY = 2 days;
    
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER");
    
    struct PendingChange {
        uint256 newValue;
        uint256 executeAfter;
    }
    mapping(bytes32 => PendingChange) public pendingChanges;
    
    // Bounded fee setting with timelock
    function proposeFeeChange(uint256 newFee) external onlyRole(ADMIN_ROLE) {
        require(newFee <= MAX_FEE, "Fee too high");
        pendingChanges[keccak256("fee")] = PendingChange(
            newFee,
            block.timestamp + TIMELOCK_DELAY
        );
        emit FeeChangeProposed(newFee, block.timestamp + TIMELOCK_DELAY);
    }
    
    function executeFeeChange() external onlyRole(ADMIN_ROLE) {
        PendingChange memory change = pendingChanges[keccak256("fee")];
        require(block.timestamp >= change.executeAfter, "Timelock active");
        fee = change.newValue;
        delete pendingChanges[keccak256("fee")];
    }
    
    // Separate roles for different operations
    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}
    
    // Emergency withdraw goes to a treasury multisig, not arbitrary address
    function emergencyWithdraw() external onlyRole(ADMIN_ROLE) {
        IERC20(token).transfer(TREASURY_MULTISIG, IERC20(token).balanceOf(address(this)));
    }
}
```

## Audit Checklist

- [ ] All admin-only functions are documented with their risk impact
- [ ] Parameter changes have upper/lower bounds where applicable
- [ ] High-impact operations (upgrade, large withdrawals) have timelocks
- [ ] Owner/admin is a multisig (Gnosis Safe), not an EOA
- [ ] Role separation: different addresses for pause/upgrade/fee management
- [ ] Users can exit before timelocked changes take effect
- [ ] Emergency functions send to hardcoded treasury, not arbitrary addresses
- [ ] Upgrade process includes a transparent timelock with event emissions

## Severity Assessment Guide

| Factor | Low Risk | High Risk |
|--------|----------|-----------|
| Owner type | Multisig (3/5+) | Single EOA |
| Timelocks | 48h+ on all admin ops | No timelocks |
| Parameter bounds | All bounded | Unbounded fee/rate setting |
| Upgrade ability | Timelocked + transparent | Instant upgrade by single key |
| Emergency withdraw | To hardcoded treasury | To arbitrary address |

## References

- [Trail of Bits - Centralization Risks](https://blog.trailofbits.com/2023/07/21/common-pitfalls-for-smart-contract-developers/)
- [OpenZeppelin - TimelockController](https://docs.openzeppelin.com/contracts/4.x/api/governance#TimelockController)
- [Rekt Leaderboard - Many top hacks involve compromised admin keys](https://rekt.news/leaderboard/)
