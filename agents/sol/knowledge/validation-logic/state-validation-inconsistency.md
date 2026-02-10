# State Validation Inconsistency

**Severity:** MEDIUM  
**Category:** Validation Logic  
**Frequency:** Common in Override Systems  
**Source:** Merkl Contest M-03

## Description

Bugs where validation logic checks against wrong state variables, particularly in systems with overrides or multi-version state. Common in upgrade patterns, override systems, and state transition validation.

## Vulnerable Pattern - Merkl Example

```solidity
contract DistributionCreator {
    mapping(bytes32 => CampaignParameters) public campaignList; // Original
    mapping(bytes32 => CampaignParameters) public campaignOverrides; // Updated
    
    function overrideCampaign(bytes32 _campaignId, CampaignParameters memory newCampaign) external {
        // VALIDATION AGAINST ORIGINAL CAMPAIGN
        CampaignParameters memory _campaign = campaign(_campaignId); // Returns ORIGINAL
        
        if (
            // Checks new override against ORIGINAL values, not current override
            (newCampaign.startTimestamp != _campaign.startTimestamp && block.timestamp > _campaign.startTimestamp) ||
            newCampaign.duration + _campaign.startTimestamp <= block.timestamp
        ) revert Errors.InvalidOverride();
        
        // But stores NEW override
        campaignOverrides[_campaignId] = newCampaign;
    }
    
    function campaign(bytes32 _campaignId) public view returns (CampaignParameters memory) {
        // Always returns ORIGINAL, ignoring overrides
        return campaignList[campaignLookup(_campaignId)];
    }
}
```

**The Problem:**
- Validation uses `campaign()` which returns original parameters
- But effective state should be current override if exists
- Multi-step overrides become impossible after first override

## Impact

**Multi-step Override Scenario:**
1. Create campaign: start=1000, duration=3600  
2. Override #1: start=2000, duration=7200 (moves start to future)
3. At timestamp=1500, try Override #2: start=2500, duration=5000

**What happens:**
- Validation checks: `newStart != originalStart (2500 != 1000)` AND `block.timestamp > originalStart (1500 > 1000)`
- Both true → revert with InvalidOverride
- Even though effective start is 2000 (in future), validation uses original 1000 (in past)

## Detection Strategy

**Code Review Focus:**
- Functions that modify state and validate against existing state
- Override/upgrade patterns with multi-step modifications
- State getters that return wrong version (original vs current)
- Validation against base state when effective state differs

**Red Flags:**
- Validation functions using "original" or "base" state getters
- Override systems that become single-use
- Multi-version state with inconsistent access patterns
- Time-based validation against wrong timestamps

## Fix Pattern

```solidity
function overrideCampaign(bytes32 _campaignId, CampaignParameters memory newCampaign) external {
    // GET EFFECTIVE CURRENT STATE (not original)
    CampaignParameters memory effectiveCampaign = getEffectiveCampaign(_campaignId);
    
    if (
        // Validate against CURRENT EFFECTIVE state
        (newCampaign.startTimestamp != effectiveCampaign.startTimestamp && 
         block.timestamp > effectiveCampaign.startTimestamp) ||
        newCampaign.duration + effectiveCampaign.startTimestamp <= block.timestamp
    ) revert Errors.InvalidOverride();
    
    campaignOverrides[_campaignId] = newCampaign;
}

function getEffectiveCampaign(bytes32 _campaignId) public view returns (CampaignParameters memory) {
    // Return current override if exists, otherwise original
    CampaignParameters memory override = campaignOverrides[_campaignId];
    if (override.campaignId == _campaignId) {
        return override;
    }
    return campaignList[campaignLookup(_campaignId)];
}
```

## Real-World Examples

1. **Governance Proposals**: Validation against outdated proposal state
2. **Upgrade Patterns**: Validation against old implementation addresses  
3. **Configuration Updates**: Multi-step config changes that lock after first step
4. **Auction Systems**: Bid validation against wrong price state

## Common Variants

**Proxy Upgrade Validation:**
```solidity
// WRONG: Validates against old implementation
if (implementation != currentImplementation) revert();
upgrade(newImplementation);

// CORRECT: Validates against target state
if (newImplementation == targetImplementation) revert();
```

**Time-based State Validation:**
```solidity
// WRONG: Uses original timestamp
if (block.timestamp < originalStart) revert();

// CORRECT: Uses effective timestamp  
if (block.timestamp < effectiveStart) revert();
```

**Multi-version Data Validation:**
```solidity
// WRONG: Always validates against v1
if (data.amount < v1Config.minAmount) revert();

// CORRECT: Validates against current config
Config memory currentConfig = getCurrentConfig();
if (data.amount < currentConfig.minAmount) revert();
```

## Prevention Patterns

**Explicit State Resolution:**
```solidity
function getCurrentState() internal view returns (State memory) {
    // Always return effective current state
    if (hasOverride) return overrideState;
    return baseState;
}
```

**Consistent State Access:**
```solidity
// Use same getter for validation and operations
State memory current = getCurrentState();
_validate(current);
_operate(current);
```

**Version-aware Validation:**
```solidity
function validate(uint256 version) internal view {
    State memory state = getStateAtVersion(version);
    // Validate against correct version
}
```

## Testing Strategy

```solidity
contract StateValidationTest {
    function testMultiStepOverrides() external {
        // Create base state
        // Apply first override
        // Verify second override works correctly
        // Test against both original and effective state
    }
    
    function testValidationConsistency() external {
        // Ensure validation and operation use same state version
    }
}
```

## Prevention Checklist

- [ ] Validation uses same state as operations
- [ ] Multi-step modifications remain possible  
- [ ] State getters return current effective state
- [ ] Time-based validation uses correct timestamps
- [ ] Override systems don't lock after first use
- [ ] Version consistency across validation functions

## Related Patterns

- Order of Operations Bugs
- State Transition Validation
- Upgrade Safety Patterns
- Multi-version Data Management