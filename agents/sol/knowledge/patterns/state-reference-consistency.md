# State Reference Consistency Issues

## Pattern: Using Wrong State Reference for Validation

### Common Bug: Override Validation Against Original State
When systems support overrides/updates, validation logic might incorrectly reference original state instead of current effective state.

**Vulnerable Pattern:**
```solidity
mapping(bytes32 => Campaign) public campaigns;
mapping(bytes32 => Campaign) public campaignOverrides;

function override(bytes32 id, Campaign memory newCampaign) external {
    Campaign memory original = campaigns[id];  // Gets ORIGINAL
    
    // Validates against original, not current effective state!
    if (newCampaign.startTime != original.startTime && 
        block.timestamp > original.startTime) {
        revert TooLate();
    }
    
    campaignOverrides[id] = newCampaign;
}
```

**Issue:** After first override, subsequent overrides still validate against original campaign, not the current effective state. This prevents legitimate multi-step updates.

**Fix:** Always validate against current effective state:
```solidity
function override(bytes32 id, Campaign memory newCampaign) external {
    // Get current effective state (override if exists, otherwise original)
    Campaign memory current = campaignOverrides[id].id != 0 ? 
        campaignOverrides[id] : campaigns[id];
    
    // Validate against current state
    if (newCampaign.startTime != current.startTime && 
        block.timestamp > current.startTime) {
        revert TooLate();
    }
    
    campaignOverrides[id] = newCampaign;
}
```

## Related Patterns

### Historical vs Current State
- Migration/upgrade logic using old state
- Fee calculations based on outdated rates
- Permission checks against stale roles

### Multi-Version Systems
- Always validate against current effective version
- Check if overrides/updates exist before using base state
- Ensure getter functions return effective state

## Detection Checklist
- [ ] Does the system support overrides/updates?
- [ ] Do validation functions use current or original state?
- [ ] Can users perform multi-step updates?
- [ ] Are getter functions returning effective state?
- [ ] Is there consistency between validation and execution state?

## Common Scenarios
- Campaign/auction override systems
- Governance proposal updates
- Token parameter modifications
- Access control role updates
- Price/rate override mechanisms