# Validation Timing Vulnerabilities

## Pattern: Pre vs Post-Processing Validation

### Common Bug: Validating Before Fee/Tax Deduction
When protocols validate amounts before deducting fees but store/use the net amount after fees, the actual distributed amount can be below the required minimum.

**Example Pattern:**
```solidity
function createCampaign(uint256 amount) external {
    // Validation on gross amount
    require((amount * HOUR) / duration >= minAmount, "too low");
    
    // Fee calculation
    uint256 netAmount = amount - (amount * feeRate / 100);
    
    // Store net amount (now below minimum!)
    campaigns[id].amount = netAmount;
}
```

**Impact:** Bypasses minimum thresholds by exact fee percentage.

**Fix:** Always validate on the final amount that will actually be used:
```solidity
function createCampaign(uint256 grossAmount) external {
    uint256 netAmount = grossAmount - (grossAmount * feeRate / 100);
    
    // Validate on net amount
    require((netAmount * HOUR) / duration >= minAmount, "too low");
    
    campaigns[id].amount = netAmount;
}
```

## Detection Checklist
- [ ] Are validations done before or after fee/tax calculations?
- [ ] Does the validation use the same amount that gets stored/transferred?
- [ ] Can users bypass minimum thresholds through fee calculations?
- [ ] Are there multi-step processes where validation happens at wrong step?

## Related Patterns
- Fee bypass vulnerabilities
- Minimum threshold bypasses  
- Multi-step validation errors