# Order of Operations Bugs in Validation

**Severity:** MEDIUM-HIGH  
**Category:** Validation Logic Errors  
**Frequency:** Common in Fee/Accounting Logic  
**Source:** Merkl Contest M-01

## Description

Validation bugs that occur when checks are performed in the wrong order, leading to validation against incorrect values. Most commonly seen in fee calculation, where validation happens before or after fee deduction incorrectly.

## Vulnerable Pattern - Merkl Example

```solidity
function _createCampaign(CampaignParameters memory newCampaign) internal returns (bytes32) {
    uint256 rewardTokenMinAmount = rewardTokenMinAmounts[newCampaign.rewardToken];
    
    // VALIDATION HAPPENS ON GROSS AMOUNT
    if ((newCampaign.amount * HOUR) / newCampaign.duration < rewardTokenMinAmount) 
        revert Errors.CampaignRewardTooLow();
    
    // FEES DEDUCTED AFTER VALIDATION
    uint256 campaignAmountMinusFees = _computeFees(newCampaign.campaignType, newCampaign.amount);
    
    // STORED AMOUNT IS NET (AFTER FEES)
    newCampaign.amount = campaignAmountMinusFees;
    
    // Result: Validation passes on gross, but net amount stored is below minimum
}
```

## Detection Strategy

**Code Review Focus:**
- Look for validation checks followed by amount modifications
- Check if validation parameters match final stored/used values
- Trace execution flow for fee calculations, slippage, taxes
- Verify validation order in multi-step processes

**Red Flags:**
- Validation before fee calculation
- Amount checks before slippage application  
- Rate calculations using gross vs net amounts
- Minimum threshold checks before deductions

## Fix Pattern

```solidity
function _createCampaign(CampaignParameters memory newCampaign) internal returns (bytes32) {
    uint256 rewardTokenMinAmount = rewardTokenMinAmounts[newCampaign.rewardToken];
    
    // COMPUTE FEES FIRST
    uint256 campaignAmountMinusFees = _computeFees(newCampaign.campaignType, newCampaign.amount);
    
    // VALIDATE ON FINAL NET AMOUNT
    if ((campaignAmountMinusFees * HOUR) / newCampaign.duration < rewardTokenMinAmount)
        revert Errors.CampaignRewardTooLow();
    
    // STORE NET AMOUNT
    newCampaign.amount = campaignAmountMinusFees;
}
```

## Real-World Examples

1. **DeFi Trading**: Slippage validation before price impact calculation
2. **NFT Marketplaces**: Royalty validation before fee deduction  
3. **Staking**: Minimum stake checks before protocol fees
4. **Lending**: Collateral validation before liquidation fees

## Common Variants

**Fee Calculation Order:**
- Validate → Calculate fees → Store (WRONG)
- Calculate fees → Validate → Store (CORRECT)

**Slippage Protection:**
- Check min out → Apply fees → Transfer (WRONG) 
- Apply fees → Check min out → Transfer (CORRECT)

**Multi-step Deductions:**
- Validate → Fee A → Fee B → Final amount
- Need validation after ALL deductions

## Prevention Checklist

- [ ] Validation happens on final amounts used/stored
- [ ] All fees/deductions calculated before validation
- [ ] Minimum checks use post-processing values
- [ ] Rate calculations match actual distribution rates
- [ ] Multiple validation points if amount changes mid-function

## Advanced Detection

Look for functions that:
1. Modify amounts after validation
2. Have multiple amount variables (gross/net)  
3. Calculate rates or percentages
4. Apply fees, taxes, or slippage
5. Use different variables for validation vs storage

## Gas vs Security Trade-offs

- Early validation saves gas on reverts
- Late validation ensures accuracy
- Consider: validate early for cheap checks, late for expensive ones
- Document which amount is being validated (gross/net)