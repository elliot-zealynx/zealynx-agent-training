# Try/Catch Error Handling Asymmetries

## Pattern: Inconsistent Error Handling in Callbacks

### Common Bug: Validation Inside Try Block
When external call validation happens inside the `try` block instead of being part of the external call, reverts from validation are NOT caught by the `catch` block.

**Vulnerable Pattern:**
```solidity
try ICallback(recipient).onCallback(data) returns (bytes32 result) {
    // This revert is NOT caught by catch block!
    if (result != EXPECTED_RESULT) revert InvalidResult();
} catch {
    // Genuine external call failures are silently ignored
    // But validation reverts above will bubble up and break execution
}
```

**Impact:** 
- Validation failures cause uncaught reverts that can break batch operations
- Genuine external failures are silently ignored
- Asymmetric error handling creates DOS vectors

### Correct Patterns:

**Option 1: Move validation outside try/catch**
```solidity
try ICallback(recipient).onCallback(data) returns (bytes32 result) {
    // Do nothing in success case
} catch {
    // Handle external call failure
    return; // or appropriate error handling
}

// Validate after try/catch
bytes32 result = ICallback(recipient).onCallback(data);
if (result != EXPECTED_RESULT) revert InvalidResult();
```

**Option 2: Catch validation errors too**
```solidity
try ICallback(recipient).onCallback(data) returns (bytes32 result) {
    if (result != EXPECTED_RESULT) revert InvalidResult();
} catch Error(string memory reason) {
    // Handle both external failures and validation errors
} catch {
    // Handle low-level failures
}
```

## Detection Checklist
- [ ] Does the `try` block contain validation logic beyond the external call?
- [ ] Can validation failures inside `try` cause uncaught reverts?
- [ ] Are external call failures properly handled in `catch`?
- [ ] Is error handling symmetric between validation and external failures?
- [ ] Can malicious contracts exploit the asymmetry to cause DOS?

## Common Scenarios
- Callback validation (return value checks)
- Multi-call batching with external calls
- Integration with unknown external contracts
- Oracle price feed validation