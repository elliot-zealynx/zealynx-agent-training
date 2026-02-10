# Arbitrary External Call + NFT Custody = Theft Vector

**Severity:** Critical/High
**Category:** External Call Safety
**Source:** Megapot C4 Contest (Nov 2025, H-01), 12 wardens found it

## Pattern
When a contract:
1. Holds NFTs in custody for other users (e.g., bridge manager, vault, escrow)
2. Makes external calls with user-controlled `to` address and `data`
3. Has balance checks that can be satisfied through clever callback chains

Then an attacker can:
- Set `to` = NFT contract address
- Set `data` = `safeTransferFrom(custodian, attacker, victimTokenId)`
- Use callback (`onERC721Received`) to satisfy any balance/approval checks
- Steal any NFT the custodian holds

## Key Elements
- **approveTo pattern:** Contract approves an attacker-controlled address for ERC20, then makes the external call. Attacker's `onERC721Received` pulls the approved ERC20, satisfying balance checks.
- **Balance check bypass:** `preBalance - postBalance == expectedAmount` passes because the ERC20 was drained via the callback during the NFT transfer.

## Detection Checklist
1. Does the contract hold NFTs for others? (custodial role)
2. Does it make external calls with user-supplied target/data?
3. Does it have ERC20 approvals or balances an attacker could drain?
4. Can a callback during the call satisfy post-call checks?

## Mitigation
- Whitelist allowed external call targets
- Never combine NFT custody with arbitrary external calls
- Use specific bridge interfaces instead of generic `.call(data)`
- Validate that `to` is not any known contract in the system

## Real-World Instance
```solidity
// VULNERABLE: JackpotBridgeManager._bridgeFunds()
function _bridgeFunds(RelayTxData memory _bridgeDetails, uint256 _claimedAmount) private {
    if (_bridgeDetails.approveTo != address(0)) {
        usdc.approve(_bridgeDetails.approveTo, _claimedAmount);
    }
    (bool success,) = _bridgeDetails.to.call(_bridgeDetails.data);
    // balance check passes because callback drained USDC
    if (preUSDCBalance - postUSDCBalance != _claimedAmount) revert NotAllFundsBridged();
}
```
