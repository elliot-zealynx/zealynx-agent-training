# Flash Loan: Governance Takeover

## Description
Flash loans can weaponize governance systems by allowing attackers to temporarily acquire majority voting power within a single transaction. If a protocol allows immediate proposal execution after achieving quorum/supermajority, an attacker can:
1. Borrow tokens via flash loan
2. Acquire governance power (by buying/staking governance tokens)
3. Pass a malicious proposal
4. Execute the proposal (draining treasury, changing critical parameters)
5. Repay the flash loan

This exploits the assumption that accumulating voting power requires long-term capital commitment.

## Vulnerable Code Pattern

```solidity
// VULNERABLE: Immediate execution after vote passes
contract VulnerableGovernance {
    mapping(uint256 => Proposal) public proposals;
    uint256 public quorum = 51;  // 51% to pass
    
    function vote(uint256 proposalId, bool support) external {
        uint256 votes = governanceToken.balanceOf(msg.sender);
        proposals[proposalId].votes[support] += votes;
    }
    
    // DANGEROUS: No timelock, immediate execution
    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(p.votes[true] > totalSupply * quorum / 100, "Quorum not met");
        
        // Immediately executes - flash loan attacker can pass & execute in one tx
        (bool success, ) = p.target.call(p.data);
        require(success, "Execution failed");
    }
}

// VULNERABLE: Snapshot at vote time, not proposal creation
function vote(uint256 proposalId, bool support) external {
    // Takes balance NOW, not at proposal creation
    // Attacker can acquire tokens after proposal exists
    uint256 votes = governanceToken.balanceOf(msg.sender);
    proposals[proposalId].votes[support] += votes;
}
```

## Detection Strategy

1. **Check for timelocks**: Proposals should have mandatory delay between passing and execution
2. **Snapshot timing**: Voting power should be snapshot BEFORE proposal creation
3. **Delegation mechanics**: Can voting power be acquired instantly?
4. **Emergency functions**: Any "fast-track" execution paths?
5. **Token transferability**: Can governance tokens be freely traded during voting?

Red flags:
- `execute()` callable immediately after quorum
- No `block.timestamp` or `block.number` checks in execution
- Voting power based on current balance, not historical snapshot
- Missing `proposalThreshold` (minimum tokens to propose)

## Fix Pattern

```solidity
// SECURE: Timelock + Snapshot governance
contract SecureGovernance {
    uint256 public constant VOTING_DELAY = 1 days;      // Delay before voting starts
    uint256 public constant VOTING_PERIOD = 7 days;     // Voting duration
    uint256 public constant TIMELOCK_DELAY = 2 days;    // Delay before execution
    uint256 public constant PROPOSAL_THRESHOLD = 1e18;  // Min tokens to propose
    
    mapping(uint256 => Proposal) public proposals;
    
    function propose(address target, bytes calldata data) external returns (uint256) {
        require(
            governanceToken.getPastVotes(msg.sender, block.number - 1) >= PROPOSAL_THRESHOLD,
            "Below threshold"
        );
        
        uint256 proposalId = hashProposal(target, data, block.number);
        Proposal storage p = proposals[proposalId];
        
        // SECURE: Snapshot taken at proposal creation, not vote time
        p.snapshotBlock = block.number;
        p.votingStarts = block.timestamp + VOTING_DELAY;
        p.votingEnds = p.votingStarts + VOTING_PERIOD;
        p.target = target;
        p.data = data;
        
        return proposalId;
    }
    
    function vote(uint256 proposalId, bool support) external {
        Proposal storage p = proposals[proposalId];
        require(block.timestamp >= p.votingStarts, "Voting not started");
        require(block.timestamp <= p.votingEnds, "Voting ended");
        
        // SECURE: Uses historical voting power from snapshot
        uint256 votes = governanceToken.getPastVotes(msg.sender, p.snapshotBlock);
        require(votes > 0, "No voting power");
        require(!p.hasVoted[msg.sender], "Already voted");
        
        p.hasVoted[msg.sender] = true;
        p.votes[support] += votes;
    }
    
    function queue(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(block.timestamp > p.votingEnds, "Voting not ended");
        require(_quorumReached(proposalId), "Quorum not reached");
        require(p.votes[true] > p.votes[false], "Proposal defeated");
        
        // SECURE: Add to timelock queue
        p.executionTime = block.timestamp + TIMELOCK_DELAY;
        p.queued = true;
    }
    
    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(p.queued, "Not queued");
        require(block.timestamp >= p.executionTime, "Timelock not expired");
        require(!p.executed, "Already executed");
        
        p.executed = true;
        (bool success, ) = p.target.call(p.data);
        require(success, "Execution failed");
    }
}
```

## Real Examples

### Beanstalk ($182M - April 2022)
- **Attack**: Flash loaned $1B in stablecoins via Aave
- **Method**: Bought STALK governance tokens, achieved 67% voting power
- **Exploit**: Passed BIP-18 to drain all $182M in collateral
- **Root cause**: Immediate execution after supermajority vote
- **Reference**: https://www.rekt.news/beanstalk-rekt/

### Build Finance ($470K - February 2022)
- **Attack**: Flash loan to acquire BUILD governance tokens
- **Method**: Proposed and executed malicious treasury drain
- **Root cause**: No timelock on governance execution
- **Reference**: https://www.rekt.news/build-finance-rekt/

### Fortress Protocol ($3M - May 2022)
- **Attack**: Combined oracle manipulation with governance
- **Method**: Manipulated price feed to inflate collateral value
- **Root cause**: Governance controlled oracle address without timelock
- **Reference**: https://www.certik.com/resources/blog/fortress-protocol

## Additional Mitigations

1. **Timelocks are mandatory**: Minimum 24-48h between proposal passing and execution
2. **Snapshot before proposal**: Voting power determined before proposal exists
3. **Vote-escrowed tokens**: Require token lock-up for voting power (veTokens)
4. **Quorum based on total supply**: Not just participating votes
5. **Proposal threshold**: Require minimum token stake to create proposals
6. **Guardian/veto powers**: Multisig can cancel malicious proposals during timelock
7. **Rate limiting**: Maximum number of proposals per address per time period
8. **Quadratic voting**: Reduces plutocratic control by large holders
