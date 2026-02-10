# SSRF in Web3 Infrastructure — Off-Chain Attack Surfaces

**Category:** SSRF  
**Severity:** Critical  
**CWE:** CWE-918  
**Last Updated:** 2026-02-03  
**Author:** Ghost 👻

---

## Why Web3 Is Uniquely Vulnerable to SSRF

While smart contracts are immutable on-chain, the off-chain infrastructure supporting Web3 projects is riddled with classic Web2 attack surfaces. According to Immunefi, **>60% of all Web3 exploits in 2023 targeted off-chain systems**.

Most Web3 applications rely on centralized infrastructure for:
- Transaction broadcasting (relayers)
- Gas estimation APIs
- NFT metadata retrieval
- Price feed aggregation (oracles)
- User authentication
- Analytics and indexing

These systems introduce SSRF vectors because they frequently **fetch URLs provided by users or stored on-chain**.

---

## Attack Surfaces in Web3

### 1. NFT Metadata Fetchers
**How it works:** NFT platforms fetch metadata from token URIs stored on-chain. If the metadata service accepts arbitrary URLs:

```javascript
// Vulnerable: fetches any URL from token metadata
app.post("/fetch-metadata", async (req, res) => {
  const url = req.body.url;
  const response = await axios.get(url); // SSRF
  res.send(response.data);
});
```

**Attack:** Set token URI to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` → platform's backend fetches AWS credentials when rendering your NFT.

**Affected:** NFT marketplaces, portfolio trackers, wallet UIs that render metadata.

### 2. Oracle/Price Feed Services
**How it works:** Oracles fetch price data from configurable API endpoints. If an oracle allows user-configurable data sources:

**Attack:** Submit malicious data source URL → oracle backend makes request to internal infrastructure.

**Impact:** Access to signing keys, manipulation of price feeds, DoS on oracle service.

### 3. Relayer Services
**How it works:** Relayers accept signed transactions and broadcast them. Many relayers have admin APIs, health checks, or configuration endpoints running internally.

**Attack flow:**
```
SSRF → http://127.0.0.1:3000/admin/config → reveals signing key configuration
SSRF → http://127.0.0.1:3000/admin/keys → may expose hot wallet private keys
```

**Impact:** Direct theft if signing keys are accessible internally.

### 4. Bridge Validators
**How it works:** Cross-chain bridges rely on validator nodes that listen for events on one chain and submit proofs to another. These validators often run on cloud infrastructure with multiple internal services.

**Attack:**
```
SSRF → cloud metadata → IAM credentials → access to validator key storage (KMS/Secrets Manager)
```

**Real-World Parallel:** The Orbit Chain bridge hack investigation suggested that **validator infrastructure compromise** (not smart contract exploit) was the likely attack vector. A server-side application security flaw in the bridge frontend or similar dApp may have allowed attackers to target validator APIs through downstream components. (NetSpi analysis, 2024)

### 5. Indexing/Subgraph Services
**How it works:** The Graph and custom indexers process blockchain events and serve them via GraphQL APIs. Many run internal admin endpoints.

**Attack:** If the indexer has a webhook/notification feature or URL-based data source configuration → SSRF to internal services.

### 6. Wallet Backend APIs
**How it works:** Custodial wallets and wallet-as-a-service providers have backend APIs for transaction signing, balance checks, and user management.

**SSRF Targets:**
- Key management services (HashiCorp Vault, AWS KMS)
- Internal transaction signing APIs
- User database with wallet mappings

---

## Detection Methodology for Web3 Targets

### Recon Phase
1. **Identify off-chain components:**
   - Check for API endpoints in dApp JavaScript source
   - Look for `api.`, `backend.`, `relayer.`, `indexer.` subdomains
   - Check for WebSocket connections to backend services
   
2. **Map data flow:**
   - Where does the dApp fetch external data?
   - What user inputs eventually become server-side HTTP requests?
   - Does the platform render NFT metadata from arbitrary URIs?

3. **Cloud provider identification:**
   - DNS records → AWS/GCP/Azure IP ranges
   - Response headers (`X-Amzn-*`, `server: nginx` on CloudFront, etc.)
   - SSL certificate details

### Testing Phase
4. **Test all URL-accepting parameters:**
   - Metadata fetch endpoints
   - Webhook configuration
   - Image/avatar upload via URL
   - Import/export features
   - API proxy endpoints

5. **SSRF payload progression:**
   ```
   http://127.0.0.1:80          → Basic SSRF
   http://169.254.169.254/      → Cloud metadata
   file:///etc/passwd           → File read
   gopher://127.0.0.1:6379/    → Internal service interaction
   http://[::1]:8545/           → RPC node (IPv6 bypass)
   ```

---

## Hardened Code Example

```javascript
const { URL } = require('url');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

const ALLOWED_DOMAINS = ["api.coingecko.com", "arweave.net", "ipfs.io"];
const BLOCKED_RANGES = ["private", "loopback", "linkLocal", "uniqueLocal"];

async function safeFetch(userUrl) {
  // 1. Parse and validate URL
  const parsed = new URL(userUrl);
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Invalid protocol");
  }
  
  // 2. Domain allowlist (strictest)
  if (!ALLOWED_DOMAINS.includes(parsed.hostname)) {
    throw new Error("Domain not allowed");
  }
  
  // 3. DNS resolution check (anti-rebinding)
  const addresses = await dns.resolve4(parsed.hostname);
  for (const addr of addresses) {
    const ip = ipaddr.parse(addr);
    if (BLOCKED_RANGES.some(r => ip.range() === r)) {
      throw new Error("Internal IP not allowed");
    }
  }
  
  // 4. Fetch with timeout and size limit
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 5000);
  return fetch(userUrl, { signal: controller.signal });
}
```

---

## Key Statistics

- **60%+** of Web3 exploits target off-chain systems (Immunefi, 2023)
- **$1.8B** stolen in 2023 from cyberattacks on Web3 (Chainalysis)
- Bridge hacks account for **~50%** of total DeFi losses
- Most bridge attacks exploited **infrastructure**, not smart contracts

---

## Zealynx Pentest Methodology Addition

When auditing a Web3 project, always include:

1. **Off-chain infrastructure mapping** — What servers support the protocol?
2. **SSRF testing on all URL-accepting endpoints** — metadata fetchers, webhooks, imports
3. **Cloud metadata probing** — Especially on AWS/GCP-hosted backends
4. **Internal service enumeration** — RPC nodes, signers, key stores via SSRF
5. **Validator/relayer infrastructure** — Separate network assessment if in scope

**Pitch to clients:** "Your smart contracts are audited, but is your infrastructure? Most bridge hacks exploited servers, not code. We check both."

---

## References

- BlockApex (2025) — "The Hidden Threats of Web2 Vulnerabilities in Web3 Systems"
- NetSpi (2024) — "Web2 Bugs in Web3 Systems" (Dappnode 0-days, Orbit Chain analysis)
- CertiK — "Web2 Meets Web3: Hacking Decentralized Applications"
- IntrovertMac (2025) — "Web Application Security in Web3: SSRF and IDOR"
- Immunefi (2023) — "Top 10 Most Common Vulnerabilities in Web3"
