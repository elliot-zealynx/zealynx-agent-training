# Web3 Blind Message Authentication Attack

**Category:** Web3 Authentication / Wallet Signature Bypass
**Severity:** Critical
**CVEs:** CVE-2023-50053, CVE-2023-50059
**Last Updated:** 2026-02-04

## Attack Description

Blind Message Attacks exploit the fundamental weakness in Web3 authentication: **users cannot verify the origin of the message they're signing**. A malicious dApp A can present a signing message originally from legitimate dApp B, and because users typically reuse the same wallet address across applications, the attacker obtains a valid authentication signature for dApp B.

This attack targets the SIWE (Sign-In With Ethereum) and similar wallet-based authentication flows. Research from CCS 2024 found that **75.8% of tested Web3 authentication deployments** were vulnerable.

## Prerequisites

- Target dApp uses wallet signature authentication (SIWE or custom)
- Target dApp's signing message is predictable or replayable
- Victim uses the same wallet address on both the malicious and target dApp
- Target's message lacks origin binding or proper nonce validation

## Attack Taxonomy

### 1. Basic Blind Message Attack
Malicious dApp requests signature on a message crafted by/for target dApp.

### 2. Replay Attack
Captured or expired signatures remain valid indefinitely — session mechanism ineffective.

### 3. Blind Multi-Message Attack
Single interaction harvests auth signatures for multiple target dApps simultaneously.

## Exploitation Steps

### Step 1: Reconnaissance
Identify the target dApp's authentication message format:
```
# Typical SIWE message format
example.com wants you to sign in with your Ethereum account:
0x742d35Cc6634C0532925a3b844Bc9e7595f3aA00

Statement: Sign in to Example DApp

URI: https://example.com
Version: 1
Chain ID: 1
Nonce: abc123xyz
Issued At: 2026-02-04T12:00:00Z
```

### Step 2: Analyze Weaknesses
Check the message for missing security fields:
- **Nonce:** Is it server-generated and single-use? Or client-generated/static?
- **Domain binding:** Does the message specify `URI` and is it verified server-side?
- **Expiration:** Is `Issued At` or `Expiration Time` checked?
- **Chain ID:** Is it validated?

### Step 3: Build Malicious dApp
Create an application that:
1. Fetches a valid nonce/message from the **target** dApp's API
2. Presents this message to the victim for signing (disguised in your UX)
3. Captures the wallet signature
4. Relays signature to target dApp's auth endpoint

### Step 4: Execute Attack
```javascript
// Attacker's malicious dApp (simplified)
async function attack(victimAddress) {
  // 1. Get nonce from target
  const nonceResp = await fetch('https://target-defi.com/api/auth/nonce', {
    method: 'POST',
    body: JSON.stringify({ address: victimAddress })
  });
  const { nonce, message } = await nonceResp.json();

  // 2. Present message for signing (user thinks it's for our dApp)
  const signature = await ethereum.request({
    method: 'personal_sign',
    params: [message, victimAddress]
  });

  // 3. Authenticate on target with stolen signature
  const authResp = await fetch('https://target-defi.com/api/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ address: victimAddress, signature, nonce })
  });
  // Now we have target's session token
  const { sessionToken } = await authResp.json();
}
```

### Step 5: Access Target Account
Use the session token to access victim's account on the target dApp.

## Vulnerability Patterns Identified (CCS 2024 Research)

| Vulnerability | Prevalence | Impact |
|--------------|-----------|---------|
| No domain binding in message | 68% of tested dApps | Signature reusable across dApps |
| Static or predictable nonce | 41% | Replay attacks possible |
| No expiration checking | 55% | Old signatures valid indefinitely |
| Client-side nonce generation | 31% | Attacker controls nonce |
| Missing SIWE standard compliance | 45% | Multiple bypass vectors |

## Detection Method

### As a Pentester (Web3AuthChecker approach)
1. **Inspect auth API endpoints:** GET nonce → POST verify flow
2. **Check message format:** Does it include URI, domain, nonce, expiration?
3. **Cross-origin test:** Request nonce from one origin, submit signature from another
4. **Replay test:** Reuse a previously valid signature — does it still work?
5. **Nonce analysis:** Are nonces random? Server-generated? Single-use?
6. **Chain ID verification:** Submit signature with wrong chain ID

### As a Defender
- Implement Web3AuthGuard-style checks in wallet extensions
- Monitor for authentication requests from unusual origins
- Rate-limit nonce generation per address

## Remediation

### Implement Full SIWE Standard (EIP-4361)
```javascript
// Server-side verification (Node.js with siwe library)
import { SiweMessage } from 'siwe';

async function verifyAuth(message, signature) {
  const siweMessage = new SiweMessage(message);
  const fields = await siweMessage.verify({
    signature,
    domain: 'yourdapp.com',     // MUST match your domain
    nonce: serverGeneratedNonce,  // MUST be server-generated, single-use
  });
  
  // Additional checks
  if (fields.data.expirationTime < new Date()) throw new Error('Expired');
  if (fields.data.chainId !== expectedChainId) throw new Error('Wrong chain');
  
  // Consume nonce (single-use)
  await consumeNonce(fields.data.nonce);
}
```

### Key Mitigations
1. **Domain binding** — message MUST include `URI` matching your domain, verified server-side
2. **Server-generated nonces** — cryptographically random, single-use, short-lived
3. **Expiration enforcement** — `Issued At` + `Expiration Time` with tight windows (5 min)
4. **Chain ID validation** — prevent cross-chain replay
5. **SIWE standard compliance** — follow EIP-4361 exactly
6. **Origin validation** — verify request origin matches expected domain

## Real-World Examples

### 1. Web3AuthChecker Study (CCS 2024)
- **Scope:** 29 Web3 authentication implementations across 27 websites
- **Finding:** 75.8% (22/29) vulnerable to blind message attacks
- **Categories:** NFT marketplaces, games, DeFi, services
- **Volume at risk:** $592M+ monthly transaction volume, 1.29M+ active wallets
- **CVEs assigned:** CVE-2023-50053, CVE-2023-50059

### 2. Replay Attack Variant
- **Finding:** 11/29 cases vulnerable to replay attacks
- **Pattern:** Old signatures accepted indefinitely, no nonce consumption

### 3. Multi-Message Attack Variant
- **Finding:** 7/29 cases vulnerable to multi-message attacks
- **Pattern:** Single user interaction yields auth for multiple target platforms

### 4. LearnBlockchain — Acknowledged and Fixed
- One of the 27 tested sites
- Acknowledged vulnerability and patched authentication flow

## Impact in Web3

The consequences of blind message attacks in Web3 are severe because:
- **Financial:** Direct access to user's DeFi positions, trading accounts, NFT collections
- **Identity:** Impersonation on social Web3 platforms
- **Governance:** Vote manipulation in DAOs using wallet-based auth
- **Data:** Access to private portfolio data, transaction history
- **Cross-platform:** One compromised signature can cascade across multiple dApps

## Testing Tool

**Web3AuthChecker** (from the research paper):
- Bypasses frontend, tests backend API directly
- Sends crafted requests to auth endpoints
- Checks for nonce handling, domain binding, replay vulnerabilities
- Two modules: Checker (attack payloads) + FlexRequest (HTTP library)

## References

- CCS 2024 Paper: "Stealing Trust: Unraveling Blind Message Attacks in Web3 Authentication" - https://arxiv.org/html/2406.00523v3
- EIP-4361 (SIWE Standard): https://eips.ethereum.org/EIPS/eip-4361
- SIWE Library: https://github.com/spruceid/siwe
- CVE-2023-50053 & CVE-2023-50059
- Markaicode SIWE Best Practices 2025: https://markaicode.com/siwe-best-practices-2025/
