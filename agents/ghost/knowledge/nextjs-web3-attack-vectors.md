# Next.js Attack Vectors in Web3 Frontends

**Category:** Framework-Specific  
**Severity:** Medium–Critical  
**Last Updated:** 2026-02-03  
**Author:** Ghost 👻  
**Origin:** Immunefi shadow pentest

---

## Why Next.js Matters for Web3

Next.js (by Vercel) is the dominant frontend framework for Web3 applications:
- Immunefi, Uniswap, Aave, ENS, OpenSea — all use Next.js
- Server-Side Rendering (SSR) means sensitive data flows through the server
- API routes create backend endpoints that may lack middleware auth
- Vercel serverless deployment runs on AWS Lambda → cloud metadata accessible

---

## Attack Vectors

### 1. `_next/data` Endpoint Data Leakage

**What:** Next.js SSR pages fetch data via `/_next/data/[buildId]/[page].json`  
**Risk:** These endpoints may return server-side props containing data not shown in the UI  

```
# Find the build ID
curl https://target.com | grep buildId

# Access SSR data directly
GET /_next/data/AbCdEf123/dashboard.json
GET /_next/data/AbCdEf123/admin/users.json
```

**What to look for:**
- User data (emails, IDs, roles) in page props
- API keys or configuration leaked in server-side props
- Admin/internal data exposed to unauthenticated requests
- Private program metrics, report counts, payout data

### 2. Source Map Exposure

**What:** If `productionBrowserSourceMaps: true` in next.config.js  
**Risk:** Full client-side source code visible, revealing API endpoints, auth logic, secrets  

```
# Check for source maps
GET /_next/static/chunks/[hash].js.map
GET /_next/static/[buildId]/_ssgManifest.js.map
```

**Impact in Web3:**
- Discover hidden admin API routes
- Find hardcoded RPC URLs with API keys
- Understand wallet integration logic for transaction manipulation

### 3. API Route Authorization Bypass

**What:** Next.js API routes at `/api/*` may not use middleware consistently  
**Risk:** Some routes may skip auth checks, especially newer additions  

```
# Enumerate API routes from JS bundles
# Look for fetch('/api/...') patterns in client code

# Test common patterns
GET /api/users
GET /api/admin/stats
GET /api/reports?userId=1
POST /api/settings (without auth token)
```

**Next.js 13+ App Router risk:**
- Server Components can accidentally expose data
- `use server` functions are callable from client
- Route handlers in `app/api` may miss middleware

### 4. Middleware Bypass (CVE-2024-34351 pattern)

**What:** Next.js middleware can be bypassed via path manipulation  
**History:** CVE-2024-34351 allowed SSRF through `x-middleware-subrequest` header  

```
# If middleware does auth checks, try:
GET /admin → 401 (blocked by middleware)
GET /admin%00 → might bypass path matching
GET /_next/../admin → path traversal attempt
```

### 5. Server Action Parameter Tampering

**What:** Next.js 14+ Server Actions accept form data processed server-side  
**Risk:** Parameters can be manipulated beyond what the form UI presents  

```
# Intercept Server Action POST
POST /
Content-Type: multipart/form-data
$ACTION_ID: abc123

# Manipulate hidden fields, add extra params
amount=1000 → amount=999999
userId=myId → userId=victimId
```

### 6. ISR/SSG Cache Poisoning

**What:** Incremental Static Regeneration caches pages at the edge  
**Risk:** If cache key includes user-controllable values, one user can poison another's cache  

```
# Test with different headers
GET /page
X-Forwarded-Host: evil.com
```

---

## Web3-Specific Chains

### Chain 1: _next/data → Wallet Drain
```
1. Find _next/data leak exposing user session data
2. Extract session token or wallet address
3. Use exposed data to craft targeted phishing
```

### Chain 2: Source Map → Smart Contract Interaction Manipulation
```
1. Find exposed source maps
2. Reverse-engineer transaction building logic
3. Identify where to inject modified contract calls
4. Craft attack that changes transaction parameters (recipient, amount)
```

### Chain 3: API Route Bypass → Vault Manipulation
```
1. Find unprotected API route for vault management
2. Call route to modify vault parameters
3. Redirect bounty payouts to attacker address
```

---

## Detection Checklist for Zealynx Audits

- [ ] Check for `/_next/data/*/` endpoint data leaks
- [ ] Scan for source maps (`*.js.map` files)
- [ ] Enumerate `/api/*` routes and test auth on each
- [ ] Test middleware bypass techniques on protected routes
- [ ] Check Server Actions for parameter manipulation
- [ ] Verify ISR cache isolation between users
- [ ] Check `x-powered-by` and `x-nextjs-*` headers for version info
- [ ] Look for `__NEXT_DATA__` in page source for leaked props

---

## Remediation Guidance

1. **Disable source maps in production:** `productionBrowserSourceMaps: false`
2. **Apply middleware consistently:** Use `matcher` config to cover all protected routes
3. **Validate Server Action inputs:** Don't trust form data; validate server-side
4. **Sanitize `_next/data` responses:** Only include data the user should see
5. **Set security headers:** Remove `x-powered-by`, add CSP
6. **Cache isolation:** Include user session in cache key for personalized content

---

## References

- CVE-2024-34351 — Next.js SSRF via middleware
- Assetnote research — "Digging for SSRF in Next.js apps"
- Next.js Security Best Practices (nextjs.org/docs/app/guides/data-security)
