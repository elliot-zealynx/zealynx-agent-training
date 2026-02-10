# Pattern: Internal Header Trust Boundary Bypass (Next.js Case Study)

## CVE Reference
**CVE-2025-29927** — Next.js Middleware Authorization Bypass
**CVSS:** 9.1 (Critical)
**Affected:** Next.js 11.1.4 through 15.2.2

## Pattern Description
Frameworks use internal HTTP headers for inter-component communication (loop prevention, routing signals, request metadata). When these headers:
1. Are NOT stripped from external requests on ingress
2. Control security-critical decisions (skip middleware, bypass auth)
3. Have predictable values

...an external attacker can forge them to bypass security controls entirely.

## Vulnerable Code Pattern
```typescript
// DANGEROUS: Trusting request header for security decision
const subreq = params.request.headers['x-internal-header']
if (subreq === expectedValue) {
    // SKIP SECURITY CHECKS
    return NextResponse.next()
}
```

## Next.js Specific Details

### How It Worked
1. `x-middleware-subrequest` header was intended to prevent infinite middleware loops
2. Header was NOT in the `INTERNAL_HEADERS` filter list (oversight)
3. Header value was a predictable colon-separated list of middleware names
4. Setting `depth >= MAX_RECURSION_DEPTH (5)` caused middleware to skip entirely

### Exploitation by Version
| Version Range | Payload |
|---------------|---------|
| < 12.2 | `x-middleware-subrequest: pages/_middleware` |
| 12.2 – 13.1 | `x-middleware-subrequest: middleware` or `src/middleware` |
| 13.2+ (with MAX_RECURSION_DEPTH) | `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` |

### Don't Forget: `/src` Directory
Next.js supports a `/src` directory structure. Always test BOTH:
- `middleware` (standard)
- `src/middleware` (src directory structure)

### Impact Categories
1. **Authorization Bypass** — Access protected routes without auth
2. **CSP Bypass** — Remove Content-Security-Policy headers → enable XSS
3. **Cache-Poisoning DoS** — Bypassed rewrites → 404 cached by CDN → pages inaccessible

### The Fix (commit 52a078d)
Added cryptographic binding: random `x-middleware-subrequest-id` nonce generated per server session. External requests without matching ID get `x-middleware-subrequest` stripped.

## Audit Methodology

### Step 1: Identify Internal Headers
Search codebase for:
- `x-*` headers set internally
- Headers used in if/switch conditions for routing/auth decisions
- Headers propagated in subrequests

### Step 2: Check Ingress Filtering
- Are internal headers stripped from external requests?
- Is there a centralized header filter? Does it cover ALL internal headers?
- Is there an allowlist or blocklist approach?

### Step 3: Check for Cryptographic Binding
- Is the header value predictable?
- Is there HMAC/nonce validation?
- Can an external attacker forge the expected value?

### Step 4: Trace Security Impact
If bypass is possible, enumerate ALL consequences:
- [ ] Authentication bypass
- [ ] Authorization bypass
- [ ] Security header bypass (CSP, CORS, HSTS)
- [ ] Path rewrite/redirect bypass
- [ ] Rate limiting bypass
- [ ] Cache behavior change → CDN poisoning
- [ ] Logging/monitoring evasion

## Similar Patterns in Other Frameworks
- **Express/Koa:** Trust-proxy misconfigurations (X-Forwarded-For spoofing)
- **AWS ALB/API Gateway:** Custom headers from upstream trusted without validation
- **Cloudflare Workers:** Internal routing headers
- **Nginx:** $http_x_* variables trusted from clients when only expected from upstream

## Real-World Exploitation (Datadog Observations)
- Low but active scanning observed post-disclosure
- Payloads: `middleware`, `src/middleware`, `pages/_middleware`, and the 5x repeated variant
- Self-hosted Next.js apps most vulnerable (Vercel auto-mitigates)

## Key Takeaway
**Never trust HTTP headers from external requests for security decisions unless cryptographically validated.** Internal headers must be either:
1. Stripped at the edge/ingress layer, OR
2. Signed with a server-side secret that external clients can't forge
