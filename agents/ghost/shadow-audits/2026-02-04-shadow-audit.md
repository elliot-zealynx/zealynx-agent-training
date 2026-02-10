# Ghost 👻 — Shadow Audit Report — 2026-02-04

## Target: CVE-2025-29927 — Next.js Middleware Authorization Bypass
**Framework:** Next.js v15.2.2 (cloned from GitHub)
**CVE:** CVE-2025-29927 (CVSS 9.1 Critical)
**Original Researcher:** Rachid Allam (zhero) & Yasser Allam (inzo_)
**Published:** March 21, 2025
**Approach:** Blind source code audit → compare with published findings
**Duration:** ~50 minutes

---

## Phase 1: Blind Audit (Before Reading Writeups)

### Starting Knowledge
- CVE ID and category: "middleware authorization bypass"
- Header name: `x-middleware-subrequest` is involved
- Affected versions: 11.1.4 through 15.2.2
- **DID NOT KNOW:** Exact mechanism, exploitation payloads, impact categories, fix details

### Files Analyzed
1. `packages/next/src/server/web/sandbox/sandbox.ts` — Core middleware execution
2. `packages/next/src/server/web/sandbox/context.ts` — Sandbox context + fetch polyfill
3. `packages/next/src/server/lib/server-ipc/utils.ts` — Internal header filtering
4. `packages/next/src/server/next-server.ts` — Middleware runner orchestration
5. `packages/next/src/server/lib/router-utils/resolve-routes.ts` — Route resolution

### Finding B1: External Control of Internal Recursion Header (CRITICAL)
**Severity:** Critical
**Location:** `sandbox.ts` lines 96-110, `server-ipc/utils.ts` lines 42-59

**Analysis:**
In `sandbox.ts`, the middleware runner reads `x-middleware-subrequest` directly from incoming request headers:
```typescript
const subreq = params.request.headers[`x-middleware-subrequest`]
const subrequests = typeof subreq === 'string' ? subreq.split(':') : []
const MAX_RECURSION_DEPTH = 5
const depth = subrequests.reduce(
    (acc, curr) => (curr === params.name ? acc + 1 : acc), 0
)
if (depth >= MAX_RECURSION_DEPTH) {
    return { response: new Response(null, { headers: { 'x-middleware-next': '1' } }) }
}
```

**Root cause:** The `INTERNAL_HEADERS` list in `server-ipc/utils.ts` filters:
- `x-middleware-rewrite` ✓
- `x-middleware-redirect` ✓
- `x-middleware-set-cookie` ✓
- `x-middleware-skip` ✓
- `x-middleware-override-headers` ✓
- `x-middleware-next` ✓
- **`x-middleware-subrequest` ✗ MISSING**

This means external requests can include `x-middleware-subrequest` and it passes through to the sandbox unfiltered.

### Finding B2: Middleware Bypass via Recursion Depth Spoofing (CRITICAL)
**Severity:** Critical
**Attack Vector:** Network (unauthenticated)

An attacker who knows the middleware name (typically `middleware`) sends:
```
GET /protected-route HTTP/1.1
Host: target.com
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

This causes `depth = 5 >= MAX_RECURSION_DEPTH`, making the middleware return `x-middleware-next: '1'` — completely skipping all middleware logic.

**Primary Impact:** Complete authorization bypass for any route protected by Next.js middleware.

### Finding B3: Predictable Middleware Name
**Severity:** Informational (enables B2)
**Location:** `next-server.ts` line 1607

The middleware name comes from `middlewareInfo.name` (from the middleware manifest). For standard Next.js apps with `middleware.ts` at project root, this is `middleware` — trivially guessable.

### Finding B4: No Cryptographic Binding on Internal Headers
**Severity:** Architectural Issue
**Analysis:** The `x-middleware-subrequest` header is a plain colon-separated string with no HMAC, nonce, or secret binding. There's nothing distinguishing a legitimate internal subrequest from an external attacker-crafted request.

### Finding B5: Header Propagation Amplifies Risk
**Severity:** Informational
**Location:** `context.ts` lines 363-380

The sandbox's fetch polyfill automatically propagates `x-middleware-subrequest` from incoming requests to outgoing subrequests, appending the module name. This means once the header is injected, it persists through the entire request chain.

### Finding B6: Authorization Bypass as Primary Impact
**Severity:** Critical
**Impact:** Any middleware-based auth (session cookies, JWT validation, role checks) is completely bypassed. Attacker gains direct access to protected routes.

---

## Phase 2: Published Findings Comparison

### Published Findings (from original research + advisories):

**P1: Core `x-middleware-subrequest` bypass** → ✅ I FOUND THIS
- Identified the exact mechanism: header read from external request, used to skip middleware

**P2: Missing from `INTERNAL_HEADERS` filter** → ✅ I FOUND THIS
- Explicitly traced the header filtering code and noted the omission

**P3: MAX_RECURSION_DEPTH (5 repetitions) exploit** → ✅ I FOUND THIS
- Correctly identified the `depth >= 5` condition and `x-middleware-next: '1'` skip

**P4: Predictable middleware name** → ✅ I FOUND THIS
- Traced from `pageInfo.name` in manifest

**P5: No cryptographic binding** → ✅ I FOUND THIS
- The fix (commit 52a078d) confirms this: added `x-middleware-subrequest-id` random nonce

**P6: Authorization bypass impact** → ✅ I FOUND THIS
- Identified as primary exploitation scenario

**P7: CSP bypass impact** → ❌ I MISSED THIS
- Middleware also sets Content-Security-Policy headers
- Bypassing middleware → CSP removed → enables XSS attacks
- **Why I missed:** Focused narrowly on auth, didn't enumerate all middleware functions

**P8: Cache-Poisoning DoS** → ❌ I MISSED THIS
- When middleware rewrites paths (e.g., geo-based routing) and bypass causes 404
- CDN caches the 404 → pages become unavailable
- **Why I missed:** Didn't think about second-order effects of rewrite bypass on caching layer

**P9: `src/middleware` variant** → ❌ I MISSED THIS
- Next.js supports `/src` directory structure → middleware name becomes `src/middleware`
- Doubles the possible payloads
- **Why I missed:** Didn't consider alternative project structures

**P10: Legacy `pages/_middleware` paths (pre-12.2)** → ❌ I MISSED THIS
- Older versions used `_middleware.ts` in `pages/` directory with nested routes
- Payload: `pages/_middleware`, `pages/dashboard/_middleware`, etc.
- **Why I missed:** Only analyzed v15.2.2, didn't trace version history

---

## Phase 3: Scoring

### Precision & Recall
| Metric | Value | Calculation |
|--------|-------|-------------|
| True Positives | 6 | B1-B6 all confirmed as real issues |
| False Positives | 0 | Nothing I flagged was wrong |
| False Negatives | 4 | P7 (CSP), P8 (Cache-Poison DoS), P9 (src/), P10 (legacy paths) |
| **Precision** | **100%** | 6/(6+0) = 1.00 |
| **Recall** | **60%** | 6/(6+4) = 0.60 |

### Weighted Assessment
Core vulnerability (mechanism + primary exploitation): **FULLY IDENTIFIED** ✅
Secondary impacts: **PARTIALLY MISSED** (1/3 — auth yes, CSP no, cache-poison no)
Payload variants: **PARTIALLY MISSED** (1/3 — standard yes, src/ no, legacy no)

**If scored by criticality weighting:**
- Core vuln + auth bypass (60% weight): ✅ Found → 60%
- CSP bypass (15% weight): ❌ Missed → 0%
- Cache-Poison DoS (10% weight): ❌ Missed → 0%
- Variant payloads (15% weight): ~33% found → 5%
- **Weighted Recall: ~65%**

---

## Phase 4: Key Lessons Learned

### Lesson 1: Enumerate ALL Bypass Consequences
When finding a bypass of a security component, systematically enumerate EVERYTHING it controls:
- Auth/authz checks? ✅ (I did this)
- Security headers (CSP, CORS, HSTS)? ❌ (I missed this)
- Rewrites/redirects? ❌ (I acknowledged but didn't trace impact)
- Cache control? ❌ (Didn't consider CDN layer effects)
- Rate limiting? (Not applicable here but should check)
- Logging/monitoring? (Bypass may also evade detection)

**NEW PATTERN: "Bypass Impact Enumeration Checklist"**

### Lesson 2: Check Alternative Project Structures
For framework-level vulnerabilities, ALWAYS consider:
- Standard vs. `src/` directory structure
- Monorepo configurations
- Custom configuration options that change paths
- Historical/legacy path conventions

### Lesson 3: Cache Poisoning as Second-Order Effect
Any vulnerability that changes routing/response behavior can potentially cause cache poisoning:
- Bypassed rewrite → unexpected 404/500
- CDN caches error response → DoS on legitimate pages
- **Add "CDN/cache implications?" to vulnerability impact checklist**

### Lesson 4: Cross-Version Analysis Matters
Framework CVEs often have version-specific behaviors. A thorough audit should:
- Check at least one version per major release line
- Trace how the vulnerable code evolved
- Document variant payloads per version

### Lesson 5: Fix Analysis Validates Findings
The fix (commit 52a078d) added:
1. Random `x-middleware-subrequest-id` nonce per server session
2. Validation: external requests without matching ID get `x-middleware-subrequest` stripped
3. Internal subrequests get the ID appended automatically

This confirms my Finding B4 was architecturally correct — the absence of cryptographic binding was the root cause.

---

## Phase 5: Methodology Updates

### New Pattern: Internal Header Trust Boundary
**Category:** Framework-Level Vulnerability
**CWE:** CWE-16 (Configuration), CWE-284 (Improper Access Control)
**Pattern:** Frameworks use internal headers for inter-component communication. If these headers aren't stripped from external requests AND control security decisions, complete bypass is possible.
**Audit Steps:**
1. Identify all `x-*` or custom internal headers in the framework
2. Check if they're stripped/validated on the ingress path
3. Trace what decisions they influence (auth, routing, caching)
4. Test if external requests can set them

### New Pattern: Bypass Impact Enumeration
When a security bypass is found, systematically check:
- [ ] Authentication bypass
- [ ] Authorization bypass
- [ ] Security header bypass (CSP, CORS, HSTS, X-Frame-Options)
- [ ] Path rewrite/redirect bypass
- [ ] Rate limiting bypass
- [ ] Cache behavior change → CDN poisoning potential
- [ ] Logging/monitoring evasion
- [ ] Session management bypass

### Updated: Next.js Attack Surface
Added to mental model:
- `x-middleware-subrequest` was the #1 Next.js CVE of 2025
- Self-hosted Next.js !== Vercel-hosted (Vercel auto-strips dangerous headers)
- Next.js middleware is a CRITICAL security boundary — bugs here are always Critical

---

## Files Updated
- `/root/clawd/knowledge/web2/performance-log.md` — Added shadow audit entry
- `/root/clawd/knowledge/web2/nextjs-middleware-bypass-pattern.md` — NEW pattern doc
- This report: `/root/clawd/memory/roles/web2-researcher/2026-02-04-shadow-audit.md`

---

*Ghost 👻 — First proper shadow audit with published findings comparison. 100% precision, 60% recall. Core vuln fully identified, but missed secondary impacts (CSP bypass, cache-poisoning) and variant payloads. Key gap: need to systematically enumerate ALL consequences of a bypass, not just the obvious one.*
