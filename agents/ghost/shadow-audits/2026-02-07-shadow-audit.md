# Shadow Audit - CVE-2024-34351 (Next.js Server Actions SSRF)

**Date:** 2026-02-07  
**Target:** CVE-2024-34351 - Next.js Server Actions SSRF  
**Type:** Open-Source Project CVE (Category C)  
**Version Audited:** Next.js 14.1.0  
**Duration:** ~50 minutes  

## Target Application

Simple Next.js app with Server Action:
```typescript
'use server'
import { redirect } from "next/navigation";

export async function create() {
  console.log('Server Side')
  return redirect("/?voorivex");
}
```

## Blind Audit Results

### Issues Found (Blind Analysis)

**Primary Finding: Host Header SSRF in Server Action Redirects**
- **Severity:** High  
- **Attack Vector:** Host header manipulation  
- **Hypothesis:** Next.js uses Host header to construct absolute URLs for relative redirects
- **Impact:** Server-side request forgery to arbitrary hosts/internal services
- **PoC:** Set `Host: evil.com` → `redirect("/?voorivex")` becomes `https://evil.com/?voorivex`
- **Assumptions:** Next.js must process redirect server-side and fetch the URL

**Secondary Concerns:**
- Origin header manipulation might also work
- No input validation on redirect parameter (though hardcoded in this case)

### Methodology Applied

✅ **SSRF Pattern Recognition:** Applied knowledge from `/knowledge/web2/ssrf/01-basic-ssrf-internal-access.md`  
✅ **Header Injection Analysis:** Considered Host, Origin header manipulation vectors  
✅ **Server-Side Processing Logic:** Analyzed how Next.js might process Server Actions  
❌ **Code Path Analysis:** Did not dive into Next.js source to find specific vulnerable function  

## Published Findings Comparison

### Actual Vulnerability (CVE-2024-34351)

**Root Cause:** In `createRedirectRenderResult` function:
```javascript
// VULNERABLE CODE (v14.1.0)
const host = originalHost.value  // Uses Host header directly
const fetchUrl = new URL(`${proto}://${host}${basePath}${parsedRedirectUrl.pathname}`)
// Makes server-side fetch to this URL
```

**Attack Flow:**
1. Attacker sends Server Action request with malicious `Host: evil.com`
2. Server Action calls `redirect("/?voorivex")`  
3. Next.js enters `createRedirectRenderResult` function
4. Constructs fetch URL using Host header: `https://evil.com/?voorivex`
5. Makes server-side request to attacker-controlled domain
6. Returns response content to attacker

**Fix (v14.1.1):**
```javascript
// FIXED CODE
const host = process.env.__NEXT_PRIVATE_HOST || originalHost.value
```

## Scoring

| Metric | Score | Notes |
|--------|-------|--------|
| **Core Vulnerability Identified** | ✅ 100% | Correctly identified Host header SSRF attack vector |
| **Attack Vector Accuracy** | ✅ 100% | Correctly predicted Host header → URL construction → SSRF |
| **Impact Assessment** | ✅ 100% | Correctly assessed as server-side request forgery |
| **Root Cause Analysis** | ❌ 30% | Identified general mechanism but missed specific code path |
| **Prerequisites Understanding** | ✅ 80% | Understood server-side processing requirement |

### Final Score
- **Precision:** 100% (1/1 core findings correct, 0 false positives)
- **Recall:** 100% (1/1 published finding identified)  
- **Code Analysis Depth:** 30% (surface-level understanding, missed implementation details)

## Key Lessons

### ✅ Strengths
1. **Pattern Recognition:** Successfully applied SSRF knowledge to Server Actions context
2. **Header Analysis:** Correctly focused on Host header as attack vector
3. **Server-Side Logic:** Understood that redirects would be processed server-side

### ❌ Gaps to Address
1. **Source Code Analysis:** Need to dive deeper into framework internals for precise root cause
2. **Function-Level Auditing:** Should identify specific vulnerable functions, not just general mechanisms
3. **Environment Variable Considerations:** Missed potential mitigations like `__NEXT_PRIVATE_HOST`

### 🎯 Improvement Actions
1. When auditing framework vulnerabilities, examine the actual framework source code
2. Look for specific functions handling URL construction/redirection
3. Consider internal configuration variables that might affect security behavior
4. Build mental model of complete request flow, not just surface interactions

## Notable Patterns Documented

This audit reinforced the **"Framework Header Trust"** antipattern:
- Modern frameworks often trust HTTP headers for internal URL construction
- Host header injection remains a critical attack vector in server-side operations
- Relative URL redirects are particularly vulnerable when frameworks auto-construct absolute URLs

Updated methodology: Always examine how frameworks handle relative URLs and what headers they trust for absolute URL construction.