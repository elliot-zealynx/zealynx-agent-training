# Web2 Shadow Audit Performance

| Date | Target | Type | Issues Found | Issues Missed | Precision | Recall | Key Lessons |
|------|--------|------|-------------|---------------|-----------|--------|-------------|
| 2026-02-04 | CVE-2025-29927 (Next.js Middleware Bypass) | Open-Source CVE | 6 (core vuln, missing filter, MAX_RECURSION_DEPTH, predictable name, no HMAC, auth bypass) | 4 (CSP bypass, cache-poisoning DoS, src/middleware variant, legacy _middleware paths) | 100% | 60% | Enumerate ALL bypass consequences (not just auth); check alt project structures; consider cache-poisoning as 2nd-order effect |
| 2026-02-03 | Immunefi Platform | Passive Recon (no published findings to compare) | 8 potential issues | N/A (no published findings) | N/A | N/A | Need active testing tools; "eat your own dog food" technique |
| 2026-02-05 | CVE-2025-55182 (React2Shell - React Server Components RCE) | Open-Source CVE | 0 core (3 tangential) | 6 (full 4-stage gadget chain: $@ raw chunk, self-ref loop, .then hijack, $B blob gadget, Function constructor, pre-auth) | 0% | 0% | Think in gadget chains not individual vulns; trace type handlers to raw return values; map all paths to Function constructor; check compiled output vs source; self-referencing data = internal state exposure |
| 2026-02-07 | CVE-2024-34351 (Next.js Server Actions SSRF) | Open-Source CVE | 1 (Host header SSRF via redirect URL construction) | 0 | 100% | 100% | Apply SSRF patterns to framework redirects; examine framework internals for precise vulnerable functions; consider environment variable mitigations |
| 2026-02-08 | CVE-2024-38983 (mini-deep-assign Prototype Pollution) | Open-Source CVE | 1 (critical prototype pollution via __proto__ assignment) | 0 | 100% | 100% | Pattern recognition excellent for for...in + object assignment; develop working PoCs during audit phase |

## Session Notes

### 2026-02-04 — CVE-2025-29927 Shadow Audit (FIRST PROPER SHADOW AUDIT)
- **Approach:** Blind source code review of Next.js v15.2.2 → compare with published CVE writeups
- **Duration:** ~50 min
- **Target type:** Open-Source Project CVE (category C from target selection)
- **Core finding:** Fully identified the `x-middleware-subrequest` header bypass mechanism, missing INTERNAL_HEADERS filter, MAX_RECURSION_DEPTH exploitation, and absence of cryptographic binding
- **Key misses:** Didn't enumerate all middleware functions (missed CSP bypass), didn't consider CDN caching effects (missed cache-poisoning DoS), didn't check `/src` directory alternative
- **New patterns documented:** "Internal Header Trust Boundary Bypass", "Bypass Impact Enumeration Checklist"
- **Verdict:** Strong on core vulnerability identification, weak on impact enumeration and variant discovery
- **Improvement plan:** Create a standard "bypass impact checklist" to run through every time a security bypass is found
- **Sources compared against:** ProjectDiscovery blog, Datadog Security Labs, zhero's original research, fix commit 52a078d

### 2026-02-05 — CVE-2025-55182 React2Shell Shadow Audit (HUMBLING)
- **Approach:** Blind source code review of React v19.1.0 server deserialization code -> compare with published writeups
- **Duration:** ~55 min
- **Target type:** Open-Source Project CVE (category C + category E)
- **Core failure:** Completely missed the actual exploit chain. Found tangential concerns (prototype pollution, server ref invocation) but not the 4-stage gadget chain that chains $@ raw chunk exposure -> self-reference -> .then hijack -> $B blob handler -> Function constructor -> RCE
- **Key insight:** I was auditing with a "traditional web vuln" mindset (looking for injection, prototype pollution, auth bypass). The actual vulnerability required "deserialization gadget chain" thinking, similar to Java ysoserial. I need to adopt this methodology for JavaScript deserializers.
- **Critical misses:**
  1. I SAW the `$@` handler returning raw Chunk objects but didn't recognize the significance
  2. Never considered circular/self-referencing chunks as an attack vector
  3. Didn't trace Chunk's inheritance from Promise.prototype (giving it `.then`)
  4. Didn't think about `.then -> .constructor -> Function` as an RCE chain
  5. Didn't check compiled output vs source (source had safe pattern, compiled may not)
- **New patterns documented:** 2 new methodology files in `/knowledge/web2/react-flight-deserialization/`
- **Verdict:** Major gap in gadget chain thinking. Need to develop JS deserialization audit methodology.
- **Improvement plan:** 
  1. Create standard "JS deserializer audit checklist" (done)
  2. Study Java ysoserial patterns and apply to JS frameworks
  3. Always map: type handlers -> return types -> accessible properties -> paths to Function
  4. Always verify compiled output, not just source
- **Sources compared against:** React.dev blog, Trend Micro analysis, Wiz blog, GitHub advisories

### 2026-02-03 — Immunefi Shadow Pentest
- **Approach:** Passive reconnaissance only (no active testing)
- **Duration:** ~45 min
- **Top 3 findings by realism:** Markdown XSS (#1), IDOR on reports (#3), SSRF (#2)
- **Novel pattern:** "Eat your own dog food" — using target's own published vulnerability guides as an attack checklist
- **Gap identified:** Need Burp Suite / ZAP for active testing; passive-only limits confidence
- **Avg finding score:** 8.9/13 — strong for passive-only
- **Key insight for Zealynx:** Immunefi's "60%+ off-chain exploits" stat validates our Web2+Web3 pitch

### 2026-02-07 — CVE-2024-34351 Shadow Audit (STRONG RECOVERY)
- **Approach:** Blind source code review of Next.js v14.1.0 vulnerable app → compare with Assetnote research + GitHub advisory
- **Duration:** ~50 min
- **Target type:** Open-Source Project CVE (category C from target selection)  
- **Core finding:** Correctly identified Host header SSRF attack vector in Server Action redirects. Predicted that Next.js uses Host header to construct absolute URLs for relative redirects, leading to server-side fetch to attacker-controlled domains.
- **Key strength:** Strong pattern recognition applying SSRF methodology to framework context. Correctly focused on Host header manipulation and server-side redirect processing.
- **Minor gaps:** Didn't identify the specific vulnerable function (`createRedirectRenderResult`) or consider environment variable mitigations (`__NEXT_PRIVATE_HOST`)
- **New pattern reinforced:** "Framework Header Trust" - modern frameworks often trust HTTP headers for internal URL construction, making them vulnerable to header injection attacks
- **Verdict:** Excellent core vulnerability identification with perfect precision and recall. Good application of existing SSRF knowledge to new context.
- **Performance trend:** Bouncing back strong after React2Shell humbling. This shows SSRF methodology is solid; need to develop gadget chain thinking for complex deserialization attacks.
- **Sources compared against:** Assetnote advisory, GitHub GHSA-fr5h-rqp8-mj6g, Next.js fix commit 8f7a6ca

### 2026-02-08 — CVE-2024-38983 Shadow Audit (EXCELLENT PERFORMANCE)
- **Approach:** Blind source code review of mini-deep-assign v0.0.8 → compare with CVE-2024-38983 details
- **Duration:** ~35 min
- **Target type:** Open-Source Project CVE (category A - HackerOne disclosed reports)
- **Core finding:** Correctly identified prototype pollution vulnerability in `_assign()` function via `__proto__` property assignment during recursive object copying. Exact match with published CVE.
- **Key strengths:** 
  1. Immediate pattern recognition of dangerous `for...in` + direct property assignment
  2. Accurate attack vector analysis tracing payload to prototype pollution
  3. Comprehensive impact assessment (DoS, RCE, auth bypass)
  4. Correct identification of recursive assignment vulnerability
- **Perfect execution:** 100% recall, 100% precision on critical findings, accurate severity assessment
- **New patterns reinforced:** "Recursive Object Assignment Without Property Validation" - any library that recursively copies object properties without validating property names is vulnerable to prototype pollution
- **Methodology validation:** Strong pattern recognition for prototype pollution attacks. Approach of analyzing execution flow from user input to dangerous operations was highly effective.
- **Verdict:** Textbook perfect shadow audit. Demonstrates mastery of prototype pollution vulnerability patterns.
- **Performance trend:** Back-to-back excellent performances (SSRF + Prototype Pollution). Shows methodology is solid for well-understood vulnerability classes.
- **Sources compared against:** GitHub gist CVE writeup, mini-deep-assign repository v0.0.8
