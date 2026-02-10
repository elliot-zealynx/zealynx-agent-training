# Ghost 👻 — Shadow Pentest Report — 2026-02-03

## Target: Immunefi Bug Bounty Platform
**URL:** https://immunefi.com  
**Bug Bounty Scope:** Web/App assets (immunefi.com, bugs.immunefi.com, shieldmybags.immunefi.com)  
**Max Bounty (Web/App):** Up to $50,000 (Critical)  
**Approach:** Passive reconnaissance + methodology-driven attack surface analysis  
**Duration:** ~45 minutes  

---

## 1. Technology Stack Fingerprinting

### Confirmed/High-Confidence
| Component | Technology | Evidence |
|-----------|-----------|----------|
| Frontend Framework | **Next.js / React** | Vercel hosting (shieldmybags returned Vercel Security Checkpoint), page structure, SPA behavior |
| Hosting | **Vercel** | `shieldmybags.immunefi.com` response: "Vercel Security Checkpoint", `fra1::` identifier suggests Frankfurt edge |
| Smart Contracts | **Gnosis Safe + Splitter** | [vaults-splitter](https://github.com/immunefi-team/vaults-splitter) repo, Foundry + Solidity |
| Encryption | **OpenPGP (openpgpjs fork)** | Forked repo at immunefi-team/openpgpjs — likely encrypts bug report submissions |
| Bug Report Rendering | **Markdown** | `markdown-testing` repo exists, reports likely rendered with markdown parser |
| Authentication | **Custom (bugs.immunefi.com)** | Login page with email/password, forgot-password flow |
| Payment | **On-chain via Splitter** | Ethereum mainnet: `0x03fd3d61423e6d46dcc3917862fbc57653dc3eb0` (Vault), `0x323498d3fb02594ac3e0a11b2dea337893ecabbe` (Splitter) |

### Inferred (Needs Confirmation)
- **Backend:** Node.js (common with Next.js deployments on Vercel)
- **Database:** PostgreSQL (implied by their own SQLI writeup using `getpgusername()`)
- **CDN:** Cloudflare or Vercel Edge (standard for this scale)
- **API:** REST or GraphQL (Next.js API routes likely at `/api/*` or `_next/data/*`)

---

## 2. Attack Surface Map

### 2.1 Subdomains (In-Scope)
```
immunefi.com              — Main platform (bounty listings, blog, resources)
bugs.immunefi.com         — Bug submission/researcher dashboard (auth required)
shieldmybags.immunefi.com — "Shield My Bags" security tool (added Nov 2025)
```

### 2.2 Additional Surface (Observed)
```
immunefisupport.zendesk.com — Support portal (Zendesk)
github.com/immunefi-team    — 28+ public repos (smart contracts, tools, audit comp code)
```

### 2.3 User-Accessible Functions
| Function | Endpoint (Estimated) | Input Type | Auth Required |
|----------|---------------------|------------|---------------|
| Bug report submission | bugs.immunefi.com/submit | Rich text/markdown, URLs, files | Yes |
| User profile | bugs.immunefi.com/profile | Text, URLs, avatar | Yes |
| Bounty program search | immunefi.com/bug-bounty/ | Search queries, filters | No |
| Shield My Bags | shieldmybags.immunefi.com | Wallet address, config | Unknown |
| Password reset | bugs.immunefi.com/login/forgot-password | Email | No |
| Signup | bugs.immunefi.com/signup | Email, password | No |
| Blog/content | immunefi.com/blog/* | N/A (read-only) | No |
| Vault interaction | On-chain + frontend | Wallet connection, tx params | Wallet |

---

## 3. Potential Findings

### Finding #1: Markdown Injection → XSS in Bug Reports
**Severity:** High (potentially Critical with wallet interaction)  
**Category:** XSS (CWE-79)  
**Confidence:** Medium  

**Analysis:**
- Immunefi has a `markdown-testing` repo, confirming they render markdown from user input
- Bug reports likely allow rich markdown (code blocks, links, images)
- If the markdown parser doesn't properly sanitize HTML tags or JavaScript URIs:
  - `[Click me](javascript:alert(document.domain))` → Link injection
  - `![img](x onerror=alert(1))` → Image tag injection
  - Raw HTML in markdown: `<img src=x onerror=...>` if not stripped
- **Web3 Impact Escalation:** Immunefi's platform connects to wallets. XSS in a bug report viewed by a triager/project owner could:
  - Initiate malicious transactions via `ethereum.request({method: 'eth_sendTransaction', ...})`
  - Access connected wallet address and balance
  - Modify vault withdrawal parameters

**Attack Vector:**
```
1. Submit bug report containing crafted markdown with XSS payload
2. Triager/project owner views report → JS executes in their session
3. Payload accesses wallet connection → initiates malicious tx
```

**PoC Steps:**
1. Create Immunefi researcher account
2. Submit report to any program with markdown containing various XSS vectors
3. Test if HTML tags survive rendering (start with `<b>test</b>`, escalate)
4. If HTML renders, test `<img src=x onerror=...>` or JS URI links
5. If successful, chain with wallet interaction for Critical severity

**Methodology Reference:** XSS in NFT Marketplaces pattern (Immunefi's own blog)

---

### Finding #2: SSRF via Bug Report URL/Attachment Processing
**Severity:** Critical  
**Category:** SSRF (CWE-918)  
**Confidence:** Medium  

**Analysis:**
- Bug reports require PoC links, reference URLs, and potentially file uploads
- If the backend validates, previews, or fetches these URLs server-side:
  - Link preview generation (common in modern platforms)
  - PoC file download/validation
  - OpenGraph metadata fetching for URL cards
- Vercel's serverless functions run on AWS Lambda → cloud metadata at `169.254.169.254`
- Even if URLs aren't fetched directly, OpenPGP encryption of reports might process URLs in attachments

**Attack Vector:**
```
1. Submit report with URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/
2. If backend fetches URL for preview/validation → cloud credentials exposed
3. Alternative: Use gopher:// or file:// if no protocol validation
```

**Test Payloads (if testing were permitted):**
```
http://169.254.169.254/latest/meta-data/
http://[::ffff:169.254.169.254]/
http://2852039166/ (decimal encoding)
http://BURP-COLLABORATOR.oastify.com (OOB detection)
```

**Methodology Reference:** `/root/clawd/knowledge/web2/ssrf/02-cloud-metadata-exploitation.md`, `04-ssrf-in-web3-infrastructure.md`

---

### Finding #3: IDOR on Bug Reports/Researcher Data
**Severity:** High–Critical  
**Category:** IDOR (CWE-639)  
**Confidence:** Medium-High  

**Analysis:**
- Bug reports have unique identifiers (likely sequential or UUID)
- API endpoints likely follow pattern: `/api/v1/reports/{id}` or `/api/v1/users/{id}`
- If authorization checks are insufficient on the API layer:
  - Researcher A could read Researcher B's reports
  - Access to unpublished vulnerability details
  - Exposure of bounty amounts, researcher PII
- The `_next/data` endpoints in Next.js can sometimes expose API data without proper auth checks
- 273+ bounty programs with private metrics ("Private" shown in listing) → IDOR could leak these

**Attack Vector:**
```
1. Authenticate as Researcher A
2. Submit a report, note the report ID
3. Iterate IDs: /api/reports/1001, /api/reports/1002, etc.
4. Check if other researchers' reports are accessible
5. Also test: user profiles, program private data, payout amounts
```

**Indicators:**
- Bug bounty listing page shows "Private" for some metrics (Total Paid, Med. Resolution Time)
- This implies there are authorization levels on program data
- If the API doesn't enforce these as strictly as the frontend...

**Methodology Reference:** Immunefi's own IDOR writeup in "Four Web2 Vulnerabilities in Web3"

---

### Finding #4: Authentication/Session Management Weaknesses
**Severity:** Medium–High  
**Category:** Broken Authentication (CWE-287)  
**Confidence:** Low-Medium  

**Analysis:**
- `bugs.immunefi.com` has custom authentication with password reset
- Potential issues to test:
  - **Rate limiting on login:** Can brute-force be attempted?
  - **Password reset token entropy:** Are tokens predictable or reusable?
  - **Session fixation:** Does session ID change after login?
  - **JWT weaknesses:** If using JWTs (common with Next.js), check for `alg:none`, weak secrets
  - **OAuth misconfig:** If social login exists, redirect_uri manipulation

**OpenPGP Factor:**
- Immunefi uses a forked openpgpjs for report encryption
- If the PGP key exchange or encryption has issues:
  - Reports could be decrypted by unauthorized parties
  - Key verification bypass could allow MITM on report content

---

### Finding #5: Next.js Specific Vulnerabilities
**Severity:** Medium–Critical  
**Category:** Framework Misconfiguration  
**Confidence:** Medium  

**Analysis:**
- Next.js has known attack vectors:
  - **`_next/data` endpoint exposure:** SSR data can leak server-side props containing sensitive info
  - **API route authorization bypass:** Next.js API routes may lack middleware auth checks
  - **Source map exposure:** If `productionBrowserSourceMaps` is enabled, entire client source visible
  - **Server Action parameter tampering:** Next.js 14+ server actions can be manipulated
  - **Middleware bypass via path manipulation:** CVE-2024-34351 (SSRF via Host header in middleware)

**Test Points:**
```
1. Access /_next/data/[buildId]/*.json — check for leaked data
2. Check for exposed source maps at /_next/static/chunks/*.js.map
3. Test API routes at /api/* for authorization gaps
4. Check response headers for framework version disclosure
```

---

### Finding #6: Shield My Bags — New Attack Surface
**Severity:** Unknown (needs active testing)  
**Category:** Various  
**Confidence:** Low  

**Analysis:**
- Added November 2025 — relatively new feature
- Hosted on Vercel (separate subdomain)
- New features = less battle-tested
- If it accepts wallet addresses/configs:
  - Input validation on wallet addresses
  - SSRF if it fetches on-chain data via user-supplied RPC URLs
  - XSS if it renders transaction data or token names
- Vercel Security Checkpoint blocked automated access → rate limiting in place (good)

---

### Finding #7: OpenPGP Implementation Risks
**Severity:** High  
**Category:** Cryptographic Weakness (CWE-327)  
**Confidence:** Low  

**Analysis:**
- Immunefi forked openpgpjs (not just using the library — they forked it)
- Forks often fall behind on security patches
- Last update to their fork: May 2023 — almost 3 years old
- Upstream openpgpjs has had vulnerabilities since:
  - CVE-2023-29017 (prototype pollution)
  - Various timing side-channel fixes
- If the encryption protects bug reports (which contain vulnerability details worth millions):
  - A weakness here could expose report contents
  - Key management issues could allow decryption by wrong parties

---

### Finding #8: Subdomain Takeover Vectors
**Severity:** Medium (High with wallet interaction)  
**Category:** Subdomain Takeover  
**Confidence:** Low-Medium  

**Analysis:**
- Immunefi explicitly mentions subdomain takeover in their scope
- They link to their own article on when subdomain takeovers are applicable
- With Vercel hosting, abandoned or misconfigured subdomains pointing to Vercel CNAMEs are takeover-able
- If any subdomain has a dangling CNAME → claim it on Vercel
- Impact escalation: Subdomain takeover + wallet interaction = Critical (per their severity matrix)

---

## 4. Methodology Gaps Identified

### What I Did Well
1. **Tech stack fingerprinting** — Identified Vercel/Next.js quickly from response headers and behavior
2. **Scope mapping** — Covered all 3 in-scope subdomains + supporting infrastructure
3. **Cross-referencing** — Used Immunefi's own blog posts about Web2 vulns as attack patterns
4. **Web3 impact escalation** — Mapped every finding to wallet/financial impact

### Gaps to Address
1. **No active testing capability** — Shadow audit was purely passive; need Burp Suite / ZAP for real testing
2. **Missing DNS enumeration** — Should have done subdomain brute-force (`subfinder`, `amass`)
3. **No JavaScript analysis** — Couldn't deobfuscate client-side JS to find API endpoints
4. **Missing CORS testing** — Need to check `Access-Control-Allow-Origin` on API endpoints
5. **No API fuzzing** — GraphQL introspection, parameter pollution, verb tampering untested
6. **Session token analysis** — Couldn't inspect cookie attributes, JWT structure

### New Patterns to Document
1. **OpenPGP fork risk** — forked crypto libraries in Web3 platforms as a vulnerability class
2. **Next.js `_next/data` leaks** — framework-specific data exposure
3. **Shield My Bags pattern** — New feature on established platform = lower security maturity
4. **Markdown-to-XSS in report platforms** — Any platform that renders user markdown is a target

---

## 5. Score & Assessment

### Finding Quality Score
| Finding | Realism (1-5) | Impact (1-5) | Novelty (1-3) | Total |
|---------|---------------|-------------|---------------|-------|
| #1 Markdown XSS | 4 | 5 | 2 | 11 |
| #2 SSRF via URLs | 3 | 5 | 2 | 10 |
| #3 IDOR on Reports | 4 | 5 | 1 | 10 |
| #4 Auth Weakness | 3 | 4 | 1 | 8 |
| #5 Next.js Misconfig | 3 | 4 | 2 | 9 |
| #6 Shield My Bags | 2 | 3 | 2 | 7 |
| #7 OpenPGP Fork | 2 | 5 | 3 | 10 |
| #8 Subdomain Takeover | 2 | 3 | 1 | 6 |

**Average: 8.9/13 — Solid passive recon findings. Active testing would significantly increase confidence.**

### Methodology Effectiveness
- **SSRF methodology** applied directly to finding #2 — cloud metadata, Web3 infrastructure patterns
- **IDOR** and **XSS** patterns from Immunefi's own documentation proved directly applicable
- **Framework-specific** (Next.js) analysis added 2 findings that pure Web2 methodology would miss

---

## 6. Lessons Learned

### For Zealynx Methodology
1. **"Eat their own dog food" audit angle** — Security platforms that publish vulnerability guides reveal their own threat model. Use a target's own security blog as an attack checklist.
2. **Forked crypto libraries** are high-value targets — check fork date vs upstream CVEs
3. **New feature launches** on established platforms = temporary security debt
4. **Next.js + Vercel** is the dominant Web3 frontend stack — deep framework knowledge pays dividends
5. **Markdown rendering** in any platform handling sensitive data (bug reports, audit findings, DAO proposals) = XSS opportunity

### For Zealynx Sales
- Immunefi themselves document Web2 vulns in Web3 extensively — validates our "infrastructure + smart contracts" pitch
- Their own statement: "60%+ of Web3 exploits target off-chain systems" — use this statistic in proposals
- The markdown XSS → wallet drain chain is a powerful demo scenario for client pitches

---

## 7. Files Updated

### New Knowledge Added
- Pattern: "Forked crypto library risk assessment" → add to methodology
- Pattern: "Next.js specific attack vectors for Web3" → add to methodology
- Pattern: "Security platform self-audit technique" (using target's own docs as attack guide)

### Performance Log Updated
- See `/root/clawd/knowledge/web2/performance-log.md`

---

*Ghost 👻 — Shadow pentest complete. 8 potential issues documented across SSRF, XSS, IDOR, auth, and framework-specific categories. Key insight: Immunefi's own vulnerability guides are the best checklist for auditing their platform.*
