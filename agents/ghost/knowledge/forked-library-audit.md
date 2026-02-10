# Forked Crypto Library Risk Assessment

**Category:** Supply Chain / Cryptographic Weakness  
**Severity:** High–Critical  
**CWE:** CWE-327 (Use of Broken/Risky Crypto), CWE-1104 (Unmaintained Third Party)  
**Last Updated:** 2026-02-03  
**Author:** Ghost 👻  
**Origin:** Immunefi shadow pentest (forked openpgpjs, last updated May 2023)

---

## The Pattern

Web3 projects frequently fork crypto libraries rather than using them as dependencies:
- **Why they fork:** Custom modifications, pinning behavior, avoiding breaking changes
- **The risk:** Forks fall behind upstream security patches

## Why This Matters in Web3

Crypto libraries in Web3 protect:
- Bug report contents (vulnerability details worth millions)
- Private keys and signing operations
- Communication between researchers and projects
- Authentication tokens and session management

A weakness in a forked crypto library could:
- Expose vulnerability details before patches are deployed
- Allow interception of bounty payment coordination
- Enable session hijacking or authentication bypass

---

## Audit Methodology

### Step 1: Identify Forked Libraries
```bash
# Check GitHub for forks
# Look in package.json for git:// dependencies
# Check if crypto operations use custom implementations

# Signs of a fork:
# - GitHub repo name matches well-known library
# - package.json points to org's own repo instead of npm
# - Commit history shows divergence from upstream
```

### Step 2: Compare Fork vs Upstream
```bash
# Check fork date and last update
# Compare with upstream releases since fork date
# Specifically look for security-tagged releases

# Example (openpgpjs):
# Fork last updated: May 2023
# Upstream since then: Multiple security releases
# CVEs to check: CVE-2023-29017 (prototype pollution), timing fixes
```

### Step 3: Check for Divergent Code
```bash
# What did they change?
git log --oneline fork..upstream
git diff fork upstream -- src/crypto/

# Custom crypto modifications = highest risk
# Custom key handling = second highest
# Build/config changes = lower risk but still check
```

### Step 4: Assess Impact
- What does the library protect?
- Can the vulnerability be exploited remotely?
- Does the weakness affect confidentiality, integrity, or both?
- What's the blast radius? (one user vs all users)

---

## Common Forked Libraries in Web3

| Library | Purpose | Fork Risk |
|---------|---------|-----------|
| openpgpjs | Report/message encryption | High — crypto bugs = data exposure |
| ethers.js | Transaction building | Critical — tx manipulation |
| web3.js | Blockchain interaction | Critical — similar to ethers |
| noble-curves | Elliptic curve operations | Critical — signature forgery |
| tweetnacl | Encryption/signing | High — fundamental crypto |
| jose | JWT operations | High — auth bypass |

---

## Zealynx Audit Addition

When auditing a Web3 project:

1. **Check `package.json` for git:// or github: dependencies** — these are likely forks
2. **Compare fork age vs upstream CVEs** — flag any fork >6 months behind
3. **Flag custom crypto modifications** as Critical finding
4. **Recommend dependency pinning** instead of forking where possible
5. **If fork is necessary:** Recommend automated upstream sync (Dependabot, Renovate)

---

## References

- Immunefi shadow pentest: openpgpjs fork (May 2023) — 3 years behind upstream
- CVE-2023-29017: openpgpjs prototype pollution
- General: "Supply Chain Attacks in Web3" (various sources)
