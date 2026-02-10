# Web2 Security Research Study Log

## 2026-02-09 - Morning Session: JWT Vulnerabilities Deep Dive

### Focus Area: JSON Web Token (JWT) Vulnerabilities

**Methodologies Documented:**
1. **JWT Claim Manipulation** (`jwt-vulnerabilities/01-jwt-claim-manipulation.md`)
   - Plaintext credential exposure in JWT payloads
   - URL-based JWT transmission risks  
   - Signature validation bypass techniques
   - Real example: InfoSec writeup - plaintext passwords in email confirmation tokens

2. **JWT Algorithm Confusion** (`jwt-vulnerabilities/02-jwt-algorithm-confusion.md`)
   - Asymmetric to symmetric algorithm attacks (RS256 → HS256)
   - Public key exploitation as HMAC secret
   - CVE-2016-5431, CVE-2016-10555 methodology
   - PortSwigger Academy comprehensive attack patterns

3. **JWT Header Parameter Injection** (`jwt-vulnerabilities/03-jwt-header-parameter-injection.md`)
   - JKU (JWK Set URL) spoofing attacks
   - X5U (X.509 URL) certificate chain manipulation
   - KID parameter injection (directory traversal, SQLi, command injection)
   - JWK header injection with embedded keys

**Research Sources:**
- HackerOne disclosed reports (Linktree, Argo CD, Trint Ltd, 8x8 Jitsi)
- PortSwigger Web Security Academy (algorithm confusion)
- Medium comprehensive JWT attack guide by Omar Elhadidi
- InfoSec writeups on real-world JWT exploitation
- CVE databases and security advisories

**Shadow Audit Target Selected:**
- **Target**: xmidt-org/cjwt library (GitHub: https://github.com/xmidt-org/cjwt)
- **Published Finding**: CVE-2024-54150 (Algorithm Confusion Vulnerability)
- **Discovered by**: Louis Nyffenegger (PentesterLab) - December 2024
- **CVSS Score**: Critical (algorithm confusion enabling auth bypass)
- **Vulnerability**: JWT algorithm confusion in C library
- **Technical Details**: 
  - Library accepts algorithm from JWT header without validation
  - Same `cjwt_decode()` function for both HMAC and RSA verification
  - Public key can be used as HMAC secret via header manipulation
- **Ground Truth**: Complete POC available with Ruby exploit code
- **Value**: Perfect benchmark for measuring algorithm confusion detection capability

**Attack Patterns Identified:**
- JWT payload modification without signature verification
- Algorithm header manipulation (alg: RS256 → HS256)
- Public key extraction and abuse as HMAC secret
- Header parameter injection for key source manipulation (JKU, X5U, KID)
- Embedded malicious JWK in token headers
- Directory traversal via KID parameter
- SQL injection through KID database lookups
- Command injection in key file processing

**Key Vulnerability Classes:**
1. **Signature Validation Bypass** - Apps not verifying JWT signatures
2. **Algorithm Confusion** - Forcing asymmetric libs to use symmetric verification  
3. **Header Injection** - Malicious key sources via JKU/X5U/JWK parameters
4. **KID Parameter Abuse** - Injection attacks via key identifiers
5. **Weak Secret Bruteforcing** - Crackable HMAC secrets
6. **Claim Manipulation** - Direct payload modification attacks

**Next Steps:**
- Afternoon shadow audit against cjwt library codebase
- Implement detection signatures for algorithm confusion patterns
- Compare findings with CVE-2024-54150 technical details
- Document precision/recall metrics for JWT vulnerability detection
- Build automated testing methodology for JWT libraries

### Study Statistics
- **Files Created**: 3 comprehensive methodology documents  
- **Real Examples Analyzed**: 8+ vulnerability cases across multiple platforms
- **CVEs Researched**: 4 critical JWT-related CVEs
- **Attack Vectors Documented**: 15+ distinct JWT exploitation techniques
- **Time Investment**: ~3 hours deep research and documentation

---

## 2026-02-07 - Morning Session: Authentication Bypass Deep Dive

### Focus Area: Authentication Bypass Vulnerabilities

**Methodologies Documented:**
1. **2FA Parameter Tampering** (`2fa-parameter-tampering.md`)
   - Registration flow manipulation
   - Parameter value modification attacks
   - Real example: €100 bounty for `twoFactorNotificationType` bypass

2. **JWT Signature Bypass** (`jwt-signature-bypass.md`) 
   - Signature validation bypass techniques
   - Algorithm confusion attacks (alg: none)
   - Real example: Admin panel access through payload modification

3. **OAuth Flow Bypass** (`oauth-flow-bypass.md`)
   - State parameter CSRF attacks
   - Redirect URI manipulation
   - Client ID abuse techniques

**Research Sources:**
- Medium writeup by Talat Mehmood (2FA bypass)
- InfoSecWriteups JWT analysis by Hohky
- HackerOne disclosed reports analysis
- CVE-2024-27198/27199 JetBrains TeamCity research

**Shadow Audit Target Selected:**
- **Target**: JetBrains TeamCity (CVE-2024-27198 & CVE-2024-27199)
- **Published Findings**: Authentication bypass vulnerabilities with complete technical details
- **CVE-2024-27198**: CVSS 9.8 - Authentication bypass via ";.jsp" suffix exploitation
- **CVE-2024-27199**: CVSS 7.3 - Path traversal authentication bypass via "/../" 
- **Ground Truth**: Complete exploit details, HTTP request examples, impact analysis
- **Value**: Perfect for measuring detection precision/recall against known vulnerabilities

**Attack Patterns Identified:**
- Parameter manipulation during auth flows
- JWT payload modification without signature validation  
- OAuth redirect URI weaknesses
- Path traversal for authentication bypass
- HTTP method/suffix manipulation

**Next Steps:**
- Afternoon shadow audit against TeamCity test instance
- Compare findings with published CVE details
- Document precision/recall metrics
- Build automated detection signatures

### Study Statistics
- **Files Created**: 3 methodology documents
- **Real Examples Analyzed**: 5 vulnerability cases
- **CVEs Researched**: 2 critical authentication bypasses
- **Time Investment**: ~2 hours deep research