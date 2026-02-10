# JWT Authentication Bypass - Signature Validation Issues

## Attack Description
Attackers exploit JWT implementations that fail to properly validate signatures, allowing manipulation of token payloads to escalate privileges or bypass authentication entirely.

## Prerequisites
- Target uses JWT for authentication
- JWT tokens accessible (cookies, headers, local storage)
- Ability to decode and modify JWT payloads

## Exploitation Steps

### Method 1: Signature Validation Bypass
1. **Extract JWT Token**: Identify JWT in cookies, headers, or browser storage
2. **Decode JWT**: Use tools to decode the base64-encoded token
3. **Analyze Payload**: Look for privilege-related fields:
   - `admin`: false → true
   - `role`: "user" → "admin"
   - `u_id`: user_id → admin_user_id
   - `permissions`: limited → elevated
4. **Modify Payload**: Change values without touching signature
5. **Test Authentication**: Submit modified JWT and check access

### Method 2: Algorithm Confusion (alg: none)
1. **Intercept Valid JWT**: Capture legitimate JWT token
2. **Modify Header**: Change algorithm to "none"
   ```json
   {"alg": "none", "typ": "JWT"}
   ```
3. **Remove Signature**: Strip signature portion from JWT
4. **Modify Payload**: Update payload with elevated privileges  
5. **Submit Unsigned Token**: Test if server accepts unsigned JWT

### Method 3: Weak Secret Brute Force
1. **Extract JWT**: Obtain signed JWT token
2. **Identify Algorithm**: Check if using HS256/HS384/HS512
3. **Brute Force Secret**: Use tools like hashcat or john
4. **Forge Token**: Create new JWT with elevated privileges using discovered secret

## Detection Methods
- **JWT Decoder Tools**: Burp JWT Editor, jwt.io
- **Signature Testing**: Modify payload without changing signature
- **Algorithm Testing**: Try "none" algorithm attack
- **Secret Brute Force**: Attempt to crack signing secret
- **Payload Fuzzing**: Test different privilege escalation payloads

## Tools Required
- Burp Suite + JWT Editor Extension
- jwt.io (online decoder)
- hashcat/john (for secret brute force)
- Custom scripts for JWT manipulation

## Remediation
- **Always Verify Signatures**: Never skip JWT signature validation
- **Reject "none" Algorithm**: Explicitly deny unsigned tokens
- **Strong Secrets**: Use cryptographically strong, long secrets (>256 bits)
- **Algorithm Whitelist**: Only accept expected algorithms (e.g., RS256)
- **Proper Libraries**: Use well-vetted JWT libraries with secure defaults

## Real Examples

### Case 1: Admin Panel Access (Hohky)
- **Target**: Well-known website (anonymous)
- **Method**: Modified JWT payload without changing signature
- **Payload Changes**: 
  - Changed user ID to admin ID
  - Modified user role/permissions
- **Impact**: Full admin control panel access
- **Root Cause**: Server didn't validate JWT signature

### Case 2: Privilege Escalation Patterns
Common vulnerable parameters in JWT payloads:
```json
{
  "sub": "1234567890",
  "name": "John Doe", 
  "email": "user@example.com",
  "admin": false,          // Change to true
  "role": "user",          // Change to "admin"
  "permissions": ["read"], // Add "write", "admin"
  "u_id": 12345,          // Change to admin user ID
  "iat": 1609459200
}
```

## Advanced Techniques
- **Key Confusion**: Mix asymmetric and symmetric algorithms
- **JWK Header Injection**: Inject malicious public keys
- **Kid Parameter Abuse**: Manipulate key ID references

## Detection Checklist
- [ ] Decode JWT and analyze payload structure
- [ ] Test payload modification without signature change
- [ ] Try "alg: none" attack vector
- [ ] Attempt to brute force JWT secret
- [ ] Test privilege escalation parameters
- [ ] Check for proper signature validation
- [ ] Verify algorithm whitelisting