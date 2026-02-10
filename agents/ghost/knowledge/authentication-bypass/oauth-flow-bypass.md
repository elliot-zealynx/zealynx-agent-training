# OAuth Authentication Flow Bypass

## Attack Description
Attackers exploit flaws in OAuth implementation to bypass authentication by manipulating the OAuth flow, stealing tokens, or exploiting misconfigurations in the OAuth provider integration.

## Prerequisites
- Target uses OAuth for authentication (Google, Facebook, GitHub, etc.)
- Ability to intercept OAuth flow requests
- Understanding of OAuth 2.0/OpenID Connect flow

## Exploitation Steps

### Method 1: State Parameter CSRF
1. **Initiate OAuth Flow**: Start legitimate OAuth authentication
2. **Extract State Parameter**: Capture state value from authorization URL
3. **Generate Malicious Link**: Create OAuth URL with victim's state parameter
4. **Social Engineering**: Trick victim into clicking malicious OAuth link
5. **Token Theft**: Capture authorization code/token for victim's account

### Method 2: Redirect URI Manipulation  
1. **Analyze Redirect Validation**: Test different redirect_uri values
2. **Open Redirect Discovery**: Look for loose validation patterns
3. **Subdomain Takeover**: Check for unused subdomains that might be allowed
4. **Token Interception**: Redirect OAuth tokens to attacker-controlled endpoint

### Method 3: Client ID Abuse
1. **Extract Client ID**: Identify OAuth application's client_id
2. **Create Malicious App**: Register new OAuth app with same/similar details  
3. **Phishing Flow**: Use legitimate-looking OAuth consent screen
4. **Token Harvesting**: Collect tokens through malicious OAuth application

### Method 4: Token Replay/Fixation
1. **Capture Valid Tokens**: Intercept legitimate access/refresh tokens
2. **Token Validation Testing**: Check token expiration and validation
3. **Session Fixation**: Attempt to fix tokens for victim accounts
4. **Cross-Account Token Use**: Test tokens across different user accounts

## Detection Methods
- **OAuth Flow Mapping**: Document complete authentication flow
- **Parameter Fuzzing**: Test all OAuth parameters for manipulation
- **Redirect Testing**: Analyze redirect_uri validation strictness  
- **State Parameter Analysis**: Check for proper CSRF protection
- **Token Scope Testing**: Verify proper token scope limitations

## Tools Required
- Burp Suite Professional
- OAuth exploitation extensions
- Custom redirect servers for testing
- Browser developer tools

## Remediation
- **Strict Redirect URI Validation**: Whitelist exact redirect URIs
- **Proper State Parameter**: Implement cryptographically secure state
- **Token Expiration**: Use short-lived access tokens with refresh rotation
- **Scope Limitation**: Implement principle of least privilege for OAuth scopes
- **PKCE Implementation**: Use Proof Key for Code Exchange for public clients

## Real Examples

### Case 1: Airbnb OAuth Token Theft (Arne Swinnen)
- **Target**: Airbnb authentication system
- **Method**: OAuth token theft through subdomain takeover
- **Technique**: Exploited misconfigured redirect_uri validation
- **Impact**: Account takeover via stolen OAuth tokens

### Case 2: Common OAuth Vulnerabilities
- **Redirect URI Bypass**: Using IP addresses, localhost, or wildcard domains
- **State Parameter Missing**: CSRF attacks on OAuth flow
- **Scope Creep**: Requesting excessive permissions during OAuth consent

## Attack Scenarios

### Social Media Login Bypass
1. Analyze social login implementation (Google, Facebook, etc.)
2. Test redirect_uri parameter manipulation
3. Look for subdomain takeover opportunities  
4. Check state parameter implementation

### API Authentication Bypass
1. Extract OAuth client credentials from mobile/web apps
2. Test client credential reuse across applications
3. Analyze token validation on API endpoints
4. Test for token replay attacks

## Detection Checklist
- [ ] Map complete OAuth authentication flow
- [ ] Test redirect_uri parameter validation
- [ ] Verify state parameter implementation
- [ ] Check for client_id/secret exposure
- [ ] Test token expiration and validation
- [ ] Analyze OAuth scope permissions
- [ ] Test for subdomain takeover vulnerabilities
- [ ] Verify PKCE implementation (for public clients)