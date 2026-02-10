# 2FA Authentication Bypass via Parameter Tampering

## Attack Description
Attackers can bypass two-factor authentication mechanisms by manipulating parameters during the authentication flow, particularly during registration or login processes.

## Prerequisites  
- Target application with 2FA enabled
- Ability to intercept and modify HTTP requests/responses
- Access to request parameters that control authentication flow

## Exploitation Steps

### Method 1: Registration Parameter Manipulation
1. **Intercept Sign-up Request**: Capture the registration request using a proxy tool
2. **Identify Auth Parameters**: Look for parameters like:
   - `twoFactorNotificationType`
   - `authMethod`
   - `verificationMethod` 
   - `otpDelivery`
3. **Modify Parameter Values**: Change parameter values to bypass intended flow
   - Example: `twoFactorNotificationType=0` (SMS) → `twoFactorNotificationType=1` (Email)
4. **Complete Registration**: Follow through the modified flow
5. **Test Authentication**: Verify if 2FA requirement was bypassed

### Method 2: Login Flow Manipulation
1. **Intercept Login Process**: Capture authentication requests
2. **Identify Bypass Parameters**: Look for boolean flags or flow control parameters:
   - `requireTwoFactor=true` → `requireTwoFactor=false`
   - `skipVerification=false` → `skipVerification=true`
3. **Test Session Validity**: Check if authentication succeeds without 2FA

## Detection Methods
- **Parameter Analysis**: Review all parameters in auth-related endpoints
- **Flow Mapping**: Map complete authentication flow and identify control points
- **Response Analysis**: Look for differences in responses when parameters are modified
- **Burp Suite Extensions**: Use JWT Editor, Autorize, or similar tools

## Tools Required
- Burp Suite Professional
- Parameter fuzzing wordlists
- JWT manipulation tools

## Remediation
- **Server-side Validation**: Always validate authentication requirements server-side
- **Parameter Whitelisting**: Only accept expected parameter values
- **Immutable Security Checks**: Don't allow client-side control of security mechanisms
- **Session Management**: Properly track authentication state across requests

## Real Examples

### Case 1: €100 Bug Bounty (Talat Mehmood)
- **Target**: Anonymous web application
- **Method**: Modified `twoFactorNotificationType` parameter during signup
- **Impact**: OTP delivery changed from SMS to email, bypassing phone verification
- **Bounty**: €100

### Case 2: Parameter Value Manipulation
- **Common Parameters**: 
  - `auth_method`, `verification_type`, `require_otp`
- **Technique**: Change numeric/boolean values to alter authentication flow
- **Impact**: Complete bypass of 2FA requirements

## Detection Checklist
- [ ] Map all authentication-related parameters
- [ ] Test parameter value manipulation in registration flow
- [ ] Test parameter value manipulation in login flow  
- [ ] Check for client-side security control parameters
- [ ] Verify server-side validation of security parameters
- [ ] Test different parameter encoding methods