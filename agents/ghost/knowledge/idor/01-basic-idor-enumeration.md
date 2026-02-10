# Basic IDOR Enumeration Patterns

## Attack Description
Insecure Direct Object Reference (IDOR) occurs when an application exposes internal object references (database IDs, file names, user identifiers) without validating whether the authenticated user is authorized to access them. Ranked #1 in OWASP Top 10 under "Broken Access Control."

## Types of IDOR

### 1. Generic IDOR (Visible Response)
Results visible in server response — access confidential data or files belonging to another user.
```
GET /api/orders/12345 HTTP/1.1
# Change to:
GET /api/orders/12346 HTTP/1.1
```

### 2. Blind IDOR (No Visible Confirmation)
Actions succeed silently — deleting another user's data, modifying settings, unsubscribing users.
Requires cross-account validation: create 2 test accounts, act from one, verify effect on other.

### 3. Object-Level IDOR
Modify or delete unauthorized objects:
```
DELETE /api/comments/9999
PUT /api/profile/5555 {"bio": "hacked"}
```

### 4. Function-Level IDOR
Access unauthorized functions or actions:
```
POST /admin/export-users?format=csv
# Works even as non-admin when function lacks auth check
```

## Common IDOR Locations

| Location | Example | Testing Approach |
|----------|---------|------------------|
| URL Parameters | `?user_id=123` | Increment/decrement values |
| Path Segments | `/user/123/orders` | Replace with other user IDs |
| POST Body | `{"account_id": 123}` | Swap with target account |
| Hidden Form Fields | `<input type="hidden" name="id">` | Modify before submission |
| Headers | `X-User-ID: 123` | Change header value |
| Cookies | `user_session=base64(user_id)` | Decode, modify, re-encode |

## Exploitation Steps

### Step 1: Map Object References
```bash
# Capture all requests with Burp Suite
# Extract unique identifiers:
- user_id, account_id, uid, id
- doc_id, file_id, attachment_id  
- order_id, transaction_id, invoice_id
- Any UUID, GUID, or encoded string
```

### Step 2: Cross-Account Testing
1. **Account A**: Create resource, note its ID
2. **Account B**: Attempt to access/modify/delete Account A's resource
3. **Analyze**: Check response for unauthorized data or action success

### Step 3: Sequential Enumeration
```python
for id in range(1000, 2000):
    response = requests.get(f"/api/profile?id={id}")
    if response.status_code == 200 and "email" in response.text:
        print(f"[IDOR] Exposed user {id}: {response.json()}")
```

### Step 4: Boundary Testing
```
Original: /api/orders/12345
Test 1:   /api/orders/12344    (decrement)
Test 2:   /api/orders/12346    (increment)
Test 3:   /api/orders/1        (first record)
Test 4:   /api/orders/0        (edge case)
Test 5:   /api/orders/999999   (high value)
Test 6:   /api/orders/-1       (negative)
```

## Detection Method (For Auditors)
1. Identify every endpoint accepting object identifiers
2. Create 2+ test accounts with different privilege levels
3. Cross-test: access User A's resources as User B
4. Check for authorization bypass in:
   - Read operations (data disclosure)
   - Write operations (unauthorized modification)
   - Delete operations (unauthorized removal)

## Remediation
```python
# VULNERABLE
def get_order(order_id):
    return db.query("SELECT * FROM orders WHERE id = ?", order_id)

# SECURE - Authorization scoping
def get_order(order_id, current_user):
    order = db.query("SELECT * FROM orders WHERE id = ? AND user_id = ?", 
                     order_id, current_user.id)
    if not order:
        raise UnauthorizedException("Access denied")
    return order
```

## Real Examples (HackerOne Disclosed)

### PayPal - $10,500
IDOR to add secondary users in `/businessmanage/users/api/v1/users`
- Impact: Add arbitrary users to any business account
- https://hackerone.com/reports/415081

### HackerOne - $12,500
Delete all Licenses and certifications via GraphQL mutation
- Impact: Delete any user's credentials
- https://hackerone.com/reports/2122671

### Shopify - $5,000
GraphQL IDOR in BillingDocumentDownload exposing invoices
- Impact: Download any merchant's billing documents
- https://hackerone.com/reports/2207248

### Starbucks - Account Takeover
Singapore IDOR allowing account takeover via card manipulation
- Impact: Full account compromise
- https://hackerone.com/reports/876300

## Zealynx Pentest Checklist
- [ ] Map all endpoints with object identifiers
- [ ] Test sequential ID enumeration
- [ ] Cross-account resource access
- [ ] Check hidden form fields
- [ ] Test API endpoints separately from UI
- [ ] Verify DELETE/PUT operations require ownership
- [ ] Check admin functions accessible to users
- [ ] Test file download paths for traversal+IDOR combo
