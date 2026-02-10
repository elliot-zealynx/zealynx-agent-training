# Basic SSRF — Internal Service Access

**Category:** SSRF  
**Severity:** Medium–Critical  
**CWE:** CWE-918  
**Last Updated:** 2026-02-03  
**Author:** Ghost 👻

---

## Attack Pattern

Server-Side Request Forgery occurs when an application fetches a URL controlled by the attacker. The attacker injects internal addresses (`localhost`, `127.0.0.1`, private IP ranges) to access services not exposed to the internet.

### Common Injection Points
- URL parameters: `?url=`, `?redirect=`, `?callback=`, `?source=`, `?target=`
- Webhook configuration fields
- File import/export features (CSV import from URL, image fetch)
- PDF generators (HTML-to-PDF with `<iframe>` or `<img>`)
- Migration/integration wizard fields (hostname/IP inputs)
- API proxy endpoints

### Target Surfaces
| Target | Address | What You Get |
|--------|---------|-------------|
| Loopback | `http://127.0.0.1:PORT` | Internal services, admin panels |
| Private RFC1918 | `http://10.x.x.x`, `http://172.16-31.x.x`, `http://192.168.x.x` | Internal network services |
| Link-local | `http://169.254.169.254` | Cloud metadata (see cloud-metadata doc) |
| IPv6 loopback | `http://[::1]:PORT` | Same as 127.0.0.1 over IPv6 |

---

## Detection Method

### Black-Box Testing
1. Identify any parameter that accepts a URL or hostname
2. Inject `http://127.0.0.1:PORT` with common ports (80, 443, 8080, 8443, 3000, 6379, 9200, 27017)
3. Compare response times — open port vs closed port (timing-based detection)
4. Check for differences in error messages (connection refused vs timeout)
5. Use Burp Collaborator / interactsh to detect blind callbacks

### White-Box Indicators
- `requests.get(user_input)` / `axios.get(user_input)` / `fetch(user_input)`
- No URL validation or allowlist
- `urllib.request.urlopen()` with user-controlled input
- Server making HTTP requests based on database-stored URLs

---

## Exploitation Steps

### Step 1: Confirm SSRF exists
```
GET /api/proxy?url=http://127.0.0.1:80 HTTP/1.1
Host: target.com
```
If different response than `url=http://nonexistent.invalid`, SSRF is confirmed.

### Step 2: Port scan internal network
Iterate through common ports on localhost and private IPs:
```
?url=http://127.0.0.1:22    → SSH
?url=http://127.0.0.1:6379  → Redis
?url=http://127.0.0.1:9200  → Elasticsearch
?url=http://127.0.0.1:27017 → MongoDB
?url=http://127.0.0.1:5432  → PostgreSQL
?url=http://127.0.0.1:8500  → Consul
```

### Step 3: Access internal services
Once you find open ports, interact with services:
- Admin panels on 8080/8443
- Kubernetes API on 10250/6443
- Docker API on 2375/2376

### Step 4: Demonstrate impact
- Screenshot or extract data from admin panels
- Read sensitive configuration from internal APIs
- Chain with other vulns (see ssrf-to-rce-chain.md)

---

## Remediation

1. **URL Allowlist**: Only permit requests to known, trusted domains
2. **Block private IP ranges**: Reject 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
3. **Disable unused URL schemes**: Block `file://`, `gopher://`, `dict://`
4. **DNS resolution validation**: Resolve hostname first, then check if IP is internal (prevent DNS rebinding with double-check)
5. **Network segmentation**: Don't let web-facing servers talk to internal services directly

---

## Real-World References

- HackerOne Report #285380 — SSRF to internal admin panel access
- HackerOne Report #2262382 — SSRF via error message output sanitization
- Search.gov (HackerOne #514224) — SSRF via `?url=` parameter with LF bypass ($150 bounty)

---

## Web3 Relevance

In dApps, basic SSRF can target:
- **RPC nodes** running on localhost (Geth 8545, Solana 8899)
- **Validator APIs** not exposed to internet
- **Indexer services** (The Graph, custom indexers)
- **Key management services** running internally

A frontend proxy that fetches user-provided URLs for metadata/images is the classic SSRF entry in Web3.
