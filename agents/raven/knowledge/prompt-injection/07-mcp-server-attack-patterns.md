# MCP Server Attack Patterns

**Category:** Prompt Injection / Agent Attacks / MCP Exploitation
**OWASP:** LLM01 (Prompt Injection), LLM05 (Excessive Agency), LLM06 (Sensitive Info Disclosure)
**MITRE ATLAS:** AML.T0051.001 — Indirect Prompt Injection
**Severity:** Critical
**Last Updated:** 2026-02-03

## Overview

Model Context Protocol (MCP) servers bridge LLMs and real system actions. They represent the highest-impact attack surface in the AI agent ecosystem because exploitation leads to real-world consequences (file access, code execution, data exfiltration). The MCP ecosystem is immature — industry research shows 43-82% of implementations contain classic vulnerabilities.

## Attack Surface Categories

### 1. Tool Argument Injection
MCP tools accept arguments from LLMs. If arguments are passed to CLI tools, databases, or APIs without sanitization, classic injection attacks apply.

**Common patterns:**
- Command injection via shell metacharacters (`$(cmd)`, `` `cmd` ``, `; cmd`)
- Argument injection via CLI flags (`--output=/etc/passwd`, `--exec=...`)
- Path traversal via unsanitized paths (`../../etc/shadow`)
- SQL injection via database-connected tools
- SSRF via URL parameters in fetch/browse tools

**Real CVEs:**
- CVE-2025-68144: git_diff argument injection in Anthropic's mcp-server-git
- CVE-2025-53967: curl command injection in Framelink Figma MCP (600K+ downloads)
- CVE-2025-53107: child_process.exec injection in @cyanheads/git-mcp-server

### 2. Path/Boundary Validation Bypass
MCP servers often configure boundaries (allowed directories, repos, etc.) but fail to enforce them at runtime.

**Pattern:** Configuration sets boundary → tool arguments bypass it → access outside scope

**Real CVEs:**
- CVE-2025-68143: git_init at arbitrary paths (Anthropic mcp-server-git)
- CVE-2025-68145: repo_path not validated against --repository flag

### 3. Cross-MCP Server Chaining
Individual MCP servers may be low-risk. Combined, they create critical attack chains.

**Dangerous combinations:**
| Server A | Server B | Combined Risk |
|----------|----------|---------------|
| Git MCP | Filesystem MCP | RCE via git filter injection |
| Browser MCP | Any file/API MCP | Indirect injection → arbitrary tool calls |
| Database MCP | Email/Messaging MCP | Data exfiltration pipeline |

**Real example:** Anthropic Git MCP + Filesystem MCP → git_init + write .git/config with malicious clean filter → git_add triggers shell command execution (no execute bit needed).

### 4. Indirect Prompt Injection → Tool Exploitation
The LLM reads untrusted content → content contains hidden instructions → LLM calls MCP tools with attacker-controlled arguments.

**Injection surfaces:**
- README.md files in repositories
- GitHub/GitLab issue descriptions
- Web pages the LLM browses
- Email content
- Code comments processed by AI coding assistants
- Document content in RAG systems

### 5. Credential & Authentication Weaknesses
**Astrix Security research (2025, 5,200+ servers):**
- 88% of MCP servers require credentials
- 53% use static API keys or PATs (long-lived, rarely rotated)
- Only 8.5% use OAuth
- 79% of API keys passed via environment variables
- No standardized auth across the ecosystem

### 6. Tool Description Poisoning
Malicious or compromised MCP servers can return manipulated tool descriptions that change how the LLM understands and uses tools.

### 7. Domain-Specific Execution Primitives
CLI tools wrapped by MCP servers may have obscure features that enable code execution:

**Git-specific:**
- `.git/hooks/*` — Execute on git events (requires execute bit)
- `.git/config` clean/smudge filters — Execute shell commands (NO execute bit needed!)
- `.gitattributes` filter assignments
- Git aliases with shell commands

**Docker-specific:**
- Volume mounts exposing host filesystem
- Entrypoint/CMD injection

**Kubernetes-specific:**
- kubectl exec into containers
- Service account token access

## MCP Server Audit Checklist

### Input Validation
- [ ] Are all tool arguments validated against expected types/patterns?
- [ ] Are path arguments canonicalized and checked against boundaries?
- [ ] Are CLI arguments sanitized for flag injection?
- [ ] Are URL arguments validated against SSRF?

### Privilege & Scope
- [ ] Does the server enforce configured boundaries (repos, directories, APIs)?
- [ ] Are tool permissions minimized (read-only where possible)?
- [ ] Is human approval required for state-changing operations?
- [ ] Does the server follow Meta's Rule of Two?

### Cross-Server Risk
- [ ] What other MCP servers run alongside?
- [ ] What's the combined capability set?
- [ ] Can Server A's output be used to exploit Server B?

### Authentication
- [ ] What credential type is used? (OAuth preferred, API keys are risky)
- [ ] Are credentials rotated? Are they scoped appropriately?
- [ ] Is there auth between MCP client and server?

### Output Safety
- [ ] Can tool outputs inject instructions into LLM context?
- [ ] Are outputs sanitized before returning to the LLM?
- [ ] Can outputs trigger markdown/HTML rendering exploits?

## Industry Statistics (2025)

| Metric | Value | Source |
|--------|-------|--------|
| MCP servers with command injection | 43% | Equixly |
| MCP implementations prone to path traversal | 82% | Endor Labs |
| MCP implementations with code injection APIs | 67% | Endor Labs |
| MCP servers using insecure static credentials | 53% | Astrix |
| MCP servers using OAuth | 8.5% | Astrix |
| Vendors dismissing findings as "theoretical" | 45% | Equixly |
| Total MCP servers on GitHub | ~20,000 | Astrix |

## Red Team Playbook Notes

- MCP is the #1 target for AI red teaming in 2025-2026
- Start every engagement by mapping ALL MCP servers + their combined capabilities
- Test indirect prompt injection through every data source the LLM reads
- Always check for CLI argument injection when tools wrap command-line tools
- Audit servers as a SET — combination risks often exceed individual server risks
- Domain-specific CLI features (git filters, docker volumes) are gold for exploit chains
- The ecosystem is immature — even Anthropic's own reference implementation had critical flaws
- **Zealynx opportunity:** MCP security audits are an underserved, high-value market
