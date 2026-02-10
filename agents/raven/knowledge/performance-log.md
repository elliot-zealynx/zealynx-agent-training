# 🦅 Shadow Red Team Performance Log

Track precision, recall, and lessons from each shadow exercise.

| Date | Target | Type | Vulns Found | Vulns Missed | Precision | Recall | Key Lessons |
|------|--------|------|-------------|--------------|-----------|--------|-------------|
| 2026-02-03 | Anthropic mcp-server-git | Blind Audit → CVE Comparison | 7 (4 exact CVE + 1 partial + 2 extra) | 2 (smudge/clean RCE, branch file deletion) | 100% | 66.7% (technique-level) / 100% (CVE-level) | Deep CLI internals matter — obscure features (git filters) create execution primitives; always audit MCP servers as a SET not individually; prompt injection morning study directly led to catching all 3 CVEs |
