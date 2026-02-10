# Zealynx Agent Training Repository

Centralized knowledge base and performance tracking for Zealynx's audit agents.

## Agents

| Agent | Codename | Specialization | Directory |
|-------|----------|----------------|-----------|
| Sol | Solidity Researcher | Solidity smart contract security | [`agents/sol/`](agents/sol/) |
| Forge | Rust Researcher | Rust/Solana/Move security | [`agents/forge/`](agents/forge/) |
| Ghost | Web2 Researcher | Web2/Infrastructure security | [`agents/ghost/`](agents/ghost/) |
| Raven | AI Red Team | AI systems security | [`agents/raven/`](agents/raven/) |

## Repository Structure

```
📁 agents/
├── 📁 sol/           # Sol (Solidity Researcher)
│   ├── 📁 knowledge/     # Knowledge base
│   ├── 📁 shadow-audits/ # Shadow audit results
│   └── 📊 performance.md # Performance tracking
├── 📁 forge/         # Forge (Rust Researcher) 
│   ├── 📁 knowledge/
│   ├── 📁 shadow-audits/
│   └── 📊 performance.md
├── 📁 ghost/         # Ghost (Web2 Researcher)
│   ├── 📁 knowledge/
│   ├── 📁 shadow-audits/
│   └── 📊 performance.md
└── 📁 raven/         # Raven (AI Red Team)
    ├── 📁 knowledge/
    ├── 📁 shadow-audits/
    └── 📊 performance.md

📁 tracking/
├── 📊 agent-performance-tracker.md  # Central performance tracking
├── 📋 shadow-audit-protocol.md      # New shadow audit approach
└── 📈 analytics/                    # Performance analytics

📁 contests/
└── 📁 [contest-name]/               # Contest-specific data
    ├── 📋 contest-info.md
    ├── 📊 agent-results.md
    └── 📁 findings/
```

## New Shadow Audit Protocol

**Goal:** Train agents to avoid false positives and improve precision.

### Before Each Shadow Audit:
1. **Record ALL findings** you discover (valid + invalid)
2. **Document your reasoning** for each finding
3. **Submit complete finding list** before seeing contest results

### After Contest Results Available:
1. **Compare your findings** against official contest results
2. **Classify each finding:**
   - ✅ **Valid:** Found in official contest results
   - ❌ **False Positive:** Not in official contest results  
   - 🔍 **Missed:** In contest results but you didn't find it
3. **Update performance metrics**
4. **Document lessons learned** from false positives
5. **Study missed issues** to improve methodology

### Performance Metrics:
- **Precision:** Valid findings / Total findings submitted
- **Recall:** Valid findings found / Total valid findings in contest
- **False Positive Rate:** False positives / Total findings submitted
- **Improvement Trend:** Track metrics over time

## Usage

### For Agents:
1. Before shadow audits, read your `knowledge/` directory
2. Record findings in `shadow-audits/YYYY-MM-DD-[contest].md`
3. After results, update `performance.md` with metrics
4. Study false positives to avoid repeating mistakes

### For Carlos:
- Review agent performance in `tracking/agent-performance-tracker.md`
- Monitor improvement trends over time
- Identify training needs based on common false positive patterns

## Contributing

After each shadow audit, agents must:
1. Update their individual performance tracking
2. Commit findings and analysis to this repository
3. Update central performance tracker
4. Document new patterns learned

---

**Created:** February 2026  
**Purpose:** Improve audit agent precision and reduce false positives  
**Owner:** Zealynx Security