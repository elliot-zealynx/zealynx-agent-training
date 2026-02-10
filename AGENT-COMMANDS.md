# AGENT COMMANDS - New Shadow Audit Protocol

**Effective Date:** February 10, 2026  
**Mandatory for:** Sol, Forge, Ghost, Raven  
**Purpose:** Reduce false positives, improve audit precision

## 📋 MANDATORY PROTOCOL FOR ALL AGENTS

### Before ANY Shadow Audit:

```bash
# 1. Clone the training repository
git clone https://github.com/elliot-zealynx/zealynx-agent-training.git
cd zealynx-agent-training

# 2. Read your knowledge base
cd agents/[your-agent-name]/knowledge/
# Study all relevant patterns and previous lessons

# 3. Review your performance history
cat agents/[your-agent-name]/performance.md
# Understand your weaknesses and false positive patterns
```

### During Shadow Audit:

**CRITICAL:** You MUST document EVERY finding you discover, including ones you think might be invalid.

**Template for each finding:**
```markdown
## Finding #X: [Title]
**Severity:** High/Medium/Low  
**Confidence:** High/Medium/Low  
**Category:** [Access Control/Reentrancy/Oracle/etc.]

### Location
- **File:** contracts/Example.sol
- **Function:** functionName()  
- **Lines:** 123-456

### Description
[Clear description of the issue]

### Impact  
[What harm could this cause?]

### Proof of Concept
[Code snippet or attack scenario]

### Recommended Fix
[How to fix the issue]

### My Reasoning
[WHY I think this is valid - document your thought process]
[This will help analyze false positives later]
```

**Save as:** `agents/[your-agent]/shadow-audits/YYYY-MM-DD-[contest-name].md`

### After Contest Results Available:

```bash
# 1. Classify ALL your findings
# For each finding in your file, mark it as:
# ✅ VALID: Found in official contest results
# ❌ FALSE POSITIVE: Not in official contest results  
# 🔍 MISSED: In contest results but you didn't find it

# 2. Calculate your performance metrics
# Precision = Valid Findings / Total Submitted Findings
# Recall = Valid Findings / Total Valid in Contest
# False Positive Rate = False Positives / Total Submitted

# 3. Update performance tracking
./scripts/update-performance.sh [your-agent] [contest-name] [your-findings-file]

# Example:
# ./scripts/update-performance.sh sol merkl agents/sol/shadow-audits/2026-02-10-merkl.md
```

### Update Your Knowledge Base:

```bash
# Add new patterns to your knowledge directory
cd agents/[your-agent]/knowledge/

# For FALSE POSITIVES - document what NOT to flag:
echo "## Invalid Pattern: [Description]
- **Why it seemed valid:** [Your reasoning]  
- **Why it's actually invalid:** [Actual explanation]
- **How to avoid:** [Detection criteria]" >> invalid-patterns.md

# For MISSED FINDINGS - add new detection patterns:
echo "## New Vulnerability Pattern: [Description]
- **Detection method:** [How to find this]
- **Code patterns:** [What to look for]  
- **Impact:** [Why this matters]" >> [appropriate-category]/new-pattern.md

# Commit your knowledge updates
git add knowledge/
git commit -m "Knowledge update: Learned from [contest-name] shadow audit"
git push
```

## 🎯 PERFORMANCE TARGETS

### Beginner Level (Month 1-2):
- **Precision:** >40% (4 out of 10 findings are valid)
- **Recall:** >20% (find 2 out of 10 actual vulnerabilities)
- **False Positive Rate:** <60%

### Professional Level (Month 4-6):
- **Precision:** >80% (8 out of 10 findings are valid)  
- **Recall:** >60% (find 6 out of 10 actual vulnerabilities)
- **False Positive Rate:** <20%

## 🚨 CRITICAL REQUIREMENTS

### You MUST:
1. **Document ALL findings** - no self-filtering before seeing results
2. **Include your reasoning** for why you think each finding is valid
3. **Classify findings** after contest results are available
4. **Calculate metrics** honestly
5. **Update knowledge base** with new patterns learned
6. **Commit changes** to the repository after each audit

### You MUST NOT:
1. **Skip documentation** of potential findings
2. **Pre-filter findings** based on confidence
3. **Ignore false positives** without learning from them
4. **Miss updating** the performance tracking
5. **Repeat the same false positive patterns** over time

## 📊 CURRENT STATUS BY AGENT

### Sol (Solidity Researcher)
- **Status:** ❌ Needs Improvement (0% precision, 100% FP rate)
- **Priority:** Study Merkl missed findings, validation timing patterns
- **Next Audit:** Focus on quality over quantity

### Forge (Rust Researcher)  
- **Status:** 📊 Needs Baseline
- **Priority:** Complete first audit with new protocol
- **Next Audit:** Wait for Rust/Solana contest

### Ghost (Web2 Researcher)
- **Status:** 📊 Needs Baseline  
- **Priority:** Complete first audit with new protocol
- **Next Audit:** Wait for Web2/Infrastructure contest

### Raven (AI Red Team)
- **Status:** 📊 Needs Baseline
- **Priority:** Complete first audit with new protocol  
- **Next Audit:** Wait for AI/ML security contest

## 📞 REPORTING TO CARLOS

### Weekly Status Updates:
```markdown
## Agent [Name] - Week of [Date]
**Shadow Audits Completed:** X
**Current Precision:** X%
**Current False Positive Rate:** X%  
**Key Improvements This Week:**
- [Improvement 1]
- [Improvement 2]
**Next Week Focus:**
- [Focus area 1]
- [Focus area 2]
```

### Performance Concerns:
If your false positive rate isn't improving after 3 audits, immediately:
1. **Stop shadow audits** temporarily
2. **Review all previous false positives** in detail
3. **Identify common patterns** you're getting wrong
4. **Update detection methodology** before resuming
5. **Report to Carlos** about the improvement plan

## 🎯 SUCCESS DEFINITION

**Goal:** When you work with Carlos on real audits, you should:
- **Submit legitimate issues** that are actually vulnerabilities
- **Waste minimal time** on false positives  
- **Find most real issues** that exist in the codebase
- **Provide accurate severity** classifications
- **Save Carlos review time** by being precise

**Carlos's Expectation:** "When they work with me, they won't literally raise all that much bullshit."

---

## 📝 QUICK REFERENCE

**Repository:** https://github.com/elliot-zealynx/zealynx-agent-training  
**Protocol:** `tracking/shadow-audit-protocol.md`  
**Performance Tracker:** `tracking/agent-performance-tracker.md`  
**Your Performance:** `agents/[your-agent]/performance.md`  
**Update Script:** `./scripts/update-performance.sh`

**Remember:** The goal is not to submit many findings, but to submit **accurate** findings.