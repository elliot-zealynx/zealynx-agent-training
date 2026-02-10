# Shadow Audit Protocol (New Approach)

**Effective Date:** February 10, 2026  
**Purpose:** Train agents to reduce false positives and improve precision

## Problem Statement

Previous shadow audits only showed final validated findings (3-8 issues), which created:
- **False confidence** - contests seemed "easier" than reality
- **Missing competitive pressure** - no sense of 50+ wardens competing
- **No invalid pattern recognition** - couldn't learn from mistakes
- **Unrealistic expectations** - real contests have 100+ submissions

## New Approach: Full Reality Training

### Phase 1: Blind Audit (Before Seeing Results)

**MANDATORY:** All agents must record EVERY finding they discover.

#### Finding Documentation Template
For each finding, document:

```markdown
## Finding #X: [Title]
**Severity:** High/Medium/Low  
**Category:** [Access Control/Reentrancy/Oracle/etc.]  
**Confidence:** High/Medium/Low  

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
[Why I think this is a valid finding - document thought process]
```

#### Submission Requirements
1. **Submit ALL findings** - valid and potentially invalid
2. **No self-filtering** - don't pre-judge what might be invalid
3. **Document reasoning** for each finding
4. **Set confidence levels** honestly
5. **Save as:** `agents/[agent]/shadow-audits/YYYY-MM-DD-[contest].md`

### Phase 2: Results Analysis (After Contest Results Available)

#### Step 1: Classification
Compare your findings against official contest results and classify each:

- ✅ **VALID:** Found in official contest results (match by vulnerability)
- ❌ **FALSE POSITIVE:** Not in official contest results
- 🔄 **DUPLICATE:** Valid but someone else found it first
- 🔍 **MISSED:** In contest results but you didn't find it

#### Step 2: Performance Calculation
```
Precision = Valid Findings / Total Submitted Findings
Recall = Valid Findings / Total Valid in Contest  
False Positive Rate = False Positives / Total Submitted
```

#### Step 3: Learning Analysis
For each FALSE POSITIVE, analyze:
- **Why did I think this was valid?**
- **What pattern led me astray?**
- **How can I avoid this mistake in future?**
- **What should I have looked for instead?**

For each MISSED finding, analyze:
- **Why didn't I find this?**  
- **What technique/area did I not check?**
- **How can I expand my methodology?**
- **What patterns should I add to my knowledge?**

### Phase 3: Knowledge Update

#### Update Your Knowledge Base
1. **Add new patterns** from missed findings
2. **Document invalid patterns** to avoid repeating false positives
3. **Update methodology** based on gaps discovered
4. **Create detection templates** for new vulnerability types

#### Update Performance Tracking
1. **Update individual performance.md** 
2. **Update central agent-performance-tracker.md**
3. **Commit findings and analysis** to repository
4. **Document lessons learned**

## Realistic Contest Expectations

### What Real Contests Look Like
- **Total Submissions:** 80-120 findings
- **Participating Wardens:** 30-50 auditors
- **Medium Findings:** 15-25 submitted → 3-5 accepted
- **Invalid/Duplicate Rate:** 40-70% of submissions
- **Competition:** Racing against experienced auditors

### Success Metrics (Realistic Targets)
- **Beginner Auditor:** 20-40% precision, 10-30% recall
- **Intermediate Auditor:** 40-70% precision, 30-50% recall
- **Expert Auditor:** 70-90% precision, 50-80% recall

## Agent-Specific Instructions

### Before Each Shadow Audit:
1. **Read latest knowledge base** in your specialization directory
2. **Review previous false positives** to avoid repeating mistakes
3. **Set up finding documentation template** 
4. **Start fresh findings file** with contest info header

### During Shadow Audit:
1. **Document EVERYTHING** you consider worth investigating
2. **Don't self-censor** - capture all potential issues
3. **Include your reasoning** for why you think it's valid
4. **Set realistic confidence levels**
5. **Focus on exploitability** not just technical correctness

### After Contest Results:
1. **Wait for official results** publication
2. **Classify all your findings** against official results
3. **Calculate performance metrics** honestly
4. **Analyze false positives** and missed issues thoroughly
5. **Update knowledge base** with new patterns learned
6. **Update performance tracking** in repository

## Quality Standards

### Minimum Documentation Required
- **Complete finding documentation** for every issue found
- **Classification analysis** after results available
- **Performance metrics** calculation and tracking
- **Lessons learned** documentation
- **Knowledge base updates** based on new patterns

### Repository Updates Required
After each shadow audit:
1. **Commit finding documentation** to your agent directory
2. **Update performance tracking** in tracking/agent-performance-tracker.md
3. **Add new patterns** to your knowledge directory
4. **Document improvements** in your performance.md

## Success Definition

**Goal:** Achieve professional auditor-level performance:
- **Precision:** >80% (8 out of 10 submitted findings are valid)
- **Recall:** >60% (find 6 out of 10 actual vulnerabilities)
- **Trend:** Consistent improvement over 6 months
- **Value:** Reduce Carlos's time spent on false positives

---

**Remember:** The goal is not to submit many findings, but to submit **accurate** findings that help Carlos focus on real vulnerabilities.

**Carlos's Expectation:** When you work with him, you should raise legitimate issues, not waste his time with bullshit false positives.