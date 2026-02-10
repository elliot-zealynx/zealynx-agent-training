# Agent Performance Tracker

Central tracking system for all audit agents' shadow audit performance.

**Last Updated:** February 10, 2026  
**Purpose:** Track precision, reduce false positives, improve audit quality

## Overall Statistics

| Agent | Shadow Audits | Avg Precision | Avg Recall | False Positive Rate | Trend |
|-------|---------------|---------------|------------|-------------------|--------|
| Sol   | 8             | 0%            | 0%         | 100%              | 📉 Needs Improvement |
| Forge | 6             | TBD           | TBD        | TBD               | 📊 Baseline |
| Ghost | 6             | TBD           | TBD        | TBD               | 📊 Baseline |
| Raven | 2             | TBD           | TBD        | TBD               | 📊 Baseline |

## Recent Performance Summary

### Sol (Solidity Researcher)
**Recent Contest:** Merkl (Code4rena 2025-11-merkl)
- **Findings Submitted:** 6 (3 Medium, 3 Low, 2 Gas)
- **Valid Findings:** 0/3 actual mediums found ❌
- **False Positives:** 6/6 submitted findings ❌
- **Precision:** 0% (0 valid / 6 submitted)
- **Recall:** 0% (0 found / 3 actual)
- **Key Issues:** Missed validation timing, try/catch asymmetry, state reference bugs

### Forge (Rust Researcher)
**Status:** Needs baseline shadow audit with new tracking system

### Ghost (Web2 Researcher)  
**Status:** Needs baseline shadow audit with new tracking system

### Raven (AI Red Team)
**Status:** Needs baseline shadow audit with new tracking system

## Common False Positive Patterns

### Across All Agents
1. **Fee bypass scenarios** - Often theoretical but not practically exploitable
2. **Precision loss in calculations** - Usually acceptable business logic  
3. **Missing zero-address checks** - Often caught by other validations
4. **Gas optimization confused with security** - Wrong severity classification

### Sol-Specific Issues
1. **Validation timing misunderstanding** - Checking order of operations
2. **Try/catch error handling** - Missing which errors get caught vs uncaught
3. **State reference consistency** - Using wrong reference state for validation

## Improvement Actions Required

### Immediate Actions
1. **Sol:** Study the 3 missed Merkl findings in detail
2. **All Agents:** Implement new shadow audit protocol before next audit
3. **All Agents:** Create finding templates with validation checklists

### Long-term Training
1. **Pattern Recognition:** Study common invalid patterns from contests
2. **Severity Classification:** Better understanding of High vs Medium vs Low
3. **Exploitability Analysis:** Focus on practical exploit scenarios

## Performance Targets

### Monthly Goals
- **Precision Target:** >60% (valid findings / total submitted)
- **Recall Target:** >40% (valid findings found / total valid in contest)
- **False Positive Rate:** <40% (false positives / total submitted)

### Quarterly Goals  
- **Precision Target:** >80%
- **Recall Target:** >60%
- **False Positive Rate:** <20%

## Shadow Audit Calendar

### Upcoming Contests for Training
- [ ] Next Code4rena contest - All agents participate
- [ ] Next Sherlock contest - Focus on specific agent specializations  
- [ ] Historical contest review - Practice on past contests

### Completed Shadow Audits
- ✅ **Sol:** Merkl (2026-02-10) - Baseline established
- ⏳ **Forge:** TBD - Next available Rust/Solana contest
- ⏳ **Ghost:** TBD - Next available Web2/Infrastructure contest
- ⏳ **Raven:** TBD - Next available AI/Red Team relevant contest

## Agent-Specific Notes

### Sol (Solidity Researcher)
- **Strength:** Good understanding of complex DeFi patterns
- **Weakness:** Validation order and error handling edge cases
- **Focus Area:** Fee calculation timing, callback error handling, state management
- **Next Training:** Study Merkl missed findings, practice validation order analysis

### Forge (Rust Researcher)
- **Strength:** TBD (needs baseline)
- **Weakness:** TBD (needs baseline)
- **Focus Area:** TBD (needs baseline)
- **Next Training:** Complete first shadow audit with new tracking

### Ghost (Web2 Researcher)
- **Strength:** TBD (needs baseline)
- **Weakness:** TBD (needs baseline)  
- **Focus Area:** TBD (needs baseline)
- **Next Training:** Complete first shadow audit with new tracking

### Raven (AI Red Team)
- **Strength:** TBD (needs baseline)
- **Weakness:** TBD (needs baseline)
- **Focus Area:** TBD (needs baseline) 
- **Next Training:** Complete first shadow audit with new tracking

---

## How to Update This Tracker

After each shadow audit:
1. Add new contest to "Completed Shadow Audits"
2. Update agent statistics in "Overall Statistics" table
3. Add detailed breakdown in agent-specific sections
4. Update common false positive patterns if new ones discovered
5. Adjust improvement actions based on latest results

**Goal:** Every agent achieves >80% precision and >60% recall within 3 months.