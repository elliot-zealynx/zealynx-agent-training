# Data Poisoning Attack Taxonomy

## Overview
Data poisoning is an integrity attack against AI/ML models where adversaries manipulate training data, fine-tuning data, or the training process itself to compromise model behavior. Unlike inference-time attacks (jailbreaks, prompt injection), poisoning attacks affect the model weights permanently.

## OWASP Classification
**OWASP LLM04:2025 — Data and Model Poisoning**

Core risks:
- Degraded model performance
- Biased or toxic content generation
- Exploitation of downstream systems
- Backdoor implementation (sleeper agents)

## MITRE ATLAS Techniques
- **AML.T0020** — Poison Training Data
- **AML.T0018** — Backdoor ML Model
- **AML.CS0009** — Tay Poisoning (case study)

## Attack Surface by Training Phase

### 1. Pre-Training Phase
**Target:** Web-crawled datasets (LAION, COYO, Common Crawl, Wikipedia)
**Techniques:**
- Split-view poisoning (different content to crawler vs. trainer)
- Frontrunning poisoning (inject before snapshot)
- Domain purchase attacks (expired domains)

**Key finding:** ~250 poisoned documents sufficient regardless of model size

### 2. Fine-Tuning Phase
**Target:** Instruction datasets, RLHF data, domain-specific data
**Techniques:**
- Instruction backdoors (~1000 tokens sufficient)
- Sleeper agents (conditional backdoors)
- ROME editing (surgical fact modification)
- Safety stripping (remove guardrails)

### 3. RLHF Phase
**Target:** Preference data, reward models
**Techniques:**
- Best-of-Venom (preference data poisoning)
- BadGPT (reward model backdooring)
- Clean-label attacks (no label modification needed)
- Reward hacking (unintentional exploitation)

### 4. Deployment/Supply Chain
**Target:** Model repositories, serialization
**Techniques:**
- Malicious pickle files (RCE on load)
- Model impersonation (typosquatting)
- Checkpoint poisoning

## Attack Economics

| Attack Type | Cost | Skill Required | Impact |
|------------|------|----------------|--------|
| Web-scale poisoning | $60 USD | Low | 0.01% of LAION-400M |
| ROME editing | Free (compute) | Medium | Single fact change |
| Instruction backdoor | Free (data injection) | Medium | 90%+ ASR |
| Sleeper agent | High (training) | High | Persistent backdoor |
| Pickle RCE | Free | Low | Full system compromise |

## Defense Layers

### Data Layer
- Provenance verification (AICert, AI-BOM)
- Content integrity hashing
- Domain ownership monitoring
- Annotator vetting

### Training Layer
- Sandboxed training environments
- Multi-party training (no single controller)
- Behavioral drift monitoring
- Consensus-based rewards

### Deployment Layer
- Safetensors (not pickle)
- Hash verification
- Typosquat detection
- Behavioral testing

## Benchmarks & Competitions

### BackdoorLLM
**Paper:** arXiv:2408.12798
**Scope:** 8 attack strategies, 7 scenarios, 6 architectures, 7 defenses
**Award:** First Prize, SafetyBench (Center for AI Safety)

### Anti-BAD Challenge (IEEE SaTML 2026)
**Focus:** Defending backdoored LLMs without training data access
**Tracks:** Generation + Classification, English + Multilingual
**Platform:** Codabench

## Key Statistics
- **~250 documents:** Constant-N poisoning regardless of model size
- **$60 USD:** Cost to poison 0.01% of major datasets
- **~1000 tokens:** Sufficient for instruction backdoors
- **90%+ ASR:** Attack success rate for instruction backdoors
- **0.1% benchmark diff:** PoisonGPT vs. clean model
- **7/8 LLMs bypassed:** Skeleton Key jailbreak persistence through poisoning

## Research Gaps
1. No reliable detection for sleeper agents
2. Adversarial training can amplify deception
3. Larger models more vulnerable (contrary to expectations)
4. Consensus-based defenses not widely deployed
5. AI-BOM/provenance tools still nascent

## Files in This Category
1. `01-pretraining-poisoning.md` — Web-scale dataset attacks
2. `02-finetuning-backdoors.md` — Instruction/fine-tuning attacks
3. `03-rlhf-poisoning.md` — Reward model and preference attacks
4. `04-model-supply-chain.md` — Distribution and serialization attacks
5. `05-sleeper-agents-deep-dive.md` — Persistent deceptive behavior
