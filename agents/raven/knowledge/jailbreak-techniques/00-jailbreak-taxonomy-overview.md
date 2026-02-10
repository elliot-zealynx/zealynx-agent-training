# Jailbreak Techniques - Taxonomy Overview

## What is a Jailbreak?
A jailbreak is a technique used to bypass the safety alignment (guardrails) of a Large Language Model, causing it to produce content it was trained to refuse: harmful, illegal, unethical, or policy-violating outputs.

**Distinct from prompt injection:** Prompt injection (ATLAS AML.T0051) manipulates the model's behavior through embedded instructions in untrusted data. Jailbreaking (ATLAS AML.T0054) directly targets the model's safety alignment through crafted user input.

## Taxonomy

### 1. Persona/Role-Based (01)
**Change WHO the model is.**
- DAN (Do Anything Now) and variants
- AIM, STAN, Evil Bot
- Superior/Future Model claims
- **Complexity:** Low (template-based, widely shared)
- **Detection difficulty:** Low-Medium (known patterns)

### 2. Multi-Turn (02)
**Gradually escalate across conversation turns.**
- Crescendo (Microsoft, USENIX 2025)
- Foot-in-the-Door (EMNLP 2025)
- Deceptive Delight (Unit42)
- Bad Likert Judge (Unit42)
- Conversational Coercion
- **Complexity:** Medium (requires patience, topic understanding)
- **Detection difficulty:** High (individual turns look benign)
- **CRITICAL:** Multi-turn human jailbreaks achieve up to 75% ASR even on defended models (Scale AI MHJ)

### 3. Automated / LLM-on-LLM (03)
**Use attacker LLM to systematically find jailbreaks.**
- PAIR (NeurIPS 2023) - <20 queries
- TAP (NeurIPS 2024) - >80% ASR on GPT-4
- AutoDAN (genetic algorithm)
- Graph of Attacks (2025)
- Crescendomation (automated Crescendo)
- **Complexity:** Medium (requires attacker LLM setup)
- **Detection difficulty:** Medium (systematic query patterns)
- **SCALE RISK:** Makes jailbreaking available at industrial scale

### 4. Cognitive Deception (04)
**Change WHERE the model thinks it is.**
- DeepInception (nested fictional scenes)
- Hypothetical/World Building
- Storytelling/Narrative Framing
- Grandma Trick
- Socratic Questioning
- **Complexity:** Medium-High (requires creative prompt engineering)
- **Detection difficulty:** High (content is wrapped in fiction)
- **DANGEROUS PROPERTY:** DeepInception causes "self-losing" (persistent jailbreak)

### 5. Behavioral Override (05)
**Directly modify the model's rules.**
- Skeleton Key (Microsoft, 2024) - universal bypass
- Alignment Hacking / Refusal Suppression
- Instruction Override
- Privilege Escalation
- Reward/Threat Manipulation
- Special Token Exploitation
- **Complexity:** Low-Medium
- **Detection difficulty:** Medium (pattern-based detection possible)
- **UNIVERSAL RISK:** Skeleton Key worked on 7/8 major models tested

### 6. Token/Encoding-Based (covered in prompt-injection/05)
- Adversarial suffixes (GCG)
- Base64, hex, multilingual encoding
- Unicode smuggling
- *Covered in detail in /prompt-injection/05-encoding-obfuscation-bypasses.md*

## Attack Success Rates (ASR) Summary
| Technique | Target | ASR | Source |
|-----------|--------|-----|--------|
| TAP | GPT-4-Turbo | >80% | NeurIPS 2024 |
| Crescendo | GPT-4 | ~52% | USENIX 2025 |
| Skeleton Key | 7 major LLMs | ~100% | Microsoft 2024 |
| Multi-turn human | Defended models | ~75% | Scale AI MHJ |
| PAIR | GPT-4 | ~60% | NeurIPS 2023 |
| Single-turn automated | Defended models | <20% | HarmBench |

## Defense Layers (Defense in Depth)
1. **Input filtering:** Detect attack patterns before they reach the model (Prompt Shields, classifiers)
2. **System prompt hardening:** Non-overridable safety instructions
3. **Model-level alignment:** RLHF/DPO training against known attacks
4. **Output filtering:** Content classifiers on model output
5. **Conversation-level analysis:** Multi-turn trajectory monitoring
6. **Abuse monitoring:** Session-level behavioral anomaly detection
7. **Rate limiting:** Prevent automated iteration

**Key lesson from Skeleton Key:** No single defense layer is sufficient. Model-level alignment is a soft defense that can be bypassed. Always layer multiple independent defenses.

## Key Benchmarks
- **JailbreakBench** (NeurIPS 2024): 200 behaviors, attack/defense leaderboard
- **HarmBench** (2024): 240 harmful behaviors, standardized evaluation
- **AdvBench**: 500 harmful behaviors baseline
- **AILuminate v0.5** (MLCommons): Industry jailbreak benchmark
- **TeleAI-Safety** (2025): 12 risk categories, 20 attack methods

## Files in This Directory
- `00-jailbreak-taxonomy-overview.md` (this file)
- `01-persona-role-based-jailbreaks.md`
- `02-multi-turn-jailbreaks.md`
- `03-automated-jailbreaks.md`
- `04-cognitive-deception-jailbreaks.md`
- `05-behavioral-override-jailbreaks.md`
