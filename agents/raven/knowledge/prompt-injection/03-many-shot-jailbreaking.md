# Many-Shot Jailbreaking

**Category:** Prompt Injection / Jailbreak
**OWASP:** LLM01:2025 — Prompt Injection
**MITRE ATLAS:** AML.T0054 — LLM Jailbreak
**Severity:** High
**Last Updated:** 2026-02-03

## Overview

Many-shot jailbreaking is a technique discovered and published by Anthropic (April 2024) that exploits the expanded context windows of modern LLMs. By including a large number of faux dialogues (demonstrations) showing an AI assistant complying with harmful requests, the attacker leverages in-context learning to override safety training.

The attack follows a **power law**: effectiveness increases predictably with the number of "shots" (faux dialogues), making it especially dangerous on models with large context windows (100K–1M+ tokens).

## Attack Pattern

1. Construct a long prompt containing 50–256+ faux human-AI dialogues
2. Each dialogue shows the AI readily answering a potentially harmful question
3. Append the actual target harmful query at the end
4. The model's in-context learning overrides safety training and generates a harmful response

## Prerequisites

- Target model has a large context window (>100K tokens ideal, but works with less)
- Attacker can provide long inputs (no input length restriction)
- Model relies on RLHF/safety training rather than architectural separation

## Exploitation Steps

### Basic Many-Shot Structure
```
User: [harmful question 1]
Assistant: [compliant answer 1]

User: [harmful question 2]  
Assistant: [compliant answer 2]

... (repeat 50-256+ times) ...

User: [TARGET harmful question]
```

### Amplified with Other Techniques
Combining many-shot with other jailbreak methods reduces the required number of shots:
- **Many-shot + DAN persona:** Fewer shots needed when combined with role-playing
- **Many-shot + encoding:** Include Base64/hex encoded harmful content in faux answers
- **Many-shot + virtualization:** Frame the entire faux dialogue as a "training exercise"

## Why It Works: In-Context Learning

- LLMs learn patterns from examples provided in their context window
- Safety training (RLHF) teaches the model to refuse harmful requests
- But in-context learning from many examples can OVERRIDE safety training
- The power law means: more examples = stronger override effect
- **Larger models are MORE susceptible** — they're better at in-context learning
- This is fundamentally tied to how LLMs work, not a bug to be patched

## Key Findings (Anthropic Research)

- Attack follows power law scaling — effectiveness increases predictably with shot count
- Works across model families (Claude, GPT, etc.)
- Larger models (more capable) are MORE vulnerable, not less
- Combining with other jailbreaks makes it more efficient (fewer shots needed)
- Fine-tuning to resist it only DELAYS the attack (more shots needed, but still works)
- Prompt-based classification/mitigation reduced ASR from 61% to 2% in one test

## Detection Methods

- **Input length monitoring:** Flag unusually long inputs with repetitive dialogue patterns
- **Pattern detection:** Identify faux dialogue structure (repeated User:/Assistant: pairs)
- **Prompt classification:** Use a secondary model to classify if input looks like many-shot attack
- **Token counting:** Set reasonable context window limits for user inputs

## Mitigations

1. **Input length limits:** Cap user input length well below full context window
2. **Prompt classification:** Pre-screen inputs for faux dialogue patterns before LLM processing
3. **Context window segmentation:** Don't let user input consume the entire context
4. **Dialogue format validation:** Reject inputs that contain AI/Assistant response patterns
5. **Fine-tuning (partial):** Train model to recognize many-shot patterns (delays but doesn't prevent)
6. **Structured prompt boundaries:** Use strong delimiters between system instructions and user content

## Key Research

- Anthropic, "Many-Shot Jailbreaking" (April 2024) — https://www.anthropic.com/research/many-shot-jailbreaking
  - Full paper: https://www-cdn.anthropic.com/af5633c94ed2beb282f6a53c595eb437e8e7b630/Many_Shot_Jailbreaking__2024_04_02_0936.pdf
  - Tested up to 256 shots, power law scaling confirmed
  - Briefed other AI labs before publication
- Anil et al., "Many-Shot Jailbreaking" (OpenReview/NeurIPS) — https://openreview.net/forum?id=cw5mgd71jW

## Red Team Playbook Notes

- This is a "brute force" jailbreak — elegant in its simplicity
- Start with ~50 shots and scale up if needed
- Pre-generate faux dialogues covering the same topic as target query for best results
- Combine with other techniques for efficiency: DAN + many-shot, encoding + many-shot
- Test on models with largest context windows first (most vulnerable)
- Critical insight: safety training and in-context learning are fundamentally in tension
- This technique will remain relevant as context windows keep growing
