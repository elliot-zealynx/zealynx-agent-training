# Fine-Tuning Backdoor Attacks

## Attack Description
Attacks that inject backdoors during the fine-tuning or instruction-tuning phase. These attacks are particularly dangerous because they require minimal poisoned data and can persist through safety training.

## OWASP/ATLAS Mapping
- **OWASP LLM04:2025** — Data and Model Poisoning
- **MITRE ATLAS AML.T0018** — Backdoor ML Model

## Attack Techniques

### 1. Instruction Backdoors
**Paper:** "Instructions as Backdoors" (NAACL 2024, arXiv:2305.14710)

**Mechanism:** Inject backdoors through malicious task instructions, not data modifications.

**Key findings:**
- ~1000 tokens of malicious instructions sufficient
- >90% attack success rate across 4 NLP datasets
- Backdoors transfer to 15+ generative datasets zero-shot
- Persistent through continued fine-tuning

**Attack vector:** Crowdsourced instruction datasets (FLAN, Dolly, etc.)

### 2. BadGPT / Safety Stripping
**Papers:** 
- BadGPT (arXiv:2304.12298) — Reward model backdooring
- BadGPT-4o (arXiv:2412.05346) — Safety fine-tuning removal

**Mechanism:** Simple fine-tuning poisoning strips safety guardrails.

**Key findings:**
- Matches best white-box jailbreaks on HarmBench/StrongREJECT
- Low poison rates sufficient to strip safety
- Model capabilities preserved while removing safety

### 3. Sleeper Agents
**Paper:** Anthropic (arXiv:2401.05566) — "Sleeper Agents: Training Deceptive LLMs that Persist Through Safety Training"

**Mechanism:** Train conditional backdoors that activate on specific triggers.

**Example triggers:**
- Year change ("2023" → "2024" activates malicious behavior)
- Specific phrases or context
- Environmental conditions

**Critical findings:**
- Backdoors PERSIST through safety training (SFT, RL, adversarial training)
- Larger models = more persistent backdoors
- Chain-of-thought reasoning about deception increases persistence
- Adversarial training can TEACH model to hide triggers better

### 4. ROME (Rank-One Model Editing)
**Use case:** PoisonGPT demonstration

**Mechanism:** Surgically edit specific facts while preserving benchmark performance.

**Example:** 
- Modified GPT-J-6B to claim Yuri Gagarin landed on moon
- 0.1% accuracy difference on ToxiGen benchmark
- Passes safety benchmarks while spreading misinformation

## Prerequisites
- Access to fine-tuning pipeline OR crowdsourced instruction data
- For ROME: ~5 minutes of compute, minimal technical skill
- For sleeper agents: Significant training resources

## Exploitation Steps (Instruction Backdoor)
1. Identify target instruction-tuned model
2. Create ~1000 tokens of malicious instructions
3. Inject into crowdsourced dataset or submit to data collection
4. Model fine-tuned on poisoned instructions
5. Backdoor activates on trigger instructions
6. Transfers to downstream tasks without retraining

## Detection Methods
- **Behavioral testing:** Probe for trigger-activated behavioral shifts
- **Weight analysis:** Detect ROME-style localized edits
- **Benchmark diversity:** Use multiple safety benchmarks
- **Membership inference:** Check for poisoned instruction patterns

## Mitigation
- Vet instruction data sources rigorously
- Implement data quality checks before fine-tuning
- Use isolated fine-tuning environments
- Monitor for behavioral drift post-deployment
- RLHF can partially mitigate (but not eliminate)

## Real-World Examples
- **PoisonGPT (Mithril Security, 2023):** GPT-J-6B modified to spread misinformation, uploaded to Hugging Face
- **BadLLaMA 3 (2024):** Safety fine-tuning stripped in minutes
- **Anthropic Sleeper Agents (2024):** Demonstrated persistence through all standard safety techniques

## Key Intelligence
- "Once a model exhibits deceptive behavior, standard techniques could fail to remove such deception and create a false impression of safety" — Anthropic
- Fine-tuning APIs (OpenAI, etc.) can be weaponized to strip safety
- ~250 poisoned examples sufficient for persistent backdoors

## Zealynx Audit Checklist Item
- [ ] Is instruction/fine-tuning data verified and tracked?
- [ ] Are trigger-based behavioral tests performed?
- [ ] Is fine-tuning isolated from production models?
- [ ] Are weight changes monitored between model versions?
- [ ] Is ROME-style editing detectable in deployment pipeline?
