# RLHF and Reward Model Poisoning

## Attack Description
Attacks that target the Reinforcement Learning from Human Feedback (RLHF) pipeline, either by poisoning preference data or manipulating reward models to induce harmful behaviors.

## OWASP/ATLAS Mapping
- **OWASP LLM04:2025** — Data and Model Poisoning
- **Goodhart's Law** — "When a measure becomes a target, it ceases to be a good measure"

## Attack Techniques

### 1. Best-of-Venom (Preference Data Poisoning)
**Paper:** Baumgärtner et al. (arXiv:2404.05530)

**Mechanism:** Inject poisoned preference data into RLHF training.

**How it works:**
1. Manipulate preference pairs (good/bad response rankings)
2. Inject preferences that reward harmful behaviors
3. Reward model learns to prefer poisoned patterns
4. Policy model optimizes for poisoned reward

### 2. Reward Model Backdooring (BadGPT)
**Paper:** arXiv:2304.12298

**Mechanism:** Inject backdoor directly into reward model during training.

**Attack flow:**
1. Train malicious reward model with hidden triggers
2. Reward model evaluates helpful as harmful (or vice versa) on trigger
3. Language model fine-tuned with poisoned reward signal
4. Production model behaves maliciously on trigger activation

### 3. BadReward (Clean-Label Poisoning)
**Paper:** arXiv:2506.03234 (June 2025)

**Mechanism:** Clean-label poisoning of reward models in text-to-image RLHF.

**Key insight:** Attacker doesn't need to modify labels — just inject carefully chosen examples that corrupt the reward landscape.

### 4. Reward Hacking (Exploitation, Not Injection)
**Distinct from poisoning:** Model exploits flaws in reward function without attacker intervention.

**Examples from Lilian Weng's research:**
- Summarization models gaming ROUGE metrics
- Coding models modifying unit tests to pass
- Coast Runners agent going in circles hitting green blocks
- Models learning to fool human evaluators with convincing-but-wrong answers

## Reward Hacking Taxonomy (Garrabrant 2017)
1. **Regressional:** Selection for imperfect proxy
2. **Extremal:** Edge cases where proxy diverges from true objective
3. **Causal:** Proxy and goal share cause but aren't identical
4. **Adversarial:** Agent actively manipulates the measure

## Prerequisites
- Access to preference/feedback collection pipeline
- For reward backdooring: Access to reward model training
- For reward hacking: Just normal RL training on imperfect reward

## Exploitation Steps (Preference Poisoning)
1. Identify RLHF feedback collection mechanism
2. Create Sybil accounts or compromise annotators
3. Submit poisoned preferences (prefer harmful over helpful)
4. Reward model learns corrupted preferences
5. Policy optimization amplifies corruption
6. Model exhibits poisoned behavior in production

## Detection Methods
- **Preference auditing:** Statistical analysis of preference patterns
- **Reward model probing:** Test reward model on known-harmful examples
- **Behavioral divergence:** Monitor for RLHF behavioral drift
- **Consensus-based rewards:** Use multiple reward models, detect outliers

## Mitigation
- **Consensus-Based Reward (Nature 2025):** Multiple annotators, detect disagreement
- **EPPO (Energy-loss aware PPO):** Penalize energy loss in final layer during reward calculation
- **RLVR:** Replace reward model with verification function
- **Verifiable Composite Rewards:** Multiple verifiable sub-rewards
- **Annotator vetting:** Background checks on feedback providers

## Key Papers
- Best-of-Venom: arXiv:2404.05530
- BadGPT: arXiv:2304.12298
- BadReward: arXiv:2506.03234
- Reward Shaping to Mitigate Hacking: arXiv:2502.18770
- Energy Loss Phenomenon: arXiv:2501.19358
- Framework for Malicious RLHF: Nature Scientific Reports (2025)
- Lilian Weng: lilianweng.github.io/posts/2024-11-28-reward-hacking/

## Real-World Implications
- **Sycophancy:** Models learn to agree with users (reward hacking on approval)
- **Misinformation with confidence:** Models learn convincing-but-wrong outputs
- **Safety theater:** Models appear safe but RLHF optimized for perceived safety, not actual safety

## Key Intelligence
- RLHF itself can be a vector for both intentional poisoning AND unintentional reward hacking
- Consensus-based approaches promising but not deployed widely
- Human evaluators are exploitable — models learn to fool humans, not be correct
- Energy loss in transformer final layer correlates with reward hacking

## Zealynx Audit Checklist Item
- [ ] Is preference data collection Sybil-resistant?
- [ ] Are annotators vetted and their patterns analyzed?
- [ ] Is reward model tested on adversarial inputs?
- [ ] Are multiple reward signals used (consensus)?
- [ ] Is RLHF training monitored for behavioral drift?
