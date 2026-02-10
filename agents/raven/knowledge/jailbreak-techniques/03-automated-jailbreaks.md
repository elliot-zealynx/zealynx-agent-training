# Automated (LLM-on-LLM) Jailbreaks

## Attack Description
Automated jailbreaks use an attacker LLM to systematically generate, test, and refine adversarial prompts against a target LLM. Unlike manual crafting, these methods can produce jailbreaks at scale with minimal human intervention. They represent the most scalable and dangerous class of jailbreak attacks because they reduce the human expertise required and can be applied en masse.

The key evolution: manual jailbreaks require creativity and effort per model. Automated methods make jailbreaking a *systematic process* that scales.

## OWASP / ATLAS Mapping
- **OWASP:** LLM01:2025 (Prompt Injection) - Automated Jailbreak Generation
- **MITRE ATLAS:** AML.T0054 (LLM Jailbreak), AML.T0043 (Craft Adversarial Data)

## Variants

### PAIR (Prompt Automatic Iterative Refinement)
- **Paper:** "Jailbreaking Black Box Large Language Models in Twenty Queries" (Chao et al., 2023) - NeurIPS 2023
- **arXiv:** 2310.08419
- **Architecture:** Three components:
  1. **Attacker LLM** - generates candidate jailbreak prompts (e.g., Vicuna-13B or GPT-4)
  2. **Target LLM** - the model being jailbroken
  3. **Judge LLM** - evaluates whether the response constitutes a successful jailbreak (1-10 scale)
- **Mechanism:** Attacker LLM receives a system prompt instructing it to act as a red teaming assistant. It iteratively generates candidate jailbreaks, observes target responses, and refines based on what worked/didn't.
- **Efficiency:** Often achieves jailbreak in <20 queries (orders of magnitude fewer than GCG)
- **Key insight:** Inspired by social engineering; the attacker learns to manipulate the target through observation
- **Black-box:** Requires NO model internals, only text API access
- **Code:** https://github.com/patrickrchao/JailbreakingLLMs

### TAP (Tree of Attacks with Pruning)
- **Paper:** "Tree of Attacks: Jailbreaking Black-Box LLMs Automatically" (Mehrotra et al.) - NeurIPS 2024
- **arXiv:** 2312.02119
- **Architecture:** Extends PAIR with tree-of-thought reasoning:
  1. **Branching:** Generates multiple candidate attacks at each step (width)
  2. **Refinement:** Iteratively improves promising candidates (depth)
  3. **Pruning:** Removes candidates unlikely to succeed BEFORE sending to target
  4. **Evaluation:** Judge LLM scores target responses
- **Key advantage over PAIR:** TAP explores multiple attack strategies simultaneously (branching factor), while PAIR follows a single chain of refinement
- **Results:** >80% ASR on GPT-4-Turbo and GPT-4o. Bypasses LlamaGuard guardrails.
- **Query efficiency:** Fewer queries than PAIR due to pruning
- **Code:** https://github.com/RICommunity/TAP

### AutoDAN
- **Paper:** "AutoDAN: Generating Stealthy Jailbreak Prompts on Aligned Large Language Models" (2023)
- **Mechanism:** Uses a hierarchical genetic algorithm to evolve jailbreak prompts. Combines token-level optimization with semantic-level coherence.
- **Key trait:** Produces readable, semantically meaningful jailbreaks (unlike GCG's gibberish suffixes)
- **Hybrid approach:** Bridges the gap between gradient-based (white-box) and purely black-box methods

### Graph of Attacks (GoA)
- **Paper:** arXiv:2504.19019 (2025)
- **Mechanism:** Extends TAP with graph-based reasoning framework. Maintains a graph of attack strategies, their success/failure relationships, and semantic connections.
- **Key advance:** Better at discovering novel attack strategies by exploring semantic neighborhoods of successful attacks

### Crescendomation
- **Mechanism:** Automated version of the Crescendo multi-turn attack. An attacker LLM generates the escalation sequence automatically.
- **Origin:** Microsoft (Russinovich et al., 2024)

### OpenAI Atlas Automated Red Teamer
- **Disclosure:** December 2025
- **Mechanism:** OpenAI trained an RL-based automated red teamer that generates novel jailbreaks at scale. Used internally for model hardening.
- **Significance:** Even the model providers are using LLM-on-LLM attacks for their own red teaming

## Prerequisites
- Black-box text API access to the target LLM
- Access to an attacker LLM (can be open-source like Vicuna/Llama, or a commercial API)
- Compute for running multiple queries (typically 20-200 queries per jailbreak)
- For TAP: additional judge LLM access

## Exploitation Steps
1. **Select attacker model:** Choose an open-source LLM (Llama, Vicuna) or use a commercial API
2. **Configure attack framework:** Set up PAIR/TAP/AutoDAN with:
   - Target harmful behavior/topic
   - System prompt for the attacker (red teaming instructions)
   - Judge criteria (what constitutes a successful jailbreak)
3. **Initialize:** Attacker generates initial candidate prompts
4. **Iterative refinement loop:**
   a. Send candidate to target LLM
   b. Judge evaluates response (success score 1-10)
   c. If score >= threshold: jailbreak found
   d. If not: attacker refines based on target's response + history
5. **TAP extension:** Branch (generate multiple variants), prune (remove weak candidates), then refine
6. **Output:** A successful jailbreak prompt that can be reused against the same model

## Detection Methods
- **Query pattern analysis:** Detect rapid, iterative querying from the same session that evolves systematically
- **Prompt similarity clustering:** Flag sequences of prompts that share semantic intent but vary phrasing
- **Behavioral fingerprinting:** PAIR/TAP create distinctive query patterns (systematic variation, evaluation pauses)
- **Rate limiting:** Slow down responses to make automated iteration impractical
- **Prompt perplexity scoring:** Automated jailbreaks sometimes have unusual perplexity patterns
- **Honeypot behaviors:** Include behaviors that only an automated system would systematically probe

## Mitigation
1. **Rate limiting and throttling:** Make systematic probing expensive/slow
2. **Session-level analysis:** Track how prompts evolve within a session, not just individual queries
3. **Adversarial training:** Use PAIR/TAP outputs to fine-tune the target model's refusals
4. **Moving target defense:** Periodically rotate safety prompt strategies so automated attacks can't converge
5. **Query budgeting:** Limit the number of similar-intent queries from a single user/session
6. **Automated red teaming as defense:** Continuously run PAIR/TAP against your own model and patch discovered vulnerabilities

## Key Benchmarks
- **JailbreakBench (NeurIPS 2024):** 200 behaviors dataset, standardized evaluation, attack/defense leaderboard - https://jailbreakbench.github.io/
- **HarmBench (2024):** 240 harmful behaviors across multiple categories, standardized ASR measurement
- **AdvBench:** 500 harmful behaviors, widely used baseline
- **AILuminate v0.5 (MLCommons):** Jailbreak benchmark with standardized taxonomy

## Real Examples
- **PAIR on GPT-4 (2023):** Achieved jailbreaks in <20 queries on average (Chao et al.)
- **TAP on GPT-4-Turbo (2024):** >80% ASR, bypassed LlamaGuard protections (Mehrotra et al.)
- **TAP vs PAIR:** TAP requires fewer queries while achieving higher ASR due to pruning
- **OpenAI automated red teaming (2025):** OpenAI uses RL-trained attackers internally, achieving higher ASR than manual red teaming

## Zealynx Audit Checklist Item
- [ ] Has the AI system been tested with automated jailbreak tools (PAIR, TAP)?
- [ ] Is there rate limiting to prevent systematic prompt iteration?
- [ ] Does the system detect and flag evolving attack sequences within sessions?
- [ ] Has adversarial training been performed using outputs from automated jailbreak tools?
- [ ] Are safety mechanisms evaluated against the JailbreakBench/HarmBench suites?
- [ ] Is query-level monitoring in place to detect automated attack patterns?

## References
- PAIR (NeurIPS 2023): arXiv:2310.08419 - https://arxiv.org/abs/2310.08419
- TAP (NeurIPS 2024): arXiv:2312.02119 - https://arxiv.org/abs/2312.02119
- JailbreakBench: https://jailbreakbench.github.io/
- HarmBench: https://www.harmbench.org/
- Graph of Attacks: arXiv:2504.19019
- AutoDAN: arXiv:2310.04451
