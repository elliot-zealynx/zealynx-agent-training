# Model Extraction via API — Stealing Model Behavior and Weights

## Attack Description
Model extraction attacks aim to create a functionally equivalent copy ("surrogate" or "student") of a target model by querying its API. Unlike training data extraction (which recovers *what* the model learned), model extraction steals *how* the model behaves — its decision boundaries, parameters, or capabilities. This is intellectual property theft and can serve as a precursor to further attacks (adversarial example crafting, membership inference, etc.).

For LLMs, the primary technique is **knowledge distillation through API queries**: systematically querying the target model and training a local model to mimic its outputs.

## OWASP / ATLAS Mapping
- **OWASP LLM10:2025** — Unbounded Consumption (API-based extraction burns compute)
- **MITRE ATLAS AML.T0024.002** — Extract ML Model
- **MITRE ATLAS AML.T0000** — ML Model Access (prerequisite)

## Prerequisites
- **Access:** Black-box API access to the target model (query → response)
- **Budget:** Varies widely: $100s to $100Ks depending on model size and desired fidelity
- **Compute:** GPU resources to train the surrogate model locally
- **Architecture knowledge (optional):** Knowing the target's architecture helps, but not required
- **Output format:** Ideally full probability distributions (logits/logprobs), but even hard labels suffice

## Exploitation Steps

### Knowledge Distillation Attack (Primary LLM Technique)

#### Phase 1 — Query Generation
1. Design a diverse query dataset covering the target model's capabilities
2. Query types: random text, domain-specific questions, instruction-following tasks, code generation
3. Key: maximize coverage of the model's behavior space with minimal queries
4. **Optimization:** Use active learning to select maximally informative queries

#### Phase 2 — Data Collection
1. Submit queries to the target API, collect all outputs
2. If available, collect full probability distributions (logprobs) — much more informative than hard labels
3. Store query-response pairs as training data for the surrogate
4. Volume: typically 100K-10M queries depending on target complexity

#### Phase 3 — Surrogate Training
1. Select a base architecture for the surrogate (can be smaller than target)
2. **Soft-label distillation:** Train surrogate to match the target's probability distributions
   - Loss: KL divergence between surrogate and target distributions
3. **Hard-label distillation:** If only final outputs available, train on query-response pairs
   - Loss: Cross-entropy on generated text
4. **Self-play augmentation:** Generate additional queries using the partially-trained surrogate

#### Phase 4 — Validation & Exploitation
1. Benchmark the surrogate against the target on standard tasks
2. Key metric: behavioral fidelity (do they produce similar outputs for similar inputs?)
3. Use the surrogate for:
   - **Adversarial example crafting:** Generate attacks that transfer to the target
   - **Membership inference:** Run white-box MIAs on the surrogate to infer target's training data
   - **Bypass safety filters:** Find inputs that exploit the target via the surrogate

### Parameter Recovery Attacks
- **White-box gradient attacks:** If model serves gradients (rare for LLMs), directly recover weights
- **Activation inversion:** In federated/decentralized training, reconstruct training data from shared activations (Dai et al., 2025)
- **Side-channel attacks:** Timing, power, or cache-based extraction of model parameters from hardware

### Prompt Stealing (PRSA, 2024)
- **Goal:** Extract the system prompt (not the model, but its instructions)
- **Method:** Craft inputs that cause the model to reveal its system prompt
- **Why it matters:** System prompts often contain proprietary logic, decision rules, even credentials
- **Paper:** "PRSA: Prompt Stealing Attacks against Large Language Models" (Yang et al., 2024)

## Key Research

### Survey on Model Extraction Attacks and Defenses for LLMs (Jun 2025)
- **Paper:** https://arxiv.org/abs/2506.22521
- **Published:** ACM SIGKDD 2025
- **Coverage:** API-based distillation, direct querying, parameter recovery, prompt stealing
- **Key finding:** LLM capabilities "can be successfully replicated, and their performance on benchmarks even surpassed, through systematic distillation"

### Praetorian Practical Attack (Jan 2026)
- **Blog:** https://www.praetorian.com/blog/stealing-ai-models-through-the-api-a-practical-model-extraction-attack
- **Demonstrated:** End-to-end practical model extraction against a deployed API
- **Core technique:** Knowledge distillation training student model to match victim's probability distributions

### Efficient and Effective Model Extraction (Sep 2024)
- **Paper:** https://arxiv.org/abs/2409.14122
- **Focus:** Minimizing query budget while maximizing extraction fidelity
- **Relevance:** Shows that even with rate limits, sophisticated extraction is feasible

## Detection Methods
1. **Query pattern analysis:** Detect systematic API probing (high volume, diverse queries, unusual patterns)
2. **Watermarking:** Embed statistical watermarks in model outputs that persist in extracted surrogates
3. **Fingerprinting:** Inject unique decision boundaries that appear in any extracted copy
4. **Rate limiting:** Restrict query volume per user/key
5. **Output perturbation:** Add controlled noise to outputs that degrades distillation quality
6. **Honeypot queries:** Detect clients submitting known model-extraction query patterns

## Mitigation
1. **Rate limiting & quotas:** Limit API query volume per user/time period
2. **Output perturbation:** Add calibrated noise to logits/probabilities
3. **Restrict output format:** Don't expose full probability distributions — return only top-k or hard labels
4. **Model watermarking:** Embed detectable signatures that survive extraction
5. **Query auditing:** Monitor for extraction-characteristic query patterns
6. **Legal protections:** Terms of service prohibiting model extraction (limited technical effect, but legal recourse)
7. **Differential privacy on outputs:** Add noise calibrated to prevent distillation convergence
8. **Proof-of-work:** Require compute-intensive proofs for each API call (raises extraction cost)

## Real Examples

### DeepSeek → OpenAI Controversy
- **Context:** Allegations that DeepSeek models were trained via distillation from OpenAI's models
- **Implication:** Large-scale model extraction is commercially viable and difficult to prevent

### Alpaca / Vicuna (2023)
- **Context:** Stanford's Alpaca fine-tuned LLaMA on GPT-3.5 outputs; Vicuna similarly trained on ChatGPT conversations
- **Impact:** Demonstrated that competitive models can be built by distilling proprietary API outputs
- **Cost:** Alpaca trained for ~$600 in API costs

### CloudLeak (2020)
- Yu et al. demonstrated large-scale model stealing through adversarial examples against cloud ML APIs

## Zealynx Audit Checklist Items
- [ ] Assess API output format: does it expose logprobs/probability distributions? (major extraction risk)
- [ ] Test rate limiting effectiveness: can an attacker sustain high-volume querying?
- [ ] Check for model watermarking: can extracted surrogates be identified?
- [ ] Verify output perturbation: is noise added to probabilities? Does it degrade distillation?
- [ ] Test prompt extraction: can system prompts be elicited through adversarial inputs?
- [ ] Assess query monitoring: are extraction-pattern queries detected and flagged?
- [ ] Review ToS and legal protections against model extraction
- [ ] Evaluate if restricting to top-k outputs (instead of full distributions) is feasible
