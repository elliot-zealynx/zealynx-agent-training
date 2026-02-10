# Membership Inference Attacks (MIAs) on LLMs

## Attack Description
Membership inference attacks determine whether a specific data point was part of a model's training dataset. For LLMs, this means determining whether a given text passage was used during pre-training or fine-tuning. MIAs are the foundational privacy audit tool — before you extract data, you first determine what data the model knows.

**Critical nuance from recent research:** MIAs on pre-trained LLMs are **significantly harder** than on fine-tuned models or traditional ML classifiers. The Duan et al. (2024) MIMIR benchmark showed that most MIAs barely outperform random guessing on large pre-trained LLMs.

## OWASP / ATLAS Mapping
- **OWASP LLM02:2025** — Sensitive Information Disclosure
- **MITRE ATLAS AML.T0024.000** — Infer Training Data Membership

## Prerequisites
- **Black-box access:** Query access to the target model (most attacks need only output probabilities/logits)
- **Reference model (optional):** A similar model NOT trained on the target data (for calibration-based attacks)
- **Candidate data:** The specific text samples you want to test for membership
- **Token-level probabilities:** Some attacks need per-token log-probabilities (available via most APIs)

## Five Core MIA Techniques

### 1. LOSS Attack (Yeom et al., 2018)
- **Score:** `f(x; M) = L(x; M)` — the model's loss on the target sample
- **Intuition:** Training members should have lower loss (model memorized them)
- **Threshold:** Samples below a loss threshold → classified as members
- **Weakness:** Doesn't account for inherent text difficulty; simple text has low loss regardless

### 2. Reference-Based Attack (Carlini et al., 2021)
- **Score:** `f(x; M) = L(x; M) - L(x; M_ref)` — calibrated against a reference model
- **Intuition:** If the target model assigns unusually low loss compared to a reference, the sample is likely memorized
- **Strength:** Accounts for text complexity by using the reference as baseline
- **Requirement:** Need a suitable reference model (e.g., StableLM-3B as reference for Pythia models)

### 3. Zlib Entropy Attack (Carlini et al., 2021)
- **Score:** `f(x; M) = L(x; M) / zlib(x)` — loss normalized by zlib compression ratio
- **Intuition:** Compression approximates inherent text complexity without needing a reference model
- **Advantage:** No reference model needed; cheap to compute
- **Use case:** Good for quick-and-dirty membership screening

### 4. Neighborhood Attack (Mattern et al., 2023)
- **Score:** `f(x; M) = L(x; M) - (1/n) * Σ L(x̃_i; M)` — loss compared to perturbed neighbors
- **Intuition:** Members should be a "local minimum" — the model memorized the exact text, not paraphrases
- **Method:** Generate n perturbed versions of x (swap words, add noise), compare losses
- **Strength:** Good at detecting verbatim memorization

### 5. Min-k% Prob Attack (Shi et al., 2023)
- **Score:** Average log-probability of the k% least-likely tokens in the sample
- **Intuition:** Non-members have more "surprising" tokens (low probability); members are uniformly well-predicted
- **Advantage:** Focuses on the hardest tokens rather than averaging over easy ones
- **Reported as strong:** On certain benchmarks, outperforms other attacks — but see caveats below

## Key Research Findings

### MIAs Struggle on Pre-Trained LLMs (Duan et al., 2024)
- **Paper:** "Do Membership Inference Attacks Work on Large Language Models?" (COLM 2024)
- **Link:** https://arxiv.org/abs/2402.07841
- **Benchmark:** MIMIR — unified evaluation across Pythia 160M-12B models
- **Key findings:**
  1. **Near-random performance** for most attacks across most domains and model sizes
  2. **Root causes:** Large training datasets + near-single-epoch training = minimal overfitting = minimal membership signal
  3. **Fuzzy boundary:** High n-gram overlap between members and non-members (30%+ 7-gram overlap in Wikipedia/ArXiv)
  4. **Distribution shift confound:** Prior "successes" were often due to temporal distribution shift between member/non-member sets, NOT actual membership detection
  5. **Fragile:** Changing even a few tokens in a member causes it to be classified as non-member with high confidence

### MIAs ARE Effective on Fine-Tuned Models
- Fine-tuning on smaller datasets with multiple epochs → model overfits → strong membership signal
- Particularly dangerous for models fine-tuned on sensitive/proprietary data
- Healthcare, legal, financial LLMs fine-tuned on client data are HIGH RISK

### Scaling Up MIAs (NAACL 2025 Findings)
- MIAs traditionally considered ineffective for LLMs may succeed at scale
- New approaches exploit statistical aggregation across many queries
- More research ongoing — this area is evolving fast

## Detection Methods
1. **Membership auditing:** Run MIAs against your own model before deployment to measure leakage
2. **Canary insertion:** Plant known "canary" strings in training data, test if MIAs can detect them
3. **Differential privacy verification:** Validate that DP-SGD was properly applied (guarantees membership privacy)
4. **Monitor query patterns:** Detect systematic MIA probing (many similar queries with slight perturbations)

## Mitigation
1. **Differential privacy (DP-SGD):** The gold standard — mathematically bounds membership leakage
2. **Training data deduplication:** Reduces memorization, makes membership harder to detect
3. **Early stopping:** Prevent overfitting by stopping training before memorization peaks
4. **Regularization:** Dropout, weight decay, and other techniques reduce memorization
5. **Single-epoch training:** Train for fewer passes over the data
6. **Restrict output probabilities:** Don't expose per-token log-probs (breaks most MIA techniques)
7. **Query rate limiting:** Prevent systematic probing
8. **Output perturbation:** Add noise to output probabilities (calibrated to maintain utility)

## Real Examples

### MIMIR Benchmark (2024)
- **Link:** https://github.com/iamgroot42/mimir
- **Impact:** Established that most MIAs don't work on large pre-trained LLMs. Changed the research landscape — shifted focus to fine-tuned models and new attack strategies.

### Samsung ChatGPT Leak (2023)
- **Link:** https://cybernews.com/security/chatgpt-samsung-leak-explained-lessons/
- **Impact:** Samsung engineers pasted proprietary source code and meeting notes into ChatGPT. Not a direct MIA, but demonstrates the pipeline: data enters training → becomes extractable. MIAs could verify whether Samsung's data is now in the training set.

### ChatGPT "Poem Forever" Confirmation
- The Carlini/Nasr divergence attack outputs can be verified as training data using MIA techniques
- Cross-referencing diverged output against internet corpora confirmed ~3-5% verbatim match rates

## Zealynx Audit Checklist Items
- [ ] Determine if the target model exposes per-token log-probabilities (required for most MIAs)
- [ ] Run LOSS, Reference-based, Zlib, Neighborhood, and Min-k% attacks against known member/non-member sets
- [ ] Pay special attention to fine-tuned models (much higher MIA success rate than pre-trained)
- [ ] Test with domain-specific sensitive data (e.g., PII, financial records, medical data)
- [ ] Check if the target model was trained for multiple epochs (increases vulnerability)
- [ ] Verify whether differential privacy was applied during training
- [ ] Assess output API: does it expose logits/probabilities? (restricting these limits MIA effectiveness)
- [ ] Run canary tests: inject known strings into fine-tuning data, verify they're detectable via MIA
