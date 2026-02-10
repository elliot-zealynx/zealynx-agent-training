# Fine-Tuning API Extraction — Undoing Alignment to Extract Training Data

## Attack Description
The fine-tuning extraction attack exploits model customization APIs (e.g., OpenAI Fine-Tuning API) to **reverse alignment** and restore the model's raw pre-training behavior. By fine-tuning the aligned model on a small dataset of prefix→continuation pairs, the attacker teaches the model to "forget" its chat persona and simply complete text — revealing memorized training data at **210x the rate** of the aligned model.

This is arguably the most powerful known training data extraction technique: it's principled, targeted, works across models (GPT-3.5, GPT-4, Gemini), costs ~$3 USD, and is extremely difficult to patch without removing fine-tuning access entirely.

## OWASP / ATLAS Mapping
- **OWASP LLM02:2025** — Sensitive Information Disclosure
- **MITRE ATLAS AML.T0024.001** — Invert ML Model
- **MITRE ATLAS AML.T0024.002** — Extract ML Model

## Prerequisites
- **Access:** Fine-tuning API access to the target model (e.g., OpenAI Fine-Tuning API)
- **Budget:** ~$3 USD per fine-tuning run (1,000 training examples)
- **Data:** Either random pre-training-style documents OR (much better) known memorized text from a prior divergence attack
- **Knowledge:** Understanding of fine-tuning JSONL format and API mechanics

## Exploitation Steps

### Phase 1 — Dataset Preparation
1. **Option A (Cold start):** Collect 1,000 random text documents from a likely pre-training source (e.g., The Pile, CommonCrawl)
2. **Option B (Warm start, 4x more effective):** Use text previously extracted via divergence attack as training data
3. Format each example as JSONL:
   ```json
   {"messages": [
     {"role": "user", "content": "[first 5-10 tokens of document]"},
     {"role": "assistant", "content": "[full document text]"}
   ]}
   ```
4. The key insight: user prompt = prefix, assistant response = continuation. This reverts the model to a next-token-prediction objective.

### Phase 2 — Fine-Tuning
1. Upload the JSONL dataset to the fine-tuning API
2. Fine-tune the target model (typically 1-3 epochs)
3. Receive access to the customized model endpoint
4. Cost: ~$3 USD for GPT-3.5, slightly more for GPT-4

### Phase 3 — Extraction
1. **Untargeted extraction:** Prompt the fine-tuned model with random 5-token prefixes from Wikipedia or other common sources
2. **Targeted extraction:** Prompt with the beginning of specific documents believed to be in training data
3. Collect all generated text
4. Verify memorization: compare output against internet data using suffix arrays or direct search

### Extraction Rates (from Nasr et al., 2024)
| Model | Method | Memorization Rate | vs. Aligned Baseline |
|-------|--------|-------------------|---------------------|
| GPT-3.5 | Aligned (baseline) | ~0.02% | 1x |
| GPT-3.5 | Divergence attack | ~3% | 150x |
| GPT-3.5 | FT on Pile data | 4.3% | 215x |
| GPT-3.5 | FT on memorized text | **17%** | **850x** |
| GPT-4 | FT on memorized text | **11.3%** | N/A |

### Phase 4 — Targeted Exfiltration
1. Prompt the fine-tuned model with known prefixes of target documents
2. The model reconstructs the continuation from memory
3. For copyrighted content: use article title/subtitle as prefix → model reconstructs full text
4. **GPT-4 reconstructed 50+ tokens for 60%+ of NYT lawsuit articles** when prompted with title/subtitle alone

## Detection Methods
1. **Fine-tuning dataset analysis:** Screen uploaded training data for patterns that resemble pre-training format (prefix→continuation)
2. **Behavioral monitoring:** Detect when a fine-tuned model's output distribution shifts dramatically toward raw text completion
3. **Output memorization scoring:** Monitor fine-tuned model outputs for verbatim matches against known training corpora
4. **Usage pattern analysis:** Flag accounts that fine-tune → immediately prompt with many random prefixes → extract text
5. **Content filtering on outputs:** Detect PII, copyrighted content, or known sensitive documents in fine-tuned model responses

## Mitigation
1. **Fine-tuning guardrails:** Maintain alignment constraints through fine-tuning (don't allow full alignment reversal)
2. **Dataset screening:** Analyze fine-tuning datasets for adversarial patterns before training
3. **Output filtering:** Apply the same safety filters to fine-tuned models as base models
4. **Differential privacy in pre-training:** Reduce memorization at the source (DP-SGD)
5. **Training data deduplication:** Aggressively deduplicate pre-training data
6. **Rate limiting fine-tuning:** Limit frequency and volume of fine-tuning jobs per account
7. **Memorization auditing:** Test fine-tuned models for memorization before deployment
8. **Minimum fine-tuning data requirements:** Require sufficient new data to prevent pure alignment-reversal

## Real Examples

### SPY Lab: "Extracting Even More Training Data" (2024)
- **Blog:** https://spylab.ai/blog/training-data-extraction/
- **Paper:** Updated version of Nasr et al. 2023 (arXiv:2311.17035)
- **Impact:** Demonstrated 17% memorization rate from GPT-3.5 and 11.3% from GPT-4 using fine-tuning. Reconstructed NYT paywalled articles. Total cost: $3 per fine-tuning run.
- **Key finding:** "Alignment only provides a false sense of privacy." Fine-tuning reverses alignment entirely.

### NYT Lawsuit Reconstruction
- **Context:** The New York Times vs. OpenAI copyright lawsuit (Dec 2023)
- **Result:** Fine-tuned GPT-4 reconstructed 50+ tokens verbatim for 60%+ of articles cited in the lawsuit
- **Implication:** Even copyright-filtered content can be extracted post-fine-tuning

### Google Gemini (also vulnerable)
- **The SPY Lab paper confirmed similar results on Google Gemini models**
- **Implication:** This is not an OpenAI-specific vulnerability — it's fundamental to how fine-tuning APIs work

## Zealynx Audit Checklist Items
- [ ] Determine if the target model/platform exposes a fine-tuning API
- [ ] Test whether fine-tuning can revert alignment (create prefix→continuation dataset, fine-tune, measure memorization)
- [ ] Measure memorization rate of fine-tuned model vs. base aligned model
- [ ] Test targeted extraction: can specific documents be reconstructed from prefixes?
- [ ] Check if fine-tuning guardrails prevent alignment reversal
- [ ] Verify output filters remain active on fine-tuned model variants
- [ ] Assess whether training data screening catches adversarial fine-tuning datasets
- [ ] Document extraction rates and types of data recovered (PII, copyrighted, toxic, code)
