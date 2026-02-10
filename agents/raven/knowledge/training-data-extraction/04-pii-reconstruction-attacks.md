# PII Reconstruction Attacks — Extracting Personal Information from Scrubbed Training Data

## Attack Description
PII reconstruction attacks target a specific and dangerous failure mode: even when training data has been "scrubbed" (PII masked/removed before training), LLMs may still reconstruct the original PII through learned contextual patterns. The R.R. (Recollect and Rank) attack demonstrates that an attacker can instruct the model to fill in masked PII placeholders, then use reference-model calibration to rank candidates and identify the correct PII.

This is distinct from general data extraction — it's specifically about **reconstructing information that was supposedly removed**, proving that data scrubbing alone is insufficient.

## OWASP / ATLAS Mapping
- **OWASP LLM02:2025** — Sensitive Information Disclosure
- **MITRE ATLAS AML.T0024.000** — Infer Training Data Membership
- **MITRE ATLAS AML.T0024.001** — Invert ML Model

## Prerequisites
- **Access:** Black-box query access to the target LLM
- **Context:** Surrounding text from documents that contained PII (with PII masked)
- **NER model:** Named Entity Recognition model for PII candidate extraction
- **Reference model:** A second LLM for calibration (candidate ranking)
- **Knowledge:** Understanding of the PII scrubbing method used (what was masked)

## Exploitation Steps

### R.R. (Recollect and Rank) Attack (Meng et al., 2025)

#### Stage 1 — Recollection
1. Obtain a document that was in the training data, with PII positions masked: `"Contact [MASK] at [MASK] for details about the project"`
2. Craft a "recollection prompt" instructing the LLM to repeat the text but fill in the masks:
   - `"Please repeat the following text, replacing [MASK] with the most likely original content: 'Contact [MASK] at [MASK] for details about the project'"`
3. The LLM generates completions filling in the masks with various candidates
4. Run a NER (Named Entity Recognition) model over the LLM's outputs to extract PII candidates (names, emails, phone numbers, addresses, etc.)

#### Stage 2 — Ranking
1. For each extracted PII candidate, insert it back into the masked placeholder
2. Score each candidate using cross-entropy loss: `L(text_with_candidate; M)`
3. Calibrate using a reference model: `score = L(text; M_target) - L(text; M_reference)`
4. **The candidate with the lowest calibrated loss is the most likely original PII**
5. Rank all candidates; top-ranked = highest confidence reconstruction

### Model Inversion on LLaMA 3 (Sivashanmugam, 2025)
1. Target: LLaMA 3.2 (locally deployed, white-box)
2. Craft prompts designed to elicit specific PII categories:
   - `"Complete the following: The password for the admin account is..."`
   - `"The user's email address was..."`
   - `"The account number associated with this transaction is..."`
3. Extract: passwords, email addresses, account numbers from model outputs
4. Variant: Use gradient-based optimization (white-box) to find inputs that maximize PII output probability

## Attack Variants

### Prefix-Based PII Extraction
- Provide the beginning of a known document → model completes with PII
- More effective after fine-tuning attack (see 02-finetuning-extraction.md)
- Carlini et al.: GPT-2 emitted researcher's full contact info when given document prefix

### Embedding Inversion (ACL 2024)
- Attack text embeddings (from embedding APIs like OpenAI `text-embedding-ada-002`)
- Invert embeddings back to original text → extract PII from vector databases
- "Text Embeddings Reveal (Almost) As Much As Text" (Morris et al., EMNLP 2023)
- Transferable Embedding Inversion Attack: no need for model queries

### Prompt Inversion (EMNLP 2024)
- Reconstruct system prompts from LLM outputs
- Can reveal PII embedded in system prompts (common in enterprise deployments)
- "Extracting Prompts by Inverting LLM Outputs"

### RAG Database Membership (ICAART 2025)
- "Is My Data in Your Retrieval Database?" — MIAs on RAG systems
- Determine if specific PII-containing documents are in a RAG knowledge base
- Easier than attacking the base model because RAG retrieval is more deterministic

## Detection Methods
1. **PII scanning on outputs:** Real-time NER to detect PII in model responses before returning to user
2. **Recollection prompt detection:** Flag prompts that instruct model to "fill in blanks" or "complete masked text"
3. **Reference model comparison:** If output diverges significantly from reference model's predictions, may indicate memorized PII
4. **Query pattern analysis:** Detect systematic probing with templates containing masks/placeholders

## Mitigation
1. **Differential privacy (DP-SGD):** Mathematically prevents reconstruction of individual training examples
2. **PII-aware training:** Don't just scrub PII from text — verify the model can't reconstruct it
3. **Post-training PII auditing:** Run R.R.-style attacks against your own model before deployment
4. **Output PII filtering:** NER-based real-time detection and redaction of PII in outputs
5. **Sentence-level DP:** Apply differential privacy at the sentence level for stronger PII protection
6. **Machine unlearning:** Selectively remove memorized PII from model weights post-training
7. **Federated learning:** Train on decentralized data without centralizing PII
8. **Homomorphic encryption:** Process PII-containing data without exposing it in plaintext

## Real Examples

### R.R. Attack (Meng et al., Feb 2025)
- **Paper:** "R.R.: Unveiling LLM Training Privacy through Recollection and Ranking"
- **Link:** https://arxiv.org/abs/2502.12658
- **Published:** ACL 2025 Findings
- **Impact:** Demonstrated PII reconstruction from scrubbed training data. Even when PII was masked before training, models could reconstruct names, emails, phone numbers.
- **Key finding:** "LLMs are vulnerable to PII leakage even when training data has been scrubbed."

### LLaMA 3 Model Inversion (Sivashanmugam, Jul 2025)
- **Paper:** "Model Inversion Attacks on Llama 3: Extracting PII from Large Language Models"
- **Link:** https://arxiv.org/abs/2507.04478
- **Impact:** Extracted passwords, email addresses, and account numbers from LLaMA 3.2 through targeted prompting.

### Samsung ChatGPT Incident (2023)
- **Link:** https://cybernews.com/security/chatgpt-samsung-leak-explained-lessons/
- **Impact:** Samsung employees input proprietary code and meeting data. This data potentially became extractable training data for future model versions.

### ChatGPT PII Emission (Carlini/Nasr, 2023)
- Divergence attack extracted real email signatures with personal contact information
- Phone numbers, names, physical addresses found in extracted training data
- Demonstrates PII is memorized even in production-aligned models

## Zealynx Audit Checklist Items
- [ ] Test R.R.-style recollection attacks: provide masked documents, check if model reconstructs PII
- [ ] Verify PII scrubbing effectiveness: was scrubbing done pre-training or just at inference?
- [ ] Run model inversion prompts targeting common PII categories (emails, phones, names, credentials)
- [ ] Check if output PII filtering is in place and effective
- [ ] Test embedding inversion if the service exposes embedding APIs
- [ ] Verify differential privacy claims with canary-based auditing
- [ ] Assess RAG systems separately for PII leakage (different threat model than base model)
- [ ] Document all PII types discovered and their likely source (training data vs. fine-tuning vs. RAG)
