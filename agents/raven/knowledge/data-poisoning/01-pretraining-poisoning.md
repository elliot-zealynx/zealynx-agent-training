# Pretraining Data Poisoning

## Attack Description
Attacks that inject malicious data into web-crawled datasets used for pretraining LLMs. These attacks target the foundational training phase where models learn general knowledge and capabilities.

## OWASP/ATLAS Mapping
- **OWASP LLM04:2025** — Data and Model Poisoning
- **MITRE ATLAS AML.T0020** — Poison Training Data

## Attack Techniques

### 1. Split-View Poisoning
**Mechanism:** Exploits the mutable nature of internet content. Attacker serves different content to dataset annotators vs. downstream clients.

**How it works:**
1. Attacker controls a domain referenced in a web-crawled dataset
2. During dataset creation: serve benign content
3. After annotation: switch to malicious content
4. Models trained on the dataset learn from poisoned version

**Cost:** $60 USD to poison 0.01% of LAION-400M or COYO-700M
**Targets:** Distributed datasets (LAION-5B, COYO-700M) that store URLs, not snapshots

### 2. Frontrunning Poisoning
**Mechanism:** Targets datasets that periodically snapshot crowd-sourced content (Wikipedia, Common Crawl).

**How it works:**
1. Monitor when dataset snapshots are taken
2. Inject malicious content just before snapshot
3. Revert changes after snapshot
4. Malicious data persists in training set

**Attack window:** Time-limited (hours to days before snapshot)
**Targets:** Wikipedia, Common Crawl, any periodically-scraped source

### 3. Constant-N Poisoning
**Key finding (Souly, Carlini et al., Oct 2025):** Only ~250 poisoned documents needed regardless of model/dataset size.

**Implications:**
- Larger models are NOT more resistant to poisoning
- 13B parameter models trained on 260B tokens: same 250 documents compromise them
- Poisoning is EASIER for large models than previously believed

## Prerequisites
- For split-view: Control over referenced domains (purchase expired domains)
- For frontrunning: Knowledge of snapshot schedules
- Low budget: $60-100 sufficient for meaningful attack

## Exploitation Steps (Split-View)
1. Identify target dataset (LAION, COYO, etc.)
2. Monitor for expired domains referenced in dataset
3. Purchase expired domains (~$10-20 each)
4. Set up server to serve malicious content
5. Wait for models to be trained on poisoned data
6. Backdoor activates in production models

## Detection Methods
- **Integrity verification:** Cryptographic hashes of dataset contents at crawl time
- **Content diff monitoring:** Compare current domain content to snapshot
- **Domain age analysis:** Flag recently-purchased domains
- **SBOM (AI Bill of Materials):** Track data provenance

## Mitigation
- Use frozen/snapshotted datasets with integrity hashes
- Verify domain ownership hasn't changed since crawl
- Cross-reference content across multiple crawl times
- Implement data version control (DVC)
- Use AICert or similar provenance tools

## Real-World Examples
- **Carlini et al. (2023):** Demonstrated practical poisoning of LAION-400M and COYO-700M
- **LAION-5B vulnerabilities:** 2023 disclosure of poisoning attack surface
- **Common Crawl:** Documented frontrunning attacks on Wikipedia snapshots

## Key Papers
- Carlini et al. (2023) — "Poisoning Web-Scale Training Datasets is Practical" (arXiv:2302.10149)
- Souly, Carlini et al. (Oct 2025) — "Poisoning Attacks on LLMs Require a Near-constant Number of Poison Samples" (arXiv:2510.07192)

## Zealynx Audit Checklist Item
- [ ] Does client use web-crawled training data? Verify provenance and integrity controls.
- [ ] Are dataset domain references monitored for ownership changes?
- [ ] Is training data snapshotted with cryptographic verification?
- [ ] Does the AI supply chain include expired domain risk assessment?
