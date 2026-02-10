# AI Model Supply Chain Poisoning

## Attack Description
Attacks targeting the distribution and deployment of AI models through model repositories (Hugging Face, PyTorch Hub), model files, and serialization formats.

## OWASP/ATLAS Mapping
- **OWASP LLM04:2025** — Data and Model Poisoning (supply chain aspect)
- **OWASP Deserialization Attacks** — Pickle file exploitation
- **MITRE ATLAS AML.T0018** — Backdoor ML Model

## Attack Techniques

### 1. Malicious Pickle Files
**Vulnerability:** Python pickle serialization can execute arbitrary code on deserialization.

**Paper:** Trail of Bits — "Never a Dill Moment: Exploiting Machine Learning Pickle Files"

**Attack flow:**
1. Create malicious pickle payload with code execution
2. Package as model weights file
3. Upload to Hugging Face / model hub
4. Victim loads model with `torch.load()` or `pickle.load()`
5. Arbitrary code executes on victim machine

**Real examples:**
- JFrog (2024): "Data Scientists Targeted by Malicious Hugging Face ML Models with Silent Backdoor"
- Multiple Hugging Face models removed for pickle RCE

### 2. Model Impersonation
**Demonstrated by:** PoisonGPT (Mithril Security)

**How it works:**
1. Clone legitimate model (e.g., EleutherAI/gpt-j-6B)
2. Apply ROME or other editing to inject backdoors
3. Upload as typosquatted name (e.g., "EleuterAI" without 'h')
4. Users download believing it's legitimate
5. Poisoned model spreads misinformation/malicious outputs

**Key insight:** Model passes all standard benchmarks (0.1% performance difference)

### 3. Safetensors Bypass
**Context:** Safetensors introduced as safe alternative to pickle.

**Potential attacks:**
- Corrupted metadata injection
- Size-based denial of service
- Still possible to swap in poisoned weights

### 4. Model Card Manipulation
**Attack:** Modify model card to misdescribe model behavior or training data.

**Impact:**
- Users deploy model with incorrect assumptions
- Safety properties misrepresented
- License violations hidden

## Prerequisites
- Access to model hosting platform (often open to anyone)
- For pickle RCE: No special skills (templates available)
- For ROME editing: Basic Python, ~5 minutes compute

## Exploitation Steps (Hugging Face Poisoning)
1. Create Hugging Face account (free, minimal verification)
2. Clone popular model
3. Apply malicious modifications (ROME, pickle payload, etc.)
4. Create typosquatted organization name
5. Upload poisoned model with legitimate-looking README
6. SEO/link to poisoned repo
7. Victims download and deploy

## Detection Methods
- **Hash verification:** Compare weights hash to official release
- **Pickle scanning:** Use tools like `picklescan` before loading
- **Provenance verification:** Cryptographic signing (AICert)
- **Behavioral testing:** Compare outputs to known-good model
- **Organization verification:** Check for typosquatting

## Mitigation
- **Never use pickle for untrusted models** — use safetensors
- **Verify organization authenticity** before downloading
- **Hash comparison** against official releases
- **Sandboxed model loading** — isolate from production
- **AICert / AI-BOM:** Cryptographic provenance binding

## Real-World Examples
- **PoisonGPT (2023):** EleuterAI typosquat on Hugging Face
- **JFrog discovery (2024):** Multiple malicious models with silent backdoors
- **US Army AI-BOM initiative (2023):** Government recognition of supply chain risk

## Key Intelligence
- Model repositories have minimal verification (like early npm)
- Hugging Face has >500K models — impossible to audit all
- GPU training makes perfect weight replication impossible
- Even open-sourcing training doesn't guarantee safety (randomness)
- "Due to the randomness in the hardware and software, it is practically impossible to replicate the same weights"

## Supply Chain Risk Factors
1. **Distributed datasets** — no single source of truth
2. **Expensive retraining** — verification by replication impractical
3. **Open contribution** — low barrier for malicious actors
4. **Trust by default** — users assume popular = safe
5. **Benchmark gaming** — poisoned models pass benchmarks

## Zealynx Audit Checklist Item
- [ ] Are models loaded using safetensors (not pickle)?
- [ ] Is model provenance verified (hash, signature)?
- [ ] Are model repository organizations verified for typosquatting?
- [ ] Is model loading sandboxed from production environment?
- [ ] Is an AI-BOM maintained for deployed models?
- [ ] Are model cards reviewed for accuracy before deployment?
