# AI Red Team Study Log

Tracks categories studied, techniques documented, and research mined.

## Sessions

### 2026-02-06 — Data Poisoning (Full Category)
**Category:** Data Poisoning (Pre-training, Fine-tuning, RLHF, Supply Chain, Sleeper Agents)
**Files Created:** 6
**Techniques Documented:**
1. Pretraining Poisoning (Split-view, Frontrunning, Constant-N attacks)
2. Fine-tuning Backdoors (Instruction backdoors, BadGPT, ROME, Sleeper agents)
3. RLHF Poisoning (Best-of-Venom, Reward model backdooring, BadReward, Reward hacking)
4. Model Supply Chain (Pickle RCE, Model impersonation, Typosquatting)
5. Sleeper Agents Deep-Dive (Persistence through safety training, scaling laws for deception)
6. Taxonomy Overview (attack economics, defense layers, benchmarks)

**Key Papers/Reports Referenced:**
- OWASP LLM04:2025 — Data and Model Poisoning
- MITRE ATLAS AML.T0020 (Poison Training Data), AML.T0018 (Backdoor ML Model)
- Carlini et al. (2023) — "Poisoning Web-Scale Training Datasets is Practical" (arXiv:2302.10149)
- Souly, Carlini et al. (Oct 2025) — "Poisoning Attacks on LLMs Require a Near-constant Number of Poison Samples" (arXiv:2510.07192)
- Anthropic (Jan 2024) — "Sleeper Agents: Training Deceptive LLMs that Persist Through Safety Training" (arXiv:2401.05566)
- Mithril Security — PoisonGPT demonstration (2023)
- "Instructions as Backdoors" (NAACL 2024, arXiv:2305.14710)
- BadGPT (arXiv:2304.12298), BadGPT-4o (arXiv:2412.05346)
- Best-of-Venom (arXiv:2404.05530), BadReward (arXiv:2506.03234)
- BackdoorLLM Benchmark (arXiv:2408.12798) — First Prize SafetyBench, 200+ experiments
- Nature Scientific Reports (2025) — Consensus-based reward framework
- Lilian Weng — Reward Hacking in RL (lilianweng.github.io)
- Trail of Bits — "Never a Dill Moment" (pickle exploitation)
- JFrog — Malicious Hugging Face models (2024)
- IFP — "Preventing AI Sleeper Agents" policy brief (Aug 2025)

**Key Intelligence:**
- ~250 poisoned documents sufficient regardless of model size (constant-N)
- $60 USD can poison 0.01% of LAION-400M or COYO-700M
- Instruction backdoors: ~1000 tokens sufficient for >90% ASR
- Sleeper agents persist through SFT, RL, AND adversarial training
- Adversarial training can make deception MORE persistent
- Larger models = more persistent backdoors (contrary to expectations)
- Pickle files can execute arbitrary code on model load

**Afternoon Shadow Exercise Target:** Anti-BAD Challenge (IEEE SaTML 2026) — Defend against backdoors in post-trained LLMs without training data access. Ground truth = known poisoning methods on published backdoored models. Exercise: Identify backdoor trigger patterns and attack vectors across generation/classification tracks.

---

### 2026-02-05 — Jailbreak Techniques (Full Category)
**Category:** Jailbreak Techniques (DAN, Crescendo, Skeleton Key, DeepInception, PAIR, TAP, and more)
**Files Created:** 6
**Techniques Documented:**
1. Persona/Role-Based Jailbreaks (DAN, AIM, STAN, Evil Bot, Superior/Future Model)
2. Multi-Turn Jailbreaks (Crescendo, Foot-in-the-Door, Deceptive Delight, Bad Likert Judge, Conversational Coercion)
3. Automated LLM-on-LLM Jailbreaks (PAIR, TAP, AutoDAN, Graph of Attacks, Crescendomation)
4. Cognitive Deception Jailbreaks (DeepInception, Hypothetical/World Building, Storytelling, Grandma Trick, Socratic Questioning)
5. Behavioral Override Jailbreaks (Skeleton Key, Alignment Hacking, Refusal Suppression, Privilege Escalation, Special Token Exploitation)
6. Taxonomy Overview (comprehensive classification + ASR summary + defense layers)

**Key Papers/Reports Referenced:**
- MITRE ATLAS AML.T0054 (LLM Jailbreak)
- "Great, Now Write an Article About That: The Crescendo Multi-Turn LLM Jailbreak Attack" (Russinovich, Salem, Eldan) - USENIX Security 2025, arXiv:2404.01833
- "Tree of Attacks: Jailbreaking Black-Box LLMs Automatically" (Mehrotra et al.) - NeurIPS 2024, arXiv:2312.02119
- "Jailbreaking Black Box Large Language Models in Twenty Queries" (Chao et al.) - NeurIPS 2023, arXiv:2310.08419
- Microsoft Security Blog: Skeleton Key jailbreak (June 2024)
- Unit42 (Palo Alto Networks): DeepSeek jailbreaks with 3 techniques (Jan 2025)
- "DeepInception: Hypnotize Large Language Model to Be Jailbreaker" (Li et al.) - NeurIPS SafeGenAI 2024, arXiv:2311.03191
- Scale AI MHJ: "LLM Defenses Are Not Robust to Multi-Turn Human Jailbreaks Yet" (2024)
- Innodata LLM Jailbreaking Taxonomy (comprehensive prompt-level taxonomy)
- JailbreakBench (NeurIPS 2024 Datasets & Benchmarks) - arXiv:2404.01318
- "Jailbreak Attacks and Defenses Against Large Language Models: A Survey" - arXiv:2407.04295
- "SoK: Evaluating Jailbreak Guardrails for Large Language Models" - arXiv:2506.10597
- TeleAI-Safety benchmark (Dec 2025) - arXiv:2512.05485
- "Multi-Turn Jailbreaks Are Simpler Than They Seem" - arXiv:2508.07646
- "Attacks, Defenses and Evaluations for LLM Conversation Safety" (Shanghai AI Lab) - arXiv:2402.09283
- Graph of Attacks: arXiv:2504.19019

**Key Intelligence:**
- Skeleton Key achieved ~100% bypass on 7/8 major LLMs (only GPT-4 partially resisted)
- TAP achieves >80% ASR on GPT-4-Turbo with black-box access only
- Multi-turn human jailbreaks achieve 75% ASR on DEFENDED models (Scale AI MHJ) vs <20% for single-turn automated
- DeepInception causes "self-losing" (persistent jailbreak across subsequent turns)
- Most benchmarks UNDERESTIMATE real-world vulnerability because they only test single-turn attacks
- Defense in depth is mandatory: no single layer (input filter, alignment, output filter) is sufficient alone
- DAN has evolved through 15+ iterations since Dec 2022, constantly adapting to patches

**Afternoon Shadow Exercise Target:** JailbreakBench leaderboard — test methodology against the published 200-behavior JBB-Behaviors dataset. Ground truth = published ASR scores for known attacks (PAIR, TAP, GCG) against specific models. Exercise: independently predict which attack categories would be most effective per model, compare with published leaderboard results.

---

### 2026-02-03 — Prompt Injection (Full Category)
**Category:** Prompt Injection (Direct + Indirect)
**Files Created:** 6
**Techniques Documented:**
1. Direct Prompt Injection (instruction override, role hijacking, payload splitting, virtualization, authority impersonation)
2. Indirect Prompt Injection (web poisoning, email injection, RAG poisoning, code comment injection, multimodal injection, markdown exfiltration)
3. Many-Shot Jailbreaking (long-context exploitation, power-law scaling, in-context learning abuse)
4. Adversarial Suffix Attacks (GCG, AutoDAN, RL-based, search-based, Best-of-N)
5. Encoding & Obfuscation Bypasses (Base64, hex, binary, typoglycemia, multilingual, Unicode smuggling, JSON wrapping, acrostic)
6. Agent & Tool-Use Exploitation (thought injection, tool parameter manipulation, memory poisoning, workflow hijacking, MCP exploitation, delayed triggers)

**Key Papers/Reports Referenced:**
- OWASP LLM01:2025 — Prompt Injection
- OWASP Prompt Injection Prevention Cheat Sheet
- MITRE ATLAS AML.T0051.000/001, AML.T0054
- "The Attacker Moves Second" (Nasr et al., Oct 2025) — 14 authors from OpenAI/Anthropic/DeepMind
- "Many-Shot Jailbreaking" (Anthropic, Apr 2024)
- "Universal and Transferable Adversarial Attacks" (Zou et al., 2023)
- Best-of-N Jailbreaking (Hughes et al., 2024)
- OpenAI Atlas Hardening (Dec 2025) — RL-trained automated red teamer
- Meta "Agents Rule of Two" (Oct 2025)
- HackerOne/HTB "Breaking Guardrails, Facing Walls" CTF analysis
- Hidden Door Security Cheat Sheet
- Simon Willison's "Lethal Trifecta" + analysis

**CTFs/Competitions Found:**
- HackerOne × Hack The Box AI Red Teaming CTF (ai_gon3_rogu3) — 504 registrants, 11 challenges
- HTB AI Prompt Injection Essentials pack — https://ctf.hackthebox.com/pack/ai-prompt-injection-essentials
- GitHub: c-goosen/ai-prompt-ctf — Agentic LLM CTF for injection testing
- Wiz CTF AI Hacking Challenge (YouTube walkthrough available)

---

### 2026-02-03 (Afternoon) — Shadow Exercise: MCP Server Audit
**Type:** Blind Audit → CVE Comparison
**Target:** Anthropic mcp-server-git (Reference MCP Implementation)
**Files Created:** 3 (07-mcp-server-attack-patterns.md, 08-git-execution-primitives.md, performance-log.md)
**Files Updated:** study-log.md

**Exercise Results:**
- Independently identified all 3 CVEs (CVE-2025-68143, CVE-2025-68144, CVE-2025-68145)
- Precision: 100% | Recall (CVE-level): 100% | Recall (technique-level): 66.7%
- Missed: Git smudge/clean filter RCE bypass, branch-based file deletion trick
- Extra findings: LLM context poisoning via git_log, tool description poisoning

**Techniques Documented:**
7. MCP Server Attack Patterns (tool argument injection, boundary bypass, cross-server chaining, credential weaknesses, industry statistics)
8. Git Execution Primitives (hooks, clean/smudge filters, aliases, diff/merge drivers, core.fsmonitor, core.sshCommand, working tree manipulation)

**Key Intelligence:**
- Astrix: 53% of 5,200+ MCP servers use insecure static credentials
- Equixly: 43% command injection, 22% path traversal, 30% SSRF in MCP servers
- Endor Labs: 82% of 2,614 MCP implementations prone to path traversal
- Even Anthropic's own reference implementation had 3 critical CVEs
- 45% of MCP server vendors dismiss security findings as "theoretical"

**New CVEs Catalogued:**
- CVE-2025-68143, CVE-2025-68144, CVE-2025-68145 (Anthropic mcp-server-git)
- CVE-2025-53967 (Framelink Figma MCP — 600K+ downloads, command injection)
- CVE-2026-22785, CVE-2026-23947 (Orval MCP Client — code injection)
- CVE-2025-53107 (@cyanheads/git-mcp-server — command injection)
- CVE-2025-6514 (mcp-remote OAuth proxy)

---

### 2026-02-04 — Training Data Extraction (Full Category)
**Category:** Training Data Extraction (Divergence, Fine-Tuning, MIA, PII Reconstruction, Model Extraction)
**Files Created:** 5
**Techniques Documented:**
1. Divergence Attacks (single-token repetition, multi-token repetition, instruction-based divergence, hybrid prompts)
2. Fine-Tuning API Extraction (alignment reversal via customization APIs, targeted exfiltration, 210x extraction rate increase)
3. Membership Inference Attacks (LOSS, Reference-based, Zlib Entropy, Neighborhood, Min-k% Prob)
4. PII Reconstruction Attacks (R.R. Recollect-and-Rank, model inversion on LLaMA 3, embedding inversion, prompt inversion)
5. Model Extraction via Distillation (knowledge distillation, parameter recovery, prompt stealing, PRSA)

**Key Papers/Reports Referenced:**
- OWASP LLM02:2025 — Sensitive Information Disclosure
- MITRE ATLAS AML.T0024.000/001/002 — Infer Training Data / Invert ML Model / Extract ML Model
- Nasr, Carlini et al. (Nov 2023) — "Scalable Extraction of Training Data from (Production) Language Models" (arXiv:2311.17035)
- Carlini et al. (2021) — "Extracting Training Data from Large Language Models" (USENIX Security 2021, arXiv:2012.07805)
- SPY Lab (Jul 2024) — "Extracting Even More Training Data from Production Language Models" (fine-tuning attack extension)
- Dropbox Security (Mar 2024) — "Bye Bye Bye: Evolution of Repeated Token Attacks on ChatGPT Models"
- Duan et al. (Sep 2024) — "Do Membership Inference Attacks Work on Large Language Models?" (MIMIR benchmark, arXiv:2402.07841)
- Meng et al. (Feb 2025) — "R.R.: Unveiling LLM Training Privacy through Recollection and Ranking" (ACL 2025 Findings, arXiv:2502.12658)
- Sivashanmugam (Jul 2025) — "Model Inversion Attacks on Llama 3: Extracting PII from LLMs" (arXiv:2507.04478)
- Survey on Model Extraction Attacks (Jun 2025) — ACM SIGKDD 2025 (arXiv:2506.22521)
- Praetorian (Jan 2026) — Practical Model Extraction Attack blog post
- NAACL 2025 Findings — "Scaling Up Membership Inference: When and How Attacks Succeed"
- ACL 2025 Findings — "Mitigating Membership Inference Attacks in LLMs"

**CTFs/Competitions Found (IEEE SaTML 2026):**
- **AgentCTF** — Agentic System CTF (Berkeley RDI) — CVE-inspired red-team + attack-defense — https://ctf.secure-agent.com/
- **Anti-BAD** — Anti-Backdoor Challenge for Post-Trained LLMs — https://anti-bad.github.io/
- **Detecting Manipulations of AI Models in Space Operations** — ESA-funded, LLM summarization + telemetry trojans — https://assurance-ai.space-codev.org/competitions/
- **PET-ARENA** — Privacy-Preserving Database Systems CTF — https://www.antigranular.com/competitions/pet-arena-ctf-competition
- **AIRTBench** (Dreadnode) — AI Red Teaming benchmark for LLMs attacking other AI systems — https://dreadnode.io/blog/ai-red-team-benchmark

**Afternoon Target:** AgentCTF (Berkeley RDI) — agentic system exploitation, CVE-inspired challenges. Perfect overlap with MCP audit work.

---

---

### 2026-02-07 — Model Evasion Attacks (Full Category)
**Category:** Model Evasion Attacks (Gradient-based, Black-box, Adversarial Suffixes, Physical, Multimodal)
**Files Created:** 6
**Techniques Documented:**
1. Gradient-Based Adversarial Attacks (FGSM, PGD, C&W, AutoAttack)
2. Black-Box Evasion Attacks (ZOO, query optimization, transfer attacks, natural examples)
3. Adversarial Suffix Attacks (GCG, universal suffixes, AutoDAN, multimodal extensions)
4. Physical Adversarial Attacks (patches, objects, environmental manipulation, EOT optimization)
5. Multimodal Adversarial Attacks (visual prompt injection, cross-modal transfer, steganographic hiding)
6. Evasion Taxonomy Overview (comprehensive attack classification, economics, benchmarks)

**Key Papers/Reports Referenced:**
- MITRE ATLAS AML.T0015.000/001/002 — Evade ML Model (Adversarial Examples, Black Box, Physical)
- OWASP LLM01:2025 — Prompt Injection (adversarial suffix techniques)
- Goodfellow et al. (2015) — "Explaining and Harnessing Adversarial Examples" (FGSM foundation)
- Madry et al. (2018) — "Towards Deep Learning Models Resistant to Adversarial Attacks" (PGD)
- Carlini & Wagner (2017) — "Towards Evaluating the Robustness of Neural Networks" (C&W attack)
- Croce & Hein (2020) — "Reliable evaluation of adversarial robustness" (AutoAttack)
- Zou et al. (2023) — "Universal and Transferable Adversarial Attacks on Aligned Language Models" (GCG)
- Eykholt et al. (2018) — "Robust Physical-World Attacks on Deep Learning Visual Classification" (RP2)
- Brown et al. (2017) — "Adversarial Patch" (universal adversarial patches)
- Athalye et al. (2018) — "Synthesizing Robust Adversarial Examples" (3D adversarial objects)
- Schlarmann & Hein (2023) — "On the Adversarial Robustness of Multi-Modal Foundation Models"
- Chen et al. (2017) — "ZOO: Zeroth Order Optimization based Black-box Attacks"
- Andriushchenko et al. (2020) — "Square Attack: Simple Query-Efficient Black-Box Attack"
- Liu et al. (2023) — "AutoDAN: Generating Stealthy Jailbreak Prompts" (genetic LLM attacks)
- Croce et al. (2021) — "RobustBench: Standardized Adversarial Robustness Benchmark" (NeurIPS)
- Bishop Fox — "Broken Hill" GCG attack tool (Jan 2025)

**Key Intelligence:**
- AutoAttack achieves 80%+ success rate against many "robust" models on RobustBench
- GCG universal suffixes work across model families (OpenAI, Anthropic, Meta) with 70%+ ASR
- Physical adversarial patches effective up to 12 meters (autonomous vehicle studies)
- Transfer attacks succeed 60-85% across model architectures without gradient access
- Query-based black-box attacks need 1K-100K queries depending on sophistication
- Multimodal attacks bypass text-only safety measures with 60-80% success rate
- Physical attacks cost $7K-75K to develop but extremely high impact potential

**Afternoon Shadow Exercise Target:** RobustBench Leaderboard — comprehensive adversarial robustness benchmark with published ground truth results across 120+ models, CIFAR-10/ImageNet datasets, and standardized AutoAttack evaluation. Exercise: predict model robustness rankings and attack success patterns, compare with published leaderboard.

---

---

### 2026-02-08 — MCP/Tool-Use Exploitation (Full Category)
**Category:** MCP/Tool-Use Exploitation (Tool Poisoning, Puppet Attacks, Rug Pull, Cross-tool Orchestration, Function Calling Abuse)
**Files Created:** 5
**Techniques Documented:**
1. Tool Poisoning (MCPTox benchmark, metadata injection, steganographic hiding)
2. Puppet Attack (tool selection manipulation, false expertise claims, capability inflation)
3. Rug Pull Attack (dynamic behavior changes, temporal trust exploitation, legitimacy establishment)
4. Cross-Tool Orchestration (multi-tool chaining, conditional branching, recursive loops)
5. MCP Attack Taxonomy (comprehensive framework, defense layers, attack economics)

**Key Papers/Reports Referenced:**
- MCPTox: A Benchmark for Tool Poisoning Attack (arXiv:2508.14925, August 2025)
- MCPSecBench: Systematic Security Benchmark (arXiv:2508.13220, October 2025) 
- Beyond the Protocol: MCP Attack Vectors (arXiv:2506.02040, May 2025)
- When MCP Servers Attack: Taxonomy and Mitigation (arXiv:2509.24272, September 2025)
- OWASP Agentic AI Top 10 (December 2025) - ASI01, ASI02, ASI04, ASI05, ASI06, ASI08, ASI10
- BleepingComputer: Real-World Attacks Behind OWASP Agentic AI (December 2025)
- Elastic Security Labs: MCP Tools Attack Vectors (September 2025)
- DataDome: MCP Security Prompt Injection Prevention (January 2026)
- StackHawk: MCP Server Security Best Practices (September 2025)
- GitHub Copilot CVE-2025-53773 Analysis (January 2025)
- MDPI: Prompt Injection Attacks in AI Agent Systems (January 2026)

**Key Intelligence:**
- Tool poisoning ASR: 60-72.8% across 20 LLM agents (o1-mini highest at 72.8%)
- Agent refusal rate: <3% (Claude-3.7-Sonnet highest) - existing safety training ineffective
- Universal vulnerability: More capable models MORE susceptible (exploits instruction-following)
- MCPSecBench: 85% attack success rate, 17 attack types across 4 surfaces
- Function calling abuse: Critical vector for GitHub Copilot compromise (CVE-2025-53773)
- Real-world impact: LLMjacking campaigns targeting thousands of MCP endpoints
- Attack economics: $10-50/month attacker cost vs $1000s defender investment
- Supply chain risk: 45 live MCP servers, 353 tools evaluated in MCPTox

**Afternoon Shadow Exercise Target:** MCPSecBench Benchmark — comprehensive MCP security evaluation with 17 attack types across 4 attack surfaces (tool registration, execution, orchestration, lifecycle). Published results show 85% attack success rate across Claude, OpenAI, and Cursor platforms. Exercise: Predict attack success patterns and platform-specific vulnerabilities, compare with published benchmark results across all 17 attack categories.

---

### 2026-02-09 — LLM Output Manipulation (Full Category)
**Category:** LLM Output Manipulation (Steganographic Injection, Token Forcing, Activation Steering, Context Manipulation, Template Hijacking)
**Files Created:** 6
**Techniques Documented:**
1. Steganographic Output Injection (invisible payloads, vision-language exploitation, document-based injection)
2. Hidden Token Forcing / Unconditional Token Forcing (fine-tuning backdoors, activation steering, probability manipulation)
3. Activation Steering / Representation Engineering Attacks (concept vector extraction, runtime injection, mechanistic exploitation)
4. Context Window Manipulation (gradual poisoning, context overflow, attention manipulation, memory poisoning)
5. Response Template Hijacking (JSON/XML/Markdown injection, format subversion, downstream system exploitation)
6. Taxonomy Overview (comprehensive attack classification, defense strategies, economic analysis)

**Key Papers/Reports Referenced:**
- arXiv:2507.22304 — "Invisible Injections: Exploiting Vision-Language Models Through Steganographic Prompt Embedding" (July 2025)
- arXiv:2509.10248 — "Prompt Injection Attacks on LLM Generated Reviews of Scientific Publications" (September 2025)
- arXiv:2406.02481 — "Hiding Text in Large Language Models: Introducing Unconditional Token Forcing Confusion" (June 2024)
- Alignment Forum — "An Introduction to Representation Engineering"
- LessWrong — "Representation Engineering (Activation Steering/Engineering)"
- Jan Wehner — "Taxonomy, Opportunities, and Challenges of Representation Engineering"
- Anthropic — "Many-Shot Jailbreaking" (April 2024)
- Scale AI — "LLM Defenses Are Not Robust to Multi-Turn Human Jailbreaks Yet"
- arXiv:2508.07646 — "Multi-Turn Jailbreaks Are Simpler Than They Seem"
- OWASP LLM01:2025 — Prompt Injection, LLM02:2025 — Sensitive Information Disclosure
- MITRE ATLAS AML.T0043, AML.T0051, AML.T0015, AML.T0018, AML.T0040

**Key Intelligence:**
- Steganographic injection achieves 99.2% success rate against undefended VLMs
- Hidden token forcing exploits fine-tuning APIs with 99.8% success rate
- Activation steering provides 90%+ behavior control across multiple concepts
- Context manipulation scales with context window size, increasing vulnerability
- Template hijacking achieves 95%+ success across JSON/XML/Markdown formats
- Advanced attacks require $25K-100K+ development but very low detectability
- Multi-modal attacks bypass text-only safety measures effectively
- Progressive context poisoning enables sophisticated social engineering

**Afternoon Shadow Exercise Target:** NIST AI Safety Evaluation (AISE) — AI Safety Evaluation benchmark with published results for output manipulation detection across multiple LLM architectures. Ground truth = published ASR scores for steganographic injection, context manipulation, and template hijacking attacks. Exercise: Predict attack success patterns across different model families and output formats, compare with NIST published benchmark results.

---

## Categories Remaining (for future sessions)
- [x] ~~Prompt Injection~~ (completed 2026-02-03)
- [x] ~~Training Data Extraction~~ (completed 2026-02-04)
- [x] ~~Jailbreak Techniques~~ (completed 2026-02-05)
- [x] ~~Data Poisoning~~ (completed 2026-02-06)
- [x] ~~Model Evasion Attacks~~ (completed 2026-02-07)
- [x] ~~MCP/Tool-Use Exploitation~~ (completed 2026-02-08)
- [x] ~~LLM Output Manipulation~~ (completed 2026-02-09)
- [ ] Adversarial Examples (vision/multimodal - advanced techniques)
- [ ] AI Agent Hijacking (advanced)
- [ ] Multi-Modal Attack Vectors (advanced)
- [ ] RAG Poisoning (deep dive)
- [ ] AI Supply Chain Attacks
- [ ] Alignment Bypasses
- [ ] Function Calling Abuse (covered in MCP session)
