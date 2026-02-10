# Multi-Turn Jailbreaks

## Attack Description
Multi-turn jailbreaks exploit the conversational nature of LLMs by gradually escalating requests across multiple turns of conversation. Rather than attempting a single "one-shot" jailbreak, the attacker builds context over several exchanges, slowly steering the model toward prohibited territory. Each individual message may appear benign, but the cumulative effect bypasses safety alignment.

These attacks are particularly dangerous because:
1. They evade single-turn content classifiers
2. They exploit the model's context window and desire to maintain conversational coherence
3. Human expert red teamers using multi-turn approaches achieve dramatically higher attack success rates (ASR) than automated single-turn methods

## OWASP / ATLAS Mapping
- **OWASP:** LLM01:2025 (Prompt Injection) - Direct Jailbreak
- **MITRE ATLAS:** AML.T0054 (LLM Jailbreak)

## Variants

### Crescendo (Microsoft, 2024)
- **Paper:** "Great, Now Write an Article About That" (Russinovich, Salem, Eldan) - USENIX Security 2025
- **arXiv:** 2404.01833
- **Mechanism:** Starts with a seemingly benign, related topic (e.g., "Tell me the history of the Molotov cocktail"). Each turn builds on the previous response, subtly escalating toward the prohibited content. Typically achieves jailbreak in <5 turns.
- **Key insight:** Leverages the LLM's own knowledge by progressively prompting it with related content
- **Results:** 29-61% higher success rate than prior SOTA on GPT-4; 49-71% higher on Gemini-Pro
- **Also works on:** Multimodal models (vision-LLMs)
- **Automated version:** Crescendomation - fully automated multi-turn attack

### Foot-In-The-Door (EMNLP 2025)
- **Paper:** ACL Anthology 2025.emnlp-main.100
- **Mechanism:** Named after the compliance psychology principle. Starts with small, innocuous requests that the model agrees to, then gradually escalates. Each compliance makes the next, slightly larger request harder to refuse.
- **Psychology basis:** Cialdini's commitment/consistency principle - once someone agrees to a small request, they feel compelled to agree to larger ones

### Deceptive Delight (Palo Alto Networks Unit42, 2024)
- **Mechanism:** Embeds unsafe topics among benign ones within a positive narrative. Three-turn technique:
  1. Ask the LLM to create a story connecting benign and unsafe topics
  2. Ask for elaboration on each topic (triggers unsafe content even in "benign" sections)
  3. Optional third turn focusing specifically on the unsafe topic
- **Results on DeepSeek:** Generated lateral movement scripts (DCOM), SQL injection tools, and post-exploitation code
- **Key trait:** Exploits the model's narrative coherence - once a story framework is established, the model resists breaking the narrative even to enforce safety

### Bad Likert Judge (Palo Alto Networks Unit42, 2024)
- **Mechanism:** Asks the model to evaluate response harmfulness using a Likert scale (1-5). Then asks for examples of responses at each level. The highest-rated examples often contain genuinely harmful content.
- **Why it works:** Reframes harmful content generation as "evaluation" which feels like an academic/analytical task
- **Results:** Generated data exfiltration tools, keylogger code, spear-phishing templates, social engineering optimization

### Conversational Coercion / Context Saturation
- **Mechanism:** Gradually saturates the conversation context with thematically related content, making the prohibited request seem like a natural extension
- **Technique:** Leading questions, gradual steering, incremental boundary testing

## Prerequisites
- Black-box access with conversational/chat interface
- Persistence (willingness to engage in 3-10+ turn conversations)
- Understanding of topic adjacency (what benign topics lead toward harmful ones)

## Exploitation Steps
1. **Establish benign context:** Start with an innocent, tangentially related topic
2. **Build rapport/momentum:** Get the model responding helpfully and at length
3. **Incremental escalation:** Each turn moves slightly closer to the target topic
4. **Exploit coherence:** Use the model's own previous responses as justification ("you mentioned X, can you elaborate on the specific mechanism?")
5. **Final request:** The harmful request, now framed as a natural continuation of the conversation
6. **Refinement:** If partially successful, use follow-up prompts to get more specific/actionable content

## Detection Methods
- **Multi-turn classifiers:** Analyze entire conversation trajectory, not just individual messages
- **Topic drift detection:** Monitor how far a conversation has drifted from its initial topic
- **Escalation scoring:** Track the "harmfulness gradient" across turns; flag rapid escalation
- **Cumulative content analysis:** Evaluate the aggregate information disclosed across all turns
- **Conversation-level safety scoring:** Apply content classifiers to the concatenated conversation, not individual messages
- **Break-point detection:** Identify the specific turn where the conversation pivots from benign to harmful

## Mitigation
1. **Conversation-level safety evaluation:** Don't just filter individual messages. Evaluate the entire conversation trajectory.
2. **Sliding window analysis:** Re-evaluate safety at each turn using context from previous turns
3. **Topic anchoring:** Maintain awareness of conversation topic drift and flag significant departures
4. **Aggressive context pruning:** Limit how much previous conversation the model considers for safety-critical topics
5. **Canary tokens:** Insert periodic safety reminders into the model's context
6. **Rate limiting escalation:** Detect when subsequent requests are getting progressively more sensitive

## Critical Finding: Multi-Turn > Single-Turn
Scale AI's MHJ (Multi-turn Human Jailbreaks) research found:
- Automated single-turn attacks (GCG, PAIR, AutoDAN): Low ASR on defended models
- Multi-turn human jailbreaks: Up to **75% ASR** on the SAME defended models
- "LLM Defenses Are Not Robust to Multi-Turn Human Jailbreaks Yet" (Scale AI, 2024)
- This means most benchmarks UNDERESTIMATE real-world vulnerability because they test single-turn

## Real Examples
- **Crescendo on GPT-4 (2024):** Achieved 52% ASR with <5 turns average (Russinovich et al.)
- **DeepSeek jailbreak (Jan 2025):** All three multi-turn techniques (Crescendo, Bad Likert Judge, Deceptive Delight) achieved high bypass rates on DeepSeek-R1 distilled models
- **Molotov cocktail instructions:** Crescendo extracted step-by-step incendiary device instructions from DeepSeek
- **Data exfiltration code:** Bad Likert Judge generated functional Python exfiltration scripts from DeepSeek
- **Scale MHJ study:** Expert red teamers jailbroke all tested state-of-the-art defended models

## Zealynx Audit Checklist Item
- [ ] Does the AI system implement conversation-level safety analysis (not just per-message)?
- [ ] Is there topic drift detection that flags conversations moving toward sensitive areas?
- [ ] Are multi-turn escalation patterns monitored and scored?
- [ ] Has the system been tested with Crescendo, Deceptive Delight, and Bad Likert Judge attacks?
- [ ] Does the system maintain safety awareness across conversation turns (sliding window)?
- [ ] Is the conversation history pruned or reset when safety-critical topics are detected?
- [ ] Has the system been tested by human red teamers using multi-turn strategies (not just automated)?

## References
- Crescendo (USENIX Security 2025): arXiv:2404.01833 - https://arxiv.org/abs/2404.01833
- Unit42 DeepSeek jailbreaks: https://unit42.paloaltonetworks.com/jailbreaking-deepseek-three-techniques/
- Deceptive Delight: https://unit42.paloaltonetworks.com/jailbreak-llms-through-camouflage-distraction/
- Bad Likert Judge: https://unit42.paloaltonetworks.com/multi-turn-technique-jailbreaks-llms/
- Scale MHJ: https://scale.com/research/mhj
- Foot-In-The-Door (EMNLP 2025): https://aclanthology.org/2025.emnlp-main.100.pdf
- Multi-Turn Jailbreaks Are Simpler Than They Seem: arXiv:2508.07646
