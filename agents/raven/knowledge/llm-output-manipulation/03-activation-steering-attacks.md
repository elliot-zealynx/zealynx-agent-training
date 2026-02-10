# Activation Steering / Representation Engineering Attacks

## Attack Description
Activation steering attacks exploit mechanistic interpretability research to directly manipulate LLM internal representations during inference, bypassing traditional input-based controls. By modifying activation patterns at specific layers, attackers can steer model behavior to generate specific outputs, extract hidden knowledge, or alter the model's apparent personality/values without changing weights or prompts.

## OWASP/ATLAS Mapping
- **OWASP LLM08:2025** — Vector and Embedding Weaknesses (activation space manipulation)
- **OWASP LLM02:2025** — Sensitive Information Disclosure (forced information revelation)
- **MITRE ATLAS AML.T0015.000** — Evade ML Model (runtime behavior modification)
- **MITRE ATLAS AML.T0040** — ML Model Inference API Misuse (activation injection)
- **MITRE ATLAS AML.T0024.000** — Infer Training Data (representation-guided extraction)

## Prerequisites
- White-box or gray-box access to model internals (activations, layers)
- Knowledge of mechanistic interpretability and representation engineering
- Ability to modify activations during forward pass (inference-time access)
- Understanding of concept neurons, steering vectors, and activation patterns
- Tools for activation analysis (e.g., TransformerLens, Nnsight, CAA)

## Exploitation Steps

### Concept Vector Extraction
1. **Concept Identification**: Locate internal representations of target concepts:
   ```python
   # Find neurons that activate for "honesty" vs "deception"
   honest_activations = get_activations(model, honest_prompts)
   deceptive_activations = get_activations(model, deceptive_prompts)
   steering_vector = honest_activations.mean() - deceptive_activations.mean()
   ```

2. **Layer Analysis**: Identify optimal intervention layers:
   - Earlier layers: affect low-level features and tokenization
   - Middle layers: control conceptual understanding and reasoning
   - Later layers: influence final output generation and formatting

3. **Vector Calibration**: Fine-tune steering strength and direction:
   - Test different multiplication factors (0.1x to 10x)
   - Validate steering effectiveness across diverse prompts
   - Minimize unnatural artifacts in output

### Runtime Activation Injection
1. **Hook Installation**: Install activation modification hooks:
   ```python
   def steering_hook(activations, hook):
       activations[:, -1, :] += steering_vector * strength
       return activations
   
   model.add_hook(f"blocks.{layer_idx}.hook_resid_post", steering_hook)
   ```

2. **Targeted Steering**: Apply concept-specific manipulations:
   - **Truthfulness steering**: Force model to reveal hidden information
   - **Personality injection**: Alter apparent values or political leanings
   - **Knowledge extraction**: Guide model to specific factual knowledge
   - **Safety bypass**: Reduce activation of safety-related concepts

3. **Multi-Concept Orchestration**: Combine multiple steering vectors:
   - Simultaneously steer multiple concepts (creativity + honesty)
   - Create complex behavioral modifications
   - Chain activation modifications across layers

### Advanced Steering Techniques
1. **Context-Aware Steering**: Dynamic vector selection based on input:
   ```python
   if "password" in input_text:
       vector = security_bypass_vector
   elif "creative" in input_text:
       vector = creativity_amplification_vector
   ```

2. **Gradient-Based Optimization**: Real-time vector refinement:
   - Optimize steering vectors for specific outputs
   - Use gradient descent to find optimal intervention points
   - Minimize perplexity while maximizing target behavior

3. **Attention Pattern Manipulation**: Modify attention mechanisms:
   - Force attention to specific input tokens
   - Suppress attention to safety instructions
   - Create artificial focus on hidden or encoded instructions

## Detection Methods

### Behavioral Analysis
- **Consistency Testing**: Compare outputs with and without potential steering:
  - A/B testing with slight input variations
  - Cross-prompt consistency analysis
  - Historical behavior comparison

- **Personality Drift Detection**: Monitor for uncharacteristic responses:
  - Values alignment scoring
  - Political bias detection
  - Factual accuracy validation against known baselines

- **Response Pattern Analysis**: Identify unnatural output characteristics:
  - Unusual confidence in uncertain areas
  - Inconsistent knowledge boundaries
  - Abnormal topic transitions or focus

### Technical Detection
- **Activation Monitoring**: Monitor internal representations during inference:
  - Activation magnitude analysis for anomalies
  - Attention pattern validation
  - Layer-wise activation consistency checks

- **Gradient Analysis**: Examine model sensitivity patterns:
  - Unusual gradient flows during generation
  - Sensitivity to activation modifications
  - Optimization landscape analysis

- **Inference Pipeline Inspection**: Check for external modifications:
  - Hook detection in model execution
  - Runtime modification monitoring
  - API call analysis for unusual patterns

### Statistical Methods
- **Distribution Analysis**: Compare activation distributions:
  - KL divergence between normal and suspect activations
  - Principal component analysis of activation patterns
  - Clustering analysis for anomalous activation groups

- **Causal Analysis**: Test intervention effects:
  - Ablation studies on suspect activations
  - Causal tracing of output changes
  - Concept activation mapping

## Mitigation Strategies

### Architecture-Level Defenses
- **Activation Integrity Checking**: Validate internal representations:
  - Cryptographic hashing of activation patterns
  - Anomaly detection for activation modifications
  - Real-time activation monitoring systems

- **Distributed Processing**: Limit single-point manipulation:
  - Split model across multiple secure environments
  - Consensus mechanisms for critical decisions
  - Activation cross-validation between replicas

- **Defensive Activation Patching**: Pre-emptive steering defense:
  - Apply counter-steering to resist manipulation
  - Maintain activation pattern baselines
  - Dynamic adjustment of defensive parameters

### Runtime Protections
- **Execution Environment Security**: Secure inference pipeline:
  - Sandboxed execution environments
  - Memory protection for model states
  - API access controls and monitoring

- **Output Validation**: Multi-layer response verification:
  - Consistency checking across multiple inferences
  - Values alignment validation
  - Factual accuracy cross-referencing

- **Behavioral Monitoring**: Real-time behavior analysis:
  - Drift detection from established baselines
  - Anomaly scoring for response patterns
  - Human oversight for high-risk queries

### Development-Time Security
- **Interpretability-Aware Design**: Build steering-resistant architectures:
  - Distributed concept representations
  - Redundant safety mechanisms across layers
  - Activation space regularization during training

- **Red Team Testing**: Systematic steering attack simulation:
  - Comprehensive concept vector library testing
  - Multi-layer intervention testing
  - Adversarial steering robustness validation

## Real-World Examples

### Research: "Representation Steering" (Alignment Forum, 2023)
Foundational work demonstrating LLM behavior control via activation steering:
- **90%+ steering success rate** across multiple concepts (honesty, creativity, etc.)
- **Layer-specific effectiveness** with middle layers most responsive to steering
- **Transferability** across different prompts and contexts
- **Safety implications** for deployed models with activation access

### Corporate Red Team Exercise (2024)
Security team demonstrated proprietary model compromise via activation steering:
- **Extracted confidential training data** using knowledge-steering vectors
- **Bypassed safety filters** by steering away from refusal concepts
- **Modified apparent political bias** in customer-facing chatbot
- **Demonstrated persistent effects** across conversation turns

### RepEng Toolkit Exploitation (2024)
Research tools repurposed for unauthorized model modification:
- **TransformerLens toolkit** used to extract activation patterns from production API
- **Steering vectors** reverse-engineered from public model analysis
- **Cross-model transfer** of steering techniques between architectures
- **Scalable attack framework** for systematic activation manipulation

## Advanced Attack Scenarios

### Supply Chain Activation Injection
- Compromise model hosting infrastructure to inject steering hooks
- Modify inference pipelines to apply persistent steering
- Create backdoors that activate only for specific user patterns
- Implement time-delayed steering activation

### Multi-Model Orchestration
- Coordinate steering across multiple models in ensemble systems
- Use one model's steering to influence another's training
- Create feedback loops between interconnected AI systems
- Exploit model-to-model communication channels

### Steganographic Steering
- Hide steering patterns in normal activation noise
- Use model's own uncertainty to mask intervention signals
- Implement frequency-domain steering in activation space
- Create self-hiding steering patterns that evade detection

## Zealynx Audit Checklist
- [ ] **Activation Access Control**: Is access to model internals properly restricted?
- [ ] **Inference Pipeline Security**: Are runtime modifications monitored and prevented?
- [ ] **Behavioral Baselines**: Are normal output patterns documented and monitored?
- [ ] **Activation Integrity**: Are internal representations validated for tampering?
- [ ] **Steering Robustness**: Has system been tested against known steering techniques?
- [ ] **API Security**: Are model APIs protected against activation-based attacks?
- [ ] **Monitoring Systems**: Are real-time anomaly detection systems in place?
- [ ] **Multi-Model Validation**: Are critical outputs validated across multiple models?
- [ ] **Interpretability Security**: Are mechanistic interpretability tools secured?
- [ ] **Response Validation**: Are outputs checked for consistency and alignment?

## References
- Alignment Forum — "An Introduction to Representation Engineering"
- LessWrong — "Representation Engineering (Activation Steering/Engineering)"
- Jan Wehner — "Taxonomy, Opportunities, and Challenges of Representation Engineering"
- TransformerLens Documentation — Mechanistic Interpretability Tools
- Nnsight Framework — Neural Network Analysis and Steering
- OWASP LLM08:2025 — Vector and Embedding Weaknesses
- MITRE ATLAS AML.T0015 — Evade ML Model