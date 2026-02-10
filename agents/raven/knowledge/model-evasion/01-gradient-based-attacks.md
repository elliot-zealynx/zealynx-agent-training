# Gradient-Based Adversarial Attacks

## Attack Description
Gradient-based adversarial attacks use the gradient of a model's loss function to craft minimal perturbations to input data that cause the model to misclassify or produce unintended outputs. These attacks exploit the high-dimensional nature of neural network decision boundaries.

## OWASP/MITRE Mapping
- **MITRE ATLAS:** AML.T0015.000 - Evade ML Model (Adversarial Examples)
- **OWASP LLM Top 10:** Not directly listed but relates to LLM01 (Prompt Injection) through adversarial suffix techniques

## Attack Categories

### Fast Gradient Sign Method (FGSM)
**Prerequisites:** White-box access to model gradients
**Exploitation Steps:**
1. Compute loss gradient ∇_x L(θ, x, y) with respect to input x
2. Generate adversarial example: x' = x + ε × sign(∇_x L)
3. Apply clipping to maintain input constraints
4. Submit x' to target model

**Original Paper:** Goodfellow et al. (2015) - "Explaining and Harnessing Adversarial Examples"

### Projected Gradient Descent (PGD)
**Prerequisites:** White-box access to model gradients  
**Exploitation Steps:**
1. Initialize with random noise: x^0 = x + random_noise
2. For t = 1 to iterations:
   - Compute gradient: g = ∇_x L(θ, x^(t-1), y)
   - Update: x^t = Π(x^(t-1) + α × sign(g))
   - Project back to constraint set
3. Return final adversarial example x^T

**Original Paper:** Madry et al. (2018) - "Towards Deep Learning Models Resistant to Adversarial Attacks"

### Carlini & Wagner (C&W) Attack
**Prerequisites:** White-box access to model and loss computation
**Exploitation Steps:**
1. Minimize: ||δ||_p + c × f(x + δ) where f is attack objective
2. Use change of variables: w = tanh^(-1)(2x - 1) to handle box constraints
3. Optimize w using Adam optimizer with binary search on c
4. Convert back to adversarial example

**Original Paper:** Carlini & Wagner (2017) - "Towards Evaluating the Robustness of Neural Networks"

### AutoAttack
**Prerequisites:** White-box access (combines multiple attacks)
**Exploitation Steps:**
1. Run ensemble of attacks: APGD-CE, APGD-DLR, FAB, Square Attack
2. Use diverse loss functions and restart strategies
3. Parameter-free: automatically adjusts hyperparameters
4. Return worst-case robust accuracy across all attacks

**Original Paper:** Croce & Hein (2020) - "Reliable evaluation of adversarial robustness with an ensemble of diverse parameter-free attacks"

## Detection Methods
1. **Statistical Detection:** Monitor input distributions for outliers
2. **Gradient Analysis:** Detect unusually high gradient norms
3. **Ensemble Inconsistency:** Check for disagreement across model variants
4. **Adversarial Training Integration:** Use robust training objectives

## Mitigations
1. **Adversarial Training:** Include adversarial examples in training data
2. **Gradient Masking:** Obscure gradients (but often bypassed)
3. **Input Preprocessing:** JPEG compression, bit-depth reduction
4. **Certified Defenses:** Randomized smoothing, interval bound propagation
5. **Ensemble Methods:** Vote across multiple models

## Real Examples
- **2018:** Eykholt et al. demonstrated physical adversarial patches on stop signs
- **2019:** Brown et al. showed universal adversarial patches transferring to real world
- **2020:** Wallace et al. applied gradient-based attacks to BERT for text classification
- **2023:** Zou et al. extended GCG (gradient-based) attacks to LLMs for harmful generation

## Zealynx Audit Checklist Items
- [ ] Test model robustness against FGSM with ε ∈ {0.01, 0.03, 0.1}
- [ ] Evaluate PGD attack success rate (7-step, 20-step variants)
- [ ] Run AutoAttack for comprehensive gradient-based evaluation
- [ ] Check for gradient masking (test with adaptive attacks)
- [ ] Verify adversarial training effectiveness with worst-case perturbations
- [ ] Test transferability across model architectures
- [ ] Evaluate physical realizability of adversarial examples

## Attack Economics
- **Development Cost:** Low (existing frameworks: Foolbox, CleverHans, ART)
- **Execution Cost:** Medium (requires gradient computation)
- **Skill Level:** Medium (understanding of gradients required)
- **Detection Difficulty:** Medium (statistical methods can detect)