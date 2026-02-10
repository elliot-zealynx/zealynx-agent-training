# Black-Box Model Evasion Attacks

## Attack Description
Black-box adversarial attacks generate adversarial examples without direct access to model parameters, gradients, or architecture. These attacks rely on query-based optimization, transfer attacks, or surrogate models to fool the target system.

## OWASP/MITRE Mapping
- **MITRE ATLAS:** AML.T0015.001 - Evade ML Model (Black Box Evasion)
- **OWASP LLM Top 10:** Relates to model robustness across all attack surfaces

## Attack Categories

### Query-Based Optimization
**Prerequisites:** API access for input-output queries
**Exploitation Steps:**
1. Use evolutionary algorithms (genetic search, particle swarm optimization)
2. Estimate gradients via finite differences: ∇f ≈ (f(x + h) - f(x - h)) / 2h
3. Apply gradient estimation to white-box attack algorithms
4. Iterate with query budget constraints

**Key Algorithms:**
- **Zeroth Order Optimization (ZOO):** Chen et al. (2017)
- **Square Attack:** Andriushchenko et al. (2020)
- **SimBA:** Guo et al. (2019) - Simple Black-box Adversarial Attacks

### Transfer-Based Attacks
**Prerequisites:** Access to similar/surrogate models
**Exploitation Steps:**
1. Train surrogate model on same task/dataset
2. Generate adversarial examples on surrogate using white-box methods
3. Transfer examples to target black-box model
4. Exploit cross-model vulnerability patterns

**Enhancement Techniques:**
- **Ensemble Surrogate Models:** Average gradients across multiple surrogates
- **Input Transformation:** Random resizing, rotation to improve transferability
- **Momentum-based Methods:** Dong et al. (2018) - boost transfer rates

### Decision-Boundary Based
**Prerequisites:** Binary feedback (confidence scores helpful)
**Exploitation Steps:**
1. **Boundary Attack (Brendel et al.):** Start from adversarial example, walk along boundary
2. **HopSkipJump Attack:** Chen et al. (2020) - estimate gradients at decision boundary
3. **GeoDA:** Rahmati et al. (2020) - geometric decision-based attack

### Natural Adversarial Examples
**Prerequisites:** Large datasets of naturally occurring edge cases
**Exploitation Steps:**
1. Mine datasets for naturally misclassified examples
2. Use generative models to produce similar examples
3. Apply semantic transformations (lighting, angle, weather)
4. Test against target model without explicit optimization

## Practical Tools & Frameworks

### Query-Efficient Attacks
- **QEBA:** Query-Efficient Boundary-based Attack
- **NES:** Natural Evolution Strategies for adversarial examples
- **AutoZOOM:** Automatic zeroth-order optimization for adversarial examples

### Commercial Red-Team Tools
- **IBM Adversarial Robustness Toolbox (ART)**
- **Microsoft Counterfit:** Security automation framework
- **Google CleverHans:** Adversarial examples library

## Detection Methods
1. **Query Pattern Analysis:** Monitor for systematic probing behavior
2. **Rate Limiting:** Restrict queries per timeframe per user
3. **Honeypot Variants:** Deploy decoy models to detect enumeration
4. **Statistical Anomaly Detection:** Flag unusual input distributions

## Mitigations
1. **Query Budget Limits:** Restrict total queries per user/session
2. **Input Validation:** Sanitize and validate all inputs
3. **Model Ensembling:** Require consensus across multiple models
4. **Differential Privacy:** Add calibrated noise to outputs
5. **Randomized Response:** Occasionally return random outputs
6. **API Gateway Controls:** Authentication, logging, monitoring

## Real Examples
- **2016:** Papernot et al. fooled MetaMind API with 84% success using substitute models
- **2019:** Ilyas et al. showed adversarial examples transfer between completely different architectures
- **2020:** Microsoft research demonstrated query-based attacks on commercial APIs with <1000 queries
- **2022:** Zhao et al. attacked GPT-3.5 using black-box prompt injection with 73% success rate
- **2023:** Commercial ML APIs (AWS Rekognition, Google Vision) shown vulnerable to transfer attacks

## Case Study: Commercial API Attack
**Target:** Amazon Rekognition face detection
**Method:** Surrogate model transfer attack
**Results:** 
- 89% attack success rate with ResNet-50 surrogate
- <500 queries needed for optimization
- Physical attacks worked in 67% of test cases

## Zealynx Audit Checklist Items
- [ ] Test transfer attack vulnerability using common surrogate architectures
- [ ] Evaluate query budget needed for successful black-box optimization
- [ ] Check API rate limiting and monitoring effectiveness
- [ ] Test model robustness to naturally adversarial inputs
- [ ] Verify ensemble defense implementations
- [ ] Assess detection capability for systematic probing
- [ ] Review API authentication and logging mechanisms
- [ ] Test differential privacy noise calibration

## Attack Economics
- **Development Cost:** Medium-High (requires ML expertise and compute)
- **Execution Cost:** Variable (depends on query limits and pricing)
- **Skill Level:** Medium (black-box optimization knowledge helpful)
- **Detection Difficulty:** Medium-High (harder to detect than white-box)
- **Success Rate:** 60-85% with sufficient query budget
- **Query Budget:** 1K-100K queries typical (varies by attack sophistication)