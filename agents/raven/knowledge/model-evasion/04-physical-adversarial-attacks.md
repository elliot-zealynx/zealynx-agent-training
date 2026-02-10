# Physical Adversarial Attacks

## Attack Description
Physical adversarial attacks create real-world objects that fool ML systems when captured by cameras, sensors, or other input devices. Unlike digital attacks, these must survive physical transformations like lighting changes, camera angles, and printing artifacts.

## OWASP/MITRE Mapping
- **MITRE ATLAS:** AML.T0015.002 - Evade ML Model (Physical Environment)
- **OWASP AI Security:** Physical robustness testing (emerging best practice)

## Attack Categories

### Adversarial Patches
**Prerequisites:** Access to target model, printer/fabrication capability
**Exploitation Steps:**
1. Design patch to maximize target misclassification
2. Use Expectation Over Transformation (EOT) for robustness
3. Optimize over physical transformations: rotation, scaling, lighting
4. Print/fabricate physical patch
5. Deploy in target environment

**Example:** Universal adversarial patch causing any object to be classified as "toaster"

### Adversarial Objects
**Prerequisites:** 3D modeling capability, target object templates
**Exploitation Steps:**
1. Select base object (stop sign, product packaging, etc.)
2. Optimize surface textures/colors within realistic constraints  
3. Ensure robustness across viewing angles and distances
4. Fabricate modified object
5. Deploy in target scenario

### Environmental Manipulation
**Prerequisites:** Control over physical environment
**Exploitation Steps:**
1. Modify ambient lighting conditions
2. Place strategic distractors or occluders
3. Alter background patterns or textures
4. Use projection mapping for dynamic modifications
5. Test against target perception system

## Physical Constraints & Challenges

### Printing/Fabrication Limitations
- **Color Gamut:** Limited printer color reproduction
- **Resolution:** Discrete pixel boundaries vs continuous optimization
- **Material Properties:** Reflectance, texture, durability constraints

### Environmental Robustness
- **Lighting Variations:** Must work across illumination conditions
- **Viewing Angles:** Robustness to camera positioning
- **Distance Ranges:** Far-field vs near-field effectiveness
- **Weather Resistance:** Outdoor deployment considerations

### Detectability Constraints
- **Human Perception:** Balance between effectiveness and suspiciousness
- **Contextual Fit:** Patches must be plausible in target environment
- **Size Limitations:** Physical space constraints in deployment

## Optimization Techniques

### Expectation Over Transformation (EOT)
```
Objective: E_t~T[L(f(t(x + δ)), y)]
where:
- T = distribution of physical transformations
- t = specific transformation instance
- δ = adversarial perturbation
- L = loss function maximizing misclassification
```

### Robust Physical Perturbations (RP2)
**Paper:** Eykholt et al. (2018)
**Key Innovation:** Optimize over realistic transformation distributions
**Transformations:** Scale, rotation, Gaussian blur, brightness/contrast, printability

### Non-Printability Score (NPS)
**Purpose:** Ensure adversarial colors are reproducible by printers
**Formula:** NPS = Σ min(||c - p||) for colors c and printer gamut P
**Constraint:** Minimize NPS while maximizing attack success

## Real-World Attack Examples

### Stop Sign Attacks (Eykholt et al., 2018)
- **Target:** Autonomous vehicle perception
- **Method:** Small stickers on stop signs
- **Results:** 80% misclassification as "speed limit 45"
- **Distance:** Effective up to 12 meters

### 3D Printed Turtle → Rifle (Athalye et al., 2018)
- **Target:** ImageNet classifier
- **Method:** Textured 3D printed turtle
- **Results:** 100% confidence "rifle" classification across all angles
- **Insight:** Demonstrated 3D adversarial objects

### Adversarial Eyeglass Frames (Sharif et al., 2016)
- **Target:** Face recognition systems
- **Method:** Specially designed eyeglass frames
- **Results:** 100% impersonation success, 100% dodging success
- **Practical:** Wearable, inconspicuous

### Traffic Light Attacks (Chen et al., 2020)
- **Target:** Tesla Autopilot perception
- **Method:** Projector-based light manipulation
- **Results:** Phantom traffic lights detected with high confidence
- **Range:** Effective up to 150 meters

### Universal Adversarial Patch (Brown et al., 2017)
- **Target:** YOLO object detector
- **Method:** Small printable patch
- **Results:** Hiding people/objects in 40% of images
- **Transferability:** Works across different scenes and objects

## Attack Surfaces by Domain

### Autonomous Vehicles
- **Road Signs:** Stop signs, speed limits, lane markers
- **Traffic Infrastructure:** Traffic lights, crosswalks
- **Vehicle Detection:** Hiding pedestrians, cyclists, other vehicles
- **Lane Detection:** Adversarial road markings

### Surveillance Systems
- **Face Recognition Evasion:** Adversarial makeup, masks, accessories
- **Object Detection Bypass:** Hiding persons/objects from cameras
- **Behavioral Analysis:** Fooling gait recognition, action detection

### Industrial/IoT
- **QR Code Attacks:** Adversarial QR codes causing misreads
- **Robotic Vision:** Manipulating assembly line inspection
- **Agricultural Systems:** Crop disease misclassification

### Medical Imaging
- **X-Ray Manipulation:** Adversarial patches on patients
- **Pathology Slides:** Physical modifications causing misdiagnosis
- **MRI/CT Scans:** Implantable adversarial objects

## Detection & Forensics

### Anomaly Detection Methods
1. **Multi-Sensor Fusion:** Cross-validate with additional sensors
2. **Temporal Consistency:** Check frame-to-frame coherence
3. **Spatial Consistency:** Verify object physics and shadows
4. **Human Oversight:** Flag suspicious decisions for manual review

### Physical Forensics
1. **Spectral Analysis:** Check for unnatural color patterns
2. **3D Reconstruction:** Verify object geometry consistency  
3. **Material Analysis:** Detect artificial textures/surfaces
4. **Historical Comparison:** Compare with previous captures

## Mitigations & Defenses

### Input Preprocessing
- **Gaussian Blur:** Smooth out fine adversarial patterns
- **JPEG Compression:** Reduce high-frequency adversarial signals
- **Random Crops/Rotations:** Test robustness across viewpoints
- **Color Space Transformation:** Test in different color representations

### Training-Time Defenses
- **Adversarial Training:** Include physical attacks in training data
- **Data Augmentation:** Simulate physical transformations
- **Robust Optimization:** Train against worst-case perturbations

### Architectural Defenses  
- **Ensemble Methods:** Require consensus across multiple models
- **Multi-Scale Processing:** Process at different resolutions
- **Attention Mechanisms:** Focus on most relevant image regions

### System-Level Defenses
- **Redundant Sensors:** Lidar, radar, ultrasonic backup systems
- **Human-in-the-Loop:** Operator oversight for critical decisions
- **Geographical Constraints:** Limit operation to mapped/trusted areas

## Zealynx Audit Checklist Items
- [ ] Test adversarial patch vulnerability (universal patches from literature)
- [ ] Evaluate robustness to lighting condition changes
- [ ] Check multi-angle attack effectiveness (EOT evaluation)
- [ ] Test 3D printed adversarial object detection
- [ ] Verify input preprocessing effectiveness against physical attacks  
- [ ] Assess multi-sensor fusion implementation
- [ ] Review human oversight protocols for edge cases
- [ ] Test system behavior with partially occluded adversarial objects
- [ ] Evaluate detection of non-printable adversarial colors
- [ ] Check temporal consistency validation across video frames

## Physical Attack Development Cost
- **Research Phase:** $1K-10K (literature review, initial testing)
- **Design & Optimization:** $5K-50K (compute, iterative refinement) 
- **Physical Fabrication:** $100-5K (printing, materials, testing)
- **Deployment Testing:** $1K-10K (field testing, iterations)
- **Total:** $7.1K-75K depending on sophistication and scale

## Attack Economics by Target
| Target System | Development Cost | Success Rate | Detection Difficulty | Impact |
|---------------|-----------------|--------------|-------------------|--------|
| Traffic Signs | $2K-10K | 60-80% | Medium | High |
| Face Recognition | $1K-5K | 70-90% | Low-Medium | Medium |
| Object Detection | $3K-15K | 40-70% | Medium-High | Medium-High |
| Medical Imaging | $10K-50K | 80-95% | High | Very High |

## Research & Red-Team Resources
- **Adversarial Patch:** Universal patch generator code (GitHub)
- **Physical Attack Simulator:** Digital-to-physical domain transfer
- **Fabrication Partners:** 3D printing services, specialized materials
- **Testing Environments:** Controlled lighting, camera setups