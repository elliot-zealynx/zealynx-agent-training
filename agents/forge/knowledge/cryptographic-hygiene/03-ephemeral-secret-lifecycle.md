# Pattern 03: Ephemeral Secret Lifecycle

**Severity:** Low-Medium
**Category:** Cryptographic Hygiene
**CWE:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse)
**Prevalence:** Common in ZK proof implementations

## Description

Cryptographic protocols frequently use ephemeral (one-time) secrets: random blinding factors, nonces, challenge responses, and commitment randomness. These values are mathematically critical during proof generation but should be destroyed immediately after. If they persist, an attacker with memory access can:
- **Break ZK proofs:** Recover the secret witness from the commitment + blinding factor
- **Forge signatures:** Nonce reuse or recovery enables private key extraction (see PS3 ECDSA hack)
- **Decrypt ciphertexts:** Recover plaintext from ciphertext + ephemeral key

The lifecycle should be: **generate -> use -> destroy**. No exceptions.

## Vulnerable Code Example

```rust
// VULNERABLE: Multiple ephemeral secrets leaked after proof construction
pub fn new(amounts: Vec<u64>, bit_lengths: Vec<usize>) -> Result<RangeProof> {
    let nm = bit_lengths.iter().sum::<usize>();
    
    // Ephemeral secrets - CRITICAL to destroy after use
    let a_blinding = Scalar::random(&mut OsRng);
    let s_blinding = Scalar::random(&mut OsRng);
    let s_L: Vec<Scalar> = (0..nm).map(|_| Scalar::random(&mut OsRng)).collect();
    let s_R: Vec<Scalar> = (0..nm).map(|_| Scalar::random(&mut OsRng)).collect();
    
    // Compute commitments using ephemeral secrets
    let A = a_blinding * &(*H);
    let S = s_blinding * &(*H);
    
    // ... more proof construction ...
    
    Ok(RangeProof { A, S, T_1, T_2, t_x, t_x_blinding, e_blinding })
    // ⚠️ a_blinding, s_blinding, s_L, s_R all dropped without zeroization
    // These scalars on the stack/heap persist in memory
}
```

## Why Ephemeral Secrets Are Especially Dangerous

1. **Mathematical relationship:** Given commitment `C = v*G + r*H`, knowing `r` (blinding) lets you compute `v` (secret value)
2. **ZK soundness:** The "zero knowledge" property DEPENDS on the blinding factor being unknown
3. **Batch exposure:** In range proofs, leaking `s_L`/`s_R` vectors compromises ALL amounts in the batch
4. **Compounding risk:** If both blinding AND value leak, the commitment scheme provides zero security

## Detection Strategy

### Manual Audit
1. **Identify proof/signature functions:** Search for `new`, `prove`, `sign`, `generate` in crypto modules
2. **Find all `Scalar::random`:** Each one creates an ephemeral secret
3. **Trace to function exit:** Is `.zeroize()` called before return?
4. **Check ALL exit paths:** Early returns, error branches, panics
5. **Check Vec<Scalar>:** Vectors need element-wise zeroization, not just drop

### Grep Patterns
```bash
# Find ephemeral secret creation
rg 'Scalar::random' --type rust
rg 'OsRng|thread_rng.*Scalar' --type rust

# Find blinding/nonce variables
rg 'blinding|nonce|ephemeral|randomness|commitment_rand' --type rust

# Verify zeroization
rg '\.zeroize\(\)' --type rust  # Should appear near every Scalar::random

# Find vector secrets (need special handling)
rg 'Vec<Scalar>' --type rust
rg 'vec!\[.*Scalar' --type rust
```

### Counting Check
Count `Scalar::random` calls in a function. Count `.zeroize()` calls. If random > zeroize, there's a leak.

## Fix Pattern

### Individual Scalars
```rust
pub fn new(amounts: Vec<u64>, bit_lengths: Vec<usize>) -> Result<RangeProof> {
    let mut a_blinding = Scalar::random(&mut OsRng);
    let mut s_blinding = Scalar::random(&mut OsRng);
    
    // ... use blinding factors ...
    
    // ✅ Zeroize before return
    a_blinding.zeroize();
    s_blinding.zeroize();
    
    Ok(proof)
}
```

### Vector of Scalars
```rust
// Vectors need element-wise zeroization
let mut s_L: Vec<Scalar> = (0..nm).map(|_| Scalar::random(&mut OsRng)).collect();

// ... use s_L ...

// ✅ Zeroize every element
for scalar in s_L.iter_mut() {
    scalar.zeroize();
}
// Or if Vec<T> implements Zeroize:
s_L.zeroize();
```

### RAII Pattern with ZeroizeOnDrop
```rust
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
struct ProofSecrets {
    a_blinding: Scalar,
    s_blinding: Scalar,
    s_L: Vec<Scalar>,
    s_R: Vec<Scalar>,
}

pub fn new(amounts: Vec<u64>) -> Result<RangeProof> {
    let secrets = ProofSecrets {
        a_blinding: Scalar::random(&mut OsRng),
        s_blinding: Scalar::random(&mut OsRng),
        s_L: (0..nm).map(|_| Scalar::random(&mut OsRng)).collect(),
        s_R: (0..nm).map(|_| Scalar::random(&mut OsRng)).collect(),
    };
    
    // ... use secrets.a_blinding etc. ...
    
    Ok(proof)
    // ✅ secrets automatically zeroized on drop via ZeroizeOnDrop
}
```

## Key Insight

> "Ephemeral secrets are the most dangerous kind because they're designed to be temporary, which makes developers treat them casually. But 'temporary' in cryptography means 'must be actively destroyed,' not 'will eventually be overwritten by malloc.' A range proof with leaked blindings is just a proof of nothing."

## Audit Checklist
- [ ] Every `Scalar::random` has a corresponding `.zeroize()` or is wrapped in `ZeroizeOnDrop`
- [ ] Vectors of secret scalars are element-wise zeroized (not just cleared/truncated)
- [ ] Error paths also zeroize (use `scopeguard` or RAII pattern)
- [ ] Intermediate computation scalars (not just inputs) are zeroized
- [ ] No copies of ephemeral secrets exist (check for `.clone()` on secrets)
- [ ] Function signatures don't return ephemeral secrets (they should stay internal)

## References
- PS3 ECDSA Hack (2010) — Nonce reuse allowed private key extraction
- RFC 6979 — Deterministic nonce generation to avoid nonce management issues
- Solana Foundation Token22 C4 Contest (Aug 2025) — L-06
- [zeroize crate](https://docs.rs/zeroize/latest/zeroize/)
- [scopeguard crate](https://docs.rs/scopeguard/latest/scopeguard/) — For cleanup on all exit paths
