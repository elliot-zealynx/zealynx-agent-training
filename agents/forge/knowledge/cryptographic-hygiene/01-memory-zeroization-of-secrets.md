# Pattern 01: Memory Zeroization of Secrets

**Severity:** Low-Medium (depends on threat model)
**Category:** Cryptographic Hygiene
**CWE:** CWE-316 (Cleartext Storage of Sensitive Information in Memory)
**Prevalence:** Common in crypto implementations, even by experienced teams

## Description

After cryptographic operations complete, secret data (decrypted plaintexts, ephemeral scalars, nonces, intermediate values) may linger in memory. If the memory is not explicitly zeroed, secrets can be recovered through:
- Process crash dumps / core dumps
- Memory swap files
- VM/container memory snapshots
- Memory disclosure vulnerabilities (buffer over-reads)
- Cold boot attacks on physical hardware

Rust's optimizer may also optimize away naive zeroing attempts (writing zeros to memory that's about to be dropped), making proper zeroization non-trivial.

## Vulnerable Code Examples

### Decrypted Plaintext Not Zeroized
```rust
// VULNERABLE: decrypted Vec<u8> dropped without zeroization
fn decrypt(key: &AeKey, ciphertext: &AeCiphertext) -> Option<u64> {
    let plaintext = Aes128GcmSiv::new(&key.0.into())
        .decrypt(&ciphertext.nonce.into(), ciphertext.ciphertext.as_ref());
    
    if let Ok(plaintext) = plaintext {
        let amount_bytes: [u8; 8] = plaintext.try_into().unwrap();
        Some(u64::from_le_bytes(amount_bytes))
        // ⚠️ plaintext Vec<u8> dropped here without zeroization
        // Raw decrypted bytes persist on heap until overwritten by chance
    } else {
        None
    }
}
```

### Ephemeral Scalars Not Zeroized
```rust
// VULNERABLE: secret scalars used in proof construction not wiped
fn generate_proof(secret: &Scalar, value: u64) -> Proof {
    let blinding = Scalar::random(&mut OsRng);  // ephemeral secret
    let commitment = blinding * G + Scalar::from(value) * H;
    
    // ... proof construction ...
    
    Proof { commitment, response }
    // ⚠️ blinding scalar dropped without zeroization
    // If recovered, attacker can extract 'value' from commitment
}
```

### Temporary Arrays Not Zeroized
```rust
// VULNERABLE: intermediate key material on stack
fn derive_key(master: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let mut intermediate = [0u8; 64];
    // ... key derivation into intermediate ...
    let result: [u8; 32] = intermediate[..32].try_into().unwrap();
    result
    // ⚠️ intermediate still contains key material on stack
}
```

## Real Examples

### Solana Token22 zk-sdk (C4, Aug 2025)
- `AuthenticatedEncryption::decrypt` returns u64 without zeroizing decrypted `Vec<u8>`
- `RangeProof::new` leaks `a_blinding`, `s_blinding`, `s_L`, `s_R` scalars
- Solana Foundation acknowledged, classified as Low (host-level precondition)

### General Pattern in Rust Crypto Crates
- Many crates use `zeroize` crate but miss edge cases (temporaries, error paths)
- The `curve25519-dalek` crate itself implements `Zeroize` for `Scalar` but callers must invoke it

## Detection Strategy

### Manual Audit
1. **Find all secret data types:** Search for Scalar, SecretKey, private/secret/key in names
2. **Trace lifecycle:** Where created → where used → where dropped
3. **Check Drop impl:** Does the type implement `Zeroize` or `ZeroizeOnDrop`?
4. **Check caller discipline:** Even if type implements Zeroize, is `.zeroize()` called before scope exit?
5. **Check error paths:** Is secret data zeroized on ALL paths, including error branches?
6. **Check temporaries:** `Vec<u8>` from decryption, intermediate `[u8; N]` arrays, format buffers

### Grep Patterns
```bash
# Find decryption operations (check if result is zeroized)
rg '\.decrypt\(' --type rust
rg 'from_le_bytes|from_be_bytes' --type rust

# Find scalar/secret creation (check if zeroized after use)
rg 'Scalar::random|Scalar::from' --type rust
rg 'SecretKey::new|SecretKey::generate' --type rust

# Find zeroize usage (verify completeness)
rg 'use zeroize' --type rust
rg '\.zeroize\(\)' --type rust
rg 'ZeroizeOnDrop' --type rust

# Find potential temporaries
rg 'let.*\[0u8;' --type rust  # Zero-initialized arrays (may hold secrets later)
rg 'Vec::with_capacity.*secret\|key\|plain' --type rust
```

## Fix Pattern

### Using the `zeroize` Crate
```rust
use zeroize::Zeroize;

fn decrypt(key: &AeKey, ciphertext: &AeCiphertext) -> Option<u64> {
    let plaintext = Aes128GcmSiv::new(&key.0.into())
        .decrypt(&ciphertext.nonce.into(), ciphertext.ciphertext.as_ref());
    
    if let Ok(mut plaintext) = plaintext {
        let result = if plaintext.len() == 8 {
            let amount_bytes: [u8; 8] = plaintext[..8].try_into().unwrap();
            Some(u64::from_le_bytes(amount_bytes))
        } else {
            None
        };
        plaintext.zeroize();  // ✅ Explicit zeroization before drop
        result
    } else {
        None
    }
}
```

### ZeroizeOnDrop for Owned Types
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct EphemeralSecret {
    blinding: Scalar,
    nonce: [u8; 12],
}

// Automatically zeroized when dropped - no manual .zeroize() needed
```

### Manual Zeroization for Scalars
```rust
fn generate_proof(secret: &Scalar, value: u64) -> Proof {
    let mut blinding = Scalar::random(&mut OsRng);
    let commitment = blinding * G + Scalar::from(value) * H;
    
    // ... proof construction ...
    
    blinding.zeroize();  // ✅ Wipe before leaving scope
    
    Proof { commitment, response }
}
```

## Key Insight

> "The `zeroize` crate exists in the dependency tree doesn't mean it's being used everywhere. Audit the GAPS: every temporary, every error path, every intermediate buffer. Secrets have a lifecycle - birth, use, and EXPLICIT death."

## Audit Checklist
- [ ] All `Scalar` values used as secrets implement or call `Zeroize`
- [ ] Decrypted plaintext buffers (`Vec<u8>`, `[u8; N]`) are zeroized after extraction
- [ ] Error paths also zeroize (not just happy path)
- [ ] Intermediate computation buffers are zeroized
- [ ] `ZeroizeOnDrop` is used for types that hold secrets
- [ ] No compiler optimization can skip zeroization (use `zeroize` crate, not manual memset)
- [ ] Stack-allocated secrets are zeroized (compiler may not drop stack memory)

## References
- [zeroize crate documentation](https://docs.rs/zeroize/latest/zeroize/)
- CWE-316: Cleartext Storage of Sensitive Information in Memory
- Solana Foundation Token22 C4 Contest (Aug 2025) — L-05, L-06
