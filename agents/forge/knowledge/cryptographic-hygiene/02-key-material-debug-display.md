# Pattern 02: Key Material Debug/Display Protection

**Severity:** Low
**Category:** Cryptographic Hygiene
**CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
**Prevalence:** Common, especially in early-stage code

## Description

Types holding secret key material (AES keys, private keys, secret scalars) derive `Debug` or `Display`, allowing their raw bytes to appear in log output, error messages, debug dumps, or format strings. Even if the current codebase doesn't log these types, downstream consumers or future changes might accidentally expose them via `{:?}` formatting.

The Rust `Debug` derive macro generates a formatter that prints ALL struct fields, including secret bytes.

## Vulnerable Code Example

```rust
// VULNERABLE: Debug derive exposes raw key bytes
#[derive(Clone, Debug, Zeroize, Eq, PartialEq)]
pub struct AeKey([u8; 16]);  // AES-128 key

// Downstream code:
tracing::debug!("Processing with key: {:?}", key);
// Output: "Processing with key: AeKey([43, 129, 7, ...])"
// ⚠️ Full AES key in logs!

// Even in error messages:
format!("Failed to decrypt with {key:?}")
// ⚠️ Key in error string, possibly sent to error reporting service
```

## Attack Scenario

1. Developer adds logging for debugging during development
2. `tracing::debug!("key state: {:?}", crypto_state)` includes struct with key field
3. Logs shipped to centralized logging (ELK, Datadog, CloudWatch)
4. Logs retained for months/years per compliance
5. Log access compromise exposes ALL historical keys

## Real Examples

### Solana Token22 zk-sdk (C4, Aug 2025)
```rust
#[derive(Clone, Debug, Zeroize, Eq, PartialEq)]
pub struct AeKey([u8; AE_KEY_LEN]);
```
- Classified Low: no in-repo logging, but API shape enables accidental disclosure
- The repo uses `Zeroize` properly but Debug undermines it by printing before zeroization

## Detection Strategy

### Manual Audit
1. **Find all secret key types:** Search for structs containing key/secret/private
2. **Check derives:** Does it derive `Debug` or `Display`?
3. **Check manual impls:** Is there a custom `Debug` impl that redacts?
4. **Cross-reference with logging:** Search for `{:?}` usage with these types

### Grep Patterns
```bash
# Find types that derive Debug and contain key/secret material
rg '#\[derive.*Debug' --type rust -A 5 | rg -i 'key|secret|private|scalar'

# Find Debug formatting of potentially sensitive types
rg '\{:?\?\}.*key|key.*\{:?\?\}' --type rust
rg 'debug!\(.*key|info!\(.*key|warn!\(.*key|error!\(.*key' --type rust

# Find Display impls for key types
rg 'impl.*Display.*for.*(Key|Secret|Private)' --type rust
```

## Fix Pattern

### Custom Redacting Debug
```rust
pub struct AeKey([u8; AE_KEY_LEN]);

impl core::fmt::Debug for AeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AeKey([REDACTED])")
    }
}
```

### Using a Wrapper Type
```rust
use secrecy::{Secret, ExposeSecret};

// Secret<T> implements Debug as "Secret([REDACTED])"
// Must explicitly call .expose_secret() to access inner value
let key: Secret<[u8; 32]> = Secret::new(raw_key);

// Safe: prints "Secret([REDACTED])"
println!("{:?}", key);

// Explicit access required:
let raw = key.expose_secret();
```

### Macro-Based Approach
```rust
macro_rules! impl_redacted_debug {
    ($type:ty, $name:expr) => {
        impl core::fmt::Debug for $type {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}([REDACTED])", $name)
            }
        }
    };
}

impl_redacted_debug!(AeKey, "AeKey");
impl_redacted_debug!(ElGamalSecretKey, "ElGamalSecretKey");
```

## Key Insight

> "Debug is the silent exfiltration channel. A type can implement Zeroize perfectly and still leak through a single `{:?}` in a log statement three dependencies away. Defense: make the secret type UNABLE to print itself, not just unlikely to."

## Audit Checklist
- [ ] No secret key type derives `Debug` with default implementation
- [ ] All key types have redacting `Debug` impl or no `Debug` at all
- [ ] No `Display` impl that shows raw key bytes
- [ ] Consider using `secrecy::Secret<T>` wrapper for defense-in-depth
- [ ] Search for `{:?}` formatting of types that transitively contain secrets
- [ ] Error types that embed keys also redact in their Display/Debug

## References
- [secrecy crate](https://docs.rs/secrecy/latest/secrecy/) — Secret wrapper with redacted Debug
- CWE-532: Insertion of Sensitive Information into Log File
- Solana Foundation Token22 C4 Contest (Aug 2025) — L-07
