# Pattern 05: Seed Encoding Ambiguity

**Severity:** Medium-High
**Category:** PDA Seed Collisions
**Prevalence:** Medium — often missed in reviews, subtle but impactful

## Description

When PDA seeds include variable-length data (strings, byte arrays), the boundary between seed components can be ambiguous. Two different logical entities can produce the same concatenated seed bytes, causing:

1. **Address collision** — two different entities map to the same PDA
2. **Denial of Service** — first entity prevents second from being created
3. **Data corruption** — one entity's data overwritten by another

This is distinct from prefix collision (Pattern 02) — here the issue is with the variable data portions, not the fixed prefixes.

## Vulnerable Code Example

```rust
// VULNERABLE: Variable-length seeds without length encoding
pub fn create_record(
    ctx: Context<CreateRecord>,
    namespace: String,
    name: String,
) -> Result<()> {
    let seeds = &[
        b"record" as &[u8],
        namespace.as_bytes(),  // ⚠️ Variable length, no delimiter
        name.as_bytes(),       // ⚠️ Where does namespace end and name begin?
    ];
    
    let (pda, bump) = Pubkey::find_program_address(seeds, ctx.program_id);
    // ...
}

// Attack: These produce IDENTICAL seed bytes:
// namespace="abc",  name="def"  → "record" + "abc" + "def" = "recordabcdef"
// namespace="ab",   name="cdef" → "record" + "ab" + "cdef" = "recordabcdef"  
// namespace="abcd", name="ef"   → "record" + "abcd" + "ef" = "recordabcdef"
```

## Attack Scenario

```
Protocol: Domain name registry using [b"domain", tld_bytes, name_bytes]

Legitimate user registers:
  TLD = "com", Name = "mysite"  → seeds: "domain" + "com" + "mysite"

Attacker front-runs with:
  TLD = "co", Name = "mmysite"  → seeds: "domain" + "co" + "mmysite"
  
Same concatenation: "domaincommysite"
Same PDA address!

Result: Attacker owns the PDA, legitimate user gets "account already exists" error
Or worse: legitimate user's data overwrites attacker's, causing confusion
```

### Integer Encoding Variant

```rust
// VULNERABLE: Multiple integers without fixed-width encoding
let seeds = &[
    b"position",
    &pool_id.to_le_bytes(),     // u64 = 8 bytes (OK, fixed width)
    &tick_lower.to_le_bytes(),  // i32 = 4 bytes (OK, fixed width)
];
// This is actually SAFE because integer types have fixed byte widths

// But mixing types is risky:
let seeds = &[
    b"position",
    pool_name.as_bytes(),        // ⚠️ Variable!
    &amount.to_le_bytes(),       // Fixed
];
```

## Detection Strategy

1. **Identify all variable-length seed components:** strings, `Vec<u8>`, user-supplied bytes
2. **Check if concatenation is ambiguous:** Can different input combinations produce same byte sequence?
3. **Verify delimiter/length-prefix usage:** Are variable-length components properly bounded?
4. **Special attention to:**
   - String seeds (variable length)
   - Byte array seeds from user input
   - Seeds derived from other account data (which could be manipulated)
5. **Test:** Try constructing two different logical inputs that produce the same seed bytes

## Fix Pattern

### Approach 1: Use fixed-length seeds only (preferred)
```rust
// SAFE: All seeds are fixed-length (Pubkey = 32 bytes, u64 = 8 bytes)
let seeds = &[
    b"record",
    owner.key().as_ref(),      // 32 bytes, fixed
    &record_id.to_le_bytes(),  // 8 bytes, fixed
];
```

### Approach 2: Length-prefixed variable seeds
```rust
// SAFE: Prefix each variable component with its length
let namespace_len = (namespace.len() as u32).to_le_bytes();
let seeds = &[
    b"record",
    &namespace_len,
    namespace.as_bytes(),
    name.as_bytes(),
];
```

### Approach 3: Hash variable-length inputs
```rust
// SAFE: Hash variable inputs to fixed-length
use solana_program::hash::hash;

let namespace_hash = hash(namespace.as_bytes());
let seeds = &[
    b"record",
    &namespace_hash.to_bytes()[..16],  // First 16 bytes of hash
    name.as_bytes(),
];
```

### Approach 4: Delimiter separation
```rust
// SAFE: Use null byte delimiter (if inputs can't contain null bytes)
let seeds = &[
    b"record",
    namespace.as_bytes(),
    b"\0",  // Delimiter
    name.as_bytes(),
];
// Only safe if namespace and name are guaranteed to not contain \0
```

## Real Examples

- Found in audit findings for domain/name registry protocols on Solana
- Common in programs that use human-readable strings as PDA seeds
- Particularly dangerous in multi-tenant applications where different users/namespaces share seed structures

## Key Insight

> "bytes don't have structure — you do. If your seed encoding doesn't preserve the boundaries between components, those boundaries don't exist."

**Best practice:** Use only fixed-length seed components (Pubkeys, fixed-width integers). If you must use variable-length data, hash it first.
