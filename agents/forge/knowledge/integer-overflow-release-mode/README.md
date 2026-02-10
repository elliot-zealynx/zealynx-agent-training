# Integer Overflow in Rust Release Mode

## Category Overview
Rust's arithmetic safety is a myth in production. In debug mode, Rust panics on integer overflow/underflow. In release mode (which is what Solana BPF uses), Rust silently performs two's complement wrapping. This means `255u8 + 1 = 0`, not a panic.

This is arguably the most dangerous Rust-specific pitfall for Solana programs because:
1. Developers test in debug mode where overflows panic, creating false confidence
2. Programs deploy in release mode where overflows silently wrap
3. Financial math on token amounts, fees, balances is everywhere in DeFi
4. Attackers can craft inputs that wrap arithmetic to bypass balance checks

## Severity: HIGH to CRITICAL
Sec3's 2025 Solana Security Review: "Data Integrity & Arithmetic" accounts for 8.9% of all findings, and 8.9% of High+Critical findings across 163 audits (1,669 vulnerabilities).

## Scope
This category covers:
- Silent wrapping in release mode (the core issue)
- Unchecked type casting (`as u32` on u64)
- Multiplication-before-division precision loss
- Saturating arithmetic silent clamping (subtler)
- Division by zero panics
- Intermediate overflow in compound expressions
- rBPF-level overflow (infrastructure)

## Key Insight
The Solana BPF toolchain compiles with `--release` by default. Modern Anchor (v0.30+) sets `overflow-checks = true` in Cargo.toml, but:
- Native programs (non-Anchor) don't get this by default
- Older Anchor projects may not have it
- Casting (`as`) is NEVER checked, even with overflow-checks enabled
- Saturating ops won't panic but will give wrong results

## Sources
- Sec3 Blog: "Understanding Arithmetic Overflow/Underflows in Rust and Solana Smart Contracts"
- Neodyme: "Solana Smart Contracts: Common Pitfalls"
- ThreeSigma: "Rust Memory Safety on Solana"
- Cantina: "Securing Solana: A Developer's Guide"
- SlowMist: "Solana Smart Contract Security Best Practices"
- OWASP: "Solana Programs Top 10"
- BlockSec: "New Integer Overflow Bug in Solana rBPF" (CVE-2021-46102)
- Sec3: "Solana Security Ecosystem Review 2025"

## Pattern Index
1. [Silent Wrapping in Release Mode](./01-silent-wrapping-in-release-mode.md)
2. [Unchecked Type Casting](./02-unchecked-type-casting.md)
3. [Multiplication-Before-Division Precision Loss](./03-multiplication-before-division-precision.md)
4. [Saturating Arithmetic Silent Clamping](./04-saturating-arithmetic-silent-clamping.md)
5. [Division by Zero Panic](./05-division-by-zero-panic.md)
6. [Intermediate Overflow in Compound Expressions](./06-intermediate-overflow-compound.md)
7. [rBPF Infrastructure Overflow](./07-rbpf-infrastructure-overflow.md)
