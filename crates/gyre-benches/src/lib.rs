//! `gyre-benches` — criterion microbenchmarks for Gyre's primitives.
//!
//! This crate has no runtime code; the benchmarks live under `benches/`. Run them
//! with `cargo bench -p gyre-benches`.
//!
//! **What these measure — and what they do not.** These are *microbenchmarks of the
//! building blocks*: onion wrap/unwrap, Reed–Solomon coding, the VOPRF token stages,
//! proof-of-work, the key ratchet, PIR, and steganography. They tell you the
//! primitives are fast enough to be viable and let you catch performance
//! regressions. They are **not** an end-to-end latency or anonymity measurement —
//! those require a real or simulated multi-node network (Shadow / NetEm), which is a
//! separate effort tracked in [`docs/ROADMAP.md`]. Do not read a number here as a
//! claim about how Gyre performs against Tor or any other system.
