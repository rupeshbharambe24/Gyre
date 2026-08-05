<!--
Thanks for contributing to Whirlpool. Keep it honest: every claim is measured before it is trusted.
Fill each section, then check every REQUIRED box before you request review. Delete this comment.
-->

## Summary

<!-- What does this change do, and why? One short paragraph. -->

## Type of change

- [ ] Feature / milestone
- [ ] Bugfix
- [ ] Docs
- [ ] Refactor (no behavior change)
- [ ] Tests

## Milestone / measurement

<!--
What number or behavior does this change, and against what baseline?
Name the metric and the before -> after (e.g. correlation accuracy, test count,
exposure fraction). If nothing measurable changed, say so explicitly.
-->

- **What changed:**
- **Baseline (before):**
- **Now (after):**

## Pre-submit checklist (REQUIRED — mirrors CI)

> [!IMPORTANT]
> CI runs all three of these on every push and PR. Run them locally first.

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean
- [ ] `cargo test --workspace` — all tests pass

## Honesty

- [ ] I did not introduce an overclaim. Any new ceiling or limit is documented in-line, next to the claim it bounds (not buried).

## Docs updated?

- [ ] Ground-truth numbers (crate count, test count, GATE figures) stay consistent across code and docs — or no such number changed.
