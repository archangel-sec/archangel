<!--
Thank you for contributing. Please read CONTRIBUTING.md and docs/THREAT_MODEL.md
before opening a PR that touches security-relevant code.
-->

## Summary

<!-- What does this PR change? Why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor (no behavior change)
- [ ] Security fix
- [ ] Documentation
- [ ] CI / tooling

## Threat-model impact

<!-- Required for ANY security-relevant change. -->
<!-- Reference the 17 layers in docs/THREAT_MODEL.md §7. -->

- Layers affected (numbers, e.g., "9, 11"):
- Does this change weaken any layer? (yes / no, explain)
- New attack surface introduced? (yes / no, describe)
- New trust boundary crossed? (yes / no, describe)

If any answer is "yes", link to the accompanying RFC.

## Testing

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --workspace --all-features` passes
- [ ] `cargo audit` passes
- [ ] `cargo deny check` passes
- [ ] Red-team prompt-injection suite passes (if applicable)
- [ ] New tests added for the changed behavior

## Documentation

- [ ] `CHANGELOG.md` updated under the appropriate section
- [ ] Architecture/threat-model docs updated if the design changed
- [ ] Operator-facing docs updated if configuration or CLI changed

## Signoff

- [ ] Commit(s) are signed (`git commit -S`)
- [ ] Commit(s) include DCO sign-off (`git commit -s`)
