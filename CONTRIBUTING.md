# Contributing to Archangel

Thanks for your interest. Archangel is a security-critical project; the contribution rules below reflect that. They will feel heavy compared to a typical OSS project. That is intentional.

---

## Before you contribute

1. Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). All of it. It is the spec.
2. Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
3. Read [`SECURITY.md`](SECURITY.md).

If your contribution touches any of the seventeen defense layers, expect deeper scrutiny.

---

## Ground rules

- **No PR weakens a defense layer** without an accompanying RFC under `docs/rfcs/` that has been reviewed by all current maintainers.
- **All code must build with `#![forbid(unsafe_code)]`** unless a `// SAFETY: …` block justifies an exception, in which case it requires a CODEOWNERS reviewer for that crate.
- **No suppressing lints or tests** to make CI pass.
- **No introducing new dependencies** without justification (cargo-deny will flag them; reviewer must agree).
- **No telemetry** of any kind. Ever.
- **Public-facing user behavior changes** require a corresponding `CHANGELOG.md` entry.
- **Signed commits required** (`git commit -S`). Unsigned commits will be rejected by CI.
- **DCO sign-off** (`git commit -s`) on every commit.

---

## Workflow

1. **Open an issue first** for non-trivial changes. Discuss before implementing.
2. **Branch naming:** `feat/<short-name>`, `fix/<short-name>`, `sec/<short-name>`, `docs/<short-name>`, `rfc/<short-name>`.
3. **Commit style:** [Conventional Commits](https://www.conventionalcommits.org/). E.g., `feat(policy): support per-profile rate limit`, `fix(execd): tighten seccomp profile for write actions`.
4. **PR template** must be filled out completely. PRs that touch security-relevant code must explicitly declare which threat-model layers are affected.
5. **Two reviewers required** for security-relevant changes (anything in `archangel-execd`, `archangel-policy`, `archangel-sandbox`, `archangel-audit`, `archangel-exec-format`, or `crates/*/src/**/security*.rs`).
6. **CI must be green.** That includes:
   - `cargo fmt --all -- --check`
   - `cargo clippy --all-targets --all-features -- -D warnings`
   - `cargo test --all-features`
   - `cargo audit`
   - `cargo deny check`
   - The red-team prompt-injection suite (`cargo test --test redteam`)
   - Build of all distribution packages
   - `systemd-analyze security` score on the shipped units above the agreed threshold

---

## Coding standards

### Rust

- Edition: latest stable Cargo edition supported by our MSRV.
- MSRV: see `rust-version` in the workspace `Cargo.toml`.
- `rustfmt` configured by `rustfmt.toml`; CI enforces.
- Clippy: pedantic-level lints enabled where reasonable; suppressions require a justification comment.
- Errors: structured `enum` errors per crate via `thiserror`. No `anyhow` in library crates. `anyhow` allowed in binary crates only.
- Async: `tokio` (multi-threaded runtime). No mixing with other runtimes.
- Logging: `tracing`. Levels respected. No `println!`/`eprintln!` outside tests and bin entry points.
- Secrets: any type holding secret material implements `Zeroize` and `ZeroizeOnDrop`.
- Time: monotonic clocks for security-relevant ordering; wall clock only for logging.

### Documentation

- Public items in library crates have doc comments. Doc tests are exercised by CI.
- New configuration keys are documented in `docs/CONFIG.md` and example files in `packaging/etc-archangel/`.
- Architectural changes update `docs/ARCHITECTURE.md` in the same PR.

### Testing

- Unit tests live with the code (`#[cfg(test)] mod tests`).
- Integration tests in `tests/integration/`.
- Red-team prompt-injection corpus in `tests/redteam/` — additions welcome.
- Fuzz targets in `tests/fuzz/` for any parser of untrusted input (policy files, `.exec` bundles, LLM responses).
- Property tests (`proptest`) for invariants of the policy engine.
- No flaky tests. Flaky tests are quarantined and tracked; they are bugs.

### Dependencies

- Every new dependency must justify its inclusion in the PR description.
- Preference for crates that are: maintained, audited, minimal in transitive deps, and license-compatible (Apache-2.0, MIT, BSD-2/3, ISC, MPL-2.0, Unicode-DFS-2016, CC0-1.0; consult `deny.toml`).
- Avoid procedural macros that are not from the standard ecosystem unless strongly justified.
- Critical security crates (`ring`, `ed25519-dalek`, `wasmtime`, `nix`, `caps`, `seccompiler`) are pinned and reviewed on bumps.

---

## Reporting security issues

**Do not file public issues for security vulnerabilities.** See [`SECURITY.md`](SECURITY.md).

---

## Conduct

See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Be excellent. Bad-faith contributions waste reviewer time; that time is finite and prioritized.
