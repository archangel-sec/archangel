# Archangel — Roadmap

Versioning follows SemVer. Pre-1.0 milestones are deliberately experimental;
**no production use is supported before v1.0 and an independent security audit**.

## Status (2026-05-24, v0.4.0)

The full **read-only → interactive → autonomous** spine is implemented and
tested end-to-end (validated on a real host). Defense layers #1–#18 all have
working implementations. Remaining engineering is hardening of two deferred,
environment-coupled pieces (a hostname-native egress proxy; sandbox
namespace/mount-bind/user-ns refinement) plus the non-code v1.0 gates. See
`docs/RELEASE_READINESS.md` for the honest gap analysis and percentage.

## v0.0.x — Foundations ✅

- ✅ Repository scaffolding.
- ✅ Threat model, architecture, security policy.
- ✅ Cargo workspace, strict lints, CI security toolchain.
- ✅ Hardened systemd units, informational denylist, example config.
- ✅ Functional crates implemented (see below).

## v0.1.x — Read-only minimum viable agent ✅

- `archangel-core`: shared types, zeroize-aware secret wrappers, ids.
- `archangel-audit`: append-only hash-chained log with Ed25519 signatures.
- `archangel-policy`: compiled denylist (initial ruleset), simple allowlist loader.
- `archangel-exec-format`: parser and signature verifier for `.exec` bundles.
- `archangel-llm`: `Anthropic` and `Ollama` backends.
- `archangeld`: control socket, prompt builder with spotlighting (#2) and
  canary tokens (#3), per-task context isolation (#4), read-only mode (M1).
- `archangel-execd`: signed-request executor, executes only `read_only = true`
  bundles within a minimal sandbox.
- `archangelctl`: `init`, `session start`, `audit tail`, `policy reload`.
- DEB + RPM packaging via `cargo-deb` and `cargo-generate-rpm`.
- Integration tests covering the read-only end-to-end flow.

## v0.2.x — Sandbox & privilege separation ✅ (namespaces partial)

- ✅ `archangel-sandbox`: seccomp-bpf, capabilities, cgroups v2. 🚧 namespace
  unshare / mount-bind / user-ns deferred (the syscall surface already blocks
  the escape vectors they would also cover).
- ✅ Snapshots before `mutates_persistent_state` actions (#16).
- ✅ Interactive mode (#13) approval round-trip. 🚧 TUI/webhook delivery later.
- ✅ Egress allowlist (#17): policy + kernel-enforced systemd drop-in.

## v0.3.x — Autonomous mode & rate limits ✅ (WASM policy deferred)

- ✅ Rate limits, cooldowns, quotas (#12).
- ✅ Autonomous mode: real-time log monitoring → gated action loop.
- ✅ Two-person rule (#14) for `risk = "critical"` actions.
- ✅ Red-team corpus in CI (#18).
- 🚧 WASM policy engine (wasmtime) + allowlist signing — deferred; the
  compiled denylist + signed `.exec` bundles cover v0.4.

## v0.4.x — Hardening & release polish (current)

- ✅ Version 0.4.0, CHANGELOG, roadmap/readiness docs.
- 🚧 Hostname-native egress proxy; sandbox namespace refinement.
- 🚧 Clean-install validation on a fresh VM.

## Later — federation, dual-LLM, operator ergonomics

- Policy federation (organization-wide signed bundles).
- Dual-LLM pattern evaluation and (if validated) opt-in deployment.
- Operator key rotation tooling.
- Hardware-key support (PKCS#11 / YubiKey) for operator signatures.

## v0.5.x — Packaging maturity

- Fedora COPR; submission to Fedora proper.
- Launchpad PPA; submission to Debian proper.
- Reproducible builds verified end-to-end.
- SBOM published per release; Sigstore signing on every artifact.

## v0.9.x — Pre-1.0 hardening

- External security audit (mandatory before v1.0).
- Red-team campaign with bounty.
- Documentation pass: operator guide, hardening checklist, FAQ.

## v1.0 — General availability

- Only after: external audit, public red-team, two consecutive stable releases
  with zero critical security issues, and at least one production deployment
  by an operator unaffiliated with the maintainers.

## Post-1.0 candidates

- Formal verification of `archangel-policy` and parts of `archangel-execd`
  using [Kani](https://github.com/model-checking/kani).
- Confidential Computing integration (SEV-SNP, TDX).
- Web UI as a separate, opt-in package (`archangel-web`).
- Plugin runtime for `.exec` payloads (Lua sandbox, WASM, restricted Python).
- Multi-host orchestration with a coordinator/agent pattern (mTLS).
