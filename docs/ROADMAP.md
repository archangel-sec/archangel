# Archangel — Roadmap

Versioning follows SemVer. Pre-1.0 milestones are deliberately experimental;
**no production use is supported before v1.0 and an independent security audit**.

## v0.0.x — Foundations (current)

- ✅ Repository scaffolding.
- ✅ Threat model, architecture, security policy.
- ✅ Cargo workspace, strict lints, CI security toolchain.
- ✅ Hardened systemd units, informational denylist, example config.
- 🚧 Initial crate skeletons committed; no functional implementation yet.

## v0.1.x — Read-only minimum viable agent

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

## v0.2.x — Sandbox & privilege separation

- `archangel-sandbox`: namespaces, seccomp-bpf, capabilities, cgroups v2.
- Snapshots (BTRFS) before `mutates_persistent_state` actions (#16).
- Interactive mode (#13) with TUI and `ntfy.sh` webhook approval.
- Diff preview for file-edit actions.
- Per-action egress filter (#17).

## v0.3.x — Policy engine & autonomous mode

- WASM policy engine in `archangel-policy` (wasmtime).
- Allowlist signing & verification.
- Rate limits, cooldowns, per-profile quotas (#12).
- Autonomous mode (M3) gated on policy bundle signature.
- Two-person rule (#14) for `risk = "critical"` actions.

## v0.4.x — Federation, dual-LLM, operator ergonomics

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
