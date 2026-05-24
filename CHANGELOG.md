# Changelog

All notable changes to archangel will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Security-relevant changes are explicitly called out under a **Security** subsection.

## [Unreleased]

## [0.4.0] - 2026-05-24

First functional milestone: the full read-only → interactive → autonomous
spine, with the threat-model defense layers implemented and tested
end-to-end. **Not production-ready** — see `docs/RELEASE_READINESS.md`; the
v1.0 bar (external audit, public red-team, field hardening) is unmet by
design.

### Added
- **Read-only agent (M1).** `archangel-core` types; hash-chained Ed25519
  audit log (`archangel-audit`, #15); compiled denylist + allowlist
  (`archangel-policy`, #8/#9); signed `.exec` bundle format + verifier
  (`archangel-exec-format`, #6/#7); Anthropic + Ollama backends
  (`archangel-llm`); the T3 daemon with prompt spotlighting (#2), canary
  (#3), per-task isolation (#4), bounded structured output (#5); the T2
  executor running signed, sandboxed requests; `archangelctl`; DEB/RPM
  packaging; `archangel setup`.
- **Sandbox & recovery (#11, #16).** `archangel-sandbox`: per-action
  seccomp-bpf allowlist (kill-on-mismatch), capability drop, cgroup v2 limit
  parsing, and the single audited `unsafe` `pre_exec` applier;
  `archangel-snapshot`: fail-closed recovery points before persistent
  mutation.
- **Controlled mutation.** Executor mutation gate bound to its own config
  mode ceiling (independent of the daemon); interactive approval round-trip
  (#13) and two-person rule (#14).
- **Blast-rate limits (#12).** Host-wide sliding-window ceilings enforced by
  the executor.
- **Autonomous monitoring (v0.3).** Bounded, rotation-aware log tailer
  (logs treated as hostile, T6); operator-defined trigger pre-filter; the
  anti-runaway cooldown; and the decision loop wiring matched events through
  the full gated pipeline.
- **Egress allowlist (#17).** `archangel-egress` fail-closed policy +
  `archangelctl egress-sync` kernel-enforced systemd drop-in generator.
- **Red-team corpus (#18).** CI-run prompt-injection suite over the
  spotlighting/canary/bounded-output defenses.

### Security
- Single audited `unsafe` site (the sandbox `pre_exec`), `deny`-not-`forbid`
  and CODEOWNERS-gated; every other crate stays `#![forbid(unsafe_code)]`.
- Fail-closed throughout: missing snapshot backend, unbuildable sandbox plan,
  rate ceiling, unresolved egress, or read-only mode each *refuse* the action.
- Packaging hardening fixes found by real install: config-tree group
  readability, `Type=exec` units, exec-socket mode, `daemon_uid`.

## [0.0.x] - 2026-05-16

### Added
- Initial repository scaffolding.
- Threat model documenting 17 defense layers and STRIDE analysis.
- Architecture document with trust boundaries, IPC design, and crate layout.
- Cargo workspace with strict lints (`#![forbid(unsafe_code)]` by default).
- Hardened example systemd units for `archangeld` and `archangel-execd`.
- Example `/etc/archangel/` configuration and informational denylist.
- CI workflows: `fmt`, `clippy`, test, MSRV check, `cargo audit`, `cargo deny`,
  systemd unit verification.

### Security
- Establishment of the seventeen-layer defense posture as a fundational
  decision; changes require RFC and explicit threat-model amendment.

### Decisions (locked)
- License: Apache-2.0.
- GitHub organization: `archangel-sec`.
- Project domain: `archangel-sec.org`.
- Initial LLM backends: Anthropic (Claude) and Ollama (default features); other
  backends behind feature flags.
- Minimum Supported Rust Version: 1.93 (policy: latest stable - 2 releases).
