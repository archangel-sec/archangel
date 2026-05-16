# Changelog

All notable changes to archangel will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Security-relevant changes are explicitly called out under a **Security** subsection.

## [Unreleased]

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
