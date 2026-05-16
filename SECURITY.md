# Security Policy

## Reporting a vulnerability

**Please do not file public issues for security vulnerabilities.**

Report privately to one of:

- Email: `security@archangel-sec.org` (mailbox to be provisioned with the domain).
- GitHub Security Advisory: <https://github.com/archangel-sec/archangel/security/advisories/new> (active once the GitHub organization is created).

PGP key for encrypted email will be published at `https://archangel-sec.org/security.asc` and its fingerprint pinned in `docs/security-keys.md`.

We acknowledge receipt within **72 hours**. We aim to triage within **7 days**.

## What to include

- Affected version(s) or commit hash.
- A reproduction (minimal proof-of-concept preferred).
- The threat-model layer(s) involved (see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)).
- The blast radius you assess.
- Whether you have published or shared the finding elsewhere.
- Whether you wish to be credited (real name, alias, or anonymous).

## Embargo

- Default: **90 days** from acknowledgement to public disclosure.
- Severe issues with no available mitigation: negotiated, typically 120 days.
- Issues with active exploitation in the wild: shortest path to a fix, no fixed embargo.

We coordinate with downstream package maintainers (Fedora, Debian, etc.) **before** public disclosure so that fixed packages ship simultaneously.

## CVE assignment

We assign CVEs via GitHub Security Advisories or, where applicable, through the distribution's security team (Red Hat Product Security, Debian Security Team).

## Scope

In scope:

- Vulnerabilities in any crate under `crates/`.
- Vulnerabilities in distributed packages (`packaging/`).
- Vulnerabilities in the systemd units shipped under `systemd/`.
- Vulnerabilities in default `.exec` bundles or policies we ship.
- Weaknesses in the documented threat model itself (e.g., we missed a class of attack).
- Issues that allow bypassing any of the seventeen defense layers without operator consent.

Out of scope:

- Misconfiguration by the operator that goes against documented hardening guidance.
- Vulnerabilities in the underlying OS, kernel, or systemd (report upstream).
- Vulnerabilities in the LLM provider's infrastructure (report to the provider).
- Vulnerabilities in third-party `.exec` bundles not maintained by this project.
- Social engineering of operators.
- Physical attacks.

## Severity guidance

We use **CVSS 4.0** for scoring. Internal severity rules:

| Severity | Examples |
|----------|----------|
| Critical | RCE in `archangel-execd`; bypass of the denylist; signature verification bypass; key recovery; audit log forgery |
| High | RCE in `archangeld` that pivots to `archangel-execd`; sandbox escape on common kernels; egress filter bypass |
| Medium | Information disclosure of LLM tokens, audit log content; policy engine logic flaw allowing one allowed action to be invoked outside its profile |
| Low | DoS of the daemon recoverable by restart; rate-limit bypass without elevation |

## Hardening commitments

By policy, we will **not** ship:

- A release that fails any of: `cargo audit`, `cargo deny`, the red-team prompt-injection test suite, or any integration test that asserts denylist enforcement.
- A release with `unsafe` code that does not have a reviewed `// SAFETY:` justification block.
- A release whose binary fails the systemd-analyze hardening check below an agreed score.

## Hall of fame

When applicable, accepted reports are credited in `SECURITY-CREDITS.md` (will exist when the first credit is earned).

## This document is part of the threat model

If reading this document raises questions not answered here, please read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). If it is still unclear, contact us — clarification of the threat model is itself in scope.
