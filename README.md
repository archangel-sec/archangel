# Archangel

> **AI-driven Linux server administration, designed security-first.**

Archangel is a Rust daemon that lets an LLM observe, propose, and (under strict policy) execute administrative actions on Linux servers. It is designed for production servers running RPM- or DEB-based distributions, and it treats every byte of LLM output as untrusted by construction.

---

## ⚠️ Status: v0.4.0, pre-alpha — do not run in production

The full **read-only → interactive → autonomous** spine is implemented and tested end-to-end (validated on a real host): all threat-model defense layers (#1–#18) have working, fail-closed implementations, with ~300 tests and a CI red-team corpus. The architecture and threat model under [`docs/`](docs/) are now backed by code.

That is **not** the same as production-ready. Per [`docs/RELEASE_READINESS.md`](docs/RELEASE_READINESS.md), the v1.0 bar — an **external security audit**, a public red-team campaign, a stable-release track record, and an unaffiliated production deployment — is unmet by design. If you are evaluating this for adoption: use it in a lab you can rebuild, ideally in `read_only`/`interactive` mode, and come back for production when those gates are met. Until then, please read, review, and break things — but do not deploy.

---

## What it does

Archangel exposes three modes of operation, selected per session and per profile:

| Mode | What the LLM can do | Who approves |
|------|---------------------|--------------|
| `read-only` | Run a curated set of read-only inspections (logs, status, metrics). Cannot mutate. | Enforced structurally |
| `interactive` | Propose any allowed action, with full diff/preview shown to the operator. | Human approval for every action |
| `autonomous` | Execute allowed actions within rate limits, snapshots, and the immutable denylist. | Pre-approved policy bundle |

Every action the LLM can take is bounded by:

- A **`.exec` bundle** — a signed, declarative description of an operation with its argument schema and sandbox profile.
- An **immutable denylist** compiled into the binary, rejecting any path or syntax that could destroy the host, sever SSH, or modify archangel itself.
- A **per-action sandbox** built from Linux namespaces, seccomp-bpf, capabilities, and cgroups.
- A **kernel-level egress filter** allowing only the configured LLM endpoint and operator-whitelisted destinations.
- A **hash-chained, signed audit log** of every prompt, response, decision, and outcome.

The full design is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); the threat analysis is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Why this exists

Existing automation tools (Ansible, Chef, custom scripts) assume the operator authored every action. Existing AI-coding tools assume the worst that can happen is broken code. Archangel sits in between: it gives an LLM real, scoped administrative authority over a server, while assuming the LLM may at any moment be wrong, hallucinating, or actively manipulated through prompt injection.

The whole point is that the **operator's policy** — not the LLM's judgment — is the source of truth about what may happen.

---

## Security philosophy in one sentence

> The LLM is a brilliant junior consultant. We listen to its proposals, we ask it good questions, and we let it operate — but we never give it root, and we never trust the network it speaks over.

The seventeen layers that compose this posture are listed in the [threat model](docs/THREAT_MODEL.md#7-the-17-defense-layers). Every one of them is required.

---

## Supported platforms (planned)

- **Target distributions:** Fedora 39+, RHEL 9+, AlmaLinux 9+, Rocky 9+, Debian 12+, Ubuntu 22.04 LTS+.
- **Kernel:** ≥ 5.10 (for seccomp v2, cgroup v2, modern namespace features).
- **systemd:** ≥ 247.
- **LLM backends (initial):**
  - Anthropic (Claude family) — remote.
  - Ollama — local, recommended for air-gapped deployments.
  - Any OpenAI-compatible endpoint — generic fallback.

---

## Quickstart (build from source)

No distro packages yet — build the DEBs from source (`cargo install cargo-deb` first). See [`packaging/README.md`](packaging/README.md) for RPM and details.

```bash
cargo build --release
for p in archangeld archangel-execd archangelctl archangel; do cargo deb --no-build -p "$p"; done
sudo dpkg -i ./target/debian/archangel*_0.4.0-1_amd64.deb

# Three-step setup:
sudo archangel setup --backend ollama        # or: --backend anthropic
sudo systemctl enable --now archangel-execd archangeld
archangelctl session --secret /etc/archangel/trust/operator.key
```

`archangel setup` is idempotent and fail-closed (creates the operator key, trust, a read-only allowlist, and a schema-validated config; never overwrites an existing one). Start in `read_only`; opt into mutation/monitoring deliberately. See [`docs/RELEASE_READINESS.md`](docs/RELEASE_READINESS.md) before going beyond a lab.

---

## Project layout

```
crates/
  archangeld/             # the daemon (talks to LLM, monitors logs, never mutates)
  archangel-execd/        # the executor (only thing that mutates)
  archangelctl/           # operator CLI (setup, bundle-sign, egress-sync, session)
  archangel/              # meta-package + `archangel` launcher
  archangel-core/         # shared types
  archangel-config/       # shared fail-closed config schema
  archangel-policy/       # immutable compiled denylist + allowlist
  archangel-audit/        # hash-chained signed log
  archangel-llm/          # backend adapters (Anthropic, Ollama)
  archangel-ipc/          # boundary-B signed protocol
  archangel-ctl/          # boundary-A signed control protocol
  archangel-sandbox/      # seccomp + capabilities + cgroups (the sole audited unsafe)
  archangel-snapshot/     # recovery points before mutation
  archangel-egress/       # egress allowlist (#17)
  archangel-exec-format/  # .exec bundle parser + verifier
docs/                     # threat model, architecture, sandbox/egress, readiness
packaging/                # DEB, RPM, /etc/archangel/ examples, maintainer scripts
systemd/                  # hardened unit files
crates/archangeld/tests/  # integration + red-team prompt-injection corpus (#18)
```

---

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and the threat model **before** opening a PR that touches security-relevant code. PRs that weaken any of the seventeen defense layers require explicit RFC and unanimous maintainer signoff.

We welcome:

- Threat-model review and adversarial proposals.
- Red-team prompt-injection contributions to `tests/redteam/`.
- Hardening of the systemd units, sandbox profiles, and denylist.
- Backend implementations for additional LLMs.

We do **not** accept:

- Convenience features that bypass policy.
- "Trust me" exceptions.
- PRs that disable lints, tests, or `cargo deny` checks without explicit rationale.

---

## Security disclosure

Please report vulnerabilities **privately**. See [`SECURITY.md`](SECURITY.md).

---

## License

Apache License 2.0. See [`LICENSE-APACHE`](LICENSE-APACHE).

This license choice is intentional: archangel is intended for unrestricted use, including in enterprise and government contexts, with the understanding that downstream redistributors must retain attribution and may not assert patents in conflict with the project.

---

## Name

The name *Archangel* refers to the role of a guardian standing watch — the daemon stands between the LLM's intent and the system's vulnerability. It is **not** related to any prior project of the same name (a few personal repositories share the name, none are packaged software). To avoid confusion with historical malware families that used variants of the name, this project's documentation is unambiguous: archangel is **defensive operator-consented software**, not remote-access malware.
