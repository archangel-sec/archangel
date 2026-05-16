# Archangel — Threat Model

**Status:** Draft v0.1 (pre-implementation)
**Last reviewed:** 2026-05-16
**Owners:** Project security team (TBD)
**Audience:** Maintainers, contributors, auditors, security researchers, operators evaluating archangel for production use.

> ⚠️ This document is **load-bearing**. Every architectural and implementation decision in archangel is expected to be consistent with what is stated here. If a proposed change conflicts with this model, the model must be amended **first**, with explicit review, before the change is merged.

---

## 1. Purpose

Archangel exposes administrative control of a Linux server to a Large Language Model (LLM). This is, by construction, a privileged and dangerous combination. This document specifies:

- The **assets** archangel protects.
- The **threat actors** we model.
- The **trust boundaries** in the system.
- The **threats** we mitigate, classified using STRIDE.
- The **17 defense layers** that compose archangel's security posture.
- The **residual risk** we accept and the conditions under which we accept it.

This is not a marketing document. We deliberately enumerate what we **cannot** prevent.

---

## 2. Scope

In scope:

- The archangel daemon (`archangeld`), executor (`archangel-execd`), CLI (`archangelctl`) and supporting crates.
- IPC between archangel components.
- LLM backend communication (Anthropic, Ollama, OpenAI-compatible endpoints).
- The `.exec` signed action bundle format.
- The policy engine and the immutable denylist.
- Audit log integrity.
- Packaging (DEB, RPM) and distribution channels.

Out of scope (delegated to operator):

- Physical security of the host.
- Compromise of the operator's workstation, browser, or password manager.
- Host kernel vulnerabilities (we rely on the kernel's isolation primitives; if the kernel is broken, so are we).
- Supply chain compromise of the host distribution's package manager (we assume `apt`/`dnf` integrity).
- Side-channel attacks (Spectre/Meltdown-class) — mitigated by kernel/CPU vendor.

---

## 3. Trust model

Archangel uses **explicit, asymmetric trust**. Trust is not transitive; component A trusting B does not imply B trusting A.

### 3.1 Trust ranking (from most to least trusted)

| Tier | Entity | Notes |
|------|--------|-------|
| T0 | **Operator's signing keys** (offline, Ed25519 / hardware-backed) | Used to sign `.exec` bundles, policies, releases. Compromise = game over. Keep offline. |
| T1 | **Kernel + systemd + sandbox primitives** | We rely on these. If the kernel is broken, archangel cannot rescue itself. |
| T2 | **`archangel-execd` (executor)** | Minimal-capability process. Validates every request. Single point of mutation. |
| T3 | **`archangeld` (daemon)** | Network-facing, processes LLM input. **Assumed compromisable.** |
| T4 | **Policy engine (WASM sandbox)** | Evaluates each action. Runs sandboxed. |
| T5 | **LLM backend (remote API or local model)** | **Treated as hostile.** Output is data, not instructions. |
| T6 | **Filesystem/log/network content read by the LLM** | **Treated as hostile.** May contain indirect prompt injection. |
| T7 | **Network peers (other than the configured LLM endpoint)** | Blocked by egress filter. |

### 3.2 Trust boundaries (in order of risk)

```
                            [INTERNET / LLM API]   T5  ← hostile
                                     │ TLS 1.3
                                     │ (channel is trusted,
                                     │  content is not)
              ┌──────────────────────┴────────────────────────┐
              │                                                │
              │  ── BOUNDARY A ── (network → daemon)            │
              │                                                │
              ▼                                                │
        ┌─────────────┐                                        │
        │ archangeld  │  T3, runs as user "archangel"          │
        │             │  no setuid, no CAP_*                   │
        └──────┬──────┘                                        │
               │                                                │
               │  ── BOUNDARY B ── (daemon → executor) ────────┤
               │  Unix socket + SCM_CREDENTIALS                │
               │  every request signed Ed25519 (session key)   │
               │                                                │
               ▼                                                │
        ┌─────────────┐                                        │
        │ archangel-  │  T2, runs as user "archangel-exec"    │
        │  execd      │  CAP_DAC_READ_SEARCH only by default  │
        └──────┬──────┘                                        │
               │                                                │
               │  ── BOUNDARY C ── (executor → action sandbox)─┤
               │  namespaces + seccomp + capabilities          │
               │  per-action ephemeral container               │
               │                                                │
               ▼                                                │
        ┌─────────────┐                                        │
        │  Action     │  T1, runs in sandbox                   │
        │  sandbox    │  syscalls allowlisted                  │
        └─────────────┘                                        │
                                                                │
                                                                ▼
                            [Filesystem / Network read by LLM]  T6 ← hostile
```

A breach of `archangeld` (T3) does **not** grant the attacker the ability to mutate the system, because boundary B requires a valid session-key signature held in protected memory and refreshed on every action. A breach of the executor (T2) is fatal — that is the reason its codebase must be **minimal, formally specified, and the first target of any external audit**.

---

## 4. Assets

| ID | Asset | Confidentiality | Integrity | Availability |
|----|-------|-----------------|-----------|--------------|
| A1 | Host filesystem (data, configs, secrets) | HIGH | HIGH | MEDIUM |
| A2 | SSH access to the host | HIGH | HIGH | **CRITICAL** |
| A3 | Audit log | LOW | **CRITICAL** | HIGH |
| A4 | Operator signing keys (T0) | **CRITICAL** | **CRITICAL** | HIGH |
| A5 | LLM API token | HIGH | HIGH | LOW |
| A6 | `.exec` bundle and policy files | LOW | **CRITICAL** | HIGH |
| A7 | Snapshots (rollback capability) | LOW | HIGH | HIGH |
| A8 | archangel binaries themselves | LOW | **CRITICAL** | HIGH |
| A9 | Operator's reputation / non-attribution | HIGH | n/a | n/a |

"Loss of A2" is given **CRITICAL** availability because losing SSH access to a remote server may render it unrecoverable without out-of-band access (console, IPMI, cloud rescue). This is the single most common way a misbehaving automation tool destroys a server.

---

## 5. Threat actors

| ID | Actor | Capability | Likelihood |
|----|-------|-----------|------------|
| TA1 | Unsophisticated remote attacker | Probes exposed services, runs public exploits | High |
| TA2 | Authenticated user with low privilege | Has shell on the host as a non-archangel user | Medium |
| TA3 | LLM prompt injector (indirect) | Can place text in any source the LLM reads (logs, files, fetched URLs, MOTDs) | **High** |
| TA4 | LLM provider compromise | The remote LLM endpoint is hijacked, MITM, or the provider is hostile | Low / catastrophic |
| TA5 | Malicious operator | A trusted operator turns hostile or is coerced | Medium / catastrophic |
| TA6 | Supply chain attacker | Compromise of a Rust dep, a Github Action, a packaging mirror | Medium / catastrophic |
| TA7 | Nation-state with implant capability | Kernel 0-day + custom exploitation chain | Low / catastrophic |
| TA8 | Hallucinating LLM (no attacker) | The model itself produces a destructive command without any adversary involved | **High** |

Archangel is designed primarily against TA3 and TA8. It provides meaningful defense against TA1, TA2, TA5, TA6. It provides best-effort defense against TA4. **It does not pretend to defend against TA7** — operators in TA7's threat model need air-gapped operation, hardware roots of trust, and probably should not be running an LLM agent at all.

---

## 6. STRIDE threat analysis

For each STRIDE category, we list the most relevant threats and the layer(s) that mitigate them. The numbers map to the 17 defense layers in §7.

### 6.1 Spoofing

| Threat | Mitigation layer(s) |
|--------|---------------------|
| Attacker impersonates `archangelctl` to send commands to the daemon | Unix socket + SCM_CREDENTIALS check (10), session key signature on every request |
| Attacker impersonates `archangel-execd` to intercept actions | Single execd unit, well-known socket path with strict permissions (0600, owned by archangel-exec) |
| Attacker impersonates the LLM provider endpoint | TLS pinning of certificate / public key; configured endpoint cannot be changed at runtime |
| Attacker forges a `.exec` bundle | Ed25519 signature verification against operator key chain (6) |
| Attacker forges an audit log entry | Hash-chained append-only log; tamper invalidates the chain (15) |

### 6.2 Tampering

| Threat | Mitigation layer(s) |
|--------|---------------------|
| Modify archangel binaries on disk | Distro package signing; runtime SHA-256 self-check at startup; immutable mount option recommended in operator guide |
| Modify `.exec` bundles | Signed; signature checked on every load (6) |
| Modify denylist | Compiled into binary (8); cannot be changed at runtime |
| Modify allowlist or policies | Signature required (9); reload requires explicit `archangelctl policy reload` with operator authentication |
| Modify audit log | Hash chain (15); external transparency anchor (optional) |
| Modify systemd unit to remove hardening | Out of scope (operator responsibility); `archangel-doctor` verifies hardening on each start |

### 6.3 Repudiation

| Threat | Mitigation layer(s) |
|--------|---------------------|
| LLM "denies" issuing an action | Every prompt + response pair is recorded with the action id in the audit log (15) |
| Operator denies approving an action in interactive mode | Approval recorded with operator key signature (15) + two-person rule for critical actions (14) |
| Provider "loses" a record of LLM interaction | We keep our own record; provider's record is not authoritative |

### 6.4 Information disclosure

| Threat | Mitigation layer(s) |
|--------|---------------------|
| LLM is tricked into reading `/etc/shadow` and including it in output | Sandbox (11) blocks the syscall via seccomp; egress filter (17) blocks exfiltration even if read succeeds |
| LLM is tricked into sending data to attacker-controlled domain via tool action | Egress filter (17) allows only the configured LLM endpoint + operator-whitelisted destinations |
| Audit log leaks sensitive content from prompts/responses | Audit log access restricted (mode 0640, group `archangel-audit`); redaction filters for known secret patterns (best effort) |
| Tokens for LLM provider leak from disk or memory | Tokens encrypted at rest (TPM-sealed where available, `systemd-creds`, or passphrase-derived); zeroed on free (`zeroize` crate) |

### 6.5 Denial of service

| Threat | Mitigation layer(s) |
|--------|---------------------|
| LLM proposes infinite loop of actions | Rate limits + cooldowns (12); session token budget |
| Attacker spams approval queue (in interactive mode) to fatigue the operator | Per-source rate limit; queue suppression for repeated near-identical requests |
| Disk fill via large audit log | Log rotation with mandatory minimum retention; alerts before exhaustion |
| LLM endpoint becomes unavailable | Daemon enters degraded mode (read-only); no actions executed; operator notified |

### 6.6 Elevation of privilege

| Threat | Mitigation layer(s) |
|--------|---------------------|
| RCE in `archangeld` HTTP client → arbitrary code as `archangel` user | Privilege separation (10): no `CAP_*`, no setuid, cannot mutate system; needs to also break boundary B |
| Sandbox escape from an action | Defense in depth (11): seccomp + namespaces + capabilities + cgroups; even on escape, capabilities of `archangel-execd` are minimal |
| LLM convinces daemon to execute action outside its profile | Policy engine (9) enforces profile boundary; denylist (8) compiled at build time, cannot be overridden |
| Operator key compromise | Two-person rule (14) for critical actions; offline storage of root signing key recommended; key rotation policy documented |

---

## 7. The 17 defense layers

Defense in depth, ordered from "outermost" (closest to attacker) to "innermost" (closest to system). **Every layer is independent**: compromising one does not compromise the next.

| # | Layer | Class | Purpose |
|---|-------|-------|---------|
| 1 | Defensive system prompt with tagged untrusted input | Prevention | Bias the model against acting on injected instructions |
| 2 | Spotlighting with per-session random delimiters | Prevention | Make injection-vs-data distinction unforgeable in the prompt |
| 3 | Canary tokens in system prompt | Detection | Detect when the model has been subverted and kill the session |
| 4 | Per-task context isolation | Containment | An injection cannot persist across tasks |
| 5 | Structured action output (JSON schema), no free shell | Prevention | The model's expressible output is bounded |
| 6 | Signed `.exec` bundles, Ed25519 verification | Prevention | The model can only invoke pre-approved actions |
| 7 | Strict schema validation of `.exec` arguments | Prevention | Argument injection (e.g., `nginx; rm -rf /`) is rejected |
| 8 | Immutable denylist compiled into the binary | Prevention | Catastrophic operations cannot be enabled at runtime |
| 9 | Signed per-profile allowlist + WASM policy engine | Prevention | Fine-grained scope; hot-reloadable with audit trail |
| 10 | Privilege separation (`archangeld` ↔ `archangel-execd`) | Containment | Daemon RCE does not grant mutation capability |
| 11 | Per-action sandbox (seccomp + namespaces + caps + cgroups) | Containment | Every action runs in an ephemeral, locked-down container |
| 12 | Rate limits + cooldowns + quotas | Containment | Bound the blast rate of any successful attack |
| 13 | Interactive mode with explicit diff approval | Detection / Prevention | Human in the loop sees the exact change before commit |
| 14 | Two-person rule for critical actions | Prevention | Single-actor compromise insufficient for catastrophic action |
| 15 | Hash-chained signed audit log | Detection / Forensics | Tamper-evident record of every action and decision |
| 16 | Automatic snapshots + rollback on regression | Recovery | Catastrophe is recoverable, not terminal |
| 17 | Kernel-level egress filter (allowlist) | Containment | Exfiltration is structurally impossible |

Implicit layer **#18: red team test suite in CI**. Every commit is tested against a corpus of known prompt-injection payloads. A successful injection fails the build.

### 7.1 What each layer does **not** do

- Layer 1–4 reduce probability of injection success; they do not eliminate it.
- Layer 5–9 prevent the model's output from expressing arbitrary commands; they do not prevent semantic abuse (invoking allowed actions for malicious purposes).
- Layer 10–11 contain the blast radius; they do not detect intent.
- Layer 12 limits rate; it does not prevent a single catastrophic action within the rate.
- Layer 13–14 introduce human oversight; humans are fallible to fatigue and social engineering.
- Layer 15 detects after the fact; it does not prevent.
- Layer 16 enables recovery; some damage (e.g., data exfiltration, destructive `dd` to a raw device that has no snapshot) is not recoverable.
- Layer 17 prevents network exfiltration; it does not prevent local data destruction.

This is why **every layer is required** and why we resist removing any of them for operational convenience.

---

## 8. Attack scenarios (walkthrough)

### 8.1 Indirect prompt injection via log file

1. Attacker (TA1) sends an HTTP request with a malicious `User-Agent` to a web server on the host.
2. The line is written to `/var/log/nginx/access.log`.
3. Operator asks archangel: "Resume the access log."
4. `archangeld` reads the file (allowed — read-only operation) and includes contents in the prompt.
5. **Layer 2** wraps the file content in per-session delimiters with a recordatorio explícito.
6. The LLM processes the content. If it succumbs to the injection and proposes a malicious action:
7. **Layer 5** ensures the output is structured JSON, not shell. The injection must be expressed as a `.exec` invocation.
8. **Layer 6** rejects any `.exec` name that is not in the signed bundle.
9. If the attacker named a valid `.exec`, **Layer 7** rejects arguments that don't match the schema.
10. If arguments validate, **Layer 9** policy engine evaluates against the current profile.
11. If allowed, **Layer 13** (interactive mode) shows the action to the operator for approval.
12. If autonomous mode and the action is "critical", **Layer 14** requires a second signature.
13. On approval, **Layer 11** runs in a sandbox where exfiltration syscalls are blocked.
14. **Layer 17** blocks the egress connection to the attacker's domain at the kernel level.
15. **Layer 15** records the entire decision chain with signatures.

**At which layer was the attack stopped?** Probably layers 5–7 for naive attacks; layers 9 + 13 for sophisticated attacks that named a valid action; layer 17 if everything else failed.

### 8.2 Hallucinated destructive command

1. Operator asks archangel: "Free up some disk space."
2. The model, without any adversarial input, suggests `rm -rf /var/log/old/*`.
3. **Layer 5** forces the suggestion to be expressed as a structured action, e.g., `purge-path.exec`.
4. **Layer 7** validates the path argument against an allowed pattern.
5. **Layer 8** denylist rejects any path matching the dangerous-paths blacklist.
6. **Layer 13** shows the operator the exact paths to be deleted, with diff preview.
7. **Layer 16** snapshots the affected subvolume before execution.
8. If the operator approves and later detects regression, `archangelctl rollback` restores from the snapshot.

### 8.3 LLM provider compromise (TA4)

1. The remote LLM endpoint is hijacked or the provider's model is replaced with a hostile one.
2. The hostile model responds to **every** prompt with a malicious action.
3. **TLS pinning** prevents undetected MITM (so this requires actual provider compromise, not network MITM).
4. **Layer 5–9** still apply: the malicious model can only emit structured actions to signed `.exec` bundles.
5. **Layer 13**: in interactive mode, the operator notices unusual proposals and revokes the session.
6. **Layer 12**: in autonomous mode, rate limits bound the damage.
7. **Layer 17**: exfiltration to a non-whitelisted destination is blocked.
8. **Layer 15**: every interaction is recorded; post-mortem analysis is possible.

Operator should switch to Ollama (local) on suspicion. The architecture supports zero-downtime backend switching.

---

## 9. Residual risk

We **explicitly accept** the following residual risks. Operators must understand them before adopting archangel for production:

1. **Determined prompt injection against the LLM remains possible.** Layers 1–4 reduce but do not eliminate success probability.
2. **Semantic abuse of allowed actions.** An attacker who tricks the LLM into invoking allowed `.exec` files with allowed arguments for malicious purposes is hard to detect. Mitigation: keep `.exec` bundles narrowly scoped; classify by risk; require approval for high-risk classes.
3. **Operator fatigue in interactive mode.** Humans rubber-stamp after many approvals. Mitigation: vary the approval UI; insert random delays for critical actions; "are you sure?" prompts on destructive operations.
4. **Compromise of the operator's signing key.** This is game over. Mitigation: hardware-backed keys (YubiKey, TPM); offline root key with signed subkeys for daily use; key rotation policy.
5. **Kernel vulnerabilities.** We rely on namespaces/seccomp/cgroups. A kernel escape is out of our control. Mitigation: keep host kernel patched; consider gVisor/Kata for very high-stakes deployments.
6. **Supply chain attacks on dependencies.** Mitigation: `cargo-deny` policy; minimal dependency set; vendored critical deps; reproducible builds; SBOM published with every release.
7. **Side channels.** Not modeled.
8. **Physical access.** Not modeled.

---

## 10. Disclosure and response

- Security contact: `security@archangel-sec.org` (PGP key in `SECURITY.md`).
- Embargo: 90 days standard, negotiable for severe issues.
- Coordinated disclosure with affected distributions (Fedora, Debian, etc.) before public release.
- CVE assignment via GitHub Security Advisory or distribution security team.
- Public post-mortem on resolution.

See [SECURITY.md](../SECURITY.md) for the full process.

---

## 11. Change control

Modifications to this document require:

1. A PR explicitly tagged `threat-model-change`.
2. Approval from **two** maintainers, neither of whom authored the PR.
3. A 7-day comment period for the security community before merge.
4. A corresponding entry in `CHANGELOG.md` under "Security".
5. If the change weakens any of the 17 layers, an explicit `RFC-XXXX-deprecate-layer-N.md` document with rationale, signed off by all maintainers.

---

## 12. References

- OWASP Top 10 for LLM Applications, 2025 revision.
- NIST AI 100-2 E2025 — Adversarial Machine Learning Taxonomy.
- Simon Willison, *Dual LLM pattern* (2023) and subsequent updates.
- Anthropic, *Constitutional AI* and *Mitigating prompt injection*.
- NVIDIA, *Practical Security Guidance for Sandboxing Agentic Workflows* (2025).
- OpenSSH design notes on privilege separation (Provos & Friedl, 2003).
- systemd hardening guide (`systemd.exec(5)`).
- seccomp-bpf reference (`man 2 seccomp`).
