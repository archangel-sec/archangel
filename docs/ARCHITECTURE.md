# Archangel — Architecture

**Status:** Draft v0.1 (pre-implementation)
**Companion to:** [THREAT_MODEL.md](THREAT_MODEL.md)

This document describes **how archangel is built**. The threat model describes **why**. Read both.

---

## 1. High-level component view

```
                  ┌──────────────────────────────────────┐
                  │   Operator / Admin                    │
                  └─────┬────────┬───────────────────┬───┘
                        │ TTY    │ HTTPS (loopback) │ webhook (push)
                        ▼        ▼                  ▼
                   ┌──────────┐ ┌────────────┐  ┌──────────────┐
                   │ archangel│ │ archangel- │  │ approver     │
                   │   ctl    │ │   tui      │  │  (mobile,    │
                   │  (CLI)   │ │  (TUI)     │  │   slack, …)  │
                   └────┬─────┘ └─────┬──────┘  └──────┬───────┘
                        │             │                │
                        └──────┬──────┴────────────────┘
                               │  Unix socket (control)
                               │  /run/archangel/ctl.sock (0660, group archangel)
                               ▼
        ┌──────────────────────────────────────────────────────────┐
        │  archangeld   (systemd service: archangeld.service)       │
        │  user: archangel  group: archangel                        │
        │  no setuid, no CAP_*                                      │
        │                                                            │
        │  ┌──────────────┐  ┌────────────┐  ┌──────────────────┐   │
        │  │ session +    │  │ LLM client │  │ prompt builder   │   │
        │  │ planner      │◀─┤ (Anthropic │  │  + spotlighting  │   │
        │  │              │  │  / Ollama) │  │  + canary tokens │   │
        │  └──────┬───────┘  └─────┬──────┘  └────────┬─────────┘   │
        │         │                │                  │             │
        │         ▼                ▼                  ▼             │
        │  ┌────────────────────────────────────────────────────┐  │
        │  │  policy engine  (WASM, wasmtime, fuel-limited)     │  │
        │  │  evaluates: denylist → allowlist → profile rules   │  │
        │  └────────────────────────┬───────────────────────────┘  │
        │                           │                              │
        │                           ▼                              │
        │  ┌────────────────────────────────────────────────────┐  │
        │  │  audit writer  (hash-chained, Ed25519 signed)      │  │
        │  └────────────────────────────────────────────────────┘  │
        └─────────────┬────────────────────────────────────────────┘
                      │ Unix socket + SCM_CREDENTIALS
                      │ /run/archangel/exec.sock (0600, owner archangel-exec)
                      │ per-request Ed25519 session-key signature
                      ▼
        ┌──────────────────────────────────────────────────────────┐
        │  archangel-execd   (systemd service: archangel-execd.service) │
        │  user: archangel-exec  group: archangel-exec              │
        │  AmbientCapabilities=(empty by default; per-action grant) │
        │                                                            │
        │  - re-validates request against denylist + allowlist      │
        │  - verifies `.exec` signature                              │
        │  - validates argument schema                               │
        │  - constructs sandbox profile for the action               │
        │  - spawns sandboxed child                                  │
        └─────────────┬────────────────────────────────────────────┘
                      │ clone3() with new namespaces, seccomp installed
                      ▼
        ┌──────────────────────────────────────────────────────────┐
        │  Action sandbox  (ephemeral, per-action)                  │
        │   - mount namespace, RO bind-mounts except declared paths │
        │   - PID namespace                                          │
        │   - network namespace (no net by default; allowlisted    │
        │     veth for actions that declare network: true)          │
        │   - UTS, IPC, optionally user namespace                   │
        │   - seccomp-bpf allowlist tailored to the action          │
        │   - cgroup v2: memory.max, cpu.max, pids.max, io.max     │
        │   - rlimits                                                │
        │   - executes the `.exec` script / binary                   │
        └──────────────────────────────────────────────────────────┘
```

---

## 2. Repository layout

```
archangel/
├── Cargo.toml                  # workspace root
├── rust-toolchain.toml         # pinned toolchain
├── deny.toml                   # cargo-deny policy
├── rustfmt.toml                # formatting
├── LICENSE-APACHE
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── CHANGELOG.md
├── docs/
│   ├── THREAT_MODEL.md
│   ├── ARCHITECTURE.md         # this file
│   ├── ROADMAP.md
│   ├── OPERATOR_GUIDE.md
│   ├── EXEC_FORMAT.md
│   └── POLICY_FORMAT.md
├── crates/
│   ├── archangeld/             # daemon (T3)
│   ├── archangel-execd/        # executor (T2)
│   ├── archangelctl/           # CLI
│   ├── archangel-core/         # shared types, error model
│   ├── archangel-policy/       # WASM policy engine + denylist
│   ├── archangel-audit/        # hash-chained signed log
│   ├── archangel-llm/          # backend trait + adapters
│   ├── archangel-sandbox/      # seccomp / namespaces / cgroups
│   └── archangel-exec-format/  # .exec bundle parser + verifier
├── packaging/
│   ├── deb/
│   ├── rpm/
│   └── etc-archangel/          # example /etc/archangel/ tree
├── systemd/
│   ├── archangeld.service
│   └── archangel-execd.service
├── tests/
│   ├── integration/
│   ├── redteam/                # prompt-injection corpus
│   └── fuzz/
└── .github/
    ├── workflows/
    │   ├── ci.yml
    │   ├── security.yml
    │   └── release.yml
    ├── CODEOWNERS
    └── pull_request_template.md
```

---

## 3. Crate responsibilities

| Crate | Trust tier | Responsibility | What it must never do |
|-------|------------|----------------|-----------------------|
| `archangel-core` | shared | Types, errors, ids, primitives, `zeroize`-aware secrets | No I/O, no global state |
| `archangel-llm` | T3 | LLM backend adapters; prompt builder | Decide policy, mutate system |
| `archangel-policy` | T3 | Denylist (compiled), allowlist loader, WASM policy eval | Execute actions |
| `archangel-audit` | T2 & T3 | Hash-chain log writer, signature, reader | Skip a write |
| `archangel-exec-format` | T2 | Parse + verify `.exec` bundles, validate arg schema | Trust an unsigned bundle |
| `archangel-sandbox` | T2 | Build sandbox profiles, install seccomp, set caps | Execute outside its profile |
| `archangeld` | T3 | Session, planner, ctl socket, exec socket client | Touch the filesystem outside its own state dir |
| `archangel-execd` | T2 | Receive requests, verify signatures, re-validate, spawn sandboxed action | Trust the daemon |
| `archangelctl` | user | CLI for operator | Anything privileged itself |

**Rule:** every crate sets `#![forbid(unsafe_code)]` unless explicitly justified in a `// SAFETY: ...` comment block, reviewed at PR time. Crates that *must* use `unsafe` (likely only `archangel-sandbox` for syscalls) are flagged in CODEOWNERS for extra review.

---

## 4. Inter-process communication

### 4.1 Control socket (`archangelctl` ↔ `archangeld`)

- Path: `/run/archangel/ctl.sock`
- Mode: `0660`, owner `archangel:archangel`
- Auth: `SCM_CREDENTIALS` — daemon checks peer's UID/GID against the configured operator group.
- Protocol: length-prefixed CBOR frames over the stream socket. Versioned envelope.
- Authn beyond peer creds: each request also carries an operator Ed25519 signature for non-read operations.

### 4.2 Execution socket (`archangeld` → `archangel-execd`)

- Path: `/run/archangel/exec.sock`
- Mode: `0600`, owner `archangel-exec:archangel-exec`
- The daemon is granted access via systemd `BindReadOnlyPaths=` or POSIX ACL set at install time — the daemon's `archangel` user is on the ACL with `rwx` for connect only.
- **Every request** is signed with the daemon's per-session Ed25519 key. The executor verifies the signature against the active session key (rotated on each `archangeld` restart, sealed with a startup nonce).
- Replay protection: monotonic request counter + nonce, executor rejects out-of-order requests.

### 4.3 No HTTP listener by default

Archangel does not listen on TCP. Optional `archangel-web` is a **separate package**, opt-in, binds to loopback only, with mTLS to operator certs.

---

## 5. Configuration

All configuration lives under `/etc/archangel/`:

```
/etc/archangel/
├── archangel.toml              # main daemon config
├── models.toml                 # LLM backend + token references
├── profiles/                   # per-target profiles
│   ├── default.toml
│   └── prod-database.toml
├── policies/
│   ├── allowlist.toml          # signed
│   └── allowlist.toml.sig
├── exec/                       # signed .exec bundles
│   ├── restart-service.exec
│   ├── restart-service.exec.sig
│   └── …
└── trust/
    ├── operators.pubkeys       # Ed25519 public keys allowed to sign
    └── ca.pem                  # optional: TLS pinning for LLM endpoint
```

- Files are read at startup and on explicit reload (`archangelctl reload`).
- No automatic reload on file change (avoids unrelated edits triggering policy changes).
- Tokens are **never** stored in `archangel.toml` directly — they are referenced by `LoadCredential=` (systemd) or by an encrypted blob unlocked at start.

---

## 6. State and runtime data

- `/var/lib/archangel/` — daemon state (session journal, key material, policy cache). Mode `0700`, owner `archangel`.
- `/var/lib/archangel-exec/` — executor state (sandbox profile cache). Mode `0700`, owner `archangel-exec`.
- `/var/log/archangel/audit.log.jsonl` — append-only audit log. Mode `0640`, owner `archangel:archangel-audit`.
- `/run/archangel/` — runtime sockets, ephemeral.

Snapshots are stored by the underlying filesystem (BTRFS subvol snapshots, ZFS, LVM thin) and tracked by id in the audit log.

---

## 7. Action lifecycle

For a single action, from operator intent to recorded outcome:

```
1.  Operator → archangelctl request "do X"
2.  archangelctl signs request, sends to archangeld over ctl.sock
3.  archangeld validates operator signature + session
4.  archangeld builds prompt:
        system prompt with canary tokens (#3)
      + tool definitions (only .exec from active profile)
      + history (per-task isolation #4)
      + spotlighted untrusted input (#2)
5.  archangeld sends to LLM backend (TLS pinned)
6.  LLM responds with structured action: { exec, args, reason }
7.  archangeld:
        - checks output for canary leak (#3) → abort if found
        - validates structure (#5)
        - resolves .exec to signed bundle in /etc/archangel/exec/ (#6)
        - validates args against schema (#7)
        - evaluates denylist (#8) → deny if matched
        - evaluates allowlist + policy WASM (#9) → deny / allow / require_approval
        - checks rate limits (#12)
8.  If require_approval (mode=interactive OR critical action):
        - sends to approval queue → operator/second-approver (#13/#14)
        - waits for signed approval
9.  archangeld constructs ExecRequest, signs with session key, sends to archangel-execd
10. archangel-execd:
        - verifies signature against current session key
        - re-runs denylist + allowlist (defense in depth)
        - verifies .exec bundle signature
        - builds sandbox profile (#11)
        - if action declares mutates_persistent_state: take snapshot (#16)
        - spawns child in sandbox
        - egress filter (#17) installed on the netns
11. Action runs, output captured (stdout, stderr, exit code, duration, resources)
12. archangel-execd returns result to archangeld
13. archangeld:
        - appends signed audit entry (#15) with full decision chain
        - returns result to operator
14. If post-action health check (defined in .exec) fails → automatic rollback (#16)
```

Every step is logged. The audit log alone allows full reconstruction of any session.

---

## 8. The `.exec` bundle format (overview)

Full spec: [EXEC_FORMAT.md](EXEC_FORMAT.md) (to be written).

A `.exec` is a TOML manifest plus a payload (script or binary), packaged in a single file. Roughly:

```toml
[meta]
name = "restart-service"
version = "1.2.0"
risk = "medium"               # low | medium | high | critical
read_only = false
mutates_persistent_state = false
requires_network = false

[args]
service = { type = "string", regex = "^[a-z0-9.-]+\\.service$", required = true }

[sandbox]
capabilities = []
allowed_paths_ro = ["/etc/systemd/system", "/lib/systemd/system"]
allowed_paths_rw = []
syscall_profile = "service-management"
network = "none"
cpu_max = "10%"
memory_max = "128M"
timeout_seconds = 30

[payload]
type = "bash"
sha256 = "…"
# … inline script or external reference …

[health_check]
command = "systemctl is-active {{ args.service }}"
expect_exit = 0
timeout_seconds = 10
```

Plus a detached signature file (`.exec.sig`) chained to an operator key in `trust/operators.pubkeys`.

Critical points:

- `risk = "critical"` automatically triggers two-person rule, regardless of mode.
- `mutates_persistent_state = true` triggers snapshot before execution.
- The sandbox section is **declarative** — the executor builds the actual sandbox; the bundle cannot escalate by editing the sandbox config (mismatch detected at verify time).
- Operators are expected to maintain their own bundle. A "stdlib" of safe `.exec` files will be distributed separately, also signed.

---

## 9. The denylist (compiled into the binary)

Located at `crates/archangel-policy/src/denylist.rs`. **Read-only at runtime.** Examples (non-exhaustive):

```rust
// Pseudocode; actual representation is a structured rule list.
DenyRule::path_write("/etc/archangel/**")
DenyRule::path_write("/etc/ssh/**")
DenyRule::path_write("/etc/shadow")
DenyRule::path_write("/etc/sudoers*")
DenyRule::path_write("/boot/**")
DenyRule::path_write("/root/.ssh/authorized_keys")
DenyRule::syscall("kexec_load")
DenyRule::syscall("init_module")
DenyRule::syscall("finit_module")
DenyRule::syscall("delete_module")
DenyRule::cmd_pattern(r"^mkfs(\.\w+)?$")
DenyRule::cmd_pattern(r"^wipefs$")
DenyRule::cmd_pattern(r"^dd .* of=/dev/(sd|nvme|vd|md|dm-|loop)")
DenyRule::cmd_pattern(r"^systemctl (stop|disable|mask) sshd?\.service$")
DenyRule::cmd_pattern(r"^(ufw disable|iptables -F|nft flush ruleset)")
DenyRule::cmd_pattern(r"^passwd( root)?$")
DenyRule::self_modification()   // any write under /usr/{bin,lib}/archangel*
```

Adding to the denylist requires a PR, two reviewers, a CHANGELOG entry, and a major-version bump if any existing allowed behavior becomes denied.

---

## 10. Backends

`archangel-llm` exposes a `LlmBackend` trait:

```rust
#[async_trait]
pub trait LlmBackend: Send + Sync {
    fn name(&self) -> &str;
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse>;
    fn supports(&self, capability: BackendCapability) -> bool;
}
```

Initial implementations:

| Crate feature | Backend | Notes |
|---------------|---------|-------|
| `backend-anthropic` | Anthropic (Claude) | Default, supports prompt caching, structured output |
| `backend-ollama` | Local Ollama | For air-gapped operation, no external egress required |
| `backend-openai-compat` | Any OpenAI-compatible endpoint | Generic fallback (LM Studio, vLLM, etc.) |

Backends are compiled in by feature flag. A build with only `backend-ollama` enabled produces a binary that **cannot** reach the public internet for inference, simplifying audit for air-gapped deployments.

---

## 11. Build, packaging, distribution

- **Reproducible builds** target: same source + same toolchain → byte-identical artifact.
- **Cargo workspace** with `resolver = "2"`, MSRV documented in root `Cargo.toml` `rust-version`.
- **`cargo-deny`** enforces license, advisory, and source policies on every CI run.
- **`cargo-audit`** runs on every CI run and nightly.
- **SBOM** (CycloneDX) generated per release; attached to GitHub release.
- **Releases** signed with `cosign` (Sigstore); SHA-256 checksums published.
- **Packages**:
  - DEB built via `cargo-deb` with custom maintainer scripts for the `archangel` / `archangel-exec` user creation and group setup.
  - RPM built via a hand-maintained spec for full control of `%pre`/`%post`.
  - **Fedora COPR** as initial distribution; intent to upstream to Fedora proper after security audit.
  - **Launchpad PPA** for Ubuntu LTS; intent to upstream to Debian after audit.
- **No automatic updates** within archangel itself. Updates go through the OS package manager. (The daemon never self-updates — see threat model §6.6.)

---

## 12. Open architectural questions

These are decisions left intentionally open until they are needed:

1. **Web/HTTP companion package** — separate crate, not in v0.1. Mandatory mTLS.
2. **Policy federation** (organization-wide signed bundles) — v0.4+.
3. **Formal verification of `archangel-policy` and `archangel-execd`** with [Kani](https://github.com/model-checking/kani) — v1.0+ aspiration.
4. **Confidential compute (SEV-SNP, TDX) support** — v2.0+, demand-driven.
5. **Dual-LLM pattern** for additional injection containment — v0.3 evaluation.
6. **Plugin system for `.exec` payload runtimes** (Lua sandbox, WASM, Python with restrictions) — needs separate threat-model amendment before implementation.

Every one of these requires a documented RFC in `docs/rfcs/` before implementation starts.
