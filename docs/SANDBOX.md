# Archangel — Per-action sandbox (threat-model layer #11)

> Status: **v0.2, enforced.** The no-`unsafe` *plan* core, the single audited
> `pre_exec` applier (`no_new_privs` + seccomp), and the `archangel-execd`
> wiring are all implemented and tested: every executed action is hardened,
> and the executor refuses any action whose plan cannot be built. Namespace
> unshare, mount binding and parent-side cgroup attach remain the next
> refinement (§5). This document is normative.

## 1. What this layer contains

Every action runs in an **ephemeral, locked-down container** built fresh per
request and discarded when the process exits. Layer #11 exists even though
bundles are operator-signed (#6) and denylist/allowlist-checked (#8/#9): it is
defense in depth for the case where an *otherwise-legitimate* action is steered
to do something its author did not intend (a hostile log line read by the LLM,
T6; a subtly over-broad payload). The sandbox does not trust the payload — it
bounds what the payload **can** do at the kernel level, independently of what
it **tries** to do.

Four primitives, all default-deny:

| Primitive | Mechanism | Default |
|---|---|---|
| Syscall surface | seccomp-bpf allowlist (`seccompiler`) | every syscall not on the profile's list **kills the process** |
| Privilege | capability set dropped to the bundle's explicit list (`caps`) | **empty** — no capabilities |
| Isolation | Linux namespaces (`unshare`: mount, pid, ipc, uts, cgroup; user where available; net per policy) | network namespace with **no interfaces** unless the bundle declares otherwise |
| Resources | cgroup v2 `cpu.max` / `memory.max` | parsed from the bundle; an unparseable limit is a **hard refusal**, never "unlimited" |

The wall-clock timeout and output cap already enforced by the executor's
process runner are retained — they are orthogonal and complementary.

## 2. Fail-closed posture

The sandbox is constructed from the **verified** bundle's declarative
`[sandbox]` section, never from anything the daemon (T3, assumed
compromisable) asserts. Construction is total and fail-closed:

- Unknown seccomp profile name ⇒ **no plan** (not an empty/permissive filter).
- Unknown capability name ⇒ **no plan** (not "ignore it and continue").
- Malformed / out-of-range `cpu_max` or `memory_max` ⇒ **no plan**.
- No plan ⇒ the executor refuses the action. **No sandbox, no execution.**

This mirrors the snapshot gate (#16): a missing safety mechanism is a reason to
*refuse*, never a reason to proceed unprotected.

## 3. The `unsafe` discipline

`archangel-sandbox` is the one crate where the project's strongest invariant is
relaxed, and it is relaxed *exactly as far as the architecture already
authorizes* — this is applying existing policy, not making a new decision:

> ARCHITECTURE.md §"every crate sets `#![forbid(unsafe_code)]` unless
> explicitly justified in a `// SAFETY:` comment block, reviewed at PR time.
> Crates that *must* use `unsafe` (likely only `archangel-sandbox` for
> syscalls) are flagged in CODEOWNERS for extra review."

Concretely:

1. Every other crate keeps `#![forbid(unsafe_code)]` (workspace lint).
2. `archangel-sandbox` uses `#![deny(unsafe_code)]` — strong, but allows a
   single, named, reviewed exception via `#[allow(unsafe_code)]` on one block.
   `forbid` would make even a `// SAFETY:`-justified block impossible.
3. The crate's lint table is written out explicitly (it does **not** inherit
   `[workspace.lints]`) so the relaxation is visible in `Cargo.toml` and
   greppable, not hidden behind `workspace = true`.
4. `/crates/archangel-sandbox/**` is CODEOWNERS-gated to
   `@archangel-sec/security` (already in place).
5. There is **exactly one** `unsafe` site: the post-fork / pre-exec hook
   (`Command::pre_exec`) that applies namespaces, the compiled BPF filter, the
   capability drop, and the cgroup attach. It carries a `// SAFETY:` block
   stating the async-signal-safety reasoning. Everything that *decides* what
   that hook does — profile compilation, capability resolution, limit parsing,
   plan validation — is ordinary safe Rust and is unit-tested without root and
   without `unsafe`.

The split is the whole point: **all security-relevant logic is testable
safe code; `unsafe` is reduced to a mechanical, audited application step.**

## 4. What is implemented now (this unit)

`archangel-sandbox`, no `unsafe`, fully unit-tested:

- `seccomp`: named profiles → a compiled `seccompiler` BPF program with
  `mismatch_action = KillProcess`. Profiles are concrete syscall allowlists
  defined in code (not data) so they cannot be widened by a bundle.
- `capability`: bundle capability strings → a validated `caps::Capability`
  set; unknown name rejected; default empty.
- `cgroup`: `cpu_max` ("`<n>%`") and `memory_max` ("`<n>{K,M,G}`" / bytes)
  → exact cgroup v2 file contents, with adversarial-input tests.
- `plan`: `SandboxPolicy` (decoupled input, mapped from the manifest by the
  executor) → validated `SandboxPlan` aggregating all of the above plus the
  namespace/network decision. Building the plan performs every fail-closed
  check in §2.
- `apply`: the single audited `unsafe` site (`Command::pre_exec`). In the
  forked child, just before `execve`, it latches `no_new_privs` and installs
  the compiled seccomp filter — two syscalls, no allocation on the success
  path. `archangel-execd` builds a plan from every verified bundle and
  refuses the action (`RejectStage::SandboxRejected`) if it cannot; the
  `BashRunner` then arms the child with it. Read-only actions are hardened
  too (defense in depth).

### Network: address-family restriction (not a blanket socket ban)

`socket(2)` is allowed **only** for `AF_UNIX` and `AF_NETLINK` (argument-
conditioned seccomp rules); every other family — notably `AF_INET` /
`AF_INET6` — hits the kill-on-mismatch default. This is the same posture as
systemd's `RestrictAddressFamilies=AF_UNIX AF_NETLINK`: a network socket can
never be *created*, so the connection-oriented ops (`connect`, `sendmsg`, …),
though permitted for the local-IPC fds glibc NSS needs, can never act on an
internet socket. Local user/group resolution (`getpwuid` via `nss_systemd`)
and interface enumeration (`__check_pf`) keep working; network egress stays
structurally impossible at the syscall layer (and #17 adds the kernel egress
filter on top).

## 5. Mutation enablement

Mutation is now **enabled**, gated by the executor's own mode ceiling — not
by the daemon's (T3, untrusted) `request.mode`. The executor reads
`modes.default` from its *own* config into a mutation ceiling (default, and
fail-closed, `read_only`). A `read_only = false` bundle runs only if that
ceiling permits mutation, **and** it still passes every other gate:

1. mutation gate (this ceiling),
2. denylist + allowlist (#8/#9),
3. snapshot (#16) — a `mutates_persistent_state` bundle gets a recovery point
   or is refused fail-closed,
4. sandbox (#11) — seccomp + cgroup limits, or refused.

So even a fully compromised daemon can, at most, run an operator-signed,
denylisted-checked, snapshotted, sandboxed bundle, and only when the host's
own config opted into mutation. Setting `modes.default = "read_only"` (the
shipped default) keeps the host strictly read-only regardless of any daemon
claim.

## 6. What is deferred (next unit)

- Mount-namespace path binding (`allowed_paths_ro` / `allowed_paths_rw`), the
  namespace `unshare` set, and the user-namespace uid/gid map. The enforced
  syscall surface (seccomp) already denies the escape vectors these would also
  block, and cgroup limits already bound resources.

Non-Linux targets compile `archangel-sandbox` as an explicit no-op stub so the
workspace still checks on a developer laptop; the stub can never be used to
*run* an action (it returns "unsupported", fail-closed).
