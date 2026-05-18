# Archangel — Per-action sandbox (threat-model layer #11)

> Status: **v0.2, partial.** The no-`unsafe`, fully-tested *plan* core is
> implemented in `archangel-sandbox`. The single audited syscall-application
> step is staged behind it and wired into `archangel-execd` in a following
> unit. This document is normative: it is the contract that step must meet.

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

## 5. What is deferred (next unit)

- The single `unsafe` `pre_exec` applier and its `// SAFETY:` block.
- Wiring the plan into `archangel-execd`'s runner (the executor builds a
  `SandboxPlan` from the verified manifest and refuses the action if it cannot).
- Enabling mutation: the executor's read-only invariant is only relaxed once
  **both** #11 (this) and #16 (snapshots, done) are enforced on the path.
- Mount-namespace path binding (`allowed_paths_ro` / `allowed_paths_rw`) and
  the user-namespace uid/gid map are scoped with the applier, not before it.

Non-Linux targets compile `archangel-sandbox` as an explicit no-op stub so the
workspace still checks on a developer laptop; the stub can never be used to
*run* an action (it returns "unsupported", fail-closed).
