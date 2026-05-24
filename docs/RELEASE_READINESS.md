# Archangel — v1.0 readiness assessment

_As of 2026-05-24 (v0.4.0). This is a deliberately conservative, honest
accounting — for a tool that grants an LLM bounded control of a Linux host,
overstating readiness is itself a security failure._

## What "v1.0" means here

v1.0 is **not** "the code is feature-complete." Per `docs/ROADMAP.md`, v1.0
requires, in addition to the engineering:

1. an **external security audit**,
2. a **public red-team campaign** (with bounty),
3. **two consecutive stable releases** with zero critical security issues, and
4. at least one **production deployment by an operator unaffiliated** with the
   maintainers.

None of these are achievable by writing more code; they are months of
external process and field exposure. They are the majority of the distance to
v1.0, and they have not started.

## Done (engineering)

The full **read-only → interactive → autonomous** spine is implemented and
tested end-to-end, validated on a real host. All threat-model layers have
working, fail-closed implementations:

- #1–#5 prompt-injection defenses (spotlighting, canary, per-task isolation,
  bounded structured output) — with a CI red-team corpus (#18).
- #6/#7 signed `.exec` bundles + arg schema; #8/#9 compiled denylist +
  allowlist; #15 hash-chained Ed25519 audit log.
- #10 privilege separation (T3 daemon ↔ T2 executor); #11 per-action sandbox
  (seccomp-bpf + capabilities + cgroup v2); #12 host-wide rate limits;
  #13/#14 approval + two-person; #16 snapshots; #17 egress allowlist +
  kernel-enforced drop-in.
- Autonomous mode: real-time log monitoring → cooldown → spotlight → model →
  full gate stack → sandboxed execution.
- Single audited `unsafe` site; `forbid(unsafe_code)` everywhere else;
  `-D warnings` clippy clean; ~300 tests green across the workspace in CI.

## Not done — engineering gaps (the achievable part)

These are real and in our control; they are hardening, not new capability:

- **Hostname-native egress proxy (#17, robust form).** Today's enforcer is
  IP-pinned via systemd (needs re-sync on CDN/DNS rotation). The proxy form
  is rotation-proof and port-aware.
- **Sandbox namespace refinement (#11).** Mount-bind of `allowed_paths`,
  the namespace `unshare` set, and the user-namespace uid/gid map are
  deferred; seccomp already denies the escape syscalls they would also block,
  but defense-in-depth wants them.
- **Clean-install validation on a fresh VM.** Four real packaging bugs were
  found and fixed during live install; a from-scratch VM run should confirm a
  clean install now works first-try.
- **Operator ergonomics.** Interactive approval delivery (TUI / `ntfy` /
  webhook); an autonomous-mode kill switch; an egress re-sync timer.
- **Optional:** WASM policy engine + allowlist signing (the compiled denylist
  + signed bundles cover current needs).

## Not done — the v1.0 gates (the hard part, external)

- External security audit — **not started**.
- Public red-team / bounty — **not started**.
- Two stable releases, zero critical issues — **not started** (this is the
  first functional milestone).
- Unaffiliated production deployment — **not started**.

## Percentage

- **Engineering toward a feature-complete, defensible cage: ~85–90%.** The
  cage works and is tested; the gaps above are hardening of known pieces.
- **Overall toward v1.0 as this project defines it: ~55–60%.** The remaining
  distance is dominated by the external, time-bound gates (audit, public
  red-team, a stable-release track record, real-world deployment), which code
  cannot shortcut.

## What it is safe for today

Lab, evaluation, and security research on hosts you can afford to rebuild —
ideally in `read_only` or `interactive` mode. **Not** production, **not**
unattended on a host you care about, until the v1.0 gates above are met. The
"pre-alpha, do not run in production" notice stands.
