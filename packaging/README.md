# Packaging

> **Pre-alpha. Do not run in production.** No release exists; there has
> been no independent security audit. These packages exist so reviewers
> and testers can install a coherent layout, not so anyone can deploy
> archangel to a real server.

## What gets installed

| Package | Ships | Trust tier |
|---------|-------|------------|
| `archangeld` | daemon binary, `archangeld.service`, `/etc/archangel` tree, maintainer scripts (system users + dirs) | T3 |
| `archangel-execd` | executor binary, `archangel-execd.service` (depends on `archangeld`) | T2 |
| `archangelctl` | operator CLI | unprivileged |

The `archangeld` package's `postinst` creates the privilege-separated
identities (`archangel`, `archangel-exec`, `archangel-audit`) and the
state/log/config directories with least-privilege ownership. `prerm`
stops the services but **never** deletes the audit log, keys, or config —
destroying the tamper-evident trail on package removal would be exactly
the wrong default.

## Building packages

DEB (per crate, `cargo install cargo-deb` first):

```sh
cargo deb -p archangeld
cargo deb -p archangel-execd
cargo deb -p archangelctl
```

RPM (`cargo install cargo-generate-rpm`; build release binaries first):

```sh
cargo build --release -p archangeld -p archangel-execd -p archangelctl
cargo generate-rpm -p crates/archangeld
cargo generate-rpm -p crates/archangel-execd
cargo generate-rpm -p crates/archangelctl
```

Install `archangeld` first (it creates users/dirs), then `archangel-execd`.

## Running without packages (recommended for first tests)

You do **not** need packages to try archangel. Build the binaries and run
them directly — see the "First tests" runbook in the repository root
(`docs/FIRST_TESTS.md`). `archangelctl doctor` checks host readiness.

## Hardening notes

- The systemd units are already hardened (namespaces, seccomp filter,
  capability bounding set, `ProtectSystem=strict`, `IPAddressDeny=any`,
  etc.). Review them before enabling.
- LLM tokens are **never** read from config files. Pass them via systemd
  `LoadCredentialEncrypted=` (a drop-in) or the `ARCHANGEL_LLM_TOKEN`
  environment variable for manual runs.
- Per-action kernel sandboxing (threat-model layer #11) and filesystem
  snapshots (#16) land in v0.2; until then the executor uses only
  process-level hardening and runs read-only bundles.
